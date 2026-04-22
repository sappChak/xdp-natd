use std::{net::Ipv4Addr, process::Command};

use anyhow::{Context, anyhow, ensure};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use traff_off_func_common::{ContainerInfo, HostInfo};

use crate::api::{AppError, SharedAppState};

#[derive(serde::Deserialize)]
pub struct ExposeRequest {
    container_ip: Ipv4Addr,
    container_port: u16,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        #[derive(serde::Serialize)]
        struct ErrorResponse {
            message: String,
        }

        let (status, client_message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::Capacity(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            AppError::Internal(e) => {
                tracing::error!("internal server error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                )
            }
        };

        (
            status,
            Json(ErrorResponse {
                message: client_message,
            }),
        )
            .into_response()
    }
}

fn add_iptables_rule(host_port: u16, container_ip: u32, container_port: u16) -> anyhow::Result<()> {
    let status = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            &host_port.to_string(),
            "-j",
            "DNAT",
            "--to-destination",
            &format!("{}:{}", Ipv4Addr::from_bits(container_ip), container_port),
        ])
        .status()
        .context("failed to execute iptables command")?;

    ensure!(
        status.success(),
        "failed to add iptables TCP rule for port {}",
        host_port
    );

    Ok(())
}

#[tracing::instrument(name = "Expose container's port", skip(state, req))]
pub async fn expose_port(
    State(state): State<SharedAppState>,
    Json(req): Json<ExposeRequest>,
) -> Result<Response, AppError> {
    let mut lock = state.write().await;

    let container = lock
        .container_metas
        .get(&u32::from(req.container_ip))
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Container with IP {} doesn't exist",
                req.container_ip
            ))
        })?;

    let container_info = ContainerInfo {
        container_ip: u32::from(container.ipv4),
        container_mac: container.mac_address,
        container_port: req.container_port,
        ifindex: container.ifindex,
    };

    let host_port = lock
        .port_allocator
        .allocate_next()
        .ok_or_else(|| AppError::Capacity("No available host ports left".to_string()))?;

    let (host_ip, host_ifindex) = lock.nic_info;
    let host_info = HostInfo {
        host_ip,
        host_port,
        host_ifindex,
    };

    if lock
        .rev_expose_map
        .get(&container_info.container_port, 0)
        .is_ok()
    {
        lock.port_allocator.deallocate(host_port);
        return Err(AppError::Conflict(
            "Container port is already exposed".to_string(),
        ));
    }

    if let Err(e) = lock
        .rev_expose_map
        .insert(container_info.container_port, host_info, 1)
    {
        lock.port_allocator.deallocate(host_port);
        return Err(anyhow::anyhow!("Failed to insert into rev_expose_map: {}", e).into());
    }

    if let Err(e) = lock.expose_map.insert(host_port, container_info, 1) {
        let _ = lock.rev_expose_map.remove(&container_info.container_port);
        lock.port_allocator.deallocate(host_port);
        return Err(anyhow!(
            "Failed to insert host port {} into expose_map: {}",
            host_port,
            e
        )
        .into());
    }

    if let Err(e) = add_iptables_rule(
        host_port,
        container_info.container_ip,
        container_info.container_port,
    ) {
        let _ = lock.rev_expose_map.remove(&container_info.container_port);
        let _ = lock.expose_map.remove(&host_port);
        lock.port_allocator.deallocate(host_port);
        return Err(anyhow!(
            "Failed to expose tcp port {} via iptables: {}",
            host_port,
            e
        )
        .into());
    }

    tracing::info!(
        "exposing container {}:{} on port: {}",
        Ipv4Addr::from_bits(container_info.container_ip),
        container_info.container_port,
        host_port
    );

    let response_message = format!(
        "exposing container port {} on host port {}",
        req.container_port, host_port
    );

    Ok((axum::http::StatusCode::OK, response_message).into_response())
}

fn remove_iptables_rule(
    host_port: u16,
    container_ip: u32,
    container_port: u16,
) -> anyhow::Result<()> {
    let status = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            &host_port.to_string(),
            "-j",
            "DNAT",
            "--to-destination",
            &format!("{}:{}", Ipv4Addr::from_bits(container_ip), container_port),
        ])
        .status()
        .context("failed to execute iptables command")?;

    ensure!(
        status.success(),
        "failed to remove iptables TCP rule for port {}",
        host_port
    );

    Ok(())
}

#[tracing::instrument(name = "Unexpose container's port", skip(state))]
pub async fn unexpose_port(
    State(state): State<SharedAppState>,
    Path(host_port): Path<u16>,
) -> Result<Response, AppError> {
    let mut lock = state.write().await;

    let container_info = match lock.expose_map.get(&host_port, 0) {
        Ok(info) => info,
        Err(_) => {
            return Err(AppError::NotFound(format!(
                "Host port {} is not currently exposed",
                host_port
            )));
        }
    };

    if let Err(e) = remove_iptables_rule(
        host_port,
        container_info.container_ip,
        container_info.container_port,
    ) {
        return Err(AppError::Internal(anyhow::anyhow!(
            "Failed to remove iptables rule: {}",
            e
        )));
    }

    let _ = lock.expose_map.remove(&host_port);
    let _ = lock.rev_expose_map.remove(&container_info.container_port);

    lock.port_allocator.deallocate(host_port);

    tracing::info!("successfully unexposed host port {}", host_port);

    Ok((
        axum::http::StatusCode::OK,
        format!("Unexposed host port {}", host_port),
    )
        .into_response())
}
