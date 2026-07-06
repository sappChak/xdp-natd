use anyhow::Result;

use crate::{
    ContainerMap, ExposeMap,
    api::{router::router, state::AppState},
    configuration::config::Configuration,
    port_allocator::PortAllocator,
};

async fn start_server(configuration: &Configuration, app: axum::Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{}",
        configuration.control_plane.host, configuration.control_plane.port
    ))
    .await
    .unwrap_or_else(|_| {
        eprintln!(
            "failed to bind to address: {}:{}",
            configuration.control_plane.host, configuration.control_plane.port
        );
        std::process::exit(1);
    });

    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
    Ok(())
}

pub async fn setup_axum_server(
    configuration: &Configuration,
    expose_map: ExposeMap,
    port_allocator: PortAllocator,
    containers: ContainerMap,
) -> Result<()> {
    let prefix = configuration.control_plane.prefix.clone();
    let state = AppState::new(expose_map, port_allocator, containers);
    let router = router(state, prefix);
    start_server(configuration, router).await?;
    Ok(())
}
