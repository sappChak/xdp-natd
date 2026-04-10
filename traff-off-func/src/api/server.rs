use anyhow::Result;

use crate::{
    ContainersMap, ExposeMap, RevExposeMap,
    api::{router::router, state::AppState},
    configuration::config::Configuration,
    port_allocator::PortAllocator,
};

async fn start_server(configuration: &Configuration, app: axum::Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{}",
        configuration.application.host, configuration.application.port
    ))
    .await
    .unwrap_or_else(|_| {
        eprintln!(
            "failed to bind to address: {}:{}",
            configuration.application.host, configuration.application.port
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
    rev_expose_map: RevExposeMap,
    port_allocator: PortAllocator,
    containers: ContainersMap,
    nic_addr: u32,
) -> Result<()> {
    let prefix = configuration.application.prefix.clone();
    let state = AppState::new(
        expose_map,
        rev_expose_map,
        port_allocator,
        containers,
        nic_addr,
    );
    let router = router(state, prefix);
    start_server(configuration, router).await?;
    Ok(())
}
