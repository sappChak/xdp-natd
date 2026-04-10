use std::sync::Arc;

use axum::{
    Router,
    http::Request,
    routing::{delete, get, post},
};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::Level;

use crate::api::{
    expose::{expose_port, unexpose_port},
    health_check::*,
    state::AppState,
};

pub fn router(state: AppState, prefix: String) -> Router {
    let state = Arc::new(RwLock::new(state));
    let router = Router::new()
        .route("/health_check", get(health_check))
        .route("/expose", post(expose_port))
        .route("/unexpose/{:port}", delete(unexpose_port))
        .with_state(state)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let request_id = uuid::Uuid::new_v4();
                tracing::span!(
                    Level::DEBUG,
                    "request",
                    %request_id,
                    method = ?request.method(),
                    uri = %request.uri(),
                    version = ?request.version(),
                )
            }),
        );
    Router::new().nest(prefix.as_str(), router)
}
