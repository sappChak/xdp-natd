use axum::{Router, http::Request, routing::get};
use tower_http::trace::TraceLayer;
use tracing::Level;

use crate::api::{health_check::*, state::AppState};

pub fn router(state: AppState, prefix: String) -> Router {
    let router = Router::new()
        .route("/health_check", get(health_check))
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
