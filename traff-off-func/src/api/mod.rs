use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;

use crate::api::state::AppState;

pub mod expose;
pub mod health_check;
pub mod router;
pub mod server;
pub mod state;

pub type SharedAppState = Arc<RwLock<AppState>>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Not Found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Capacity Exhausted: {0}")]
    Capacity(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
