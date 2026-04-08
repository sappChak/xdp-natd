use std::sync::Arc;

use crate::{ExposeMap, RevExposeMap};

#[derive(Clone)]
pub struct AppState {
    pub expose_map: Arc<ExposeMap>,
    pub rev_exposed_map: Arc<RevExposeMap>,
}

impl AppState {
    pub fn new(expose_map: ExposeMap, rev_exposed_map: RevExposeMap) -> Self {
        let expose_map = Arc::new(expose_map);
        let rev_exposed_map = Arc::new(rev_exposed_map);
        Self {
            expose_map,
            rev_exposed_map,
        }
    }
}
