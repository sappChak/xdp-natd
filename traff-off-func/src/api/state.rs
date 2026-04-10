use crate::{ContainersMap, ExposeMap, RevExposeMap, port_allocator::PortAllocator};

pub struct AppState {
    pub expose_map: ExposeMap,
    pub rev_expose_map: RevExposeMap,
    pub port_allocator: PortAllocator,
    pub container_metas: ContainersMap,
    pub nic_addr: u32,
}

impl AppState {
    pub fn new(
        expose_map: ExposeMap,
        rev_exposed_map: RevExposeMap,
        port_allocator: PortAllocator,
        container_metas: ContainersMap,
        nic_addr: u32,
    ) -> Self {
        Self {
            expose_map,
            rev_expose_map: rev_exposed_map,
            port_allocator,
            container_metas,
            nic_addr,
        }
    }
}
