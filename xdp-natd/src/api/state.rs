use crate::{ContainerMap, ExposeMap, port_allocator::PortAllocator};

pub struct AppState {
    pub expose_map: ExposeMap,
    pub port_allocator: PortAllocator,
    pub container_metas: ContainerMap,
}

impl AppState {
    pub fn new(
        expose_map: ExposeMap,
        port_allocator: PortAllocator,
        container_metas: ContainerMap,
    ) -> Self {
        Self {
            expose_map,
            port_allocator,
            container_metas,
        }
    }
}
