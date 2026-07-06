use std::{collections::VecDeque, ops::RangeInclusive};

pub struct PortAllocator {
    ports: VecDeque<u16>,
}

impl PortAllocator {
    pub fn new(range: RangeInclusive<u16>) -> Self {
        let ports: VecDeque<u16> = range.collect();
        Self { ports }
    }

    pub fn allocate_next(&mut self) -> Option<u16> {
        self.ports.pop_front()
    }

    pub fn deallocate(&mut self, port: u16) {
        self.ports.push_back(port);
    }
}
