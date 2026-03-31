use std::ops::RangeInclusive;
use std::collections::VecDeque;


pub struct PortAllocator {
    ports: VecDeque<u16>,
}

impl PortAllocator {
    pub fn new(range: RangeInclusive<u16>) -> Self {
        let ports: VecDeque<u16> = range.collect();
        Self { ports }
    }

    pub fn allocate_next(&mut self) -> Option<u16> {
        println!("the length is: {}", self.ports.len());
        self.ports.pop_back()
    }
}
