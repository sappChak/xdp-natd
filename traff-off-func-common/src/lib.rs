#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

pub const TIMEOUT_NEW: u64 = 30_000_000_000;
pub const TIMEOUT_EST: u64 = 180_000_000_000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostInfo {
    pub host_ip: u32,
    pub host_port: u16,
    pub host_ifindex: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContainerInfo {
    pub container_ip: u32,
    pub container_mac: [u8; 6],
    pub container_port: u16,
    pub ifindex: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FibMacs {
    pub fib_smac: [u8; 6],
    pub fib_dmac: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectionTuple {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConnectionTuple {
    pub fn new(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NATData {
    pub nat_addr: u32,
    pub nat_port: u16,
    pub fib_macs: FibMacs,
    pub devmap_key: u32,
}

impl NATData {
    pub fn new(nat_addr: u32, nat_port: u16, fib_macs: FibMacs, devmap_key: u32) -> Self {
        Self {
            nat_addr,
            nat_port,
            fib_macs,
            devmap_key,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Direction {
    Original,
    Reply,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlowState {
    pub nat: NATData,
    pub direction: Direction,
    pub seen_reply: bool,
    pub timeout: u64,
}

impl FlowState {
    pub fn new(nat: NATData, direction: Direction, timeout: u64) -> Self {
        Self {
            nat,
            direction,
            seen_reply: false,
            timeout,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for HostInfo {}

#[cfg(feature = "user")]
unsafe impl Pod for ConnectionTuple {}

#[cfg(feature = "user")]
unsafe impl Pod for FlowState {}

#[cfg(feature = "user")]
unsafe impl Pod for ContainerInfo {}
