#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct HostPair {
    pub host_ip: u32,
    pub host_port: u16,
}

#[cfg(feature = "user")]
unsafe impl Pod for HostPair {}
