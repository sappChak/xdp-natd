#![no_std]

pub mod helpers;

pub const NF_CONNTRACK_MAX: u32 = 256;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

#[derive(PartialEq, Eq)]
pub enum Flags {
    Snat,
    Dnat,
}

#[derive(Default, Clone, Copy)]
pub struct FibMacs {
    pub fib_smac: [u8; 6],
    pub fib_dmac: [u8; 6],
}

pub struct ConntrackKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConntrackKey {
    pub fn new(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        }
    }
}

#[derive(Default, Clone, Copy)]
pub struct ConntrackValue {
    pub nat_addr: u32,
    pub nat_port: u16,
    pub fib_macs: FibMacs,
    pub devmap_key: u32,
}

impl ConntrackValue {
    pub fn new(nat_addr: u32, nat_port: u16, fib_macs: FibMacs, devmap_key: u32) -> Self {
        Self {
            nat_addr,
            nat_port,
            fib_macs,
            devmap_key,
        }
    }
}
