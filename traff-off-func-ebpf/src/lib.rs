#![no_std]

pub mod helpers;

pub const NF_CONNTRACK_MAX: u32 = 256;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

// The goal is to match incoming 5-tuple:
// SNAT: outgoing: <container_ip, external_ip, container_port, external_port, proto> -> <host_ip,
// external_ip, host_port, external_port, timer>
// DNAT: incoming: <external_ip, host_ip, external_port, host_port, proto> -> <host_ip, container_ip,
// host_port, container_port, timer>
// When creating an entry in the custom conntrack table, insert entries for both ingress and
// egress directions

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

#[derive(Default)]
pub struct ConntrackValue {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub mac: Option<[u8; 6]>,
}

impl ConntrackValue {
    pub fn new(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16, mac: Option<[u8; 6]>) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            mac
        }
    }
}
