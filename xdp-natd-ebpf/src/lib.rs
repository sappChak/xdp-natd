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
