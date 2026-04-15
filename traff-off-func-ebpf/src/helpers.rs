#![allow(clippy::missing_safety_doc)]
use core::mem::{self};

use aya_ebpf::{
    bindings::{BPF_FIB_LOOKUP_DIRECT, bpf_fib_lookup},
    helpers::bpf_fib_lookup,
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::ip::IpProto;
use traff_off_func_common::{FibMacs, NATData};

use crate::AF_INET;

#[inline(always)]
fn csum_add(csum: u32, addend: u32) -> u32 {
    let res = csum.wrapping_add(addend);
    res.wrapping_add((res < addend) as u32)
}

#[inline(always)]
fn csum_fold(mut csum: u32) -> u16 {
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    !(csum as u16)
}

#[inline(always)]
pub fn csum_replace4(csum: u32, from: u32, to: u32) -> u16 {
    let tmp = csum_add(!csum, !from);
    csum_fold(csum_add(tmp, to))
}

#[inline(always)]
pub fn do_fib_lookup(
    ctx: &XdpContext,
    fib: &mut bpf_fib_lookup,
    proto: u8,
    saddr: u32,
    daddr: u32,
    tot_len: u16,
    ifindex: u32,
) -> i64 {
    fib.family = AF_INET;
    fib.l4_protocol = proto;
    fib.__bindgen_anon_3.ipv4_src = saddr;
    fib.__bindgen_anon_4.ipv4_dst = daddr;
    fib.__bindgen_anon_1.tot_len = tot_len;
    fib.ifindex = ifindex;

    // BPF_FIB_LOOKUP_DIRECT - lookup without policy checks, better perf
    unsafe {
        bpf_fib_lookup(
            ctx.ctx as *mut _,
            fib,
            core::mem::size_of_val(fib) as i32,
            BPF_FIB_LOOKUP_DIRECT,
        )
    }
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start: usize = ctx.data();
    let end: usize = ctx.data_end();
    let len: usize = mem::size_of::<T>();

    if start + len + offset > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start: usize = ctx.data();
    let end: usize = ctx.data_end();
    let len: usize = mem::size_of::<T>();

    if start + len + offset > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub unsafe fn apply_ip_dnat(
    nat: &NATData,
    ip_check: *mut u16,
    udp_check: *mut u16,
    dst_addr_ptr: *mut u32,
    dst_port_ptr: *mut u16,
) {
    unsafe {
        if *udp_check != 0 {
            *udp_check = csum_replace4(
                *udp_check as u32,
                *dst_port_ptr as u32,
                nat.nat_port.to_be() as u32,
            );
            *dst_port_ptr = nat.nat_port.to_be();

            *udp_check = csum_replace4(*udp_check as u32, *dst_addr_ptr, nat.nat_addr.to_be());

            if *udp_check == 0 {
                *udp_check = 0xFFFF;
            }
        }

        *ip_check = csum_replace4(*ip_check as u32, *dst_addr_ptr, nat.nat_addr.to_be());
        *dst_addr_ptr = nat.nat_addr.to_be();
    }
}

#[inline(always)]
pub unsafe fn apply_ip_snat(
    nat: &NATData,
    ip_check: *mut u16,
    udp_check: *mut u16,
    src_addr_ptr: *mut u32,
    src_port_ptr: *mut u16,
) {
    unsafe {
        if *udp_check != 0 {
            *udp_check = csum_replace4(
                *udp_check as u32,
                *src_port_ptr as u32,
                nat.nat_port.to_be() as u32,
            );
            *src_port_ptr = nat.nat_port.to_be();
            *udp_check = csum_replace4(*udp_check as u32, *src_addr_ptr, nat.nat_addr.to_be());

            if *udp_check == 0 {
                *udp_check = 0xFFFF;
            }
        }
        *ip_check = csum_replace4(*ip_check as u32, *src_addr_ptr, nat.nat_addr.to_be());
        *src_addr_ptr = nat.nat_addr.to_be();
    }
}

#[inline(always)]
pub fn log_fib_lookup(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) {
    debug!(
        &ctx,
        "performing fib lookup for src_ip: {}.{}.{}.{} dst_ip: {}.{}.{}.{} proto: {} tot_len: {} ingress_ifindex: {}",
        (src_ip >> 24) & 0xFF,
        (src_ip >> 16) & 0xFF,
        (src_ip >> 8) & 0xFF,
        src_ip & 0xFF,
        (dst_ip >> 24) & 0xFF,
        (dst_ip >> 16) & 0xFF,
        (dst_ip >> 8) & 0xFF,
        dst_ip & 0xFF,
        proto as u8,
        tot_len,
        ingress_ifindex
    );
}

#[inline(always)]
pub unsafe fn log_mac_address_change(
    ctx: &XdpContext,
    eth_src_addr: *mut [u8; 6],
    eth_dst_addr: *mut [u8; 6],
    new_src_mac: [u8; 6],
    new_dst_mac: [u8; 6],
) {
    unsafe {
        debug!(
            &ctx,
            "changing eth src addr from {}.{}.{}.{}.{}.{} to {}.{}.{}.{}.{}.{}",
            (*eth_src_addr)[0],
            (*eth_src_addr)[1],
            (*eth_src_addr)[2],
            (*eth_src_addr)[3],
            (*eth_src_addr)[4],
            (*eth_src_addr)[5],
            new_src_mac[0],
            new_src_mac[1],
            new_src_mac[2],
            new_src_mac[3],
            new_src_mac[4],
            new_src_mac[5]
        );
        debug!(
            &ctx,
            "changing eth dst addr from {}.{}.{}.{}.{}.{} to {}.{}.{}.{}.{}.{}",
            (*eth_dst_addr)[0],
            (*eth_dst_addr)[1],
            (*eth_dst_addr)[2],
            (*eth_dst_addr)[3],
            (*eth_dst_addr)[4],
            (*eth_dst_addr)[5],
            new_dst_mac[0],
            new_dst_mac[1],
            new_dst_mac[2],
            new_dst_mac[3],
            new_dst_mac[4],
            new_dst_mac[5]
        );
    }
}

#[inline(always)]
pub fn get_fib_macs(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) -> Option<FibMacs> {
    let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };
    log_fib_lookup(ctx, src_ip, dst_ip, proto, tot_len, ingress_ifindex);

    let rc = do_fib_lookup(
        ctx,
        &mut fib,
        proto as u8,
        src_ip,
        dst_ip,
        tot_len,
        ingress_ifindex,
    );

    if rc != 0 {
        return None;
    }

    Some(FibMacs {
        fib_smac: fib.smac,
        fib_dmac: fib.dmac,
    })
}

#[inline(always)]
pub unsafe fn rewrite_macs(
    ctx: &XdpContext,
    eth_src_addr: *mut [u8; 6],
    eth_dst_addr: *mut [u8; 6],
    fib: FibMacs,
) {
    let fib_smac = fib.fib_smac;
    let fib_dmac = fib.fib_dmac;
    unsafe {
        log_mac_address_change(ctx, eth_src_addr, eth_dst_addr, fib_smac, fib_dmac);
        *eth_src_addr = fib_smac;
        *eth_dst_addr = fib_dmac;
    }
}
