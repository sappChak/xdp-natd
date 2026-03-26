use core::mem::{self};

use aya_ebpf::{
    bindings::{BPF_FIB_LOOKUP_DIRECT, bpf_fib_lookup},
    helpers::bpf_fib_lookup,
    programs::XdpContext,
};

use crate::{AF_INET, ConntrackValue};

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
    nat: &ConntrackValue,
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
                nat.dst_port.to_be() as u32,
            );
            *dst_port_ptr = nat.dst_port.to_be();

            *udp_check = csum_replace4(*udp_check as u32, *dst_addr_ptr, nat.dst_addr.to_be());

            if *udp_check == 0 {
                *udp_check = 0xFFFF;
            }
        }

        *ip_check = csum_replace4(*ip_check as u32, *dst_addr_ptr, nat.dst_addr.to_be());
        *dst_addr_ptr = nat.dst_addr.to_be();
    }
}

#[inline(always)]
pub unsafe fn apply_ip_snat(
    nat: &ConntrackValue,
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
                nat.src_port.to_be() as u32,
            );
            *src_port_ptr = nat.src_port.to_be();
            *udp_check = csum_replace4(*udp_check as u32, *src_addr_ptr, nat.src_addr.to_be());

            if *udp_check == 0 {
                *udp_check = 0xFFFF;
            }
        }
        *ip_check = csum_replace4(*ip_check as u32, *src_addr_ptr, nat.src_addr.to_be());
        *src_addr_ptr = nat.src_addr.to_be();
    }
}
