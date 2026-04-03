#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn
)]
use core::mem::offset_of;

use aya_ebpf::{
    bindings::{BPF_NOEXIST, xdp_action},
    helpers::generated::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, DevMapHash, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use traff_off_func_common::{
    ConnectionTuple, ContainerInfo, Direction, FibMacs, FlowState, NATData, TIMEOUT_EST,
    TIMEOUT_NEW,
};
use traff_off_func_ebpf::{
    Flags,
    helpers::{apply_ip_dnat, apply_ip_snat, get_fib_macs, ptr_at, ptr_at_mut, rewrite_macs},
};

#[map(name = "REDIRECT_MAP")]
static REDIRECT_MAP: DevMapHash = DevMapHash::with_max_entries(256, 0);

#[map(name = "UDP_CONNTRACK")]
static UDP_CONNTRACK: LruHashMap<ConnectionTuple, FlowState> = LruHashMap::with_max_entries(256, 0);

#[map(name = "PNIC_IP_ARRAY")]
static PNIC_IP_ARRAY: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "EXPOSE_MAP")]
static EXPOSE_MAP: LruHashMap<u16, ContainerInfo> = LruHashMap::with_max_entries(256, 0);

#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn xdp_redirect_containers(ctx: XdpContext) -> u32 {
    try_xdp_redirect(&ctx, Flags::Snat).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
pub fn xdp_redirect_host(ctx: XdpContext) -> u32 {
    try_xdp_redirect(&ctx, Flags::Dnat).unwrap_or(xdp_action::XDP_ABORTED)
}

#[inline(always)]
fn try_xdp_redirect(ctx: &XdpContext, flag: Flags) -> Result<u32, ()> {
    let ether_type_ptr: *const EtherType = ptr_at(ctx, offset_of!(EthHdr, ether_type))?;
    match unsafe { *ether_type_ptr } {
        EtherType::Ipv4 => handle_ip_redirect(ctx, flag),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn handle_ip_redirect(ctx: &XdpContext, flag: Flags) -> Result<u32, ()> {
    let src_addr_ptr: *mut u32 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, src_addr))?;
    let dst_addr_ptr: *mut u32 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr))?;
    let ipv4_proto_ptr: *const IpProto = ptr_at(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, proto))?;

    let src_ip: u32 = u32::from_be(unsafe { *src_addr_ptr });
    let dst_ip: u32 = u32::from_be(unsafe { *dst_addr_ptr });
    let proto: IpProto = unsafe { *ipv4_proto_ptr };

    if !matches!(proto, IpProto::Udp | IpProto::Tcp | IpProto::Icmp) {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Ok(xdp_code) = REDIRECT_MAP.redirect(dst_ip, xdp_action::XDP_PASS.into()) {
        return Ok(xdp_code); // XDP_REDIRECT
    }

    if proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_src_addr: *mut [u8; 6] = ptr_at_mut(ctx, offset_of!(EthHdr, src_addr))?;
    let eth_dst_addr: *mut [u8; 6] = ptr_at_mut(ctx, offset_of!(EthHdr, dst_addr))?;

    let nat = if flag == Flags::Snat {
        process_udp_snat(ctx, src_ip, dst_ip, src_addr_ptr, eth_src_addr, proto)?
    } else {
        process_udp_dnat(ctx, src_ip, dst_ip, dst_addr_ptr, proto)?
    };

    // if none, then conntrack for dnat is missing
    let NATData {
        fib_macs,
        devmap_key,
        ..
    } = match nat {
        Some(key) => key,
        None => return Ok(xdp_action::XDP_PASS),
    };

    unsafe {
        rewrite_macs(ctx, eth_src_addr, eth_dst_addr, fib_macs);
    }

    match REDIRECT_MAP.redirect(devmap_key, xdp_action::XDP_PASS.into()) {
        Ok(code) => {
            debug!(
                ctx,
                "successfully redirecting based on the existing entry: {}", devmap_key
            );
            Ok(code)
        }
        Err(code) => {
            debug!(ctx, "something went wrong");
            Ok(code)
        }
    }
}

#[inline(always)]
fn process_udp_snat(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    src_addr_ptr: *mut u32,
    eth_src_addr: *mut [u8; 6],
    proto: IpProto,
) -> Result<Option<NATData>, ()> {
    let src_port_ptr: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, src))?;
    let dst_port_ptr: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, dst))?;
    let ip_check: *mut u16 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, check))?;
    let udp_check: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check))?;

    let src_port: u16 = u16::from_be(unsafe { *src_port_ptr });
    let dst_port: u16 = u16::from_be(unsafe { *dst_port_ptr });

    let key = ConnectionTuple::new(src_ip, dst_ip, src_port, dst_port);
    let time: u64 = unsafe { bpf_ktime_get_ns() };

    if let Some(state_ptr) = UDP_CONNTRACK.get_ptr_mut(key) {
        let state = unsafe { &mut *state_ptr };

        match state.direction {
            Direction::Original => {
                state.timeout = time
                    + if state.seen_reply {
                        TIMEOUT_EST
                    } else {
                        TIMEOUT_NEW
                    };
            }
            Direction::Reply => {
                state.seen_reply = true;
                state.timeout = time + TIMEOUT_EST;
            }
        }

        let snat = state.nat;

        unsafe {
            apply_ip_snat(&snat, ip_check, udp_check, src_addr_ptr, src_port_ptr);
        }

        let dkey = ConnectionTuple::new(dst_ip, snat.nat_addr, dst_port, snat.nat_port);
        if let Some(rev_ptr) = UDP_CONNTRACK.get_ptr_mut(dkey) {
            let rev_conn = unsafe { &mut *rev_ptr };
            rev_conn.seen_reply = state.seen_reply;
            rev_conn.timeout = state.timeout;
        }

        return Ok(Some(state.nat));
    }

    // TODO: what about host-level iperf3 -c?
    let remote_ip = dst_ip;
    let remote_port = dst_port;

    let ingress_ifindex: u32 = ctx.ingress_ifindex() as u32;
    let tot_len_ptr: *const [u8; 2] = ptr_at(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, tot_len))?;
    let tot_len: u16 = u16::from_be_bytes(unsafe { *tot_len_ptr });
    let container_mac = unsafe { *eth_src_addr };

    let (host_ip, host_port) = match PNIC_IP_ARRAY.get(0) {
        Some(ip) => (*ip, src_port), // TODO: a small chance of collision
        None => return Ok(None),
    };

    let fib_macs = if let Some(fib_macs) =
        get_fib_macs(ctx, host_ip, remote_ip, proto, tot_len, ingress_ifindex)
    {
        fib_macs
    } else {
        return Ok(None);
    };

    let snat = NATData::new(host_ip, host_port, fib_macs, 0);

    let return_macs = FibMacs {
        fib_smac: fib_macs.fib_smac,
        fib_dmac: container_mac,
    };

    let dnat = NATData::new(src_ip, src_port, return_macs, src_ip);

    let dkey = ConnectionTuple::new(remote_ip, host_ip, remote_port, host_port);
    let conn_orig = FlowState::new(snat, Direction::Original, time + TIMEOUT_NEW);
    let conn_reply = FlowState::new(dnat, Direction::Reply, time + TIMEOUT_NEW);

    let _ = UDP_CONNTRACK.insert(key, conn_orig, BPF_NOEXIST.into());
    let _ = UDP_CONNTRACK.insert(dkey, conn_reply, BPF_NOEXIST.into());

    unsafe {
        apply_ip_snat(&snat, ip_check, udp_check, src_addr_ptr, src_port_ptr);
    }

    Ok(Some(snat))
}

#[inline(always)]
fn process_udp_dnat(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    dst_addr_ptr: *mut u32,
    proto: IpProto,
) -> Result<Option<NATData>, ()> {
    let src_port_ptr: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, src))?;
    let dst_port_ptr: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, dst))?;
    let ip_check: *mut u16 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, check))?;
    let udp_check: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check))?;

    let src_port: u16 = u16::from_be(unsafe { *src_port_ptr });
    let dst_port: u16 = u16::from_be(unsafe { *dst_port_ptr });

    let key = ConnectionTuple::new(src_ip, dst_ip, src_port, dst_port);
    let time: u64 = unsafe { bpf_ktime_get_ns() };

    if let Some(state_ptr) = UDP_CONNTRACK.get_ptr_mut(key) {
        let state = unsafe { &mut *state_ptr };

        match state.direction {
            Direction::Original => {
                state.timeout = time
                    + if state.seen_reply {
                        TIMEOUT_EST
                    } else {
                        TIMEOUT_NEW
                    };
            }
            Direction::Reply => {
                state.seen_reply = true;
                state.timeout = time + TIMEOUT_EST;
            }
        }

        let dnat = state.nat;

        unsafe {
            apply_ip_dnat(&dnat, ip_check, udp_check, dst_addr_ptr, dst_port_ptr);
        }

        let skey = ConnectionTuple::new(dnat.nat_addr, src_ip, dnat.nat_port, src_port);
        if let Some(rev_ptr) = UDP_CONNTRACK.get_ptr_mut(skey) {
            let rev_conn = unsafe { &mut *rev_ptr };
            rev_conn.seen_reply = state.seen_reply;
            rev_conn.timeout = state.timeout;
        }

        return Ok(Some(dnat));
    }

    let remote_ip = src_ip;
    let remote_port = src_port;
    let host_ip = dst_ip;
    let host_port = dst_port;

    let ContainerInfo {
        container_ip,
        container_mac,
        container_port,
    } = match unsafe { EXPOSE_MAP.get(host_port) } {
        Some(info) => *info,
        None => return Ok(None), // not an exposed service, pass
    };

    let ingress_ifindex: u32 = ctx.ingress_ifindex() as u32;
    let tot_len_ptr: *const [u8; 2] = ptr_at(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, tot_len))?;
    let tot_len: u16 = u16::from_be_bytes(unsafe { *tot_len_ptr });

    let Some(fib_macs) = get_fib_macs(ctx, host_ip, remote_ip, proto, tot_len, ingress_ifindex)
    else {
        return Ok(None);
    };

    let snat = NATData::new(host_ip, host_port, fib_macs, 0);

    let return_macs = FibMacs {
        fib_smac: fib_macs.fib_smac,
        fib_dmac: container_mac,
    };
    let dnat = NATData::new(container_ip, container_port, return_macs, container_ip);

    let fwd_key = ConnectionTuple::new(remote_ip, host_ip, remote_port, host_port);
    let rev_key = ConnectionTuple::new(container_ip, remote_ip, container_port, remote_port);

    let conn_orig = FlowState::new(dnat, Direction::Original, time + TIMEOUT_NEW);
    let conn_reply = FlowState::new(snat, Direction::Reply, time + TIMEOUT_NEW);

    let _ = UDP_CONNTRACK.insert(fwd_key, conn_orig, BPF_NOEXIST.into());
    let _ = UDP_CONNTRACK.insert(rev_key, conn_reply, BPF_NOEXIST.into());

    unsafe {
        apply_ip_dnat(&dnat, ip_check, udp_check, dst_addr_ptr, dst_port_ptr);
    }

    Ok(Some(dnat))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
