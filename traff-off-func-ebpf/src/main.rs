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
    bindings::{BPF_ANY, BPF_NOEXIST, xdp_action},
    macros::{map, xdp},
    maps::{DevMapHash, HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use traff_off_func_common::HostPair;
use traff_off_func_ebpf::{
    ConntrackKey, ConntrackValue, FibMacs, Flags,
    helpers::{apply_ip_dnat, apply_ip_snat, get_fib_macs, ptr_at, ptr_at_mut, rewrite_macs},
};

#[map(name = "REDIRECT_MAP")]
static REDIRECT_MAP: DevMapHash = DevMapHash::with_max_entries(256, 0);

#[map(name = "UDP_CONNTRACK")]
static UDP_CONNTRACK: LruHashMap<ConntrackKey, ConntrackValue> =
    LruHashMap::with_max_entries(256, 0);

#[map(name = "PORT_MAP")]
static PORT_MAP: HashMap<u32, HostPair> = HashMap::with_max_entries(256, 0);

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
        return Ok(xdp_code);
    }

    if proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_src_addr: *mut [u8; 6] = ptr_at_mut(ctx, offset_of!(EthHdr, src_addr))?;
    let eth_dst_addr: *mut [u8; 6] = ptr_at_mut(ctx, offset_of!(EthHdr, dst_addr))?;

    let nat = process_udp_nat(
        ctx,
        flag,
        src_ip,
        dst_ip,
        src_addr_ptr,
        dst_addr_ptr,
        eth_src_addr,
        proto,
    )?;

    // if none, then conntrack for dnat is missing
    let ConntrackValue {
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
fn process_udp_nat(
    ctx: &XdpContext,
    flag: Flags,
    src_ip: u32,
    dst_ip: u32,
    src_addr_ptr: *mut u32,
    dst_addr_ptr: *mut u32,
    eth_src_addr: *mut [u8; 6],
    proto: IpProto,
) -> Result<Option<ConntrackValue>, ()> {
    let src_port_ptr: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, src))?;
    let dst_port_ptr: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, dst))?;
    let ip_check: *mut u16 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, check))?;
    let udp_check: *mut u16 =
        ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check))?;

    let src_port: u16 = u16::from_be(unsafe { *src_port_ptr });
    let dst_port: u16 = u16::from_be(unsafe { *dst_port_ptr });

    let key = ConntrackKey::new(src_ip, dst_ip, src_port, dst_port);

    if flag == Flags::Snat {
        let nat = match unsafe { UDP_CONNTRACK.get(&key) } {
            Some(&value) => value,
            None => {
                let ingress_ifindex: u32 = ctx.ingress_ifindex() as u32;
                let tot_len_ptr: *const [u8; 2] =
                    ptr_at(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, tot_len))?;
                let tot_len: u16 = u16::from_be_bytes(unsafe { *tot_len_ptr });

                let (host_ip, host_port) = match unsafe { PORT_MAP.get(src_ip) } {
                    Some(pair) => (pair.host_ip, pair.host_port),
                    None => return Ok(None),
                };

                let Some(fib_macs) =
                    get_fib_macs(ctx, host_ip, dst_ip, proto, tot_len, ingress_ifindex)
                else {
                    return Ok(None);
                };

                let snat = ConntrackValue::new(host_ip, host_port, fib_macs, 0);
                let _ = UDP_CONNTRACK.insert(&key, snat, BPF_NOEXIST.into());

                let dkey = ConntrackKey::new(dst_ip, host_ip, dst_port, host_port);
                let return_macs = FibMacs {
                    fib_smac: fib_macs.fib_smac,
                    fib_dmac: unsafe { *eth_src_addr },
                };
                let dnat = ConntrackValue::new(src_ip, src_port, return_macs, src_ip);
                // BPF_ANY because key is the same, but destination port is different
                let _ = UDP_CONNTRACK.insert(&dkey, dnat, BPF_ANY.into());
                snat
            }
        };

        unsafe {
            apply_ip_snat(&nat, ip_check, udp_check, src_addr_ptr, src_port_ptr);
        }

        Ok(Some(nat))
    } else {
        let dnat = match unsafe { UDP_CONNTRACK.get(&key) } {
            Some(value) => value,
            None => return Ok(None),
        };

        unsafe {
            apply_ip_dnat(dnat, ip_check, udp_check, dst_addr_ptr, dst_port_ptr);
        }

        Ok(Some(*dnat))
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
