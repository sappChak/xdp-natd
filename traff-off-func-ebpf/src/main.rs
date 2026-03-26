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
    bindings::{BPF_NOEXIST, bpf_fib_lookup, xdp_action},
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
use traff_off_func_ebpf::{
    ConntrackKey, ConntrackValue,
    helpers::{apply_ip_dnat, apply_ip_snat, do_fib_lookup, ptr_at, ptr_at_mut},
};

#[map(name = "REDIRECT_MAP")]
static REDIRECT_MAP: DevMapHash = DevMapHash::with_max_entries(256, 0);

#[map(name = "UDP_CONNTRACK")]
static UDP_CONNTRACK: LruHashMap<ConntrackKey, ConntrackValue> =
    LruHashMap::with_max_entries(256, 0);

#[map(name = "PNIC_IP_ARRAY")]
static PNIC_IP_ARRAY: Array<u32> = Array::with_max_entries(16, 0);

#[derive(PartialEq, Eq)]
enum Flags {
    Snat,
    Dnat,
}

#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn xdp_redirect_containers(ctx: XdpContext) -> u32 {
    match try_xdp_redirect(&ctx, Flags::Snat) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[xdp]
pub fn xdp_redirect_host(ctx: XdpContext) -> u32 {
    match try_xdp_redirect(&ctx, Flags::Dnat) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn handle_ip_redirect(ctx: &XdpContext, flag: Flags) -> Result<u32, ()> {
    let eth_src_addr: *mut [u8; 6] = ptr_at_mut(ctx, offset_of!(EthHdr, src_addr))?;
    let eth_dst_addr: *mut [u8; 6] = ptr_at_mut(ctx, offset_of!(EthHdr, dst_addr))?;

    let src_addr_ptr: *mut u32 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, src_addr))?;
    let dst_addr_ptr: *mut u32 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr))?;
    let tot_len_ptr: *const [u8; 2] = ptr_at(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, tot_len))?;
    let ipv4_proto_ptr: *const IpProto = ptr_at(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, proto))?;
    let ip_check: *mut u16 = ptr_at_mut(ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, check))?;

    let src_ip: u32 = u32::from_be(unsafe { *src_addr_ptr });
    let dst_ip: u32 = u32::from_be(unsafe { *dst_addr_ptr });
    let tot_len: u16 = u16::from_be_bytes(unsafe { *tot_len_ptr });
    let ingress_ifindex: u32 = ctx.ingress_ifindex() as u32;
    let proto: IpProto = unsafe { *ipv4_proto_ptr };

    match proto {
        IpProto::Udp | IpProto::Tcp | IpProto::Icmp => {
            match REDIRECT_MAP.redirect(dst_ip, xdp_action::XDP_PASS.into()) {
                Ok(xdp_code) => Ok(xdp_code),
                Err(xdp_code) => {
                    // destination IP is not container's IP, so NAT
                    if proto == IpProto::Udp {
                        let src_port_ptr: *mut u16 =
                            ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, src))?;
                        let dst_port_ptr: *mut u16 =
                            ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, dst))?;
                        let udp_check: *mut u16 = ptr_at_mut(
                            ctx,
                            EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check),
                        )?;

                        let src_port: u16 = u16::from_be(unsafe { *src_port_ptr });
                        let dst_port: u16 = u16::from_be(unsafe { *dst_port_ptr });

                        let key = ConntrackKey::new(src_ip, dst_ip, src_port, dst_port);
                        let redirect_key: (u32, Option<[u8; 6]>);

                        if flag == Flags::Snat {
                            redirect_key = (0, None);
                            // TODO: every registered container has to get it's own host port, which is
                            // preallocated from userspace
                            let (host_ip, host_port) = match PNIC_IP_ARRAY.get(0) {
                                Some(ip) => {
                                    (*ip, 8088) // port is hardcoded for testing (for now)
                                }
                                None => return Ok(xdp_action::XDP_PASS),
                            };

                            let snat =
                                ConntrackValue::new(host_ip, dst_ip, host_port, dst_port, None);
                            let nat: &ConntrackValue = match unsafe { UDP_CONNTRACK.get(&key) } {
                                Some(value) => value,
                                None => {
                                    UDP_CONNTRACK
                                        .insert(&key, &snat, BPF_NOEXIST.into())
                                        .unwrap_or_default();
                                    let dkey =
                                        ConntrackKey::new(dst_ip, host_ip, dst_port, host_port);
                                    let dnat = ConntrackValue::new(
                                        host_ip,
                                        src_ip,
                                        host_port,
                                        src_port,
                                        Some(unsafe { *eth_src_addr }),
                                    );
                                    UDP_CONNTRACK
                                        .insert(dkey, dnat, BPF_NOEXIST.into())
                                        .unwrap_or_default();
                                    &snat
                                }
                            };
                            unsafe {
                                apply_ip_snat(nat, ip_check, udp_check, src_addr_ptr, src_port_ptr);
                            }
                        } else {
                            let dnat: &ConntrackValue = match unsafe { UDP_CONNTRACK.get(&key) } {
                                Some(value) => value,
                                None => return Ok(xdp_action::XDP_PASS),
                            };
                            redirect_key = (dnat.dst_addr, dnat.mac);
                            unsafe {
                                apply_ip_dnat(
                                    dnat,
                                    ip_check,
                                    udp_check,
                                    dst_addr_ptr,
                                    dst_port_ptr,
                                );
                            }
                        }

                        let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };

                        let src_ip: u32 = u32::from_be(unsafe { *src_addr_ptr });
                        let dst_ip: u32 = u32::from_be(unsafe { *dst_addr_ptr });

                        debug!(
                            &ctx,
                            "performing fib lookup for src_ip: {}.{}.{}.{} dst_ip: {}.{}.{}.{} proto: {}",
                            (src_ip >> 24) & 0xFF,
                            (src_ip >> 16) & 0xFF,
                            (src_ip >> 8) & 0xFF,
                            src_ip & 0xFF,
                            (dst_ip >> 24) & 0xFF,
                            (dst_ip >> 16) & 0xFF,
                            (dst_ip >> 8) & 0xFF,
                            dst_ip & 0xFF,
                            proto as u8
                        );

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
                            debug!(&ctx, "haven't found a route");
                            return Ok(xdp_action::XDP_PASS);
                        }

                        debug!(&ctx, "suggested egress ifindex by fib is: {}", fib.ifindex);

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
                                fib.smac[0],
                                fib.smac[1],
                                fib.smac[2],
                                fib.smac[3],
                                fib.smac[4],
                                fib.smac[5]
                            );
                            *eth_src_addr = fib.smac;
                            debug!(
                                &ctx,
                                "changing eth dst addr from {}.{}.{}.{}.{}.{} to {}.{}.{}.{}.{}.{}",
                                (*eth_dst_addr)[0],
                                (*eth_dst_addr)[1],
                                (*eth_dst_addr)[2],
                                (*eth_dst_addr)[3],
                                (*eth_dst_addr)[4],
                                (*eth_dst_addr)[5],
                                fib.dmac[0],
                                fib.dmac[1],
                                fib.dmac[2],
                                fib.dmac[3],
                                fib.dmac[4],
                                fib.dmac[5]
                            );
                            if let Some(mac) = redirect_key.1 {
                                *eth_dst_addr = mac;
                            } else {
                                *eth_dst_addr = fib.dmac;
                            }
                        }

                        match REDIRECT_MAP.redirect(redirect_key.0, xdp_action::XDP_PASS.into()) {
                            Ok(code) => {
                                debug!(
                                    &ctx,
                                    "successfully redirecting based on the existing entry: {}",
                                    redirect_key.0
                                );
                                Ok(code)
                            }
                            Err(code) => {
                                debug!(&ctx, "something went wrong");
                                Ok(code)
                            }
                        }
                    } else {
                        Ok(xdp_code)
                    }
                }
            }
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn try_xdp_redirect(ctx: &XdpContext, flag: Flags) -> Result<u32, ()> {
    let ether_type_ptr: *const EtherType = ptr_at(ctx, offset_of!(EthHdr, ether_type))?;
    match unsafe { *ether_type_ptr } {
        EtherType::Ipv4 => handle_ip_redirect(ctx, flag),
        // EtherType::Ipv6 => todo!(),
        _ => Ok(xdp_action::XDP_PASS),
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
