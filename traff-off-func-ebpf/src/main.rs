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
use aya_ebpf::{
    bindings::{BPF_NOEXIST, xdp_action},
    helpers::generated::bpf_ktime_get_coarse_ns,
    macros::{map, xdp},
    maps::{DevMapHash, HashMap},
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use traff_off_func_common::{
    ConnectionTuple, ContainerInfo, Direction, FibMacs, FlowState, HostInfo, NATData, TIMEOUT_EST,
    TIMEOUT_NEW,
};
use traff_off_func_ebpf::{
    Flags,
    helpers::{apply_ip_dnat, apply_ip_snat, get_fib_macs, rewrite_macs},
};

const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1FFF;
const THRESHOLD_NS: u64 = 1_000_000_000;

#[map(name = "REDIRECT_MAP")]
static REDIRECT_MAP: DevMapHash = DevMapHash::with_max_entries(256, 0);

#[map(name = "UDP_CONNTRACK")]
static UDP_CONNTRACK: HashMap<ConnectionTuple, FlowState> = HashMap::with_max_entries(65536, 0);

#[map(name = "EXPOSE_MAP")]
static EXPOSE_MAP: HashMap<u16, ContainerInfo> = HashMap::with_max_entries(256, 0);

#[map(name = "REV_EXPOSE_MAP")]
static REV_EXPOSE_MAP: HashMap<u16, HostInfo> = HashMap::with_max_entries(256, 0);

#[xdp(frags)]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp(frags)]
pub fn xdp_redirect_containers(ctx: XdpContext) -> u32 {
    try_xdp_redirect(&ctx, Flags::Snat).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp(frags)]
pub fn xdp_redirect_host(ctx: XdpContext) -> u32 {
    try_xdp_redirect(&ctx, Flags::Dnat).unwrap_or(xdp_action::XDP_ABORTED)
}

#[inline(always)]
fn try_xdp_redirect(ctx: &XdpContext, flag: Flags) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + EthHdr::LEN + Ipv4Hdr::LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth = unsafe { &mut *(data as *mut EthHdr) };
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4 = unsafe { &mut *((data + EthHdr::LEN) as *mut Ipv4Hdr) };

    if !matches!(ipv4.proto, IpProto::Udp | IpProto::Tcp | IpProto::Icmp) {
        return Ok(xdp_action::XDP_PASS);
    }

    if (ipv4.vihl & 0x0F) != 5 {
        return Ok(xdp_action::XDP_PASS);
    }

    let frag_off = u16::from_be_bytes(ipv4.frags);
    if frag_off & (IP_MF | IP_OFFSET) != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let dst_ip = u32::from_be_bytes(ipv4.dst_addr);
    let src_ip = u32::from_be_bytes(ipv4.src_addr);

    if let Ok(xdp_code) = REDIRECT_MAP.redirect(dst_ip, xdp_action::XDP_PASS.into()) {
        return Ok(xdp_code);
    }

    if ipv4.proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    if data + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = unsafe { &mut *((data + EthHdr::LEN + Ipv4Hdr::LEN) as *mut UdpHdr) };

    let nat = if flag == Flags::Snat {
        process_udp_snat(ctx, src_ip, dst_ip, eth, ipv4, udp)?
    } else {
        process_udp_dnat(ctx, src_ip, dst_ip, eth, ipv4, udp)?
    };

    let NATData {
        fib_macs,
        devmap_key,
        ..
    } = match nat {
        Some(key) => key,
        None => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    unsafe {
        rewrite_macs(
            eth.src_addr.as_mut_ptr() as *mut [u8; 6],
            eth.dst_addr.as_mut_ptr() as *mut [u8; 6],
            fib_macs,
        );
    }

    match REDIRECT_MAP.redirect(devmap_key, xdp_action::XDP_PASS.into()) {
        Ok(code) => Ok(code),
        Err(code) => Ok(code),
    }
}

#[inline(always)]
fn process_udp_snat(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    eth: &mut EthHdr,
    ipv4: &mut Ipv4Hdr,
    udp: &mut UdpHdr,
) -> Result<Option<NATData>, ()> {
    let src_port = u16::from_be(unsafe { *(udp as *const UdpHdr as *const u16) });
    let dst_port = u16::from_be(unsafe { *((udp as *const UdpHdr as *const u16).add(1)) });

    let key = ConnectionTuple::new(src_ip, dst_ip, src_port, dst_port);

    if let Some(state_ptr) = UDP_CONNTRACK.get_ptr_mut(key) {
        let time: u64 = unsafe { bpf_ktime_get_coarse_ns() };
        let state = unsafe { &mut *state_ptr };
        let mut update_reverse = false;

        // lazy temporal update every second
        match state.direction {
            Direction::Original => {
                let expected_timeout = time
                    + if state.seen_reply {
                        TIMEOUT_EST
                    } else {
                        TIMEOUT_NEW
                    };
                if expected_timeout > state.timeout
                    && (expected_timeout - state.timeout) > THRESHOLD_NS
                {
                    state.timeout = expected_timeout;
                    update_reverse = true;
                }
            }
            Direction::Reply => {
                let expected_timeout = time + TIMEOUT_EST;
                if !state.seen_reply
                    || (expected_timeout > state.timeout
                        && (expected_timeout - state.timeout) > THRESHOLD_NS)
                {
                    state.seen_reply = true;
                    state.timeout = expected_timeout;
                    update_reverse = true;
                }
            }
        }

        let snat = state.nat;

        unsafe {
            apply_ip_snat(
                &snat,
                (&mut ipv4.check as *mut [u8; 2]).cast(),
                (&mut udp.check as *mut [u8; 2]).cast(),
                ipv4.src_addr.as_mut_ptr() as *mut u32,
                udp as *mut UdpHdr as *mut u16,
            );
        }

        if update_reverse {
            let dkey = ConnectionTuple::new(dst_ip, snat.nat_addr, dst_port, snat.nat_port);
            if let Some(rev_ptr) = UDP_CONNTRACK.get_ptr_mut(dkey) {
                let rev_conn = unsafe { &mut *rev_ptr };
                rev_conn.seen_reply = state.seen_reply;
                rev_conn.timeout = state.timeout;
            }
        }

        return Ok(Some(snat));
    }

    let ingress_ifindex: u32 = ctx.ingress_ifindex() as u32;
    let tot_len = u16::from_be_bytes(ipv4.tot_len);
    let container_mac = eth.src_addr;

    let HostInfo { host_ip, host_port } = match unsafe { REV_EXPOSE_MAP.get(src_port) } {
        Some(info) => *info,
        None => return Ok(None),
    };

    let fib_macs = if let Some(fib_macs) =
        get_fib_macs(ctx, host_ip, dst_ip, IpProto::Udp, tot_len, ingress_ifindex)
    {
        fib_macs
    } else {
        return Ok(None);
    };

    let snat = NATData::new(host_ip, host_port, fib_macs, 0);
    let dnat_macs = FibMacs {
        fib_smac: fib_macs.fib_smac,
        fib_dmac: container_mac,
    };
    let dnat = NATData::new(src_ip, src_port, dnat_macs, src_ip);

    let dkey = ConnectionTuple::new(dst_ip, host_ip, dst_port, host_port);
    let time: u64 = unsafe { bpf_ktime_get_coarse_ns() };
    let conn_orig = FlowState::new(snat, Direction::Original, time + TIMEOUT_NEW);
    let conn_reply = FlowState::new(dnat, Direction::Reply, time + TIMEOUT_NEW);

    let _ = UDP_CONNTRACK.insert(key, conn_orig, BPF_NOEXIST.into());
    let _ = UDP_CONNTRACK.insert(dkey, conn_reply, BPF_NOEXIST.into());

    unsafe {
        apply_ip_snat(
            &snat,
            (&mut ipv4.check as *mut [u8; 2]).cast(),
            (&mut udp.check as *mut [u8; 2]).cast(),
            ipv4.src_addr.as_mut_ptr() as *mut u32,
            udp as *mut UdpHdr as *mut u16,
        );
    }

    Ok(Some(snat))
}

#[inline(always)]
fn process_udp_dnat(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    eth: &mut EthHdr,
    ipv4: &mut Ipv4Hdr,
    udp: &mut UdpHdr,
) -> Result<Option<NATData>, ()> {
    let src_port = u16::from_be(unsafe { *(udp as *const UdpHdr as *const u16) });
    let dst_port = u16::from_be(unsafe { *((udp as *const UdpHdr as *const u16).add(1)) });

    let key = ConnectionTuple::new(src_ip, dst_ip, src_port, dst_port);

    if let Some(state_ptr) = UDP_CONNTRACK.get_ptr_mut(key) {
        let time: u64 = unsafe { bpf_ktime_get_coarse_ns() };
        let state = unsafe { &mut *state_ptr };
        let mut update_reverse = false;

        match state.direction {
            Direction::Original => {
                let expected_timeout = time
                    + if state.seen_reply {
                        TIMEOUT_EST
                    } else {
                        TIMEOUT_NEW
                    };
                if expected_timeout > state.timeout
                    && (expected_timeout - state.timeout) > THRESHOLD_NS
                {
                    state.timeout = expected_timeout;
                    update_reverse = true;
                }
            }
            Direction::Reply => {
                let expected_timeout = time + TIMEOUT_EST;
                if !state.seen_reply
                    || (expected_timeout > state.timeout
                        && (expected_timeout - state.timeout) > THRESHOLD_NS)
                {
                    state.seen_reply = true;
                    state.timeout = expected_timeout;
                    update_reverse = true;
                }
            }
        }

        let dnat = state.nat;

        unsafe {
            apply_ip_dnat(
                &dnat,
                (&mut ipv4.check as *mut [u8; 2]).cast(),
                (&mut udp.check as *mut [u8; 2]).cast(),
                ipv4.dst_addr.as_mut_ptr() as *mut u32,
                (udp as *const UdpHdr as *const u16).add(1) as *mut u16,
            );
        }

        if update_reverse {
            let skey = ConnectionTuple::new(dnat.nat_addr, src_ip, dnat.nat_port, src_port);
            if let Some(rev_ptr) = UDP_CONNTRACK.get_ptr_mut(skey) {
                let rev_conn = unsafe { &mut *rev_ptr };
                rev_conn.seen_reply = state.seen_reply;
                rev_conn.timeout = state.timeout;
            }
        }

        return Ok(Some(dnat));
    }

    let ContainerInfo {
        container_ip,
        container_mac,
        container_port,
        ifindex,
    } = match unsafe { EXPOSE_MAP.get(dst_port) } {
        Some(info) => *info,
        None => return Ok(None),
    };

    let tot_len = u16::from_be_bytes(ipv4.tot_len);
    let Some(fib_macs) = get_fib_macs(ctx, dst_ip, src_ip, IpProto::Udp, tot_len, ifindex) else {
        return Ok(None);
    };

    let snat = NATData::new(dst_ip, dst_port, fib_macs, 0);
    let host_mac = eth.dst_addr;

    let dnat_macs = FibMacs {
        fib_smac: host_mac,
        fib_dmac: container_mac,
    };
    let dnat = NATData::new(container_ip, container_port, dnat_macs, container_ip);

    let fwd_key = ConnectionTuple::new(src_ip, dst_ip, src_port, dst_port);
    let rev_key = ConnectionTuple::new(container_ip, src_ip, container_port, src_port);

    let time: u64 = unsafe { bpf_ktime_get_coarse_ns() };
    let conn_orig = FlowState::new(dnat, Direction::Original, time + TIMEOUT_NEW);
    let conn_reply = FlowState::new(snat, Direction::Reply, time + TIMEOUT_NEW);

    let _ = UDP_CONNTRACK.insert(fwd_key, conn_orig, BPF_NOEXIST.into());
    let _ = UDP_CONNTRACK.insert(rev_key, conn_reply, BPF_NOEXIST.into());

    unsafe {
        apply_ip_dnat(
            &dnat,
            (&mut ipv4.check as *mut [u8; 2]).cast(),
            (&mut udp.check as *mut [u8; 2]).cast(),
            ipv4.dst_addr.as_mut_ptr() as *mut u32,
            (udp as *const UdpHdr as *const u16).add(1) as *mut u16,
        );
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
