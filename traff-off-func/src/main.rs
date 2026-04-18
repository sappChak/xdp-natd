use std::{
    collections::HashMap,
    net::Ipv4Addr,
    os::unix::io::AsFd,
    process::Command,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, ensure};
use aya::{
    Ebpf,
    maps::DevMapHash,
    programs::{ProgramError, Xdp, XdpFlags},
};
use docker_api::{
    Docker,
    conn::TtyChunk,
    opts::{ExecCreateOpts, ExecStartOpts},
};
use futures::StreamExt;
use log::{debug, warn};
use macaddr::MacAddr6;
use nix::{
    net::if_::{if_nameindex, if_nametoindex},
    sched::CloneFlags,
};
use tokio::{signal, time};
use traff_off_func::{
    AyaHashMap, ContainerMetadata, ContainersMap, ExposeMap, PORT_RANGE, RevExposeMap,
    api::server::setup_axum_server, configuration::config::get_configuration,
    port_allocator::PortAllocator, telemetry::init_logging,
};
use traff_off_func_common::{ConnectionTuple, FlowState};

async fn get_containers(network: &str) -> Result<ContainersMap> {
    let mut container_metas = HashMap::new();
    let docker = Docker::unix("/var/run/docker.sock");
    let network_info = docker.networks().get(network).inspect().await?;

    let Some(containers) = network_info.containers else {
        return Ok(container_metas);
    };

    let exec_opts = ExecCreateOpts::builder()
        .command(vec!["cat", "/sys/class/net/eth0/iflink"])
        .attach_stdout(true)
        .attach_stderr(true)
        .build();

    for (cid, container_info) in &containers {
        let container = docker.containers().get(cid);
        let inspect = container.inspect().await?;
        let pid = inspect.state.and_then(|s| s.pid);

        debug!("{:?}", container);

        let mut exec_stream = container
            .exec(&exec_opts, &ExecStartOpts::default())
            .await?;

        while let Some(result) = exec_stream.next().await {
            let chunks = match result? {
                TtyChunk::StdOut(items) => items,
                TtyChunk::StdErr(items) => {
                    debug!(
                        "Error inside container: {}",
                        String::from_utf8_lossy(&items)
                    );
                    continue;
                }
                TtyChunk::StdIn(_) => continue,
            };

            let output = String::from_utf8_lossy(&chunks);
            let iflink: u32 = output.trim().parse().context("Failed to parse iflink")?;

            let interfaces = if_nameindex()?;
            let interface = interfaces
                .into_iter()
                .find(|i| i.index() == iflink)
                .context("Matching interface not found on host")?;

            let name = container_info.name.clone().unwrap_or_default();
            let veth = interface.name().to_string_lossy().to_string();
            let mac_address: [u8; 6] = container_info
                .mac_address
                .as_deref()
                .unwrap_or_default()
                .parse::<MacAddr6>()?
                .into_array();

            let ipv4: Ipv4Addr = container_info
                .i_pv_4_address
                .as_deref()
                .and_then(|ip| ip.split('/').next())
                .context("Missing or invalid IPv4 address")?
                .parse()?;

            debug!("interface name: {veth}, ip: {ipv4}");

            container_metas.insert(
                u32::from(ipv4),
                ContainerMetadata {
                    name,
                    veth,
                    ipv4,
                    mac_address,
                    ifindex: iflink,
                    pid,
                },
            );

            break; // move to the next container
        }
    }

    Ok(container_metas)
}

pub fn get_if_addr(ifname: &str) -> Result<u32> {
    nix::ifaddrs::getifaddrs()?
        .find_map(|ifaddr| {
            if ifaddr.interface_name == ifname {
                ifaddr
                    .address
                    .as_ref()
                    .and_then(|addr| addr.as_sockaddr_in())
                    .map(|sock_addr| sock_addr.ip().into())
            } else {
                None
            }
        })
        .context(format!(
            "Failed to find IPv4 address for interface {ifname}"
        ))
}

fn reserve_kernel_ports(range: &str) -> Result<(u16, u16)> {
    let path = "/proc/sys/net/ipv4/ip_local_reserved_ports";
    let existing = std::fs::read_to_string(path)?;
    let existing_trimmed = existing.trim();

    let new_content = if existing_trimmed.is_empty() {
        range.to_string()
    } else {
        format!("{existing_trimmed},{range}")
    };

    std::fs::write(path, new_content)?;

    let (num1, num2) = range.split_once('-').context("Invalid port range format")?;
    Ok((num1.parse()?, num2.parse()?))
}

fn get_nsecs() -> u64 {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC_COARSE)
        .expect("failed to get monotonic time");
    (ts.tv_sec() as u64) * 1_000_000_000 + (ts.tv_nsec() as u64)
}

fn parse_xdp_mode(mode: &str) -> Result<XdpFlags> {
    match mode {
        "skb" => Ok(XdpFlags::SKB_MODE),
        "native" => Ok(XdpFlags::DRV_MODE),
        _ => anyhow::bail!("invalid mode, use either 'skb' or 'native'"),
    }
}

fn setup_ebpf_logging(ebpf: &mut Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(_) => warn!("logging is not used in the ebpf program"),
        Ok(logger) => {
            tokio::task::spawn(async move {
                if let Ok(mut logger) =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                {
                    loop {
                        if let Ok(mut guard) = logger.readable_mut().await {
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                    }
                }
            });
        }
    }
}

fn attach_container_xdp(
    ebpf: &mut Ebpf,
    containers: &HashMap<u32, ContainerMetadata>,
    mode: XdpFlags,
) -> Result<()> {
    let program: &mut Xdp = ebpf
        .program_mut("xdp_redirect_containers")
        .unwrap()
        .try_into()?;
    program.load()?;

    for container in containers.values() {
        debug!(
            "attaching xdp program to: {}, ifindex: {} of container {}",
            container.veth, container.ifindex, container.name
        );
        program.attach(&container.veth, mode).context(
            "failed to attach the XDP program - try changing XdpFlags to XdpFlags::SKB_MODE",
        )?;
    }
    Ok(())
}

fn setup_devmap(ebpf: &mut Ebpf, containers: &HashMap<u32, ContainerMetadata>) -> Result<()> {
    let mut devmap = DevMapHash::try_from(ebpf.map_mut("REDIRECT_MAP").unwrap())?;
    for container in containers.values() {
        debug!(
            "inserting a pair into devmap: <{:?},{}>",
            container.ipv4, container.ifindex
        );
        devmap.insert(u32::from(container.ipv4), container.ifindex, None, 0)?;
    }
    Ok(())
}

fn setup_pnic(ebpf: &mut Ebpf, nic_name: &str, mode: XdpFlags) -> Result<u32> {
    debug!("setting up the pnic with name: {}", nic_name);
    let ifindex = if_nametoindex(nic_name)?;
    let nic_addr = get_if_addr(nic_name)?;
    debug!("ifindex of the pnic is: {}", ifindex);

    let mut devmap = DevMapHash::try_from(ebpf.map_mut("REDIRECT_MAP").unwrap())?;
    devmap.insert(0, ifindex, None, 0)?;

    let program: &mut Xdp = ebpf.program_mut("xdp_redirect_host").unwrap().try_into()?;
    program.load()?;
    program
        .attach(nic_name, mode)
        .context("failed to attach the XDP program to the provided NIC")?;

    let mut conntrack: AyaHashMap<ConnectionTuple, FlowState> =
        AyaHashMap::try_from(ebpf.take_map("UDP_CONNTRACK").unwrap())?;

    tokio::task::spawn(async move {
        let mut time_interval = time::interval(time::Duration::from_secs(30));
        loop {
            time_interval.tick().await;

            let to_remove: Vec<_> = conntrack
                .iter()
                .filter_map(|res| res.ok())
                .filter(|(_, v)| v.timeout <= get_nsecs())
                .map(|(k, _)| k)
                .collect();

            for key in to_remove {
                let _ = conntrack.remove(&key);
            }
        }
    });

    Ok(nic_addr)
}

fn attach_namespace_pass_programs(
    protected_ebpf: &Arc<Mutex<Ebpf>>,
    containers: &HashMap<u32, ContainerMetadata>,
    mode: XdpFlags,
) -> Result<()> {
    let mut handles = vec![];
    for container in containers.values() {
        if let Some(pid) = container.pid {
            let protected_ebpf_clone = Arc::clone(protected_ebpf);

            let handle = std::thread::spawn(move || {
                let net_ns_path = format!("/proc/{pid}/ns/net");
                let net_ns_file = std::fs::File::open(net_ns_path).unwrap();

                let mut guard = protected_ebpf_clone.lock().unwrap();
                let program: &mut Xdp = guard.program_mut("xdp_pass").unwrap().try_into().unwrap();

                if let Err(e) = program.load()
                    && !matches!(e, ProgramError::AlreadyLoaded)
                {
                    panic!("failed to load the XDP program: {e}");
                }

                nix::sched::setns(net_ns_file.as_fd(), CloneFlags::CLONE_NEWNET).unwrap();
                program.attach("eth0", mode).unwrap();
            });

            handles.push(handle);
        }
    }

    for handler in handles {
        let _ = handler.join();
    }

    Ok(())
}

fn clean_up() -> Result<()> {
    let status = Command::new("iptables")
        .args(["-t", "nat", "-F", "PREROUTING"])
        .status()?;
    ensure!(status.success(), "failed to flush PREROUTING iptables");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let configuration = get_configuration().expect("Failed to read configuration.");
    init_logging(&configuration)?;

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/traff-off-func"
    )))?;

    setup_ebpf_logging(&mut ebpf);

    let containers = get_containers(&configuration.dataplane.network).await?;

    let mode = parse_xdp_mode(&configuration.dataplane.mode)?;

    attach_container_xdp(&mut ebpf, &containers, mode)?;
    setup_devmap(&mut ebpf, &containers)?;

    let protected_ebpf: Arc<Mutex<Ebpf>> = Arc::new(Mutex::new(Ebpf::load(
        aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/traff-off-func")),
    )?));
    attach_namespace_pass_programs(&protected_ebpf, &containers, mode)?;

    if let Some(ref nic) = configuration.dataplane.pnic {
        let nic_addr = setup_pnic(&mut ebpf, nic, mode)?;

        let expose_map: ExposeMap = AyaHashMap::try_from(ebpf.take_map("EXPOSE_MAP").unwrap())?;
        let rev_expose_map: RevExposeMap =
            AyaHashMap::try_from(ebpf.take_map("REV_EXPOSE_MAP").unwrap())?;
        let (lower, upper) = reserve_kernel_ports(PORT_RANGE)?;
        let port_allocator = PortAllocator::new(lower..=upper);
        tokio::task::spawn(async move {
            let _ = setup_axum_server(
                &configuration,
                expose_map,
                rev_expose_map,
                port_allocator,
                containers,
                nic_addr,
            )
            .await;
        });
    }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    println!("Cleaning up...");
    clean_up()?;

    println!("Exiting...");
    Ok(())
}
