use xdp_natd_common::ContainerInfo;

pub mod api;
pub mod configuration;
pub mod port_allocator;
pub mod telemetry;

pub struct ContainerMetadata {
    pub name: String,
    pub veth: String,
    pub ipv4_address: std::net::Ipv4Addr,
    pub ifindex: u32,
    pub pid: Option<isize>,
    pub mac_address: [u8; 6],
}

pub const PORT_RANGE: &str = "10000-12000";
pub const IPERF_SERVER_PORT: u16 = 5201;

pub type ContainerMap = std::collections::HashMap<u32, ContainerMetadata>;

pub type AyaHashMap<K, V> = aya::maps::HashMap<aya::maps::MapData, K, V>;
pub type ExposeMap = AyaHashMap<u16, ContainerInfo>;
