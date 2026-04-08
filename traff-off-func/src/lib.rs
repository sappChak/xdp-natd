use traff_off_func_common::{ContainerInfo, HostInfo};
use aya::maps::HashMap;

pub mod configuration;
pub mod api;
pub mod port_allocator;
pub mod telemetry;

pub const PORT_RANGE: &str = "10000-12000";
pub const IPERF_SERVER_PORT: u16 = 5201;

pub type ExposeMap = HashMap<aya::maps::MapData, u16, ContainerInfo>;
pub type RevExposeMap = HashMap<aya::maps::MapData, u16, HostInfo>;



