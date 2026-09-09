use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Instant;

use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

use smart_default::SmartDefault;

#[derive(Clone, Copy, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum RouteStatus {
    Active = 0x0,
    #[default]
    DiscoveryUnderway = 0x1,
    DiscoveryFailed = 0x2,
    Inactive = 0x3,
    ValidationUnderway = 0x4,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct NwkRoute {
    pub dst_addr: NwkAddress,
    pub status: RouteStatus,
    #[byte(ctx = ())]
    pub no_route_cache: bool,
    #[byte(ctx = ())]
    pub many_to_one: bool,
    #[byte(ctx = ())]
    pub route_record_required: bool,
    #[byte(ctx = ())]
    pub group_id: bool,
    pub next_hop_addr: NwkAddress,
}

#[derive(Clone, Debug)]
pub struct NwkRouteDiscovery {
    pub route_request_id: u8,
    pub originator_addr: NwkAddress,
    pub sender_addr: NwkAddress,
    pub forward_cost: u8,
    pub residual_cost: u8,
    pub expiration_time: Instant,
}

#[derive(Clone, Copy, Debug, SmartDefault)]
pub struct TransactionRecord {
    pub source_address: NwkAddress,
    pub sequence_number: u8,
    #[default(Instant::MIN)]
    pub expiration_time: Instant,
}

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct RouteRecord {
    pub network_address: NwkAddress,
    pub relay_count: u8,
    pub path: zb_types::Vec<NwkAddress, 16>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum NetworkKeyType {
    #[default]
    Standard = 0x0,
}

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct IncomingFrameCounterDescriptor {
    pub sender_address: ExtendedAddress,
    pub incoming_frame_counter: u32,
}
