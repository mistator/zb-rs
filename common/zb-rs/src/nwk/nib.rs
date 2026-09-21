use core::ops::Add;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use derive_more::{Deref, DerefMut};
use embassy_time::Instant;
use ieee802154::mac::beacon::BeaconOrder;
use zb_types::common::{DeviceType, ExtendedAddress, Key, PanId};
use zb_types::common::NwkAddress;

use smart_default::SmartDefault;
use zb_types::{CapacityResult, HashMap, Vec};
use zb_types::mac::Channel;
use crate::apl::aps::types::ApsEndpoint;
use crate::apl::zdp::types::descriptors::{NodeDescriptor, NodePowerDescriptor, SimpleDescriptor};
use crate::nwk::commands::end_device_timeout_request::DeviceTimeout;
use crate::nwk::commands::link_status::LinkCost;
use crate::nwk::constants::NWK_END_DEVICE_TIMEOUT_DEFAULT;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum NeighborRelationship {
    Parent = 0,
    Child = 1,
    Sibling = 2,
    #[default]
    Other = 3,
    PreviousChild = 4,
    UnauthenticatedChild = 5,
}

#[derive(Clone, Copy, Debug)]
pub struct NwkNeighborJoinData {
    pub extended_pan_id: ExtendedAddress,
    pub pan_id: PanId,
    pub logical_channel: Channel,
    pub depth: u8,
    pub beacon_order: BeaconOrder,
    pub permit_joining: bool,
    pub potential_parent: bool,
}


#[derive(Clone, Debug, TryRead, TryWrite, SmartDefault)]
pub struct NwkNeighbor {
    pub ext_addr: Option<ExtendedAddress>,
    pub nwk_addr: NwkAddress,
    pub device_type: DeviceType,
    pub end_device_configuration: u16,
    pub device_timeout: DeviceTimeout,
    pub relationship: NeighborRelationship,

    #[byte(ignore = true)]
    pub rx_on_when_idle: bool,
    // unused
    // timeout_counter: u32,
    #[byte(ignore = true)]
    pub transmit_failure: u8,
    #[byte(ignore = true)]
    pub incoming_cost: LinkCost,
    #[byte(ignore = true)]
    pub outgoing_cost: LinkCost,
    #[default(Instant::now())]
    #[byte(ignore = true, default = Instant::now())]
    pub expiration: Instant,
    // optional
    // incoming_beacon_timestamp: u8,
    // beacon_transmission_time: u8,
    #[byte(ignore = true)]
    pub keepalive_received: bool,
    // we only support 1 MAC interface currently
    // mac_interface_index: u8,
    // optional
    // mac_unicast_bytes_transmitted: u32,
    // mac_unicast_bytes_received: u32,
    #[byte(ignore = true)]
    pub node_descriptor: Option<NodeDescriptor>,
    #[byte(ignore = true)]
    pub power_descriptor: Option<NodePowerDescriptor>,
    #[byte(ignore = true)]
    pub simple_descriptors: HashMap<ApsEndpoint, SimpleDescriptor, 32>,
    #[byte(ignore = true)]
    pub join_data: Option<NwkNeighborJoinData>,
}

pub struct NewNwkNeighbour {
    pub(crate) ext_addr: ExtendedAddress,
    pub(crate) nwk_addr: NwkAddress,
    pub(crate) device_type: DeviceType,
    pub(crate) rx_on_when_idle: bool,
    pub(crate) relationship: NeighborRelationship,
}

impl NwkNeighbor {
    pub fn new(neighbor: NewNwkNeighbour) -> Self {
        let timeout = NWK_END_DEVICE_TIMEOUT_DEFAULT;

        NwkNeighbor {
            ext_addr: Some(neighbor.ext_addr),
            nwk_addr: neighbor.nwk_addr,
            device_type: neighbor.device_type,
            rx_on_when_idle: neighbor.rx_on_when_idle,
            device_timeout: timeout,
            relationship: neighbor.relationship,
            expiration: Instant::now().add(timeout.get_duration()),
            ..Default::default()
        }
    }

    pub fn is_child(&self) -> bool {
        self.relationship == NeighborRelationship::Child
    }
    pub fn is_parent(&self) -> bool {
        self.relationship == NeighborRelationship::Parent
    }
    pub fn is_end_device(&self) -> bool {
        self.device_type == DeviceType::EndDevice
    }
    pub fn is_router(&self) -> bool {
        self.device_type == DeviceType::Router || self.device_type == DeviceType::Coordinator
    }
}

pub const NEIGHBOR_TABLE_MAX_ENTRIES: usize = 32;

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct NeighborTable {
    pub parent: NwkNeighbor,
    pub children: Vec<NwkNeighbor, NEIGHBOR_TABLE_MAX_ENTRIES>
}

impl NeighborTable {
    pub fn new(parent: NwkNeighbor) -> Self {
        Self {
            parent,
            children: Vec::new(),
        }
    }

    pub fn cleanup(&mut self) { self.children.retain(|nb| nb.expiration > Instant::now()); }

    pub fn find_by_ext_addr(&self, addr: ExtendedAddress) -> Option<&NwkNeighbor> {
        self.children.iter().find(|nb| nb.ext_addr == Some(addr))
    }

    pub fn find_by_ext_addr_and_type(
        &self,
        addr: ExtendedAddress,
        type_: DeviceType,
    ) -> Option<&NwkNeighbor> {
        self.children
            .iter()
            .find(|nb| nb.ext_addr == Some(addr) && type_ == nb.device_type)
    }

    pub fn find_by_ext_addr_and_type_mut(
        &mut self,
        addr: ExtendedAddress,
        type_: DeviceType,
    ) -> Option<&mut NwkNeighbor> {
        self.children
            .iter_mut()
            .find(|nb| nb.ext_addr == Some(addr) && type_ == nb.device_type)
    }

    pub fn find_by_ext_addr_mut(&mut self, addr: ExtendedAddress) -> Option<&mut NwkNeighbor> {
        self.children.iter_mut().find(|nb| nb.ext_addr == Some(addr))
    }

    pub fn find_by_short_addr(&self, addr: NwkAddress) -> Option<&NwkNeighbor> {
        self.children.iter().find(|nb| nb.nwk_addr == addr)
    }

    pub fn find_by_short_addr_and_device_type(
        &self,
        addr: NwkAddress,
        device_type: DeviceType,
    ) -> Option<&NwkNeighbor> {
        self.children
            .iter()
            .find(|nb| nb.nwk_addr == addr && nb.device_type == device_type)
    }

    pub fn find_by_short_addr_mut(&mut self, addr: NwkAddress) -> Option<&mut NwkNeighbor> {
        self.children.iter_mut().find(|nb| nb.nwk_addr == addr)
    }
}

#[derive(Debug, Default, Clone, Deref, DerefMut)]
pub struct AddressMap(heapless::index_map::FnvIndexMap<NwkAddress, ExtendedAddress, 64>);
impl AddressMap {
    pub fn find_ext_addr(&self, addr: &NwkAddress) -> Option<ExtendedAddress> {
        self.0.get(addr).cloned()
    }

    pub fn find_nwk_addr(&self, addr: &ExtendedAddress) -> Option<NwkAddress> {
        self.0.iter().find(|(_, ext)| **ext == *addr).map(|(nwk, _)| *nwk)
    }

    pub fn insert(&mut self, nwk: NwkAddress, ext: ExtendedAddress) -> () {
        self.0.insert(nwk, ext).ok();
    }
}

#[derive(Clone, Debug, Default, Deref, DerefMut, TryRead, TryWrite)]
pub struct NetworkSecurityMaterialDescriptorSet(
    Vec<NetworkSecurityMaterialDescriptor, 4>,
);

#[derive(Clone, Default, Debug, TryRead, TryWrite)]
pub struct NetworkSecurityMaterialDescriptor {
    pub key_seq_number: u8,
    pub outgoing_frame_counter: u32,
    #[byte(ignore = true)]
    pub incoming_frame_counter_set: Vec<IncomingFrameCounterDescriptor, 32>,
    pub key: Key,
    pub network_key_type: NetworkKeyType,
}

pub type BroadcastTransactionTable = Vec<TransactionRecord, 64>;
pub type RouteRecordTable = Vec<RouteRecord, 64>;
