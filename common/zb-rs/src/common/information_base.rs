use core::fmt::Debug;
use core::ops::Add;
use core::ops::Deref;
use core::ops::DerefMut;

use crate::nwk::constants::ROUTE_DISCOVERY_TIME;
use crate::nwk::nib::RouteStatus;
use crate::stack_profile::StackProfileParams;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Instant;
use zb_macros::BitStruct;
use zb_types::common::NwkAddress;

#[derive(Debug, Clone, Default, TryRead, TryWrite)]
pub struct ApsWindowSize {
    pub endpoint: u8,
    pub max_window_size: u8,
}

#[derive(BitStruct, Debug, Copy, Clone, Default, PartialEq)]
#[bit_struct(repr = u16)]
pub struct ParentInformation {
    pub mac_data_poll_keepalive_supported: bool,
    pub end_device_timeout_request_keepalive_supported: bool,
    pub power_negotiation_supported: bool,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteEntryKey {
    addr: NwkAddress,
    is_group: bool,
}

impl RouteEntryKey {
    pub fn new(ctx: &StackProfileParams, addr: NwkAddress, is_group: bool) -> Self {
        //let routing_addr = get_routing_address_for_address(ctx, addr);

        Self {
            addr: NwkAddress::BROADCAST_ALL, // TODO
            is_group,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RouteEntrySet(heapless::index_map::FnvIndexMap<RouteEntryKey, RouteEntry, 64>);

impl Deref for RouteEntrySet {
    type Target = heapless::index_map::FnvIndexMap<RouteEntryKey, RouteEntry, 64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RouteEntrySet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl RouteEntrySet {
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        (*self).retain(|_, route| {
            route
                .discovery
                .retain(|_, discovery| discovery.expiration_time >= now);
            matches!(
                route.status,
                RouteStatus::Active | RouteStatus::ValidationUnderway
            ) || !route.discovery.is_empty()
        });
    }
}

#[derive(Clone, Debug)]
pub struct RouteDiscoveryEntry {
    pub sender_addr: NwkAddress,
    pub forward_cost: u8,
    pub residual_cost: u8,
    pub expiration_time: Instant,
}

impl RouteDiscoveryEntry {
    pub fn new(sender_addr: NwkAddress, forward_cost: u8) -> RouteDiscoveryEntry {
        RouteDiscoveryEntry {
            sender_addr,
            forward_cost,
            residual_cost: 0,
            expiration_time: Instant::now().add(ROUTE_DISCOVERY_TIME),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct RouteEntry {
    pub status: RouteStatus,
    pub no_route_cache: bool,
    pub many_to_one: bool,
    pub next_hop_addr: NwkAddress,
    pub is_group: bool,
    pub route_record_required: bool,
    pub discovery: heapless::index_map::FnvIndexMap<(u8, NwkAddress), RouteDiscoveryEntry, 4>,
}
