use crate::common::information_base::RouteDiscoveryEntry;
use crate::common::information_base::RouteEntry;
use crate::common::information_base::RouteEntryKey;
use crate::nwk::commands::network_status::NetworkStatusCmd;
use crate::nwk::commands::network_status::NetworkStatus;
use crate::nwk::commands::route_request::RouteRequestCmd;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nib::RouteStatus;
use crate::nwk::nlme::RouteError;
use crate::stack_profile::{AddrAllocMethod, StackProfileParams};
use crate::unwrap_or_return;
use rand::RngExt;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::commands::link_status::LinkCost;
use crate::nwk::ctx::{BaseNwk, BaseNwkPrivate, InitializedNwk, InitializedState, JoinedAsEndDevice, JoinedState, Nwk, RoutingState};

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub fn assign_child_address(&mut self) -> NwkAddress {
        match self.get_profile().nwk_addr_alloc {
            AddrAllocMethod::Stochastic => loop {
                let addr = NwkAddress(self.get_rng().random_range(1..NwkAddress::MAX_NON_BROADCAST.0));

                if self.get_addr() == addr
                    || self.get_route_table()
                        .iter()
                        .any(|(_, entry)| entry.next_hop_addr == addr)
                    || self.get_route_record_table()
                        .iter()
                        .any(|item| item.network_address == addr || item.path.contains(&addr))
                    || self.get_broadcast_transaction_table()
                        .iter()
                        .any(|item| item.source_address == addr)
                    || self.lock_neighbors(|children| children.find_by_short_addr(addr).is_some())
                    || (*self.get_addr_map()).contains_key(&addr)
                {
                    continue;
                }

                return addr;
            },
            AddrAllocMethod::Distributed => {}
        }

        todo!()
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum RouteDiscoveryRequestAddress {
    Multicast(NwkAddress),
    UnicastOrBroadcast(NwkAddress),
}

#[derive(Default)]
pub struct RouteDiscoveryRequestCfg {
    pub addr: Option<RouteDiscoveryRequestAddress>,
    pub radius: Option<u8>,
    pub no_route_cache: bool,
}

type RouteDiscoveryRequestResult = Result<(), RouteError>;

const fn c_skip(ctx: &StackProfileParams, d: u8) -> u32 {
    let cm = ctx.nwk_max_children as u32;
    let lm = ctx.nwk_max_depth as u32;
    let rm = ctx.nwk_max_routers as u32;
    let d = d as u32;

    if rm == 1 {
        1 + cm * (lm - d - 1)
    } else {
        (1 + cm - rm - cm * rm.pow(lm - d - 1)) / (1 - rm)
    }
}

pub(crate) const fn distributed_nwk_is_descendant(
    ctx: &StackProfileParams,
    depth: u8,
    parent: NwkAddress,
    child: NwkAddress,
) -> bool {
    let parent = parent.0 as u32;
    let child = child.0 as u32;

    parent + c_skip(ctx, depth - 1) > child && child > parent
}

impl<T: JoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub fn tree_routing_next_hop(&self, addr: NwkAddress) -> NwkAddress {
        let rm = self.get_profile().nwk_max_routers as u32;

        let self_depth = self.lock_parent_mut(|parent| parent.join_data.unwrap().depth + 1);
        let self_addr = self.get_addr();

        if distributed_nwk_is_descendant(self.get_profile(), self_depth, self_addr, addr) {
            if (addr.0 as u32) > (self_addr.0 as u32) + rm * c_skip(self.get_profile(), self_depth) {
                addr
            } else {
                let addr = (self_addr.0 as u32)
                    + 1
                    + ((addr.0 as u32 - (self_addr.0 as u32 + 1))
                    / c_skip(self.get_profile(), self_depth))
                    * c_skip(self.get_profile(), self_depth);
                NwkAddress(addr as u16)
            }
        } else {
            self.lock_parent(|parent| parent.nwk_addr)
        }
    }

    // 3.6.3.3
    // Define the routing address of a device to be its network address if it is a
    // router or the coordinator or an end device and nwkAddrAlloc has a value of
    // 0x02, or the network address of its parent if it is an end device and
    // nwkAddrAlloc has a value of 0x00.
    pub fn get_routing_address_for_address(&self, addr: NwkAddress) -> NwkAddress {
        match self.get_profile().nwk_addr_alloc {
            AddrAllocMethod::Distributed => {
                self.get_distributed_network_routing_address(0, 0, addr.0 as u32).unwrap()
            }
            AddrAllocMethod::Stochastic => addr,
        }
    }

    fn get_distributed_network_routing_address(
        &self,
        depth: u8,
        parent_addr: u32,
        addr: u32,
    ) -> Option<NwkAddress> {
        let ctx = self.get_profile();

        let cm = ctx.nwk_max_children as u32;
        let rm = ctx.nwk_max_routers as u32;

        if addr == parent_addr {
            // We are a router or coordinator, return
            return NwkAddress(parent_addr as u16).into();
        }

        // Maximum child address for the current depth and parent
        let max_addr = parent_addr + c_skip(ctx, depth) * rm + (cm - rm);
        if addr > max_addr {
            return None;
        }

        // Network addresses are assigned to end devices in a sequential manner with the
        // nth address being A_n = A_parent + c_skip(d) * rm + n.
        if addr > (parent_addr + c_skip(ctx, depth) * rm) {
            // If the address is bigger than A_parent + c_skip(d) * rm, then it's an end
            // device and we return the parent's address.
            return NwkAddress(parent_addr as u16).into();
        } else {
            // If it's not, then we check for all possible routers one level deeper.
            for n_router in 0..rm {
                let parent_addr = parent_addr + c_skip(ctx, depth) * n_router + 1;
                if let Some(addr) =
                    self.get_distributed_network_routing_address(depth + 1, parent_addr, addr)
                {
                    return addr.into();
                }
            }
        }

        None
    }
}


impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // 3.6.3.5.1
    pub async fn initiate_unicast_discovery(
        &mut self,
        dst_addr: NwkAddress,
        no_route_cache: bool,
    ) -> RouteDiscoveryRequestResult {
        let slf_addr = self.get_addr();

        // Each device issuing a route request command frame shall maintain a counter
        // used to generate route request identifiers. When a new route request
        // command frame is created, the route request counter is incremented and the
        // value is stored in the device’s route discovery table in the Route
        // request identifier field. Other fields in the routing table and
        // route discovery table are set as described in section 3.6.3.2.
        let route_request_id = self.get_ctx().route_request_counter;

        // If the device initiating route discovery has no routing table entry
        // corresponding to the routing address of the destina- tion device, it
        // shall establish a routing table entry with status equal to
        // DISCOVERY_UNDERWAY. If the device has an existing routing table entry
        // corresponding to the routing address of the destination with status equal to
        // AC- TIVE or VALIDATION _UNDERWAY, that entry shall be used and the status
        // field of that entry shall retain its current value. If it has an existing
        // routing table entry with a status value other than ACTIVE or VALIDA-
        // TION_UNDERWAY, that entry shall be used and the status of that entry shall be
        // set to DISCOVERY_UNDERWAY.
        let key = RouteEntryKey::new(self.get_profile(), dst_addr, false);
        let route = self.get_route_table_mut()
            .entry(key)
            .and_modify(|route| {
                if route.status != RouteStatus::Active
                    && route.status != RouteStatus::ValidationUnderway
                {
                    route.status = RouteStatus::DiscoveryUnderway
                }
            })
            .or_insert(RouteEntry {
                status: RouteStatus::DiscoveryUnderway,
                no_route_cache,
                is_group: false,
                many_to_one: false,
                route_record_required: false,
                next_hop_addr: Default::default(),
                ..Default::default()
            })
            .map_err(|_| RouteError::RouteError(NetworkStatus::NoRoutingCapacity))?;

        // The device shall also establish the corresponding route discovery table entry
        // if one with the same initiator and route request ID does not already
        // exist.
        route
            .discovery
            .insert(
                (route_request_id, slf_addr),
                RouteDiscoveryEntry::new(slf_addr, 0),
            )
            .map_err(|_| RouteError::RouteError(NetworkStatus::NoRoutingCapacity))?;

        self.send_route_request_command(
            RouteRequestCmd {
                dst_addr: RouteDiscoveryRequestAddress::UnicastOrBroadcast(dst_addr),
                ieee_destination: None,
                route_request_id,
                path_cost: 0,
            },
        )
        .await
        .map_err(RouteError::from)
    }
}

pub struct ReceivedCommandFrame<'a, T> {
    pub mac_src_addr: NwkAddress,
    pub header: NwkHeader,
    pub cmd: &'a mut T,
}

impl<'a, T> ReceivedCommandFrame<'a, T> {
    pub fn originator_addr(&self) -> NwkAddress {
        self.header.source
    }

    pub fn originator_ieee_addr(&self) -> Option<ExtendedAddress> {
        self.header.source_ieee
    }
}

// 3.6.3.1
pub fn compute_routing_cost(/* lqi: u8 */) -> LinkCost {
    let lqi = 0; // TODO
    if lqi <= 16 {
        LinkCost::_7
    } else if lqi <= 32 {
        LinkCost::_6
    } else if lqi <= 64 {
        LinkCost::_5
    } else if lqi <= 96 {
        LinkCost::_4
    } else if lqi <= 128 {
        LinkCost::_3
    } else if lqi <= 192 {
        LinkCost::_2
    } else {
        LinkCost::_1
    }
}

impl<T: JoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // Address conflicts
    // 3.6.1.9
    async fn detect_addr_conflict_self(
        &mut self,
        hdr: &NwkHeader,
    ) -> bool {
        if hdr.destination == self.get_addr() {
            if let Some(ext_addr) = hdr.destination_ieee
                && ext_addr != self.get_ext_addr()
            {
                // local address conflict
            }
        }

        let addr_map = &mut self.get_addr_map_mut();
        let current_ext_addr = if let Some(source_ieee) = hdr.source_ieee {
            match addr_map.entry(hdr.source).or_insert(source_ieee) {
                Ok(addr) => Some(addr),
                Err(_) => return false,
            }
        } else {
            addr_map.get_mut(&hdr.source)
        };

        let src_ieee = unwrap_or_return!(hdr.source_ieee, false);
        match current_ext_addr {
            Some(ext_addr) => {
                if *ext_addr != src_ieee {
                    self.send_network_status_cmd(
                        NetworkStatusCmd {
                            status: NetworkStatus::AddressConflict(hdr.source),
                            dest_short_addr: NwkAddress::BROADCAST_RX_ON_IDLE,
                            dest_extended_addr: None,
                        },
                    )
                        .await
                        .ok(); // TODO
                    // address conflict
                    return true;
                }
            }
            None => {
                let _ = addr_map.insert(hdr.source, src_ieee);
            }
        }

        false
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsEndDevice, D, S> {
    async fn handle_addr_conflict(&mut self, hdr: &NwkHeader) -> bool {
        self.detect_addr_conflict_self(hdr).await
    }
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    async fn handle_addr_conflict(&mut self, hdr: &NwkHeader) -> bool {
        if self.detect_addr_conflict_self(hdr).await {
            return true;
        }

        let src_ieee = unwrap_or_return!(hdr.source_ieee, false);
        if self.lock_neighbors(|children| children
            .find_by_short_addr(hdr.source)
            .map(|nb| nb.ext_addr.is_some() && nb.ext_addr.unwrap() == src_ieee)
            .is_some())
        {
            // address_conflict
            return true; //TODO
        }

        // TODO: check address conflict for broadcast frames:
        // broadcast frame with src address = self src address and not in the BTT

        false
    }

    pub(crate) fn is_address_conflict(
        &self,
        nwk_addr: &NwkAddress,
        ext_addr: &ExtendedAddress,
        check_self: bool,
    ) -> bool {
        if check_self && self.get_addr() == *nwk_addr {
            return true;
        }

        let addr_map = &self.get_addr_map();
        if let Some(addr) = addr_map.get(nwk_addr) {
            return *addr != *ext_addr;
        };

        self.lock_neighbors(|children| children
            .find_by_short_addr(*nwk_addr)
            .map(|nb| nb.ext_addr.is_some() && nb.ext_addr.unwrap() == *ext_addr)
            .unwrap_or(false))
    }
}
