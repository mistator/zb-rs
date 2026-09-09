use core::cmp::{PartialEq, max};

use crate::common::information_base::RouteDiscoveryEntry;
use crate::common::information_base::RouteEntry;
use crate::common::information_base::RouteEntryKey;
use crate::nwk::commands::Command;
use crate::nwk::constants::MAX_ROUTE_REQUEST_JITTER;
use crate::nwk::constants::MIN_ROUTE_REQUEST_JITTER;
use crate::nwk::constants::ROUTE_REQUEST_RETRIES;
use crate::nwk::constants::ROUTE_REQUEST_RETRY_INTERVAL;
use crate::nwk::ctx::{Initialized, Joined, JoinedDevice, Nwk, Router};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nib::RouteStatus;
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::nwk::service::routing::RouteDiscoveryRequestAddress;
use crate::nwk::service::routing::compute_routing_cost;
use crate::nwk::service::routing::distributed_nwk_is_descendant;
use crate::stack_profile::AddrAllocMethod;
use crate::unwrap_or_return;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Timer;
use rand::RngExt;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(TryRead, TryWrite, PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum ManyToOne {
    NotManyToOne = 0x0,
    ManyToOneRouteRecordSupported = 0x01,
    ManyToOneRouteRecordNotSupported = 0x02,
}

#[derive(BitStruct, Clone, Copy, Debug)]
#[bit_struct(repr = u8)]
pub struct CommandOptions {
    #[bit_struct(skip = 3)]
    pub many_to_one: ManyToOne,
    pub destination_ieee: bool,
    pub multicast: bool
}

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct RouteRequest {
    pub command_options: CommandOptions,
    pub route_request_id: u8,
    pub dst_addr: NwkAddress,
    pub path_cost: u8,
    #[byte(parse_if = command_options.destination_ieee)]
    pub destination_ieee_address: Option<ExtendedAddress>,
}

impl RouteRequest {
    pub fn is_unicast(&self) -> bool {
        self.command_options.multicast == false && self.dst_addr.is_unicast()
    }

    pub fn is_multicast(&self) -> bool {
        self.command_options.multicast
    }

    pub fn is_many_to_one(&self) -> bool {
        self.dst_addr.is_broadcast()
    }

    pub fn no_route_cache(&self) -> bool {
        self.command_options.many_to_one == ManyToOne::ManyToOneRouteRecordNotSupported
    }
}

#[derive(Debug, Clone)]
pub struct RouteRequestCmd {
    pub dst_addr: RouteDiscoveryRequestAddress,
    pub ieee_destination: Option<ExtendedAddress>,
    pub route_request_id: u8,
    pub path_cost: u8,
}

impl<T: JoinedDevice, D: NwkMac, S: StorageRegion>Nwk<Initialized<Joined<T>>, D, S> {
    // 3.4.1
    // The NWK layer may choose to buffer the received frame pending route discovery
    // or, if the frame is a unicast frame and the NIB attribute nwkUseTreeRouting
    // has a value of TRUE, set the discover route sub-field of the frame control
    // field in the NWK header to 0 and forward the data frame along the tree.
    // Once the device creates the route discovery table and routing table entries,
    // the route request command frame shall be created with the payload depicted in
    // Figure 3-12. The individual fields are populated as follows: • The command
    // frame identifier field shall be set to indicate the command frame is a route
    // request, see Table 3-49.
    // • The Route request identifier field shall be set to the value stored in the
    // route discovery table entry. • The multicast flag and destination address
    // fields shall be set in accordance with the destination address for which the
    // route is to be discovered. • The path cost field shall be set to 0.
    // Once created, the route request command frame is ready for broadcast and is
    // passed to the MAC sub-layer using the MCPS-DATA.request primitive.
    // When broadcasting a route request command frame at the initiation of route
    // discovery, the NWK layer shall retry the broadcast nwkcInitialRREQRetries
    // times after the initial broadcast, resulting in a maximum of nwkcIni-
    // tialRREQRetries + 1 transmissions. The retries will be separated by a time
    // interval of nwkcRREQRetryInterval Oc- tetDurations.
    // The many-to-one route discovery procedure shall be initiated by the NWK layer
    // of a ZigBee router or coordinator on receipt of an
    // NLME-ROUTE-DISCOVERY.request primitive from the next higher layer where the
    // DstAddr- Mode parameter has a value of 0x00. A many-to-one route request
    // command frame is not retried; however, a dis- covery table entry is still
    // created to provide loop detection during the nwkcRouteDiscoveryTime period.
    // If the No- RouteCache parameter of the NLME-ROUTE-DISCOVERY.request primitive
    // is TRUE, the many-to-one sub-field of the command options field of the
    // command frame payload shall be set to 2. Otherwise, the many-to-one sub-field
    // shall be set to 1. Note that in this case, the NWK layer should maintain a
    // route record table. The destination address field of the NWK header shall be
    // set to 0xfffc, the all-router broadcast address. The broadcast radius shall
    // be set to the value in nwkConcentratorRadius. A source device that initiates
    // a many-to-one route discovery is designated as a concentrator and referred to
    // as such in this document and the NIB attribute nwkIsConcentrator should be
    // set to TRUE. If a device has nwkIsConcentrator equal to TRUE and there is a
    // non-zero value in nwkConcentra- torDiscoveryTime, the network layer should
    // issue a route request command frame each nwkConcentratorDiscovery- Time.
    pub async fn send_route_request_command(
        &mut self,
        config: RouteRequestCmd,
    ) -> Result<(), NldeTransferError> {
        let hdr = NwkHeader::cmd(self)
            .destination(NwkAddress::BROADCAST_ROUTERS)
            .call();

        let cmd = RouteRequest {
            command_options: CommandOptions {
                many_to_one: match config.dst_addr {
                    RouteDiscoveryRequestAddress::Multicast(_) => ManyToOne::NotManyToOne,
                    RouteDiscoveryRequestAddress::UnicastOrBroadcast(addr) => {
                        if addr.is_broadcast() {
                            ManyToOne::ManyToOneRouteRecordSupported
                        } else {
                            ManyToOne::NotManyToOne
                        }
                    }
                },
                destination_ieee: config.ieee_destination.is_some(),
                multicast: matches!(config.dst_addr, RouteDiscoveryRequestAddress::Multicast(_)),
            },
            route_request_id: config.route_request_id,
            dst_addr: match config.dst_addr {
                RouteDiscoveryRequestAddress::Multicast(addr)
                | RouteDiscoveryRequestAddress::UnicastOrBroadcast(addr) => addr,
            },
            path_cost: config.path_cost,
            destination_ieee_address: config.ieee_destination,
        };

        let frame = NwkFrame::new_cmd_frame(hdr, Command::RouteRequest(cmd));

        let mut retries = 0;
        while retries <= ROUTE_REQUEST_RETRIES {
            if let Ok(_) = self.transmit_frame(&frame, NwkAddress::BROADCAST_ALL, false).await {
                break;
            }
            retries += 1;
            Timer::after(ROUTE_REQUEST_RETRY_INTERVAL).await;
        }

        todo!()
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    // 3.6.3.5.2
    // The spec implies that a route reply command shall be sent even if neither the
    // device nor any of its children is the route request destination. I believe
    // this is incorrect based on the route reply command requirement that the
    // responder address be the destination address in the corresponding route
    // request command, therefore in that case we don't send a route reply command
    pub async fn handle_route_request_command(
        &mut self,
        frame: &mut ReceivedCommandFrame<'_, RouteRequest>,
    ) -> () {
        // TODO: Move to task
        async fn relay_route_request_cmd<D: NwkMac, S: StorageRegion>(
            ctx: &mut Nwk<Initialized<Joined<Router>>, D, S>,
            frame: &ReceivedCommandFrame<'_, RouteRequest>,
        ) {
            let jitter = 2 * ctx.rng.random_range(
                MIN_ROUTE_REQUEST_JITTER.as_millis()..MAX_ROUTE_REQUEST_JITTER.as_millis(),
            );

            Timer::after_millis(jitter).await;

            let mut retries = 0;
            while retries < ROUTE_REQUEST_RETRIES {
                let dst_addr = if frame.cmd.command_options.multicast {
                    RouteDiscoveryRequestAddress::Multicast(frame.cmd.dst_addr)
                } else {
                    RouteDiscoveryRequestAddress::UnicastOrBroadcast(frame.cmd.dst_addr)
                };

                ctx.send_route_request_command(
                    RouteRequestCmd {
                        dst_addr,
                        ieee_destination: frame.cmd.destination_ieee_address,
                        route_request_id: frame.cmd.route_request_id,
                        path_cost: frame.cmd.path_cost,
                    },
                )
                    .await
                    .ok();

                retries += 1;
            }
        }

        let cmd = &frame.cmd;
        if !self.has_routing_capacity() && (cmd.is_multicast() || cmd.is_many_to_one()) {
            return;
        }

        let path_cost = if cmd.is_many_to_one() || self.ctx.get_profile().nwk_sym_link {
            match self
                .get_children()
                .iter()
                .find(|nb| nb.nwk_addr == frame.mac_src_addr)
                .map(|nb| nb.outgoing_cost)
                .unwrap_or(0)
            {
                0 => return,
                path_cost => max(path_cost, cmd.path_cost),
            }
        } else {
            cmd.path_cost
        };

        let matches_self_or_children = (cmd.is_unicast()
            && (self.ctx.addr == cmd.dst_addr
            || self
            .get_children()
            .iter()
            .find(|nb| nb.is_child() && nb.nwk_addr == cmd.dst_addr)
            .is_some()))
            || (cmd.is_multicast()
            && self.ctx
            .group_table
            .contains(&cmd.dst_addr));

        self.cleanup_route_table();
        if !self.has_routing_capacity() {
            if self.ctx.get_profile().nwk_addr_alloc == AddrAllocMethod::Distributed
                && cmd.is_unicast()
            {
                let source_nb = unwrap_or_return!(
                self.get_children()
                    .iter()
                    .find(|nb| nb.nwk_addr == frame.mac_src_addr)
            );

                let originator_is_descendant = distributed_nwk_is_descendant(
                    &self.ctx.get_profile(),
                    0, // FIXME
                    frame.originator_addr(),
                    self.ctx.addr
                );
                if (source_nb.is_parent() && originator_is_descendant)
                    || (source_nb.is_child() && !originator_is_descendant)
                {
                    return;
                }

                if matches_self_or_children {
                    self.send_route_reply_cmd(frame, path_cost).await.ok();
                } else {
                    frame.cmd.path_cost += compute_routing_cost();
                    // TODO: forward route request
                }
            } else {
                return;
            }
        } else {
            // 1. Update or create route entry (except if many-to-one) 1a. Update or create
            //    a discovery entry attached to the route entry
            // 2. Find or create (active) reverse route entry (if nwk_sym_link is true)

            // TODO: Should we add a discovery entry here?
            if cmd.is_many_to_one() || self.ctx.get_profile().nwk_sym_link {
                // Add active route to source
                let key = RouteEntryKey::new(
                    self.ctx.get_profile(),
                    frame.originator_addr(),
                    false,
                );
                unwrap_or_return!(
                self.get_router_ctx_mut().route_table
                    .entry(key)
                    .and_modify(|route| {
                        route.status = RouteStatus::Active;
                        if route.next_hop_addr != frame.mac_src_addr {
                            route.next_hop_addr = frame.mac_src_addr;
                            route.route_record_required = cmd.is_many_to_one()
                        }
                    })
                    .or_insert(RouteEntry {
                        status: RouteStatus::Active,
                        no_route_cache: cmd.no_route_cache(),
                        many_to_one: cmd.is_many_to_one(),
                        route_record_required: cmd.is_many_to_one(), /* TODO: Check if required
                                                                      * for unicast */
                        is_group: false,
                        next_hop_addr: frame.mac_src_addr,
                        ..Default::default()
                    })
                    .ok()
            );
            }

            if (cmd.is_unicast() || cmd.is_multicast()) && !matches_self_or_children {
                // Add route and discovery entries to destination if the device or any of its
                // children is not the destination
                let key = RouteEntryKey::new(
                    self.ctx.get_profile(),
                    cmd.dst_addr,
                    cmd.is_multicast(),
                );
                let route = unwrap_or_return!(
                self.get_router_ctx_mut().route_table
                    .entry(key)
                    .and_modify(|route| {
                        if !matches!(
                            route.status,
                            RouteStatus::Active | RouteStatus::ValidationUnderway
                        ) {
                            route.status = RouteStatus::DiscoveryUnderway
                        }
                    })
                    .or_insert(RouteEntry {
                        status: RouteStatus::DiscoveryUnderway,
                        no_route_cache: false,
                        many_to_one: false,
                        next_hop_addr: Default::default(),
                        is_group: cmd.is_multicast(),
                        route_record_required: false,
                        discovery: Default::default(),
                    })
                    .ok()
            );

                let new_path_cost = path_cost + compute_routing_cost();
                let key = (cmd.route_request_id, frame.originator_addr());
                unwrap_or_return!(
                route
                    .discovery
                    .entry(key)
                    .and_modify(|discovery_route| {
                        if new_path_cost >= discovery_route.forward_cost {
                            return;
                        }

                        discovery_route.forward_cost = new_path_cost;
                        discovery_route.sender_addr = frame.mac_src_addr;
                    })
                    .or_insert(RouteDiscoveryEntry::new(
                        frame.mac_src_addr,
                        new_path_cost
                    ))
                    .ok()
            );
            } else if (cmd.is_unicast() || cmd.is_multicast()) && matches_self_or_children {
                // else, send reply and return
                unwrap_or_return!(self.send_route_reply_cmd(frame, path_cost).await.ok());
            }

            // relay route request if it's a many_to_one request or the device or its
            // children are not the destination
            relay_route_request_cmd(self, frame).await;
        }
    }
}
