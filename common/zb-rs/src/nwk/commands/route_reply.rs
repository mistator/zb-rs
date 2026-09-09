use core::ops::Add;

use crate::common::information_base::RouteEntry;
use crate::common::information_base::RouteEntryKey;
use crate::nwk::commands::Command;
use crate::nwk::commands::route_request::RouteRequest;
use crate::nwk::constants::ROUTE_DISCOVERY_TIME;
use crate::nwk::constants::WAIT_BEFORE_VALIDATION;
use crate::nwk::ctx::{Initialized, Joined, Nwk, Router};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nib::RouteStatus;
use crate::nwk::nlde::TransferResult;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::nwk::service::routing::compute_routing_cost;
use crate::unwrap_or_return;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Instant;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(BitStruct, Clone, Copy, Debug)]
#[bit_struct(repr = u8)]
pub struct CommandOptions {
    #[bit_struct(skip = 3)]
    pub originator_ieee: bool,
    pub responder_ieee: bool,
    pub multicast: bool,
}

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct RouteReply {
    pub command_options: CommandOptions,
    pub route_request_id: u8,
    pub originator_address: NwkAddress,
    pub responder_address: NwkAddress,
    pub path_cost: u8,
    #[byte(parse_if = command_options.originator_ieee)]
    pub originator_ieee_address: Option<ExtendedAddress>,
    #[byte(parse_if = command_options.responder_ieee)]
    pub responder_ieee_address: Option<ExtendedAddress>,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S>  {
    pub async fn send_route_reply_cmd(
        &mut self,
        route_request: &ReceivedCommandFrame<'_, RouteRequest>,
        path_cost: u8,
    ) -> TransferResult {
        let hdr = NwkHeader::cmd(self)
            .destination(route_request.mac_src_addr)
            .call();

        /*
        let responder_ext_addr = ctx
            .as_nwk_ctx()
            .find_ext_addr(route_request.cmd.destination_address);
            TODO
         */
        let responder_ext_addr = self.get_router_ctx_mut().children
            .find_by_short_addr(route_request.cmd.dst_addr)
            .map(|nb| nb.ext_addr.unwrap());

        let cmd = Command::RouteReply(RouteReply {
            command_options: CommandOptions {
                originator_ieee: route_request.originator_ieee_addr().is_some(),
                responder_ieee: responder_ext_addr.is_some(),
                multicast: false,
            },
            route_request_id: route_request.cmd.route_request_id,
            originator_address: route_request.originator_addr(),
            responder_address: route_request.cmd.dst_addr,
            path_cost: path_cost + compute_routing_cost(),
            originator_ieee_address: route_request.originator_ieee_addr(),
            responder_ieee_address: responder_ext_addr,
        });

        let cmd_frame = NwkFrame::new_cmd_frame(hdr, cmd);

        self.transmit_frame(&cmd_frame, route_request.mac_src_addr, true).await
    }

    // 3.6.3.5.3
    pub async fn handle_route_reply_command(
        &mut self,
        frame: &mut ReceivedCommandFrame<'_, RouteReply>,
    ) -> () {
        let cmd = &frame.cmd;

        fn update_next_hop(
            route: &mut RouteEntry,
            key: (u8, NwkAddress),
            frame: &ReceivedCommandFrame<'_, RouteReply>,
        ) {
            let next_hop_changed = route.next_hop_addr != frame.mac_src_addr;
            let has_discovery = route
                .discovery
                .get_mut(&key)
                .filter(|discovery| discovery.residual_cost > frame.cmd.path_cost)
                .map(|discovery| {
                    discovery.residual_cost = frame.cmd.path_cost;
                    if next_hop_changed {
                        discovery.expiration_time = Instant::now().add(if route.is_group {
                            WAIT_BEFORE_VALIDATION
                        } else {
                            ROUTE_DISCOVERY_TIME
                        });
                    }
                })
                .is_some();

            if has_discovery {
                route.next_hop_addr = frame.mac_src_addr;
            }
        }

        self.get_router_ctx_mut().route_table.cleanup();
        if self.get_router_ctx_mut().route_table.is_full() {
            if self.ctx.get_profile().nwk_use_tree_routing {
                // TODO: send the route reply as though it were a data frame being
                // forwarded using tree routing
            } else {
                // discard frame
                return;
            }
        }

        let slf_addr = self.ctx.addr;

        let key = RouteEntryKey::new(
            &self.ctx.get_profile(),
            cmd.responder_address,
            cmd.command_options.multicast,
        );
        let discovery_key = (cmd.route_request_id, cmd.originator_address);
        let route = unwrap_or_return!(self.get_router_ctx_mut().route_table.get_mut(&key));
        if !route.discovery.contains_key(&discovery_key) {
            return;
        }

        if cmd.originator_address == slf_addr {
            if route.status == RouteStatus::DiscoveryUnderway {
                route.status = if route.is_group {
                    RouteStatus::ValidationUnderway
                } else {
                    RouteStatus::Active
                };

                update_next_hop(route, discovery_key, frame);
            } else if matches!(
            route.status,
            RouteStatus::Active | RouteStatus::ValidationUnderway
        ) {
                update_next_hop(route, discovery_key, frame);
            }
        } else {
            update_next_hop(route, discovery_key, frame);
        }

        frame.cmd.path_cost += compute_routing_cost();
    }
}
