use core::ops::Add;

use embassy_time::Instant;
use embassy_time::Timer;
use embassy_time::{Duration, TimeoutError, WithTimeout};
use itertools::Itertools;

use crate::common::information_base::RouteEntryKey;
use crate::common::security::frame::SecurityLevel;
use crate::mac::mlme::AssociateResponseStatus;
use crate::mac::types::{MacIndication, McpsDataIndication, MlmeAssociateIndication};
use crate::nwk::commands::Command;
use crate::nwk::ctx::{ED, EndDevice, Initialized, InitializedState, Joined, JoinedDevice, Nwk, NwkListen, PendingRejoin, Router};
use crate::nwk::ctx::{NeighborRelationship, NewNwkNeighbour, NwkNeighbor};
use crate::nwk::frame::CommandFrame;
use crate::nwk::frame::NwkDataFrame;
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::frame::header::{DiscoverRoute, MulticastMode};
use crate::nwk::nib::RouteStatus;
use crate::nwk::nib::TransactionRecord;
use crate::nwk::nlde::JoinMethod::Association;
use crate::nwk::nlde::NldeDataIndication;
use crate::nwk::nlde::NldeDataIndicationDstAddress;
use crate::nwk::nlde::NlmeJoinIndication;
use crate::nwk::nlde::NwkIndication;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::unwrap_or_return;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::DeviceType;
use zb_types::common::NwkAddress;
use zb_types::mac::MacAddress;

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<Initialized<T>, D, S> {
    pub(crate) async fn wait_for_frame<V>(
        &mut self,
        timeout: Duration,
        eval: fn(&NwkFrame) -> Option<V>,
    ) -> Result<V, TimeoutError> {
        async {
            loop {
                let indication = self.mac.listen().await;

                if let MacIndication::Data(mut indication) = indication {
                    match indication.dest_address {
                        None => continue,
                        Some(_) => {
                            match self.decrypt_frame(indication.payload.as_mut_slice())
                                .await
                            {
                                Err(err) => {
                                    log::warn!("error decrypting network frame: {:?}", err);
                                    continue;
                                }
                                Ok((frame, _)) => {
                                    if let Some(result) = eval(&frame) {
                                        return result;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        .with_timeout(timeout)
        .await
    }
}

impl<D: NwkMac + Sync, S: StorageRegion + Sync> NwkListen for Nwk<Initialized<Joined<Router>>, D, S> {
    // 3.6.2.2
    async fn listen_nwk(&mut self, is_authorized: bool) -> NwkIndication {
        loop {
            let result = match self.get_mac_indication().await {
                MacIndication::Data(indication) => {
                    self.handle_data_indication(is_authorized, indication).await
                }
                MacIndication::Associate(indication) => self
                    .handle_associate_indication(indication)
                    .await
                    .map(NwkIndication::Join),
                _ => None,
            };

            if result.is_some() {
                return result.unwrap();
            }
        }
    }
}
/*
impl<D: NwkMac, S: StorageRegion> NwkListen for Nwk<Initialized<Joined<EndDevice>>, D, S> {
    // 3.6.2.2
    async fn listen_nwk(&mut self, is_authorized: bool) -> NwkIndication {
    }
}

 */

impl<D: NwkMac + Sync, S: StorageRegion + Sync> NwkListen for Nwk<Initialized<PendingRejoin>, D, S> {
    async fn listen_nwk(&mut self, is_authorized: bool) -> NwkIndication {
        loop {
            let result = match self.get_mac_indication().await {
                MacIndication::Data(indication) => {
                    self.handle_data_indication(is_authorized, indication).await
                }
                _ => None,
            };

            if result.is_some() {
                return result.unwrap();
            }
        }
    }
}

impl<D: NwkMac + Sync, S: StorageRegion + Sync> NwkListen for Nwk<Initialized<Joined<EndDevice>>, D, S> {
    async fn listen_nwk(&mut self, is_authorized: bool) -> NwkIndication {
        loop {
            let result = match self.get_mac_indication().await {
                MacIndication::Data(indication) => {
                    self.handle_data_indication(is_authorized, indication).await
                }
                _ => None,
            };

            if result.is_some() {
                return result.unwrap();
            }
        }
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    async fn handle_associate_indication(
        &mut self,
        indication: MlmeAssociateIndication,
    ) -> Option<NlmeJoinIndication> {
        let capabilities = &indication.capability_information;
        self.get_router_ctx_mut().children.cleanup();
        let pan_id = self.ctx.pan_id;

        let child = {
            let child = self.get_router_ctx().children.find_by_ext_addr_and_type(
                indication.device_ext_addr,
                capabilities.device_type.into(),
            );

            if let Some(child) = child {
                child
            } else {
                self.get_router_ctx_mut()
                    .children
                    .retain(|nb| nb.ext_addr != Some(indication.device_ext_addr));
                let nwk_addr = self.assign_child_address();
                let neighbor = NwkNeighbor::new(NewNwkNeighbour {
                    ext_addr: indication.device_ext_addr,
                    nwk_addr,
                    device_type: capabilities.device_type.into(),
                    rx_on_when_idle: capabilities.rx_on_when_idle,
                    relationship: match self.ctx.get_profile().nwk_security_level {
                        SecurityLevel::None => NeighborRelationship::Child,
                        _ => NeighborRelationship::UnauthenticatedChild,
                    },
                });
                match self.get_router_ctx_mut().children.push(neighbor) {
                    Ok(_) => self.get_router_ctx()
                        .children
                        .find_by_ext_addr(indication.device_ext_addr)
                        .unwrap(),
                    Err(_) => {
                        self.mac
                            .associate_response(
                                pan_id,
                                indication.device_ext_addr,
                                AssociateResponseStatus::PanAtCapacity,
                            )
                            .await
                            .ok();
                        return None;
                    }
                }
            }
        };

        let child_addr = child.nwk_addr;
        let child_ext_addr = child.ext_addr;

        let result = self
            .mac
            .associate_response(
                pan_id,
                indication.device_ext_addr,
                AssociateResponseStatus::Success(child_addr),
            )
            .await;

        if let Err(_) = result {
            return None;
        }

        Some(NlmeJoinIndication {
            nwk_addr: child_addr,
            ext_addr: child_ext_addr.unwrap(),
            join_method: Association(indication.capability_information),
        })
    }

    async fn handle_data_indication(
        &mut self,
        is_authorized: bool,
        mut indication: McpsDataIndication,
    ) -> Option<NwkIndication> {
        let (frame, use_security) = self
            .process_incoming_indication(&mut indication, is_authorized)
            .await?;

        if !self.handle_end_device_frame(&frame) {
            return None;
        }

        // If the receiving device is a ZigBee coordinator or an operating ZigBee
        // router, that is, a router that has already in-
        // voked the NLME-START-ROUTER.request primitive, it shall process data frames
        // as follows: • Messages shall be verified to determine if an end device
        // has switched router parents. This is outlined in section 3.6.2.3
        if frame.header().radius > 0 {
            self.examine_end_devices_that_have_changed_router_parents(
                frame.header(),
                indication.src_address.unwrap(),
            );
        }


        match frame {
            NwkFrame::Data(mut dataframe) => {
                // Route data frames
                let should_indicate_frame = {
                    let hdr = &dataframe.header;
                    if hdr.radius <= 0 {
                        true
                    // Broadcast and multicast data frames shall be relayed
                    // according to the procedures outlined
                    // in sections 3.6.5 and 3.6.6.
                    } else if hdr.control.multicast {
                        self.relay_multicast_frame(&mut dataframe).await
                    } else if hdr.destination.is_broadcast() {
                        self.relay_broadcast_frame(&mut dataframe).await
                    // Unicast data frames with a destination address that does
                    // not match the device's network
                    // address shall be relayed according to
                    // the procedures outlined in section
                    // 3.6.3.3. (Under all other circumstances, unicast
                    // data frames shall be discarded immediately.)
                    // Source-routed data frames with a destination address that
                    // does not match the device’s network address
                    // shall be relayed according to the procedures outlined in
                    // section 3.6.3.3.2.
                    } else if hdr.destination.is_unicast() && hdr.destination != self.ctx.addr {
                        self.relay_unicast_frame(&mut dataframe).await
                    } else {
                        true
                    }
                };

                return if should_indicate_frame && self.frame_matches_self(&dataframe) {
                    Some(self.return_data_indication(&dataframe, &indication, use_security))
                } else {
                    return None
                }
            }
            NwkFrame::NwkCommand(mut cmd_frame) => {
                let mac_src_address =
                    if let Some(MacAddress::Short(_, addr)) = indication.src_address {
                        addr
                    } else {
                        return None;
                    };

                let header = cmd_frame.header.clone();
                match cmd_frame.command {
                    Command::RouteRequest(ref mut cmd) => {
                        self.handle_route_request_command(&mut ReceivedCommandFrame {
                            mac_src_addr: mac_src_address,
                            header,
                            cmd,
                        })
                        .await;
                    }
                    Command::RouteReply(ref mut cmd) => {
                        let dst_addr = header.destination;

                        if dst_addr != self.ctx.addr {
                            return None;
                        }

                        self.handle_route_reply_command(&mut ReceivedCommandFrame {
                            mac_src_addr: mac_src_address,
                            header,
                            cmd,
                        })
                        .await;
                    }
                    Command::RejoinRequest(ref mut cmd) => {
                        match self
                            .handle_rejoin_request_command(&ReceivedCommandFrame {
                                mac_src_addr: mac_src_address,
                                header,
                                cmd,
                            })
                            .await
                        {
                            Ok(indication) => match indication {
                                Some(indication) => {
                                    return Some(NwkIndication::Join(indication));
                                }
                                None => {}
                            },
                            Err(_) => {}
                        }
                    }
                    Command::LinkStatus(ref mut cmd) => {
                        self.handle_link_status_command(&ReceivedCommandFrame {
                            mac_src_addr: mac_src_address,
                            header,
                            cmd,
                        });
                    }
                    Command::EndDeviceTimeoutRequest(ref mut cmd) => {
                        self.handle_end_device_timeout_request_command(&ReceivedCommandFrame {
                            mac_src_addr: mac_src_address,
                            header,
                            cmd,
                        })
                        .await
                        .ok();
                    }
                    Command::NetworkStatus(_) => {}
                    Command::Leave(_) => {}
                    Command::RouteRecord(_) => {}
                    Command::RejoinResponse(_) => {}
                    Command::NetworkReport(_) => {}
                    Command::NetworkUpdate(_) => {}
                    Command::LinkPowerDelta(_) => {}
                    _ => {
                        self.handle_end_device_commands(mac_src_address, header, cmd_frame.command).await;
                    }
                }

            }
            NwkFrame::Reserved(_) => {},
            NwkFrame::InterPan(_) => {},
        }

        None
    }

    fn handle_end_device_frame(&self, frame: &NwkFrame) -> bool {
        let hdr = frame.header();

        // On receipt of a frame with the End Device Initiator sub-field of the frame
        // control set to 1, the following processing shall take place:
        if hdr.control.end_device_initiator {
            // 1. If the receiving device is an end device the message shall be dropped and
            //    no further
            // processing shall take place.

            // 2. The receiving device shall search the neighbor table for an entry where
            //    the value of the Network
            // Address matches the value of the Source Address field of the message, and the
            // device type is 0x02 (end device). If no entry is found then the
            // message shall be dropped and no further processing shall take place.
            if self.get_router_ctx()
                .children
                .find_by_short_addr_and_device_type(hdr.source, DeviceType::EndDevice)
                .is_some()
            {
                // 3. The routing device shall issue a Mgmt_Leave_Req command to the
                //    sender with the Rejoin
                // parameter set to 1 and the RemoveChildren parameter set to 0.
                // TODO:
            } else {
                return false;
            }
        }

        true
    }

    // 3.6.2.3
    // A router upon receipt of a NWK command or data message must perform the
    // following:
    fn examine_end_devices_that_have_changed_router_parents(
        &mut self,
        header: &NwkHeader,
        mac_src_address: MacAddress,
    ) -> () {
        let nwk_src_address = header.source;

        // 1. Search the neighbor table for an entry where the Network Address matches
        //    the value of the NWK
        // Source field in the message. If no match is found then go to step 6.
        // 2. Examine if the Device Type of the entry corresponds to a ZigBee End
        //    Device. If it does not, go
        // to step 6.
        let (nb_idx, _) = unwrap_or_return!(self.get_router_ctx_mut().children.iter().find_position(|nb| {
            nb.nwk_addr == nwk_src_address && nb.device_type == DeviceType::EndDevice
        }));

        // 3. Examine if the MAC source field of the message matches the NWK source
        //    field. If it does go to
        // step 6.
        if let MacAddress::Short(_, mac_src_addr) = mac_src_address
            && mac_src_addr == nwk_src_address
        {
            return;
        }

        // 4. If the message is a broadcast, examine if an entry exists in
        //    nwkBroadcastTransactionTable, if it
        // does then go to step 6. If the message is a unicast, continue processing.
        if nwk_src_address.is_broadcast() {
            if self.get_router_ctx().broadcast_transaction_table
                .iter()
                .find(|t| {
                    t.source_address == nwk_src_address
                        && t.sequence_number == header.sequence_number
                })
                .is_some()
            {
                return;
            }
        }

        // 5. At this point the message indicates it has been relayed by another device
        //    on the network acting as
        // the end device’s router parent; delete the corresponding neighbor table
        // entry.
        self.get_router_ctx_mut().children.remove(nb_idx);
        // 6. Continue to process the message.
    }

    // 3.6.5
    async fn relay_broadcast_frame(&mut self, frame: &NwkDataFrame) -> bool {
        let src_addr = frame.header.source;
        let radius = frame.header.radius;

        // Processing of a broadcast with a NWK source of the local device shall only be
        // done when the device has been powered up and operating on the network for
        // nwkNetworkBroadcastDeliveryTime.
        if src_addr == self.ctx.addr
            && Instant::now().duration_since(Instant::MIN)
                < self.ctx.get_nwk_broadcast_delivery_time()
        {
            return false;
        }

        // When a device receives a broadcast frame from a neighboring device, it shall
        // compare the destination address of the frame with its device type. If the
        // destination address does not correspond to the device type of the receiver as
        // out- lined in Table 3-69, the frame shall be discarded.
        if !self.frame_matches_self(frame) {
            return false;
        }
        // If the destination address corresponds to the device type of the
        // receiver, the device shall compare the sequence number and the source address
        // of the broadcast frame with the rec- ords in its BTT
        if !self.check_and_update_broadcast_transaction_table(frame) {
            return false;
        }

        // If we are a router, retransmit frame after random jitter
        if radius > 0 {
            // TODO: fixme
            // A ZigBee coordinator or ZigBee router operating in a non-beacon-enabled
            // ZigBee network shall retransmit a previously broadcast frame at most
            // nwkMaxBroadcastRetries times. If the device does not support passive
            // acknowledgement, then it shall retransmit the frame exactly
            // nwkMaxBroadcastRetries times.If the device supports passive acknowledgement
            // and any of its neighboring devices have not relayed the broadcast frame
            // within nwkPassiveAckTimeout OctetDurations then it shall continue to
            // retransmit the frame on the MAC interfaces which are in communication
            // with such neighbors up to a maximum of nwkMaxBroadcastRetries times.
            self.transmit_broadcast_frame(frame).await;
        }

        true
    }

    // 3.6.6.3
    // 3.6.6.4
    async fn relay_multicast_frame(&mut self, frame: &mut NwkDataFrame) -> bool {
        let mc = &mut frame.header.multicast_control.unwrap();

        if mc.multicast_mode == MulticastMode::Member {
            self.relay_member_mode_multicast(frame).await
        } else {
            // When a device receives a non-member mode multicast frame from a neighboring
            // device, the NWK layer shall de- termine whether an entry exists in
            // the nwkGroupIDTable having a group identifier field that matches the
            // destination address of the frame. If a matching entry is found, the
            // multicast control field shall be set to 0x01 (member mode)
            // and the message shall be processed as if it had been received as a member
            // mode multicast.
            if self.ctx.group_table.iter().contains(&frame.header.source) {
                mc.multicast_mode = MulticastMode::Member;
                mc.non_member_radius = mc.max_non_member_radius;

                self.relay_member_mode_multicast(frame).await
            // MCPS-DATA.request primitive to the MAC sublayer with the DstAddrMode
            // parameter set to 0x02 (16-bit network address) and the
            // DstAddr parameter set to the next hop as determined from the matching
            // routing table entry. The PANId parameter shall be set to the
            // PANId of the ZigBee network. The MAC sub-layer acknowledgement shall
            // be enabled by setting the acknowledged transmission flag of
            // the TxOptions parameter to TRUE. All other flags of the
            // TxOptions parameter shall be set based on the network configuration.
            } else {
                let key =
                    RouteEntryKey::new(self.ctx.get_profile(), frame.header.destination, true);

                // If no matching
                // nwkGroupIDTable entry is found, the device shall check its routing table for
                // an entry corresponding to the GroupID destination of the frame.
                // If there is no such routing table entry, the message shall be discarded.
                let next_hop_addr = {
                    let route = unwrap_or_return!(
                        self.get_router_ctx_mut().route_table
                            .get_mut(&key)
                            .filter(|route| matches!(
                                route.status,
                                RouteStatus::Active | RouteStatus::ValidationUnderway
                            )),
                        false
                    );

                    // If there is such an
                    // entry, the NWK layer shall examine the entry's status field. If the status is
                    // ACTIVE, the device shall (re)transmit the frame. If the
                    // status is VALIDATION_UNDERWAY, the status shall be changed to ACTIVE and the
                    // device shall (re)transmit the frame.
                    route.status = RouteStatus::Active;
                    route.next_hop_addr
                };

                // To transmit a non-member mode multicast MSDU, the NWK layer issues an
                // MCPS-DATA.request primitive to the MAC sublayer with the DstAddrMode
                // parameter set to 0x02 (16-bit network address) and the DstAddr
                // parameter set to the next hop as determined from the matching routing table
                // entry.
                self.transmit_frame(&NwkFrame::Data(frame.clone()), next_hop_addr, true).await.ok();
                true
            }
        }
    }

    async fn relay_member_mode_multicast(&mut self, frame: &mut NwkDataFrame) -> bool {
        let mc = &mut frame.header.multicast_control.unwrap();

        // When a device receives a member mode multicast frame from a neighboring
        // device, it shall compare the sequence number and the source address of
        // the multicast frame with the records in its BTT.
        if !self.check_and_update_broadcast_transaction_table(frame) {
            return false;
        }

        // When a member mode multicast frame has been received from a neighbor and
        // added to the BTT, the NWK layer shall then determine whether an entry
        // exists in the nwkGroupIDTable whose group identifier field matches the des-
        // tination group ID of the frame. If a matching entry is found, the message
        // shall be passed to the next higher layer, the multicast mode sub-field of
        // the multicast control field shall be set to 0x01 (member mode), the value of
        // the Non- memberRadius sub-field shall be set to the value of the
        // MaxNonmemberRadius sub-field in the multicast control field, and the
        // message shall be transmitted as outlined in the following paragraph.
        if self
            .ctx
            .group_table
            .iter()
            .contains(&frame.header.destination)
        {
            mc.multicast_mode = MulticastMode::Member;
            mc.non_member_radius = mc.max_non_member_radius;
        // If a matching entry is not found, the NWK layer shall examine the frame's
        // multicast NonmemberRadius field. If the value of the NonmemberRadius
        // sub-field of the multicast field is 0 the message shall be discarded,
        // along with the newly added BTR. Otherwise, the NonmemberRadius
        // sub-field shall be decremented if it is less than 0x07 and the
        // frame shall be transmitted as outlined in following paragraphs. If, as a
        // result of being decremented, this value falls to 0, the frame shall
        // not, under any circumstances, be retransmitted.
        } else {
            if mc.non_member_radius < 0x07 {
                mc.non_member_radius -= 1;
            }

            if mc.non_member_radius == 0 {
                self.get_router_ctx_mut().broadcast_transaction_table.pop();
                return false;
            }
        }

        // Member mode multicasts are transmitted using broadcasts.
        // Unlike broadcasts, there is no passive acknowledgement for multicasts
        self.transmit_broadcast_frame(frame).await;

        true
    }

    fn check_and_update_broadcast_transaction_table(&mut self, frame: &NwkDataFrame) -> bool {
        let now = Instant::now();
        let broadcast_delivery_time = self.ctx.get_nwk_broadcast_delivery_time();
        let transaction_table = &mut self.get_router_ctx_mut().broadcast_transaction_table;

        // If the device has a BTR of this particular broadcast frame in its BTT, it may
        // update the BTR to mark the neighbor- ing device as having relayed the
        // broadcast frame. It shall then drop the frame.
        if transaction_table.iter().any(|t| {
            t.source_address == frame.header.source
                && t.sequence_number == frame.header.sequence_number
                && t.expiration_time >= now
        }) {
            return false;
        }

        // If no record is found, it shall create a
        // new BTR in its BTT and may mark the neighboring device as having relayed the
        // broadcast. If, on receipt of a broadcast frame, the NWK layer finds that
        // the BTT is full and contains no expired entries, then the frame should be
        // dropped. In this situation the frame should not be retransmitted, nor should
        // it be passed up to the next higher layer.
        transaction_table.retain(|t| t.expiration_time < now);
        !transaction_table
            .push(TransactionRecord {
                source_address: frame.header.source,
                sequence_number: frame.header.sequence_number,
                expiration_time: now.add(broadcast_delivery_time),
            })
            .is_err()
    }

    // 3.6.3.3

    // A device without routing capacity shall route along the tree using
    // hierarchical routing provided that the value of the NIB attribute
    // nwkUseTreeRouting is TRUE. If the value of the NIB attribute
    // nwkUseTreeRouting is FALSE, the frame shall be discarded. If the frame is the
    // result of an NLDE-DATA.request from the NHL of the current device,
    // the NLDE shall issue the NLDE-DATA.confirm primitive with a status value of
    // ROUTE_ERROR.
    async fn relay_unicast_frame(&mut self, frame: &NwkDataFrame) -> bool {
        if self.try_unicast_direct_relay(frame).await {
            return true;
        }

        // A device that has routing capacity shall check its routing table for an entry
        // corresponding to the routing destination of the frame.
        if !self.get_router_ctx().route_table.is_full() {
            if self.try_unicast_route_table(frame).await {
                return true;
            }

            // If the device does not have a routing table entry for the routing destination
            // and it is not originating the frame using source routing, it shall
            // examine the discover route sub-field of the NWK header frame control field.
            if frame.header.control.route_discovery == DiscoverRoute::Enable {
                // If the discover
                // route sub-field has a value of 0x01, the device shall initiate route
                // discovery, as described in section 3.6.3.5.1. TODO
                false
            } else {
                // If the discover route sub-field has a value of 0 and the NIB attribute
                // nwkUseTreeRouting has a value of TRUE then the device shall route
                // along the tree using hierarchical routing.
                self.try_unicast_tree_routing(frame).await
            }
        } else {
            self.try_unicast_tree_routing(frame).await
            // If the frame is
            // being relayed on behalf of another device, the NLME shall issue a
            // network status command frame destined for the device that is
            // the source of the frame with a status of 0x04, indicating a lack of
            // routing capacity. TODO
            // It shall also issue
            // the NLME-NWK-STATUS.indication to the next higher layer with the
            // NetworkAddr parameter equal to the 16-bit network address of
            // the frame, and the Status parameter equal to 0x04, indicating a lack
            // of routing capacity. TODO
        }
    }

    pub(super) async fn try_unicast_direct_relay(&mut self, frame: &NwkDataFrame) -> bool {
        let dst_device = self.get_router_ctx_mut().children.iter().find(|nb| {
            nb.nwk_addr == frame.header.destination
                && nb.device_type == DeviceType::EndDevice
                && nb.relationship == NeighborRelationship::Child
        });

        // If the receiving device is a ZigBee router or ZigBee coordinator, and the
        // destination of the frame is a ZigBee end device and also the child of the
        // receiving device, the frame shall be routed directly to the destination using
        // the MCPS-DATA.request primitive, as described in section 3.6.2.1.
        if let Some(dst_device) = dst_device {
            let dst_addr = dst_device.nwk_addr;
            // TODO: The frame shall also set the next hop destination address equal to the
            // final destination address.
            self.transmit_frame(&NwkFrame::Data(frame.clone()), dst_addr.into(), true).await.ok();
            return true;
        }

        // Otherwise, for purposes of the ensuing discussion, define the routing
        // address of a device to be its network address if it is a router or the
        // coordinator or an end device and nwkAddrAlloc has a value of 0x02, or the
        // network address of its parent if it is an end device and nwkAddrAlloc has a
        // value of 0x00. Define the routing destination of a frame to be the
        // routing address of the frame’s NWK destination. Note that dis-
        // tributed address assignment makes it possible to derive the routing address
        // of any device from its address. See sec- tion 3.6.1.6 for details.
        let routing_dst_addr = self.get_routing_address_for_address(frame.header.destination);

        // A ZigBee router or ZigBee coordinator may check the neighbor table for an
        // entry corresponding to the routing des- tination of the frame. If there
        // is such an entry, the device may route the frame directly to the destination
        // using the MCPS-DATA.request primitive as described in section 3.6.2.1.
        if self.get_router_ctx()
            .children
            .iter()
            .find(|nb| nb.nwk_addr == routing_dst_addr)
            .is_some()
        {
            self.transmit_frame(&NwkFrame::Data(frame.clone()), routing_dst_addr.into(), true).await.ok();
            return true;
        }

        false
    }

    pub(super) async fn try_unicast_tree_routing(&mut self, frame: &NwkDataFrame) -> bool {
        if self.ctx.get_profile().nwk_use_tree_routing {
            // For hierarchical routing, if the destination is a descendant of the device,
            // the device shall route the frame to the ap- propriate child. If the
            // destination is a child, and it is also an end device, delivery of the frame
            // can fail due to the macRxOnWhenIdle state of the child device. If the
            // child has macRxOnWhenIdle set to FALSE, indirect transmission
            // as described in IEEE 802.15.4-2015 [B1] may be used to deliver the frame. If
            // the destination is not a descendant, the device shall route the frame
            // to its parent. Every other device in the network is a descendant of
            // the ZigBee coordinator and no device in the network is the de-
            // scendant of any ZigBee end device. For a ZigBee router with address A at
            // depth d, if the following logical expres- sion is true, then a
            // destination device with address D is a descendant: A < D < A +
            // Cskip(d – 1) For a definition of Cskip(d), see section 3.6.1.6.
            // If it is determined that the destination is a descendant of the receiving
            // device, the address N of the next hop device is given by:
            // N = D
            // for ZigBee end devices, where D > A + Rm x Cskip(d), and otherwise:
            // If the NWK layer on a ZigBee router or ZigBee coordinator fails to deliver a
            // unicast or multicast frame for any rea- son, the router or
            // coordinator shall make its best effort to report the failure. No failure
            // should be reported as the re- sult of a failure to deliver a
            // NLME-NWK-STATUS. The failure reporting may take one of two forms. If the
            // failed frame was being relayed as a result of a request from the next
            // higher layer, then the NWK layer shall issue an NLDE-DATA.confirm
            // with the error to the next higher layer. The value of the NetworkAddr
            // parameter of the prim- itive shall be the intended destination of the
            // frame. If the frame was being relayed on behalf of another device, then
            // the relaying device shall send a network status command frame back to the
            // source of the frame. The destination ad- dress field of the network
            // status command frame shall be taken from the destination address field of the
            // failed data frame.
            // In either case, the reasons for failure that may be reported appear in Table
            // 3-51.
            let next_hop = self.tree_routing_next_hop(frame.header.destination);
            self.transmit_frame(&NwkFrame::Data(frame.clone()), next_hop, true).await.ok();
            return true;
        }

        // If the value of the NIB attribute nwkUseTreeRouting is FALSE, the
        // frame shall be discarded
        return false;
    }

    pub(super) async fn try_unicast_route_table(&mut self, frame: &NwkDataFrame) -> bool {
        let slf_addr = self.ctx.addr;
        let key = RouteEntryKey::new(self.ctx.get_profile(), frame.header.destination, false);
        let route = unwrap_or_return!(self.get_router_ctx_mut().route_table.get_mut(&key), false);

        // If there is such an entry, and if the value of the route status field for
        // that entry is ACTIVE or VALI- DATION_UNDERWAY, the device shall relay the
        // frame using the MCPS-DATA.request primitive and set the route status
        // field of that entry to ACTIVE if it does not already have that value.
        if matches!(
            route.status,
            RouteStatus::Active | RouteStatus::ValidationUnderway
        ) {
            let next_hop = route.next_hop_addr;
            route.status = RouteStatus::Active;
            self.transmit_frame(&NwkFrame::Data(frame.clone()), next_hop.into(), true).await.ok();

            // If the many-to-one field of the
            // routing table entry is set to TRUE, the NWK shall follow the
            // procedure outlined in section 3.6.3.5.4 to determine
            // whether a route record command frame must be sent.
            // TODO
        } else if route.status == RouteStatus::DiscoveryUnderway {
            // If the device has a routing table entry corresponding to the routing
            // destination of the frame but the value of the route status field for
            // that entry is DISCOVERY_UNDERWAY, the device shall determine if it initiated
            // the discovery by consulting its discovery table.
            if route
                .discovery
                .get(&(frame.header.sequence_number, slf_addr))
                .is_none()
            {
                // otherwise, the device shall initiate route discovery as described
                // in section 3.6.3.5.1. TODO
            } else {
                // If the device initiated the discovery, the frame shall be treated
                // as though route discov- ery has been initiated for
                // this frame, The frame may optionally be buffered
                // pending route discovery or routed along the tree using
                // hierarchical routing, provided that the NIB attribute
                // nwkUseTreeRouting has a value of TRUE. If the frame is routed
                // along the tree, the discover route sub-field of the
                // NWK header frame control field shall be set to 0x00.
                // TODO
            }
        } else {
            // If the device has a routing table entry corresponding to the routing
            // destination of the frame but the route status field for that entry
            // has a value of DISCOVERY_FAILED or INACTIVE, the device may route the frame
            // along the tree using hierarchical routing, provided that the NIB
            // attribute nwkUseTreeRouting has a value of TRUE
            return self.try_unicast_tree_routing(frame).await;
        }

        true
    }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<Initialized<T>, D, S> {
    async fn get_mac_indication(&mut self) -> MacIndication {
        loop {
            match self.mac.poll_frame().await {
                Some(indication) => return indication,
                None => Timer::after_millis(10).await,
            }
        }
    }

    async fn process_incoming_indication(
        &mut self,
        indication: &mut McpsDataIndication,
        is_authorized: bool,
    ) -> Option<(NwkFrame, bool)> {
        let (mut frame, use_security) = self.decrypt_frame(indication.payload.as_mut_slice()).await.ok()?;

        // On receipt of each frame, the radius field of the NWK header shall be
        // decremented by 1.
        {
            let hdr = frame.header_mut();
            hdr.radius -= 1;

            // If the frame contains an extended address, add it to the address map table
            if let Some(source_ieee) = hdr.source_ieee {
                self.ctx
                    .addr_map
                    .insert(hdr.source, source_ieee);
            }
        }

        if !self.frame_passes_security_check(is_authorized, &frame) {
            log::warn!(
                "discarding NWK frame: security check not passed: {:?}",
                frame
            );
            return None;
        }

        Some((frame, use_security))
    }

    // If the security sub-field is set to 0, the nwkSecurityLevel attribute in the
    // NIB is non-zero, the device is currently joined and authenticated, and the
    // incoming frame is a NWK data frame, the NLDE shall discard the frame. If the
    // security sub-field is set to 0, the nwkSecurityLevel attribute in the
    // NIB is non-zero, and the incoming frame is a NWK command frame and the
    // command ID is 0x06 (rejoin request), the NLDE shall only accept the frame if
    // it is destined to itself, that is, if it does not need to be forwarded to
    // another device. Otherwise the frame shall be dropped and no further
    // processing done.

    // If the device is not joined and authenticated, or undergoing the Trust Center
    // Rejoin process, it shall perform the fol- lowing checks. If the frame is a
    // NWK command where the security sub-field of the frame is set to zero then it
    // shall only accept the frame if the command ID is 0x07 (rejoin response). If
    // the frame is a NWK data frame where the security sub-field is set to 0, the
    // device shall further examine the APDU and determine if it contains an APS
    // command ID of 0x05 (Transport Key). If the message does not contain an APS
    // Command of 0x05 (Transport Key), then the message shall be dropped and no
    // further processing done. All other messages where the security sub-field is
    // set to 0 shall be dropped and no further processing shall be done.
    fn frame_passes_security_check(&self, is_authorized: bool, frame: &NwkFrame) -> bool {
        if frame.is_secured() || self.ctx.get_profile().nwk_security_level == SecurityLevel::None {
            return true;
        }

        if is_authorized && matches!(frame, NwkFrame::Data(_)) {
            return false;
        }

        if let NwkFrame::NwkCommand(CommandFrame {
            command: Command::RejoinRequest(_),
            header,
        }) = frame
        {
            return header.destination == self.ctx.addr;
        };

        if !is_authorized {
            match frame {
                NwkFrame::Data(_) => {
                    // TODO: check ADPU and determine if its a transport key command. Otherwise,
                    // return false
                    true
                }
                NwkFrame::NwkCommand(CommandFrame {
                    command: Command::RejoinResponse(_),
                    ..
                }) => true,
                _ => false,
            }
        } else {
            true
        }
    }

    fn return_data_indication(
        &self,
        frame: &NwkDataFrame,
        indication: &McpsDataIndication,
        use_security: bool,
    ) -> NwkIndication {
        let hdr = &frame.header;

        NwkIndication::Data(NldeDataIndication {
            dst_address: match hdr.multicast_control.is_some() {
                true => NldeDataIndicationDstAddress::Multicast(hdr.destination),
                false => NldeDataIndicationDstAddress::UnicastOrBroadcast(hdr.destination),
            },
            src_address: hdr.source,
            link_quality: indication.link_quality,
            nsdu: zb_types::Vec::from_iter(frame.payload.clone()),
            security_use: use_security,
        })
    }

    fn frame_matches_self_end_device(&self, frame: &NwkDataFrame) -> bool {
        let dst_addr = frame.header.destination;

        // Multicast data frames whose group identifier is listed in the
        // nwkGroupIDTable.
        if frame.header.control.multicast {
            self.ctx.group_table.contains(&dst_addr)
        } else {
            dst_addr == self.ctx.addr || dst_addr == NwkAddress::BROADCAST_ALL
        }
    }
}

impl<T: ED, D: NwkMac, S: StorageRegion> Nwk<Initialized<T>, D, S> {

    // The following data frames shall be passed to the next higher layer using the
    // NLDE-DATA.indication primitive:
    fn frame_matches_self(&self, frame: &NwkDataFrame) -> bool {
        self.frame_matches_self_end_device(frame)
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    // The following data frames shall be passed to the next higher layer using the
    // NLDE-DATA.indication primitive:
    fn frame_matches_self(&self, frame: &NwkDataFrame) -> bool {
        self.frame_matches_self_end_device(frame) || match frame.header.destination {
            NwkAddress::BROADCAST_RX_ON_IDLE => self.mac.is_rx_on_when_idle(),
            NwkAddress::BROADCAST_ROUTERS => true,
            NwkAddress::BROADCAST_LOW_POWER => false, // TODO?
            _ => false
        }
    }
}

impl<T: JoinedDevice, D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<T>>, D, S> {
    async fn handle_end_device_commands(&mut self, mac_src_addr: NwkAddress, header: NwkHeader, mut cmd: Command) -> Option<NwkIndication> {
        match cmd {
            Command::EndDeviceTimeoutResponse(ref mut cmd) => {
                self.handle_end_device_timeout_response_command(&ReceivedCommandFrame {
                    mac_src_addr,
                    header,
                    cmd,
                })
                    .await;
            }
            _ => {},
        }

        None
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<EndDevice>>, D, S> {
    async fn handle_data_indication(
        &mut self,
        is_authorized: bool,
        mut indication: McpsDataIndication,
    ) -> Option<NwkIndication> {
        let (frame, security_use) = self.process_incoming_indication(&mut indication, is_authorized).await?;

        match frame {
            NwkFrame::Data(ref dataframe) => {
                if self.frame_matches_self(dataframe) {
                    Some(self.return_data_indication(dataframe, &indication, security_use))
                } else {
                    None
                }
            }
            NwkFrame::NwkCommand(cmd_frame) => {
                let header = cmd_frame.header;

                let mac_src_addr =
                    if let Some(MacAddress::Short(_, addr)) = indication.src_address {
                        addr
                    } else {
                        return None
                    };


                self.handle_end_device_commands(mac_src_addr, header, cmd_frame.command).await
            },
            NwkFrame::Reserved(_) => None,
            NwkFrame::InterPan(_) => None,
        }
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<PendingRejoin>, D, S> {
    async fn handle_data_indication(
        &mut self,
        is_authorized: bool,
        mut indication: McpsDataIndication,
    ) -> Option<NwkIndication> {
        let (frame, security_use) = self.process_incoming_indication(&mut indication, is_authorized).await?;

        match frame {
            NwkFrame::Data(ref dataframe) => {
                if self.frame_matches_self(dataframe) {
                    Some(self.return_data_indication(dataframe, &indication, security_use))
                } else {
                    None
                }
            }
            NwkFrame::NwkCommand(_) => None,
            NwkFrame::Reserved(_) => None,
            NwkFrame::InterPan(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::types::McpsDataIndication;
    use crate::nwk::ctx::tests::DEFAULT_NWK_ADDR;
    use crate::nwk::ctx::{EndDevice, Initialized, Joined, Nwk};
    use crate::nwk::frame::NwkFrame;
    use crate::nwk::frame::header::{FrameType, NwkHeader};
    use crate::nwk::nlde::{NldeDataIndicationDstAddress, NwkIndication};
    use zb_hal_test_mock::driver::MockDriver;
    use zb_hal_test_mock::storage::MemoryStorage;
    use zb_types::Vec;
    use zb_types::common::NwkAddress;

    const PAYLOAD: [u8; 17] = [
        0x0, 0x1, 0x4, 0xb, 0x4, 0x1, 0x1, 0x56, 0x10, 0xae, 0x0, 0x5, 0x5, 0x8, 0x5, 0xb, 0x5
    ];

    async fn quick_indication_ed(nwk: &mut Nwk<Initialized<Joined<EndDevice>>, MockDriver, MemoryStorage>, header: NwkHeader) -> Option<NwkIndication> {
        let frame = NwkFrame::new_data_frame(header, Vec::from_iter(PAYLOAD));
        let indication = McpsDataIndication::from_frame(nwk, frame).await;
        let result = nwk.handle_data_indication(true, indication).await;

        result
    }

    #[futures_test::test]
    async fn valid_frame_with_self_destination_is_indicated() {
        let mut nwk = Nwk::end_device().call();

        let header = NwkHeader::builder(&mut nwk)
            .frame_type(FrameType::Data)
            .source(NwkAddress(0))
            .destination(DEFAULT_NWK_ADDR)
            .build();

        let result = quick_indication_ed(&mut nwk, header).await;

        assert!(result.is_some());

        let indication = result.unwrap();
        assert!(matches!(indication, NwkIndication::Data(_)));
        let indication = if let NwkIndication::Data(indication) = indication {
            indication
        } else { unreachable!() };

        assert_eq!(indication.src_address, NwkAddress(0));
        assert_eq!(indication.security_use, true);
        assert_eq!(indication.dst_address, NldeDataIndicationDstAddress::UnicastOrBroadcast(DEFAULT_NWK_ADDR));
        assert_eq!(indication.nsdu[0..17], PAYLOAD);
    }

    #[futures_test::test]
    async fn valid_frame_with_other_destination_is_not_indicated() {
        let mut nwk = Nwk::end_device().call();

        let header = NwkHeader::builder(&mut nwk)
            .frame_type(FrameType::Data)
            .source(NwkAddress(0))
            .destination(NwkAddress(3883))
            .build();

        let result = quick_indication_ed(&mut nwk, header).await;
        assert!(result.is_none())
    }

    #[futures_test::test]
    async fn discard_unsecured_data_frame_secured_network() {
        let mut nwk = Nwk::end_device().call();

        let header = NwkHeader::builder(&mut nwk)
            .frame_type(FrameType::Data)
            .source(NwkAddress(0))
            .destination(DEFAULT_NWK_ADDR)
            .security(false)
            .build();

        let result = quick_indication_ed(&mut nwk, header).await;
        assert!(result.is_none())
    }
}