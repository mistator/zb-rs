use crate::apl::aps::apsde::Alias;
use crate::common::information_base::{RouteEntry, RouteEntryKey};
use crate::common::security::SecurityError;
use crate::nwk::constants::{MAX_BROADCAST_JITTER, NWK_MAX_SOURCE_ROUTE};
use crate::nwk::ctx::{
    BaseNwk, BaseNwkPrivate, InitializedNwk, InitializedState, JoinedAsEndDevice, Nwk, NwkTransmit,
    RoutingState,
};
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::frame::header::{DiscoverRoute, FrameType};
use crate::nwk::frame::header::{MulticastMode, SourceRouteSubframe};
use crate::nwk::frame::{NwkDataFrame, NwkFrame};
use crate::nwk::nib::RouteStatus;
use crate::nwk::nib::TransactionRecord;
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::security::{EncryptedFrameParams, make_encrypted_frame};
use crate::return_if_some;
use byte::BytesExt;
use core::ops::Add;
use embassy_time::Instant;
use embassy_time::Timer;
use rand::RngExt;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::NwkAddress;
use zb_types::mac::A_MAX_MAC_PAYLOAD_SIZE;

#[derive(Default)]
pub struct DataFrameConfig {
    pub dst_address: NwkAddress,
    pub alias: Option<Alias>,
    pub radius: Option<u8>,
    pub discover_route: bool,
    pub security_disable: bool,
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> NwkTransmit<D, S> for Nwk<T, D, S> {
    async fn transmit_data_frame(
        &mut self,
        nsdu: &[u8],
        config: &DataFrameConfig,
    ) -> Result<(), NldeTransferError> {
        let mut frame = self.build_data_frame(nsdu, config)?;

        if frame.header.control.multicast {
            self.route_multicast_frame(&mut frame).await
        } else if frame.header.destination.is_unicast() {
            self.route_unicast_frame(&frame).await
        } else {
            self.transmit_frame(&frame.to_frame(), config.dst_address, false).await
        }
    }
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // 3.6.3.3
    // Applicable for frames received by the network layer as well as frames intended to be
    // transmitted by higher layers
    pub(super) async fn route_unicast_frame(
        &mut self,
        frame: &NwkDataFrame,
    ) -> Result<(), NldeTransferError> {
        return_if_some!(self.try_unicast_direct_relay(frame).await);

        // A device that has routing capacity shall check its routing table for an entry
        // corresponding to the routing destination of the frame.
        if !self.get_route_table().is_full() {
            return_if_some!(self.try_unicast_route_table(frame).await);
            return_if_some!(self.try_source_routing(frame).await);
        } else {
            return_if_some!(self.try_unicast_tree_routing(frame).await);
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

        Err(NldeTransferError::RouteError)
    }

    async fn try_source_routing(
        &mut self,
        frame: &NwkDataFrame,
    ) -> Option<Result<(), NldeTransferError>> {
        let routing_address = self.get_routing_address_for_address(frame.header.destination);
        let key = RouteEntryKey::new(self.get_profile(), routing_address, false);
        let route_is_active = self
            .get_route_table_mut()
            .get_mut(&key)
            .map(|route| {
                matches!(route.status, RouteStatus::Active | RouteStatus::ValidationUnderway)
            })
            .unwrap_or(false);

        // If the device
        // does not have a routing table entry for the routing destination with a status value of ACTIVE or VALIDA-
        // TION_UNDERWAY, and it received the frame from the next higher layer, it shall check its source route table for an
        // entry corresponding to the routing destination.
        if !route_is_active
            && let Some(record) = self
                .get_route_record_table()
                .iter()
                .find(|item| item.network_address == routing_address)
            && record.path.len() < NWK_MAX_SOURCE_ROUTE as usize
        {
            //  If such an entry is found and the length is less than
            // nwkMaxSourceRoute, the device shall transmit the frame using source routing as described in section 3.6.3.3.1.

            // If there are no intermediate relay nodes, the frame shall be transmitted directly to the routing destination without
            // source routing by using the MCPS-DATA.request primitive, with the DstAddr parameter value indicating the rout-
            // ing destination.
            if record.path.len() == 0 {
                Some(self.transmit_frame(&frame.as_frame(), routing_address, true).await)
            } else {
                // If there is at least one relay node, the source route flag of the NWK header frame control field shall be set, and the
                // NWK header source route subframe shall be present. The relay count sub-field of the source route subframe shall
                // have a value equal to the number of relays in the relay list. The relay index sub-field shall have a value equal to 1
                // less than the number of relays. The relay list sub-field shall contain the list of relay addresses, least significant octet
                // first. The relay closest to the destination shall be listed first. The relay closest to the originator shall be listed last.
                let mut frame = frame.clone();
                frame.header.source_route_subframe = Some(SourceRouteSubframe {
                    relay_count: record.path.len() as u8,
                    relay_index: (record.path.len() - 1) as u8,
                    relay_list: record.path.clone(),
                });

                // The device shall relay the frame using the MCPS-DATA.request primitive. The DstAddr parameter shall have the
                // value of the final relay address in the relay list.
                let dst_addr = *record.path.last().unwrap();
                Some(self.transmit_frame(&frame.to_frame(), dst_addr, true).await)
            }
        } else {
            None
        }
    }

    // 3.6.6.2
    async fn route_multicast_frame(
        &mut self,
        frame: &mut NwkDataFrame,
    ) -> Result<(), NldeTransferError> {
        // If an NLDE-DATA.request is received by the NWK layer from its next higher layer and the multicast control field is
        // 0x01, the NWK layer shall determine whether an entry exists in the nwkGroupIDTable having a group identifier
        // field matching the destination address of the frame.
        if self.get_group_table().contains(&frame.header.destination) {
            // If a matching entry is found, the NWK layer shall multicast the
            // frame according to the procedure outlined in section 3.6.6.2.1.

            // The NWK layer shall set the multicast mode sub-field of the multicast control field to 0x01 (member mode). If the
            // BTT table is full and contains no expired entries, the message shall not be sent and the NLDE shall issue the
            // NLDE-DATA.confirm primitive with a status value of BT_TABLE_FULL. If the BTT is not full or contains an
            // expired BTR, a new BTR shall be created with the local node as the source and the multicast frame's sequence
            // number. The message shall then be transmitted according to the procedure described in the final paragraph of sec-
            // tion 3.6.6.3.
            frame
                .header
                .multicast_control
                .as_mut()
                .map(|item| item.multicast_mode = MulticastMode::Member);

            self.get_broadcast_transaction_table_mut()
                .retain(|t| t.expiration_time >= Instant::now());

            let delivery_time = self.get_nwk_broadcast_delivery_time();
            match self.get_broadcast_transaction_table_mut().push(TransactionRecord {
                source_address: frame.header.source,
                sequence_number: frame.header.sequence_number,
                expiration_time: Instant::now().add(delivery_time),
            }) {
                Err(_) => Err(NldeTransferError::BtTableFull),
                _ => self.transmit_frame(&frame.as_frame(), NwkAddress::BROADCAST_ALL, false).await,
            }
        } else {
            // If a matching entry is not found, the frame shall be
            // initiated as a non-member mode multicast using the procedure outlined in section 3.6.6.2.2.

            //
            // If there is no routing table entry corresponding to the GroupID destination of
            // the frame and the value of the DiscoverRoute parameter is 0x00 (suppress route discovery), the frame shall be dis-
            // carded and the NLDE shall issue the NLDE-DATA.confirm primitive with a status value of
            // ROUTE_DISCOVERY_FAILED. If the DiscoverRoute parameter has a value of 0x01 (enable route discovery) and
            // there is no routing table entry corresponding to the GroupID destination of the frame, then the device shall initiate
            // route discovery immediately as described in section 3.6.3.5.1. The frame may optionally be buffered pending route
            // discovery. If it is not buffered, the frame shall be discarded and the NLDE shall issue the NLDE-DATA.confirm
            // primitive with a status value of FRAME_NOT_BUFFERED.

            // The NWK layer shall set the multicast mode sub-field of the multicast control field to 0x00 (non-member mode).
            frame
                .header
                .multicast_control
                .as_mut()
                .map(|item| item.multicast_mode = MulticastMode::NonMember);

            // Then, the NWK layer shall check its routing table for an entry corresponding to the GroupID destination of the frame.
            let key = &RouteEntryKey::new(&self.get_profile(), frame.header.destination, true);
            match self.get_route_table_mut().get_mut(&key) {
                Some(
                    route @ RouteEntry {
                        status: RouteStatus::Active | RouteStatus::ValidationUnderway,
                        ..
                    },
                ) => {
                    let next_hop = route.next_hop_addr;
                    // If there is such an entry, the NWK layer shall examine the entry's status field. If the status is ACTIVE, then
                    // the device shall (re)transmit the frame.
                    if route.status == RouteStatus::Active {
                        self.transmit_frame(&frame.as_frame(), next_hop, true).await
                    } else {
                        // If the status is VALIDATION_UNDERWAY, then the status shall be
                        // changed to ACTIVE, the device shall transmit the frame according to the procedure described in the final paragraph
                        // of section 3.6.6.4, and the NLDE shall issue the NLDE-DATA.confirm primitive with the status value received from
                        // the MCPS-DATA.confirm primitive.
                        route.status = RouteStatus::Active;
                        self.transmit_frame(&frame.as_frame(), next_hop, true).await
                    }
                }
                _ => {
                    // If there is no routing table entry corresponding to the GroupID destination of
                    // the frame and the value of the DiscoverRoute parameter is 0x00 (suppress route discovery), the frame shall be dis-
                    // carded and the NLDE shall issue the NLDE-DATA.confirm primitive with a status value of
                    // ROUTE_DISCOVERY_FAILED.
                    if frame.header.control.route_discovery != DiscoverRoute::Enable {
                        Err(NldeTransferError::RouteDiscoveryFailed)
                    } else {
                        // TODO: Initiate route discovery

                        todo!()
                    }
                }
            }
        }
    }
}

impl<D: NwkMac, S: StorageRegion> NwkTransmit<D, S> for Nwk<JoinedAsEndDevice, D, S> {
    async fn transmit_data_frame(
        &mut self,
        nsdu: &[u8],
        config: &DataFrameConfig,
    ) -> Result<(), NldeTransferError> {
        let frame = self.build_data_frame(nsdu, config)?;
        let parent_addr = self.lock_parent(|parent| parent.nwk_addr);

        self.transmit_frame(&frame.to_frame(), parent_addr.into(), true).await
    }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    fn build_data_frame(
        &mut self,
        nsdu: &[u8],
        config: &DataFrameConfig,
    ) -> Result<NwkDataFrame, NldeTransferError> {
        let nwk_addr = self.get_addr();
        let (src, seq) = match &config.alias {
            None => (nwk_addr, self.get_next_seq_number()),
            Some(alias) => (alias.src_addr, alias.seq_number),
        };

        let header = NwkHeader::builder(self)
            .frame_type(FrameType::Data)
            .security(!config.security_disable)
            .route_discovery(config.discover_route)
            .destination(config.dst_address)
            .source(src)
            .sequence_number(seq)
            .maybe_radius(config.radius)
            .build();

        let payload = zb_types::Vec::from_slice(nsdu)
            .map_err(|_| NldeTransferError::InvalidRequest("frame too long"))?;
        Ok(NwkDataFrame { header, payload })
    }

    pub(crate) async fn transmit_frame(
        &mut self,
        frame: &NwkFrame,
        dst_address: NwkAddress,
        ack: bool,
    ) -> Result<(), NldeTransferError> {
        let mut mac_payload = [0u8; A_MAX_MAC_PAYLOAD_SIZE];
        let length = self.build_mac_payload(frame, &mut mac_payload)?;

        self.get_mac_mut()
            .data_transmit_request(dst_address, &mac_payload[..length], ack)
            .await
            .map_err(|err| NldeTransferError::McpsDataError(err))
    }

    pub fn build_mac_payload(
        &mut self,
        frame: &NwkFrame,
        buffer: &mut [u8; A_MAX_MAC_PAYLOAD_SIZE],
    ) -> Result<usize, SecurityError> {
        let length = if frame.is_secured()
            && !matches!(frame, NwkFrame::Reserved(_) | NwkFrame::InterPan(_))
        {
            self.encrypt_frame(frame, buffer)?
        } else {
            let offset = &mut 0;
            buffer.write_with(offset, frame.header().clone(), byte::LE)?;
            match frame {
                NwkFrame::Data(frame) => buffer.write_with(offset, frame.payload.as_slice(), ())?,
                NwkFrame::NwkCommand(frame) => {
                    buffer.write_with(offset, frame.command.clone(), ())?
                }
                _ => {}
            }
            *offset
        };

        Ok(length)
    }
}

pub fn build_mac_payload(
    frame: &NwkFrame,
    buffer: &mut [u8; A_MAX_MAC_PAYLOAD_SIZE],
    params: &EncryptedFrameParams,
) -> Result<usize, SecurityError> {
    let length = if frame.is_secured()
        && !matches!(frame, NwkFrame::Reserved(_) | NwkFrame::InterPan(_))
    {
        make_encrypted_frame(frame, buffer, params)?
    } else {
        let offset = &mut 0;
        buffer.write_with(offset, frame.header().clone(), byte::LE)?;
        match frame {
            NwkFrame::Data(frame) => buffer.write_with(offset, frame.payload.as_slice(), ())?,
            NwkFrame::NwkCommand(frame) => buffer.write_with(offset, frame.command.clone(), ())?,
            _ => {}
        }
        *offset
    };

    Ok(length)
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {}

pub(super) struct TransmitBroadcastFrameCfg {
    pub jitter: u64,
    pub nwk_passive_ack_timeout: u32,
    pub max_retries: u8,
    pub mac_payload: [u8; A_MAX_MAC_PAYLOAD_SIZE],
    pub payload_len: usize,
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub(super) async fn transmit_broadcast_frame(&mut self, frame: &NwkDataFrame) -> () {
        let mut mac_payload = [0u8; A_MAX_MAC_PAYLOAD_SIZE];
        let payload_len =
            match self.build_mac_payload(&NwkFrame::Data(frame.clone()), &mut mac_payload) {
                Ok(result) => result,
                Err(_) => return,
            };

        let _cfg = TransmitBroadcastFrameCfg {
            jitter: self.get_rng().random_range(0..MAX_BROADCAST_JITTER.as_millis()),
            nwk_passive_ack_timeout: self.get_profile().nwk_passive_ack_timeout,
            max_retries: self.get_profile().nwk_max_broadcast_retries,
            mac_payload,
            payload_len,
        };

        // ctx.spawner
        //    .spawn(transmit_broadcast_frame_task(cfg).unwrap()) TODO
    }
}

#[embassy_executor::task]
async fn transmit_broadcast_frame_task(cfg: TransmitBroadcastFrameCfg) {
    Timer::after_millis(cfg.jitter).await;

    for _ in 0..cfg.max_retries {
        {
            /*
            TODO
            let mut lck = MAC.lock().await;
            let mac = lck.as_mut().unwrap();

            mac.data_transmit_request(
                SrcAddressMode::Short,
                NwkAddress::MAX.into(),
                &cfg.mac_payload[..cfg.payload_len],
                false,
            )
            .await
            .ok();
             */
        }

        Timer::after_millis(cfg.nwk_passive_ack_timeout as u64).await
    }
}
