use crate::apl::aps::apsde::Alias;
use crate::common::information_base::RouteEntryKey;
use crate::common::security::SecurityError;
use crate::nwk::constants::MAX_BROADCAST_JITTER;
use crate::nwk::constants::NWK_MAX_SOURCE_ROUTE;
use crate::nwk::frame::header::MulticastMode;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::frame::header::{DiscoverRoute, FrameType};
use crate::nwk::frame::{NwkDataFrame, NwkFrame};
use crate::nwk::nib::RouteStatus;
use crate::nwk::nib::TransactionRecord;
use crate::nwk::nlde::NldeTransferError;
use byte::BytesExt;
use core::ops::Add;
use embassy_time::Instant;
use embassy_time::Timer;
use rand::RngExt;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::NwkAddress;
use zb_types::mac::A_MAX_MAC_PAYLOAD_SIZE;
use crate::nwk::ctx::{BaseNwk, BaseNwkPrivate, InitializedNwk, InitializedState, JoinedAsEndDevice, JoinedNwk, NonRoutingState, Nwk, NwkTransmit, RoutingState};
use crate::nwk::security::{make_encrypted_frame, EncryptedFrameParams};

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

        let parent_addr = self.lock_parent(|parent| parent.nwk_addr);
        let payload = zb_types::Vec::from_slice(nsdu)
            .map_err(|_| NldeTransferError::InvalidRequest("frame too long"))?;
        let frame = NwkFrame::new_data_frame(header, payload);

        self.transmit_frame(&frame, parent_addr, true).await
    }
}

impl<D: NwkMac, S: StorageRegion> NwkTransmit<D, S> for Nwk<JoinedAsEndDevice, D, S> {
    async fn transmit_data_frame(
        &mut self,
        nsdu: &[u8],
        config: &DataFrameConfig,
    ) -> Result<(), NldeTransferError> {
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

        let parent_addr = self.lock_parent(|parent| parent.nwk_addr);
        let payload = zb_types::Vec::from_slice(nsdu)
            .map_err(|_| NldeTransferError::InvalidRequest("frame too long"))?;
        let frame = NwkFrame::new_data_frame(header, payload);

        self.transmit_frame(&frame, parent_addr.into(), true).await
    }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
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

pub fn build_mac_payload(frame: &NwkFrame, buffer: &mut [u8; A_MAX_MAC_PAYLOAD_SIZE], params: &EncryptedFrameParams) -> Result<usize, SecurityError> {
    let length = if frame.is_secured()
        && !matches!(frame, NwkFrame::Reserved(_) | NwkFrame::InterPan(_))
    {
        make_encrypted_frame(frame, buffer, params)?
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

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    async fn route_unicast_frame(&mut self, frame: &NwkDataFrame) -> Result<(), NldeTransferError> {
        if self.try_unicast_direct_relay(frame).await {
            return Ok(());
        };

        if self.get_route_table_mut().is_full() {
            if self.try_unicast_tree_routing(frame).await {
                return Ok(());
            }

            // TODO: Send network status command frame
        } else {
            if self.try_unicast_route_table(frame).await {
                return Ok(());
            }
        }

        let routing_dst_addr =
            self.get_routing_address_for_address(frame.header.destination);
        match self.get_route_record_table().iter().find(|route| {
            route.network_address == routing_dst_addr && route.relay_count < NWK_MAX_SOURCE_ROUTE
        }) {
            Some(_route) => {
                // TODO transmit using source routing 3.6.3.3.1
            }
            None => {
                return Err(NldeTransferError::RouteError);
            }
        }

        Ok(())
    }

    async fn route_multicast_frame(&mut self, frame: &mut NwkDataFrame) {
        match self
            .get_group_table()
            .iter()
            .find(|item| **item == frame.header.destination)
        {
            Some(_) => {
                // TODO: Multicast the frame according to the procedure outlined in section
                // 3.6.6.2.1.
                frame.header.multicast_control.unwrap().multicast_mode = MulticastMode::Member;
                self.get_broadcast_transaction_table_mut()
                    .retain(|t| t.expiration_time >= Instant::now());

                let delivery_time = self.get_nwk_broadcast_delivery_time();
                match self.get_broadcast_transaction_table_mut()
                    .push(TransactionRecord {
                        source_address: frame.header.source,
                        sequence_number: frame.header.sequence_number,
                        expiration_time: Instant::now().add(delivery_time),
                    }) {
                    Err(_) => {
                        // TODO return BT_FULL
                    }
                    _ => {}
                };
            }
            None => {
                let key =
                    &RouteEntryKey::new(&self.get_profile(), frame.header.destination, true);
                let route = self.get_route_table_mut().get_mut(&key).filter(|route| {
                    matches!(
                        route.status,
                        RouteStatus::Active | RouteStatus::ValidationUnderway
                    )
                });

                frame.header.multicast_control.unwrap().multicast_mode = MulticastMode::NonMember;
                match route {
                    Some(route) => {
                        route.status = RouteStatus::Active;
                        let next_hop = route.next_hop_addr;
                        self.transmit_frame(&NwkFrame::Data(frame.clone()), next_hop, true).await.ok();
                    }
                    None => {
                        if frame.header.control.route_discovery != DiscoverRoute::Enable {
                            // TODO: return ROUTE_DISCOVERY_FAILED
                        }

                        // TODO: Initiate route discovery
                    }
                }

                // TODO: The frame shall be
                // initiated as a non-member mode multicast using the procedure
                // outlined in section 3.6.6.2.2
            }
        }
    }
}

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
        let payload_len = match self.build_mac_payload(&NwkFrame::Data(frame.clone()), &mut mac_payload) {
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
