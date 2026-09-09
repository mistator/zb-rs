use crate::mac::constants::A_RESPONSE_WAIT_TIME;
use crate::mac::types::{
    MacError, MacIndication, McpsDataError, McpsDataIndication, MlmeAssociationError,
    MlmeCommStatusError, PanDescriptor, PanDescriptorList, PollError, PollResult, ScanError,
    SrcAddressMode,
};
use crate::mac::utils::calculate_duration;
use crate::mac::utils::calculate_scan_duration_max_us;
use crate::nwk::nlme::ScanDuration;
use crate::unwrap_or_return;
use byte::BytesExt;
use embassy_time::Instant;
use embassy_time::WithTimeout;
use embassy_time::{Duration};
use ieee802154::mac;
use ieee802154::mac::FrameType;
use ieee802154::mac::Header;
use ieee802154::mac::beacon::BeaconOrder;
use ieee802154::mac::beacon::SuperframeOrder;
use ieee802154::mac::command::AssociationStatus;
use ieee802154::mac::command::Command;
use ieee802154::mac::security::SecurityContext;
use thiserror::Error;
use zb_hal::{Ieee802154Driver};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::common::PanId;
use zb_types::mac::{
    A_MAX_MAC_PAYLOAD_SIZE, A_MAX_PHY_PACKET_SIZE,
    Channel, ChannelMask, MacAddress, MacCapabilities, MacFrame,
};

struct MacCommandConfig {
    pub frame_pending: bool,
    pub ack_request: bool,
    pub destination: Option<MacAddress>,
    pub src_addr_mode: SrcAddressMode,
}

#[repr(u8)]
pub enum AssociateResponseStatus {
    Success(NwkAddress) = 0,
    PanAtCapacity = 1,
    PanAccessDenied = 2,
}

pub struct PanCoordinatorUpdate {
    pub pan_id: PanId,
    pub channel: Channel,
    pub coord_realignment: bool,
}

pub struct MlmeStartRequest {
    pub pan_coordinator_update: Option<PanCoordinatorUpdate>,
    pub beacon_order: BeaconOrder,
    pub superframe_order: SuperframeOrder,
    pub battery_life_extension: bool,
}

#[derive(Error, Debug)]
pub enum MlmeStartError {
    #[error("no short address")]
    NoShortAddress,
    #[error("invalid parameter")]
    InvalidParameter,
}

pub enum MlmeScanType {
    Ed,
    Active,
    Passive,
    Orphan,
}

pub struct MlmeScanRequest {
    pub scan_type: MlmeScanType,
    pub channel_mask: ChannelMask,
    pub duration: ScanDuration,
}

#[derive(Copy, Clone, Debug)]
pub struct Mlme<D>
where
    D: Ieee802154Driver,
{
    driver: D,
    seq_number: u8,
    mac_association_permit_timeout: Instant,
}

impl<D> Mlme<D>
where
    D: Ieee802154Driver,
{
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            seq_number: 0,
            mac_association_permit_timeout: Instant::MIN,
        }
    }

    fn sequence_number(&mut self) -> u8 {
        self.seq_number = self.seq_number.wrapping_add(1);
        self.seq_number
    }

    pub fn is_rx_on_when_idle(&self) -> bool {
        self.driver.is_rx_on_when_idle()
    }

    async fn wait_for_frame_no_timeout<T>(&mut self, eval: impl Fn(MacFrame) -> Option<T>) -> T {
        loop {
            let frame = self.driver.wait_frame().await;
            if let Some(result) = eval(frame) {
                return result;
            }
        }
    }

    async fn wait_for_frame<T>(
        &mut self,
        timeout: Duration,
        eval: fn(MacFrame) -> Option<T>,
    ) -> Result<T, MacError> {
        self.wait_for_frame_no_timeout(eval)
            .with_timeout(timeout)
            .await
            .map_err(|_| MacError::NoData)
    }

    pub fn set_association_permit_timeout(&mut self, instant: Instant) {
        self.mac_association_permit_timeout = instant;
    }

    fn beacon_request_frame(&mut self) -> [u8; 10] {
        let seq_number = self.sequence_number();
        [0x3, 0x8, seq_number, 0xff, 0xff, 0xff, 0xff, 0x7, 0x0, 0x0]
    }

    async fn scan_channel_active(
        &mut self,
        channel: Channel,
        duration: u8,
    ) -> Result<Option<PanDescriptorList>, MacError> {
        let frame = self.beacon_request_frame();

        self.driver.flush().await;
        self.driver.set_channel(channel).await;

        self.driver
            .transmit(&frame)
            .await
            .map_err(|err| MacError::RadioError(err))?;

        log::info!(
            "[MLME-SCAN] sent beacon frame to channel {}, waiting for messages...",
            channel as u8
        );

        let delay_us: u64 = calculate_scan_duration_max_us(duration).into();
        log::info!("[MLME-SCAN] waiting for response for {delay_us}us");

        let mut pds = PanDescriptorList::new();
        _ = async {
            loop {
                let pd = self
                    .wait_for_frame_no_timeout(|frame| parse_beacon(frame, channel))
                    .await;
                pds.push(pd).ok();
            }
        }
        .with_timeout(Duration::from_micros(delay_us))
        .await;

        log::info!(
            "[MLME-SCAN] pan descriptors received on channel {}: {:?}",
            channel as u8,
            pds
        );

        Ok(Some(pds))
    }

    async fn send_mac_command(
        &mut self,
        config: MacCommandConfig,
        cmd: Command,
    ) -> Result<(), byte::Error> {
        let pan_id = unwrap_or_return!(self.driver.get_pan_id(), Err(byte::Error::Incomplete));

        let header = mac::Header {
            frame_type: mac::FrameType::MacCommand,
            frame_pending: config.frame_pending,
            ack_request: config.ack_request,
            pan_id_compress: true,
            seq_no_suppress: false,
            ie_present: false,
            version: mac::FrameVersion::Ieee802154_2006,
            seq: self.sequence_number(),
            destination: config.destination.map(|item| item.into()),
            source: self.get_src_address(pan_id, config.src_addr_mode).into(),
            auxiliary_security_header: None,
        };

        let mut payload = [0u8; A_MAX_MAC_PAYLOAD_SIZE];
        let mut offset = 0;
        payload.write_with(&mut offset, cmd, ())?;

        self.transmit_frame(header, &payload[..offset]).await
    }

    async fn mac_data_request(
        &mut self,
        coord_address: Option<MacAddress>,
    ) -> Result<(), ::byte::Error> {
        self.send_mac_command(
            MacCommandConfig {
                frame_pending: false,
                ack_request: true,
                destination: coord_address,
                src_addr_mode: SrcAddressMode::Extended,
            },
            Command::DataRequest,
        )
        .await
    }

    async fn transmit_frame(
        &mut self,
        header: mac::Header,
        content: &[u8],
    ) -> Result<(), byte::Error> {
        let mut buf = [0u8; A_MAX_PHY_PACKET_SIZE];

        let offset = &mut 0;
        buf.write_with(offset, header, &Some(&mut SecurityContext::no_security()))?;
        buf.write_with(offset, content, ())?;
        // write two zeros which will be overwritten with the CRC checksum by the driver
        buf.write_with(offset, 0x0u16, byte::LE)?;

        self.driver.transmit(&buf[..*offset]).await
    }

    pub fn get_ext_addr(&self) -> ExtendedAddress {
        self.driver.get_extended_address()
    }

    pub fn get_channel_mask(&self) -> ChannelMask {
        self.driver.get_channel_mask()
    }

    pub async fn set_pan_id(&mut self, pan_id: Option<PanId>) -> () {
        self.driver.set_pan_id(pan_id).await
    }

    pub async fn set_channel(&mut self, channel: Channel) -> () {
        self.driver.set_channel(channel).await
    }

    pub async fn set_short_address(&mut self, short_address: Option<NwkAddress>) -> () {
        self.driver.set_short_address(short_address).await
    }

    pub async fn poll_frame(&mut self) -> Option<MacIndication> {
        let frame = self.driver.poll().await?;
        self.filter_frame(frame)
    }

    pub async fn listen(&mut self) -> MacIndication {
        loop {
            let frame = self.driver.wait_frame().await;
            match self.filter_frame(frame) {
                Some(indication) => return indication,
                None => continue,
            }
        }
    }

    pub fn filter_frame(&self, frame: MacFrame) -> Option<MacIndication> {
        let self_pan_id = self.driver.get_pan_id();
        let short_addr = self.driver.get_short_address();
        let ext_addr = self.get_ext_addr();

        let pan_id_matches_self = |pan_id: mac::PanId| -> bool {
            if self_pan_id.is_none() {
                return false;
            }

            pan_id.0 == self_pan_id.unwrap().0
        };

        let pan_id_is_broadcast_or_matches_self = |pan_id: mac::PanId| -> bool {
            pan_id == mac::PanId(0xffff) || pan_id_matches_self(pan_id)
        };

        match frame.header.frame_type {
            FrameType::Beacon => {
                let src = unwrap_or_return!(frame.header.source, None);

                match self_pan_id {
                    Some(pan_id) => {
                        if pan_id != PanId::from(src.pan_id()) {
                            return None;
                        }
                    }
                    None => return None,
                }
            }
            FrameType::Data | FrameType::MacCommand => {
                if self_pan_id == None || frame.header.destination.is_none() {
                    return None;
                }

                let dst = unwrap_or_return!(frame.header.destination, None);
                if !pan_id_is_broadcast_or_matches_self(dst.pan_id()) {
                    return None;
                }

                match MacAddress::from(dst) {
                    MacAddress::Short(_, addr) => {
                        if addr != NwkAddress::MAX && Some(addr) != short_addr {
                            return None;
                        }
                    }
                    MacAddress::Extended(_, addr) => {
                        if addr != ExtendedAddress::MAX && addr != ext_addr {
                            return None;
                        }
                    }
                }
            }
            _ => return None,
        }

        MacIndication::Data(McpsDataIndication {
            src_address: frame.header.source.map(Into::into),
            dest_address: frame.header.destination.map(Into::into),
            link_quality: 0, // lqi,
            payload: frame.payload,
            dsn: 0,
        })
        .into()
    }

    pub async fn associate(
        &mut self,
        channel: Channel,
        coord_address: MacAddress,
        capability_information: MacCapabilities,
    ) -> Result<(NwkAddress, ExtendedAddress), MlmeAssociationError> {
        self.driver.set_channel(channel).await;
        self.driver.set_pan_id(coord_address.pan_id().into()).await;

        self.send_mac_command(
            MacCommandConfig {
                frame_pending: false,
                ack_request: true,
                destination: coord_address.into(),
                src_addr_mode: SrcAddressMode::Extended,
            },
            Command::AssociationRequest(capability_information.into()),
        )
        .await
        .map_err(|err| {
            log::warn!("error sending mac command: {:?}", err);
            MlmeAssociationError::InvalidParameter
        })?;

        self.driver.flush().await;
        self.mac_data_request(Some(coord_address))
            .await
            .map_err(|_| MlmeAssociationError::NoData)?;

        let timeout = calculate_duration(A_RESPONSE_WAIT_TIME);
        let (short_addr, coordinator_extended_address) = self.wait_for_frame(timeout, |frame| {
            if let MacFrame {
                header: Header {
                    source: Some(mac::Address::Extended(_, coordinator_extended_address)),
                    ..
                },
                content: mac::FrameContent::Command(Command::AssociationResponse(short_addr, _)),
                ..
            } = frame {
                return Some((short_addr, coordinator_extended_address));
            }
            return None;
        }).await.map_err(|_| MlmeAssociationError::NoData)?;

        log::info!("[MLME-ASSOCIATE] success, short_addr={:?}", short_addr);

        self.driver.set_short_address(Some(short_addr.into())).await;
        Ok((short_addr.into(), coordinator_extended_address.into()))
    }

    pub async fn associate_response(
        &mut self,
        pan_id: PanId,
        ext_addr: ExtendedAddress,
        status: AssociateResponseStatus,
    ) -> Result<(), MlmeCommStatusError> {
        let response_addr = match status {
            AssociateResponseStatus::Success(addr) => addr,
            _ => NwkAddress::MAX,
        };

        let status = match status {
            AssociateResponseStatus::Success(_) => AssociationStatus::Successful,
            AssociateResponseStatus::PanAtCapacity => AssociationStatus::NetworkAtCapacity,
            AssociateResponseStatus::PanAccessDenied => AssociationStatus::AccessDenied,
        };

        self.send_mac_command(
            MacCommandConfig {
                frame_pending: false,
                ack_request: true,
                destination: Some(MacAddress::Extended(pan_id, ext_addr)),
                src_addr_mode: SrcAddressMode::Extended,
            },
            Command::AssociationResponse(response_addr.into(), status),
        )
        .await
        .map_err(|_| MlmeCommStatusError::InvalidParameter)
    }

    pub async fn scan(&mut self, req: MlmeScanRequest) -> Result<PanDescriptorList, ScanError> {
        let mut pds = PanDescriptorList::new();

        for channel in Channel::ALL {
            if !req.channel_mask.channel_is_set(channel) {
                continue;
            }

            log::info!("[MLME-SCAN] starting scan on channel: {:?}", channel as u8);
            match self.scan_channel_active(channel, req.duration.get()).await {
                Ok(Some(beacon)) => {
                    pds.extend(beacon);
                }
                Err(e) => {
                    log::error!("[MLME-SCAN] error on channel {}: {}", channel as u8, e);
                }
                _ => {}
            }
        }

        Ok(pds)
    }

    pub fn start(&mut self, _req: MlmeStartRequest) -> Result<(), MlmeStartError> {
        // TODO
        Ok(())
    }

    pub async fn data_transmit_request(
        &mut self,
        dst_addr: NwkAddress,
        payload: &[u8],
        ack: bool,
    ) -> Result<(), McpsDataError> {
        let pan_id = unwrap_or_return!(
            self.driver.get_pan_id(),
            Err(McpsDataError::ChannelAccessFailure)
        );

        let header = mac::Header {
            frame_type: mac::FrameType::Data,
            frame_pending: false,
            ack_request: ack,
            pan_id_compress: true,
            seq_no_suppress: false,
            ie_present: false,
            version: mac::FrameVersion::Ieee802154_2003,
            seq: self.sequence_number(),
            destination: mac::Address::Short(pan_id.into(), dst_addr.into()).into(),
            source: self.get_src_address(pan_id, SrcAddressMode::Short).into(),
            auxiliary_security_header: None,
        };

        self.transmit_frame(header, payload).await
            .map(|_| ())
            .map_err(|_| McpsDataError::ChannelAccessFailure)
    }

    fn get_src_address(&self, pan_id: PanId, src_address_mode: SrcAddressMode) -> mac::Address {
        match src_address_mode {
            SrcAddressMode::Short => {
                let value = self.driver.get_short_address().unwrap();
                mac::Address::Short(pan_id.into(), value.into()).into()
            }
            SrcAddressMode::Extended => {
                let value = self.driver.get_extended_address();
                mac::Address::Extended(pan_id.into(), value.into()).into()
            }
        }
    }

    pub async fn reset(&mut self, set_default_pib: bool) -> () {
        self.driver.reset(set_default_pib).await;
    }

    pub async fn poll(&mut self, coord_address: MacAddress) -> Result<PollResult, PollError> {
        self.driver.flush().await;
        self.mac_data_request(Some(coord_address))
            .await
            .map_err(|_| PollError::ChannelAccessFailure)?;

        log::debug!("[MLME-POLL] tx data req");

        // let timeout = calculate_duration(A_RESPONSE_WAIT_TIME);
        // l self.wait_for_frame(timeout, |frame| {
        // if let Frame {
        // header: Header {
        // source,
        // destination,
        // ..
        // },
        // content: mac::FrameContent::Data,
        // payload,
        // ..
        // } = frame {
        // return Some(PollResult::Success(PollResultData {
        // src_address: source.map(Address::from),
        // dest_address: destination.map(Address::from),
        // payload: Vec::from_slice(payload).unwrap(),
        // }));
        // };
        //
        // return None;
        // }).await.unwrap_or(PollResult::NoData);
        //
        todo!()
    }
}

fn parse_beacon(frame: MacFrame, channel: Channel) -> Option<PanDescriptor> {
    match frame {
        MacFrame {
            header:
                hdr @ mac::Header {
                    source: Some(source),
                    ..
                },
            content: mac::FrameContent::Beacon(beacon_content),
            payload,
            ..
        } => {
            log::debug!("[MLME-SCAN] received beacon frame");

            let beacon = payload.as_slice()
                .read_with(&mut 0, byte::LE)
                .map_err(|err| {
                    log::warn!("[MLME-SCAN] failed to parse zigbee beacon: {err:?}");
                })
                .ok()?;

            Some(PanDescriptor {
                channel,
                coord_pan_id: source.pan_id().into(),
                coord_address: source.into(),
                superframe_spec: beacon_content.superframe_spec,
                link_quality: 0, // lqi,
                security_use: hdr.has_security(),
                zigbee_beacon: beacon,
            })
        }
        other => {
            log::debug!("[MLME-SCAN] received non-beacon frame: {other:?}");
            None
        }
    }
}
