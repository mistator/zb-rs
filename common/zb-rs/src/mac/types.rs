use core::ops::Deref;
use ieee802154::mac::beacon::PendingAddress;
use ieee802154::mac::beacon::SuperframeSpecification;
use ieee802154::mac::command::AssociationStatus;
use thiserror::Error;
use zb_types::Vec;


use crate::mac::constants::A_MAX_BEACON_PAYLOAD_LENGTH;
use crate::mac::constants::MAX_PAN_DESCRIPTOR_SIZE;
use crate::nwk::nlme::ZigbeeBeacon;
use zb_types::common::Address;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::common::PanId;
use zb_types::mac::{A_MAX_MAC_PAYLOAD_SIZE, Channel, MacAddress, MacCapabilities};

#[derive(Default)]
pub enum SrcAddressMode {
    #[default]
    Short,
    Extended,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum McpsDataError {
    #[error("transaction overflow")]
    TransactionOverflow,
    #[error("transaction expired")]
    TransactionExpired,
    #[error("channel access failure")]
    ChannelAccessFailure,
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid gtx")]
    InvalidGts,
    #[error("counter error")]
    CounterError,
    #[error("unavailable key")]
    UnavailableKey,
    #[error("unsupported security")]
    UnsupportedSecurity,
    #[error("invalid parameter")]
    InvalidParameter,
}

pub struct PollResultData {
    pub src_address: Option<MacAddress>,
    pub dest_address: Option<MacAddress>,
    pub payload: Vec<u8, A_MAX_MAC_PAYLOAD_SIZE>,
}

pub enum PollResult {
    NoData,
    Success(PollResultData),
}

pub enum PollError {
    ChannelAccessFailure,
    NoAck,
    CounterError,
    FrameTooLong,
    UnavailableKey,
    UnsupportedSecurity,
    InvalidParameter,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MlmeAssociationError {
    ChannelAccessFailure,
    NoAck,
    NoData,
    UnavailableKey,
    FailedSecurityCheck,
    InvalidParameter,
    PanAtCapacity,
    PanAccessDenied,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MlmeCommStatusError {
    TransactionOverflow,
    TransactionExpired,
    ChannelAccessFailure,
    NoAck,
    UnavailableKey,
    FrameTooLong,
    FailedSecurityCheck,
    InvalidParameter,
}

#[derive(Debug, Default)]
pub struct RawNwkFrame(zb_types::Vec<u8, A_MAX_MAC_PAYLOAD_SIZE>);

impl Deref for RawNwkFrame {
    type Target = zb_types::Vec<u8, A_MAX_MAC_PAYLOAD_SIZE>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl RawNwkFrame {
    pub fn is_secured(&self) -> bool { (*self.get(1).unwrap_or_else(|| &0u8) & 0b0100_0000) > 0 }

    pub fn is_data_frame(&self) -> bool {
        (*self.get(0).unwrap_or_else(|| &0u8) & 0b1100_0000) == 0
    }
}

pub enum MacIndication {
    Data(McpsDataIndication),
    Associate(MlmeAssociateIndication),
    Poll(MlmePollIndication),
}

#[derive(Default, Debug)]
pub struct McpsDataIndication {
    pub src_address: Option<MacAddress>,
    pub dest_address: Option<MacAddress>,
    pub link_quality: u8,
    pub payload: zb_types::Vec<u8, A_MAX_MAC_PAYLOAD_SIZE>,
    pub dsn: u8,
    // pub timestamp: 3 bytes
}

pub struct MlmeAssociateIndication {
    pub device_ext_addr: ExtendedAddress,
    pub capability_information: MacCapabilities,
}

pub struct MlmePollIndication(Address);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    Ed,
    Active,
    Passive,
    Orphan,
}

#[derive(Debug, Error)]
pub enum MacError {
    #[error("no beacons received")]
    NoBeacon,
    #[error("invalid scan parameters")]
    InvalidScanParams,
    #[error("read error")]
    ReadError(byte::Error),
    #[error("radio error: {}", 0)]
    RadioError(byte::Error),
    #[error("no data")]
    NoData,
}

#[derive(Debug, Eq, Error, PartialEq)]
pub enum ScanError {
    #[error("no beacon received")]
    NoBeacon,
    #[error("invalid parameter: {}", 0)]
    InvalidParameter(&'static str),
}

#[derive(Debug)]
pub struct BeaconData {
    pub sequence_number: u8,
    pub pan_descriptor: PanDescriptor,
    pub pending_address_spec: PendingAddress,
    pub payload: Vec<u8, A_MAX_BEACON_PAYLOAD_LENGTH>,
}

pub type PanDescriptorList = Vec<PanDescriptor, MAX_PAN_DESCRIPTOR_SIZE>;

#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub struct PanDescriptor {
    pub channel: Channel,
    pub coord_pan_id: PanId,
    pub coord_address: MacAddress,
    pub superframe_spec: SuperframeSpecification,
    // pub gts_permit: bool,
    pub link_quality: u8,
    // pub timestamp: u32,
    pub security_use: bool,
    // pub ACL_Entry: u8,
    // pub security_failure: bool
    pub zigbee_beacon: ZigbeeBeacon,
}

#[derive(Debug)]
pub struct AssociationResponse {
    pub device_address: MacAddress,
    pub association_address: NwkAddress,
    pub status: AssociationStatus,
}

#[cfg(test)]
pub mod tests {
    use crate::mac::types::McpsDataIndication;
    use crate::nwk::ctx::{Initialized, InitializedState, Nwk};
    use crate::nwk::frame::NwkFrame;
    use byte::TryWrite;
    use zb_hal_test_mock::driver::MockDriver;
    use zb_hal_test_mock::storage::MemoryStorage;
    use zb_types::Vec;
    use zb_types::common::PanId;
    use zb_types::mac::{A_MAX_MAC_PAYLOAD_SIZE, MacAddress};

    impl McpsDataIndication {
        pub async fn from_frame<T: InitializedState>(nwk: &mut Nwk<Initialized<T>, MockDriver, MemoryStorage>, mut frame: NwkFrame) -> Self {
            let src = MacAddress::Short(PanId::default(), frame.header().source);
            let dest = MacAddress::Short(PanId::default(), frame.header().destination);

            let mut bytes = [0u8; A_MAX_MAC_PAYLOAD_SIZE];
            let size = if frame.header().control.security {
                nwk.encrypt_frame(&mut frame, &mut bytes).await.unwrap()
            } else {
                NwkFrame::try_write(frame, &mut bytes, byte::LE).unwrap()
            };

            McpsDataIndication {
                src_address: src.into(),
                dest_address: dest.into(),
                link_quality: 7,
                payload: Vec::from_slice(&bytes[..size]).unwrap(),
                dsn: 0,
            }
        }
    }
}