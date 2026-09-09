use thiserror::Error;

use crate::common::security::SecurityError;
use crate::mac::types::McpsDataError;
use crate::nwk::commands::network_status::NetworkStatus;
use crate::nwk::constants::MAX_NWK_PAYLOAD_SIZE;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::mac::MacCapabilities;

#[derive(Clone, Debug, PartialEq, Error)]
pub enum NldeTransferError {
    #[error("invalid request: {}", 0)]
    InvalidRequest(&'static str),
    #[error("max frame counter")]
    MaxFrameCounter,
    #[error("bad CCM output")]
    BadCcmOutput,
    #[error("route error")]
    RouteError,
    #[error("bt table full")]
    BtTableFull,
    #[error("frame not buffered")]
    FrameNotBuffered,
    #[error("security error: {}", 0)]
    SecurityError(#[from] SecurityError),
    #[error("mcps data error: {}", 0)]
    McpsDataError(#[from] McpsDataError),
    #[error("parse error")]
    ParseError(byte::Error),
}

impl From<byte::Error> for NldeTransferError {
    fn from(value: byte::Error) -> Self {
        NldeTransferError::ParseError(value.into())
    }
}

pub type TransferResult = Result<(), NldeTransferError>;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NldeDataIndicationDstAddress {
    Multicast(NwkAddress) = 0x01,
    UnicastOrBroadcast(NwkAddress) = 0x02,
}

impl Default for NldeDataIndicationDstAddress {
    fn default() -> Self {
        NldeDataIndicationDstAddress::Multicast(NwkAddress::default())
    }
}

pub enum NwkIndication {
    Data(NldeDataIndication),
    Join(NlmeJoinIndication),
    Leave(NlmeLeaveIndication),
    Status(NlmeNetworkStatusIndication),
    DutyCycle(NlmeDutyCycleModeIndication),
    SyncLoss,
}

#[derive(Default, Debug)]
pub struct NldeDataIndication {
    pub dst_address: NldeDataIndicationDstAddress,
    pub src_address: NwkAddress,
    pub nsdu: zb_types::Vec<u8, MAX_NWK_PAYLOAD_SIZE>,
    pub link_quality: u8,
    pub security_use: bool, // rx_time
}

pub enum JoinMethod {
    Association(MacCapabilities),
    Direct,
    Rejoin { secure: bool },
}

pub struct NlmeJoinIndication {
    pub(crate) nwk_addr: NwkAddress,
    pub(crate) ext_addr: ExtendedAddress,
    pub(crate) join_method: JoinMethod,
}

pub struct NlmeLeaveIndication {
    pub device_address: Option<ExtendedAddress>,
    pub rejoin: bool,
}

type NlmeNetworkStatusIndication = NetworkStatus;

pub struct NlmeDutyCycleModeIndication {
    pub interface_index: u8,
    pub status: DutyCycleStatus,
}

pub enum DutyCycleStatus {
    Normal,
    Limited,
    Critical,
    Suspended,
}
