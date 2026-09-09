use byte_derive::TryRead;
use byte_derive::TryWrite;

use crate::apl::aps::frame::ApsCommandFrame;
use crate::apl::aps::frame::ApsHeader;
use crate::apl::aps::security::types::common::RequestKeyType;
use crate::apl::aps::security::types::common::StandardKeyDescriptor;
use crate::apl::aps::security::types::common::StandardKeyType;
use crate::common::security::frame::AuxFrameHeader;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(Debug, TryRead, TryWrite)]
pub struct TransportKeyCommand {
    pub key_descriptor: StandardKeyDescriptor,
}

#[derive(Debug, TryRead, TryWrite)]
pub struct UpdateDeviceCommand {
    pub device_address: ExtendedAddress,
    pub device_short_address: NwkAddress,
    pub status: UpdateDeviceStatus,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum UpdateDeviceStatus {
    StandardDeviceSecuredRejoin = 0x00,
    StandardDeviceUnsecuredJoin = 0x01,
    DeviceLeft = 0x02,
    StandardDeviceTrustCenterRejoin = 0x03,
}

#[derive(Debug, TryRead, TryWrite)]
pub struct RemoveDeviceCommand {
    pub target_address: ExtendedAddress,
}

#[derive(Debug, TryRead, TryWrite)]
pub struct RequestKeyCommand {
    pub key_type: RequestKeyType,
}

#[derive(Debug, TryRead, TryWrite)]
pub struct SwitchKeyCommand {
    pub sequence_number: u8,
}

#[derive(Debug, TryRead, TryWrite)]
pub struct TunnelDataCommand {
    pub destination_address: ExtendedAddress,
    pub tunneled_aps_header: ApsHeader,
    pub tunneled_auxiliary_frame: AuxFrameHeader,
    pub tunneled_command: ApsCommandFrame,
    pub tunneled_aps_mic: [u8; 4],
}

#[derive(Debug, TryRead, TryWrite)]
pub struct VerifyKeyCommand {
    pub key_type: StandardKeyType,
    pub source_address: ExtendedAddress,
    pub initiator_hash_value: [u8; 16],
}

#[derive(Debug, TryRead, TryWrite)]
pub struct ConfirmKeyCommand {
    pub status: ConfirmKeyStatus,
    pub key_type: StandardKeyType,
    pub destination_address: ExtendedAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum ConfirmKeyStatus {
    Success = 0x0,
    Failure = 0xa6,
}
