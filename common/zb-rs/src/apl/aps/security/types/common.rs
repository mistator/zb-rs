use byte_derive::TryRead;
use byte_derive::TryWrite;

use zb_types::common::ExtendedAddress;
use zb_types::common::Key;

#[derive(Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum RequestKeyType {
    ApplicationLinkKey(ExtendedAddress) = 0x02,
    TrustCenterLinkKey = 0x04,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, PartialEq)]
#[repr(u8)]
pub enum StandardKeyType {
    StandardNetworkKey = 0x01,
    ApplicationLinkKey = 0x03,
    TrustCenterLinkKey = 0x04,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, PartialEq)]
#[repr(u8)]
pub enum StandardKeyDescriptor {
    StandardNetworkKey(StandardNetworkKeyDescriptor) = 0x01,
    ApplicationLinkKey(ApplicationLinkKeyDescriptor) = 0x03,
    TrustCenterLinkKey(TrustCenterLinkKeyDescriptor) = 0x04,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, PartialEq)]
pub struct StandardNetworkKeyDescriptor {
    pub key: Key,
    pub sequence_number: u8,
    pub destination_address: ExtendedAddress,
    pub source_address: ExtendedAddress,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, PartialEq)]
pub struct ApplicationLinkKeyDescriptor {
    pub key: Key,
    pub partner_address: ExtendedAddress,
    pub initiation_flag: bool,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, PartialEq)]
pub struct TrustCenterLinkKeyDescriptor {
    pub key: Key,
    pub destination_address: ExtendedAddress,
    pub source_address: ExtendedAddress,
}

#[derive(Debug, Clone, Copy)]
pub enum TransportKeyData {
    StandardNetworkKey(StandardNetworkKeyData),
    ApplicationLinkKey(ApplicationLinkKeyData),
    TrustCenterLinkKey(TrustCenterLinkKeyData),
}

#[derive(Debug, Clone, Copy)]
pub struct StandardNetworkKeyData {
    pub key_sequence: u8,
    pub key: Key,
    pub parent_address: Option<ExtendedAddress>,
}

#[derive(Debug, Clone, Copy)]
pub struct ApplicationLinkKeyData {
    pub partner_address: ExtendedAddress,
    pub key: Key,
    pub initiator: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TrustCenterLinkKeyData {
    pub key: Key,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, Default)]
pub struct DeviceKeyPairDescriptor {
    pub device_address: ExtendedAddress,
    pub key_attributes: KeyAttribute,
    pub link_key: Key,
    pub outgoing_frame_counter: u32,
    pub incoming_frame_counter: u32,
    pub link_key_type: LinkKeyType,
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite, PartialEq)]
#[repr(u8)]
pub enum KeyAttribute {
    #[default]
    ProvisionalKey = 0x00,
    UnverifiedKey = 0x01,
    VerifiedKey = 0x02,
}

#[derive(Debug, Default, TryRead, TryWrite, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum LinkKeyType {
    #[default]
    UniqueLinkKey = 0x00,
    GlobalLinkKey = 0x01,
}
