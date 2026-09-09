use crate::apl::aps::constants::MAX_APS_PAYLOAD_SIZE;
use crate::apl::aps::security::types::commands::ConfirmKeyCommand;
use crate::apl::aps::security::types::commands::RemoveDeviceCommand;
use crate::apl::aps::security::types::commands::RequestKeyCommand;
use crate::apl::aps::security::types::commands::SwitchKeyCommand;
use crate::apl::aps::security::types::commands::TransportKeyCommand;
use crate::apl::aps::security::types::commands::UpdateDeviceCommand;
use crate::apl::aps::security::types::commands::VerifyKeyCommand;
use crate::apl::aps::types::{ApsAddress, ApsEndpoint};
use byte::BytesExt;
use byte::TryWrite;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_macros::BitStruct;
use zb_types::common::NwkAddress;

#[derive(BitStruct, Debug, Clone, Copy, Eq, PartialEq)]
#[bit_struct(repr = u8)]
pub struct ApsFrameControl {
    #[bit_struct(len = 2)]
    pub frame_type: ApsFrameType,
    #[bit_struct(len = 2)]
    pub delivery_mode: DeliveryMode,
    pub ack_format: bool,
    pub security: bool,
    pub ack_request: bool,
    pub extended_header: bool
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum ApsFrameType {
    Data = 0b00,
    Command = 0b01,
    Acknowledgement = 0b10,
    InterPan = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum ExtendedFrameControlField {
    NoFragmentation = 0b00,
    FragmentationFirst {
        block_number: u8,
        ack_bitfield: Option<u8>, // TODO this shall only be set in acknowledgement frames
    } = 0b01,
    FragmentationNotFirst {
        block_number: u8,
        ack_bitfield: Option<u8>, // TODO this shall only be set in acknowledgement frames
    } = 0b10,
}

impl ExtendedFrameControlField {
    pub fn is_fragmented(&self) -> bool {
        matches!(
            self,
            Self::FragmentationFirst { .. } | Self::FragmentationNotFirst { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum DeliveryMode {
    Unicast = 0b00,
    Broadcast = 0b10,
    GroupAddressing = 0b11,
}

#[derive(Debug)]
pub enum ApsFrame {
    Data(ApsDataFrame),
    ApsCommand(ApsCommandFrame),
    Acknowledgement(ApsHeader),
}

#[derive(Clone, Debug, Eq, PartialEq, TryRead, TryWrite)]
pub struct ApsHeader {
    pub frame_control: ApsFrameControl,
    #[byte(parse_if =
        (frame_control.frame_type == ApsFrameType::Acknowledgement && !frame_control.ack_format) ||
        (frame_control.frame_type == ApsFrameType::Data && (frame_control.delivery_mode == DeliveryMode::Unicast || frame_control.delivery_mode == DeliveryMode::Broadcast)))]
    pub destination_endpoint: Option<ApsEndpoint>,
    #[byte(parse_if = frame_control.frame_type == ApsFrameType::Data && frame_control.delivery_mode == DeliveryMode::GroupAddressing)]
    pub group_address: Option<NwkAddress>,
    #[byte(parse_if =
        (frame_control.frame_type == ApsFrameType::Acknowledgement && !frame_control.ack_format) ||
        (frame_control.frame_type == ApsFrameType::Data))]
    pub cluster_id: Option<u16>,
    #[byte(parse_if =
        (frame_control.frame_type == ApsFrameType::Acknowledgement && !frame_control.ack_format) ||
        (frame_control.frame_type == ApsFrameType::Data))]
    pub profile_id: Option<u16>,
    #[byte(parse_if =
        (frame_control.frame_type == ApsFrameType::Acknowledgement && !frame_control.ack_format) ||
        (frame_control.frame_type == ApsFrameType::Data))]
    pub source_endpoint: Option<ApsEndpoint>,
    pub counter: u8,
    #[byte(parse_if = frame_control.extended_header)]
    pub extended_header: Option<ExtendedFrameControlField>,
}

#[derive(Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum ApsCommand {
    TransportKey(TransportKeyCommand) = 0x05,
    UpdateDevice(UpdateDeviceCommand) = 0x06,
    RemoveDevice(RemoveDeviceCommand) = 0x07,
    RequestKey(RequestKeyCommand) = 0x08,
    SwitchKey(SwitchKeyCommand) = 0x09,
    // TunnelData(TunnelDataCommand) = 0x0e,
    VerifyKey(VerifyKeyCommand) = 0x0f,
    ConfirmKey(ConfirmKeyCommand) = 0x10,
}

impl<'a> ApsFrame {
    pub fn from_payload(header: ApsHeader, payload: &'_ [u8]) -> byte::Result<Self> {
        match header.frame_control.frame_type {
            ApsFrameType::Data => Ok(Self::Data(ApsDataFrame {
                header,
                payload: zb_types::Vec::from_slice(payload).unwrap(),
            })),
            ApsFrameType::Command => Ok(Self::ApsCommand(ApsCommandFrame {
                header,
                command: match payload.read_with::<ApsCommand>(&mut 0, byte::LE) {
                    Ok(cmd) => cmd,
                    Err(err) => {
                        log::warn!("error reading command frame: {err:?}");
                        return Err(err);
                    }
                },
            })),
            ApsFrameType::Acknowledgement => Ok(Self::Acknowledgement(header)),
            ApsFrameType::InterPan => unimplemented!("InterPan frames not supported"),
        }
    }

    pub fn header(&self) -> &ApsHeader {
        match self {
            ApsFrame::Data(data_frame) => &data_frame.header,
            ApsFrame::ApsCommand(command_frame) => &command_frame.header,
            ApsFrame::Acknowledgement(header) => header,
        }
    }

    pub fn header_mut(&mut self) -> &mut ApsHeader {
        match self {
            ApsFrame::Data(data_frame) => &mut data_frame.header,
            ApsFrame::ApsCommand(command_frame) => &mut command_frame.header,
            ApsFrame::Acknowledgement(header) => header,
        }
    }
}

impl TryWrite<Endian> for ApsFrame {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let mut offset = 0;

        match self {
            ApsFrame::Data(data_frame) => {
                bytes.write_with(&mut offset, data_frame.header, ctx)?;
                bytes.write_with(&mut offset, data_frame.payload.as_slice(), ())?;
            }
            ApsFrame::ApsCommand(command_frame) => {
                bytes.write_with(&mut offset, command_frame.header, ctx)?;
                bytes.write_with(&mut offset, command_frame.command, ctx)?;
            }
            ApsFrame::Acknowledgement(header) => {
                bytes.write_with(&mut offset, header, ctx)?;
            }
        }

        Ok(offset)
    }
}

fn get_destination_endpoint(addr: ApsAddress) -> Option<ApsEndpoint> {
    match addr {
        ApsAddress::Group(_) => None,
        ApsAddress::Network(_, endpoint) => Some(endpoint),
    }
}

fn get_group_address(addr: ApsAddress) -> Option<NwkAddress> {
    match addr {
        ApsAddress::Group(addr) => Some(addr),
        ApsAddress::Network(_, _) => None,
    }
}

fn get_delivery_mode(addr: ApsAddress) -> DeliveryMode {
    match addr {
        ApsAddress::Group(_) => DeliveryMode::GroupAddressing,
        ApsAddress::Network(addr, _) => {
            if addr.is_broadcast() {
                DeliveryMode::Broadcast
            } else {
                DeliveryMode::Unicast
            }
        }
    }
}

pub struct DataFrameInit {
    pub(crate) dst: ApsAddress,
    pub(crate) cluster_id: u16,
    pub(crate) profile_id: u16,
    pub(crate) source_endpoint: ApsEndpoint,
    pub(crate) payload: zb_types::Vec<u8, MAX_APS_PAYLOAD_SIZE>,
    pub(crate) ack_request: bool,
    pub(crate) extended_header: Option<ExtendedFrameControlField>,
}

#[derive(Debug)]
pub struct ApsDataFrame {
    pub header: ApsHeader,
    pub payload: zb_types::Vec<u8, MAX_APS_PAYLOAD_SIZE>,
}

impl ApsDataFrame {
    pub(crate) fn new(init: DataFrameInit) -> Self {
        Self {
            header: ApsHeader {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Data,
                    delivery_mode: get_delivery_mode(init.dst),
                    ack_format: false,
                    security: false,
                    ack_request: init.ack_request,
                    extended_header: init.extended_header.is_some(),
                },
                destination_endpoint: get_destination_endpoint(init.dst),
                group_address: get_group_address(init.dst),
                cluster_id: Some(init.cluster_id),
                profile_id: Some(init.profile_id),
                source_endpoint: Some(init.source_endpoint),
                counter: 0, // will be overridden during transmission
                extended_header: init.extended_header,
            },
            payload: init.payload,
        }
    }
}

pub struct ApsCommandFrameCtr {
    pub(crate) dst_addr: NwkAddress,
    pub(crate) command: ApsCommand,
}

#[derive(TryRead, TryWrite, Debug)]
pub struct ApsCommandFrame {
    pub header: ApsHeader,
    pub command: ApsCommand,
}

impl<'a> ApsCommandFrame {
    pub(crate) fn new(init: ApsCommandFrameCtr) -> Self {
        Self {
            header: ApsHeader {
                frame_control: ApsFrameControl {
                    frame_type: ApsFrameType::Command,
                    delivery_mode: if init.dst_addr.is_broadcast() {
                        DeliveryMode::Broadcast
                    } else {
                        DeliveryMode::Unicast
                    },
                    ack_format: false,
                    extended_header: false,
                    security: false,
                    ack_request: false,
                },
                destination_endpoint: None,
                group_address: None,
                cluster_id: None,
                profile_id: None,
                source_endpoint: None,
                counter: 0, // will be overridden during transmission
                extended_header: None,
            },
            command: init.command,
        }
    }
}
