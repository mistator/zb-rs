use crate::apl::aps::constants::MAX_APS_PAYLOAD_SIZE;
use crate::zcl::command::global::GlobalZclCommand;
use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_macros::BitStruct;

#[derive(Clone, Debug)]
pub enum ZclFrameCommand {
    Global(GlobalZclCommand),
    Specific(SpecificZclCommand),
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct SpecificZclCommand {
    pub identifier: u8,
    pub data: zb_types::Vec<u8, MAX_APS_PAYLOAD_SIZE>,
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite)]
pub struct ZclHeader {
    pub frame_control: ZclFrameControl,
    #[byte(parse_if = frame_control.manufacturer_specific)]
    pub manufacturer_code: Option<u16>,
    pub sequence_number: u8,
}

#[derive(Clone, Debug)]
pub struct ZclFrame {
    pub header: ZclHeader,
    pub command: ZclFrameCommand,
}

impl ZclFrame {
    pub fn new_global_command(
        cmd: GlobalZclCommand,
        sequence_number: u8,
        direction: ZclDirection,
        disable_default_response: bool,
    ) -> Self {
        Self {
            header: ZclHeader {
                frame_control: ZclFrameControl {
                    frame_type: ZclFrameType::Global,
                    manufacturer_specific: false,
                    direction,
                    disable_default_response,
                },
                manufacturer_code: None,
                sequence_number,
            },
            command: ZclFrameCommand::Global(cmd),
        }
    }

    pub fn new_specific_command(
        cmd: SpecificZclCommand,
        manufacturer_code: u16,
        direction: ZclDirection,
        disable_default_response: bool,
    ) -> Self {
        Self {
            header: ZclHeader {
                frame_control: ZclFrameControl {
                    frame_type: ZclFrameType::Specific,
                    manufacturer_specific: true,
                    direction,
                    disable_default_response,
                },
                manufacturer_code: Some(manufacturer_code),
                sequence_number: 0,
            },
            command: ZclFrameCommand::Specific(cmd),
        }
    }
}

impl<'a> TryWrite<Endian> for ZclFrame {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let mut offset = 0;
        bytes.write_with(&mut offset, self.header, byte::LE)?;
        match self.command {
            ZclFrameCommand::Global(value) => bytes.write_with(&mut offset, value, ctx)?,
            ZclFrameCommand::Specific(value) => {
                bytes.write_with(&mut offset, value.data.as_slice(), ())?
            }
        }
        Ok(offset)
    }
}

impl<'a> TryRead<'a, Endian> for ZclFrame {
    fn try_read(bytes: &'a [u8], _: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        let header = bytes.read_with::<ZclHeader>(offset, byte::LE)?;
        let cmd = match header.frame_control.frame_type {
            ZclFrameType::Global => ZclFrameCommand::Global(bytes.read_with(offset, byte::LE)?),
            ZclFrameType::Specific => ZclFrameCommand::Specific(bytes.read_with(offset, byte::LE)?),
        };

        Ok((
            Self {
                header,
                command: cmd,
            },
            *offset,
        ))
    }
}

#[derive(BitStruct, Clone, Copy, Debug, Default)]
#[bit_struct(repr = u8)]
pub struct ZclFrameControl {
    #[bit_struct(len = 2)]
    pub frame_type: ZclFrameType,
    pub manufacturer_specific: bool,
    pub direction: ZclDirection,
    pub disable_default_response: bool
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite)]
#[repr(u8)]
pub enum ZclFrameType {
    #[default]
    Global = 0,
    Specific = 1,
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite)]
#[repr(u8)]
pub enum ZclDirection {
    #[default]
    ClientToServer = 0,
    ServerToClient = 1,
}
