pub mod header;


use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use header::NwkHeader;
use zb_macros::try_write_impl;
use crate::nwk::commands::Command;
use crate::nwk::constants::MAX_NWK_PAYLOAD_SIZE;
use crate::nwk::frame::header::DiscoverRoute;
use crate::nwk::frame::header::FrameType;
use zb_types::common::NwkAddress;

#[derive(Debug, Clone)]
pub enum NwkFrame {
    Data(NwkDataFrame),
    NwkCommand(CommandFrame),
    Reserved(NwkHeader),
    InterPan(NwkHeader),
}

impl NwkFrame {
    pub fn new_data_frame(
        header: NwkHeader,
        payload: zb_types::Vec<u8, MAX_NWK_PAYLOAD_SIZE>,
    ) -> Self {
        Self::Data(NwkDataFrame { header, payload })
    }

    pub(crate) fn new_cmd_frame(header: NwkHeader, command: Command) -> Self {
        Self::NwkCommand(CommandFrame { header, command })
    }

    pub fn header(&self) -> &NwkHeader {
        match self {
            NwkFrame::Data(NwkDataFrame { header, .. }) => header,
            NwkFrame::NwkCommand(CommandFrame { header, .. }) => header,
            NwkFrame::Reserved(header) => header,
            NwkFrame::InterPan(header) => header,
        }
    }

    pub fn header_mut(&mut self) -> &mut NwkHeader {
        match self {
            NwkFrame::Data(NwkDataFrame { header, .. }) => header,
            NwkFrame::NwkCommand(CommandFrame { header, .. }) => header,
            NwkFrame::Reserved(header) => header,
            NwkFrame::InterPan(header) => header,
        }
    }

    pub fn dst_addr(&self) -> NwkAddress { self.header().destination }

    pub fn src_addr(&self) -> NwkAddress { self.header().source }

    pub fn sequence_number(&self) -> u8 { self.header().sequence_number }

    pub fn is_secured(&self) -> bool { self.header().control.security }

    pub fn is_multicast(&self) -> bool { self.header().control.multicast }

    pub fn is_unicast(&self) -> bool {
        !self.header().control.multicast && self.src_addr().is_unicast()
    }

    pub fn is_broadcast(&self) -> bool { self.src_addr().is_broadcast() }

    pub fn is_route_discovery_enabled(&self) -> bool {
        self.header().control.route_discovery == DiscoverRoute::Enable
    }
}

impl TryRead<'_, NwkHeader> for NwkFrame {
    fn try_read(bytes: &'_ [u8], hdr: NwkHeader) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        match hdr.control.frame_type {
            FrameType::Data => Ok((
                Self::Data(NwkDataFrame {
                    header: hdr,
                    payload: zb_types::Vec::<u8, MAX_NWK_PAYLOAD_SIZE>::from_slice(
                        &bytes[*offset..],
                    )
                    .map_err(|_| byte::Error::BadInput {
                        err: "couldn't fit received content in payload",
                    })?,
                }),
                bytes.len(),
            )),
            FrameType::NwkCommand => {
                let cmd = bytes.read_with(offset, ())?;
                Ok((
                    Self::NwkCommand(CommandFrame {
                        header: hdr,
                        command: cmd,
                    }),
                    *offset,
                ))
            }
            FrameType::Reserved => Ok((Self::Reserved(hdr), *offset)),
            FrameType::InterPan => Ok((Self::InterPan(hdr), *offset)),
        }
    }
}

impl TryRead<'_, Endian> for NwkFrame {
    fn try_read(bytes: &[u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let hdr: NwkHeader = bytes.read_with(offset, ctx)?;
        let slf = bytes.read_with(offset, hdr)?;

        Ok((slf, *offset))
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &NwkFrame {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;

        match self {
            NwkFrame::Data(data) => {
                bytes.write_with(offset, &data.header, ctx)?;
                bytes.write_with(offset, data.payload.as_slice(), ())?;
            }
            NwkFrame::NwkCommand(cmd) => {
                bytes.write_with(offset, &cmd.header, ctx)?;
                bytes.write_with(offset, &cmd.command, ())?;
            }
            NwkFrame::Reserved(hdr) => bytes.write_with(offset, hdr, ctx)?,
            NwkFrame::InterPan(hdr) => bytes.write_with(offset, hdr, ctx)?,
        };

        Ok(*offset)
    }
}

#[derive(Debug, Clone)]
pub struct NwkDataFrame {
    pub header: NwkHeader,
    pub payload: zb_types::Vec<u8, MAX_NWK_PAYLOAD_SIZE>,
}

#[derive(Debug, Clone)]
pub struct CommandFrame {
    pub header: NwkHeader,
    pub command: Command,
}
