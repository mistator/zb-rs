use crate::nwk::commands::Command;
use crate::nwk::ctx::{Initialized, Joined, Nwk, Router};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::TransferResult;
use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::try_write_impl;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(Clone, Copy, Debug)]
pub enum RejoinResponse {
    Success(NwkAddress),
    PanAtCapacity,
    AccessDenied,
}

impl<'a> TryRead<'a, Endian> for RejoinResponse {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let nwk_addr = bytes.read_with::<NwkAddress>(offset, ctx)?;
        let idx = bytes.read_with::<u8>(offset, ctx)?;

        match idx {
            0 => Ok((Self::Success(nwk_addr), *offset)),
            1 => Ok((Self::PanAtCapacity, *offset)),
            2 => Ok((Self::AccessDenied, *offset)),
            _ => Err(byte::Error::BadInput {
                err: "invalid rejoin response status received",
            }),
        }
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &RejoinResponse {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;

        match self {
            RejoinResponse::Success(nwk_addr) => {
                bytes.write_with(offset, nwk_addr, ctx)?;
                bytes.write_with(offset, 0x0u8, ctx)?;
            }
            RejoinResponse::PanAtCapacity => {
                bytes.write_with(offset, NwkAddress::MAX, ctx)?;
                bytes.write_with(offset, 0x1u8, ctx)?;
            }
            RejoinResponse::AccessDenied => {
                bytes.write_with(offset, NwkAddress::MAX, ctx)?;
                bytes.write_with(offset, 0x2u8, ctx)?;
            }
        }

        Ok(*offset)
    }
}

pub struct RejoinResponseCmd {
    pub dst_addr: NwkAddress,
    pub ext_dst_addr: ExtendedAddress,
    pub rejoin_response: RejoinResponse,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S>  {
    pub async fn send_rejoin_response_cmd(
        &mut self,
        cfg: &RejoinResponseCmd,
    ) -> TransferResult {
        let hdr = NwkHeader::cmd(self)
            .destination(cfg.dst_addr)
            .destination_ieee(cfg.ext_dst_addr)
            .call();

        let cmd = Command::RejoinResponse(cfg.rejoin_response);
        let frame = NwkFrame::new_cmd_frame(hdr, cmd);

        self.transmit_frame(&frame, cfg.dst_addr, true).await
    }
}

