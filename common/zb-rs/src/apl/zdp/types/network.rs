use byte::TryRead;
use byte::TryWrite;
use byte::check_len;
use byte_derive::TryRead;
use byte_derive::TryWrite;

use zb_types::common::DeviceType;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::nib::NeighborRelationship;

pub struct MgmtLqiReq {
    start_index: u8,
}

pub struct MgmtBindReq {
    start_index: u8,
}

pub struct MgmtLeaveReq {
    ieee_addr: ExtendedAddress,
    remove_children: bool,
    rejoin: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum MgmtPermitJoiningReq {
    Disable,
    Enable(u8),
}

impl<C> TryRead<'_, C> for MgmtPermitJoiningReq {
    fn try_read(bytes: &[u8], _: C) -> byte::Result<(Self, usize)> {
        const LEN: usize = 2;
        check_len(&bytes, LEN)?;

        // We don't care about second byte:
        //
        // A value of zero for the TC_Significance field has been deprecated. The field
        // shall always be included in the message and all received frames shall
        // be treated as though set to 1, regardless of the actual received
        // value.
        match bytes[0] {
            0x00 => Ok((MgmtPermitJoiningReq::Disable, LEN)),
            // Versions of this specification prior to revision 21 allowed a value of 0xFF to be
            // interpreted as ‘forever’. Version 21 and later do not allow this. All devices
            // conforming to this specification shall interpret 0xFF as 0xFE.
            0xff => Ok((MgmtPermitJoiningReq::Enable(0xfe), LEN)),
            value => Ok((MgmtPermitJoiningReq::Enable(value), LEN)),
        }
    }
}

impl<C> TryWrite<C> for &MgmtPermitJoiningReq {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        const LEN: usize = 2;
        check_len(&bytes, 2)?;

        bytes[1] = 1;

        match self {
            MgmtPermitJoiningReq::Disable => bytes[0] = 0x00,
            MgmtPermitJoiningReq::Enable(value) => match value {
                0xff => bytes[0] = 0xfe,
                value => bytes[0] = *value,
            },
        }

        Ok(LEN)
    }
}

impl<C> TryWrite<C> for &mut MgmtPermitJoiningReq {
    fn try_write(self, bytes: &mut [u8], ctx: C) -> byte::Result<usize> {
        <&MgmtPermitJoiningReq>::try_write(self, bytes, ctx)
    }
}

impl<C> TryWrite<C> for MgmtPermitJoiningReq {
    fn try_write(self, bytes: &mut [u8], ctx: C) -> byte::Result<usize> {
        <&MgmtPermitJoiningReq>::try_write(&self, bytes, ctx)
    }
}

pub enum MgmtLqiRspStatus {
    Success,
    NotSupported,
}

pub struct MgmtLqiNeighborEntry {
    ieee_address: ExtendedAddress,
    nwk_address: NwkAddress,
    device_type: DeviceType,
    rx_on_when_idle: Option<bool>,
    relationship: NeighborRelationship,
    permit_joining: Option<bool>,
    depth: u8,
    lqi: u8,
}

pub struct MgmtLqiRsp {
    status: MgmtLqiRspStatus,
    neighbor_table_entries: u8,
    start_index: u8,
    neighbor_table_list_count: u8,
    neighbor_table_list: zb_types::Vec<MgmtLqiNeighborEntry, 3>,
}

#[derive(Clone, Copy, Debug, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum MgmtPermitJoiningRsp {
    Success = 0x0,
    InvalidRequest = 0xc2,
    NotAuthorized = 0xc3,
}
