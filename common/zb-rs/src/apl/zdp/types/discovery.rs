use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;

use crate::apl::aps::types::ApsEndpoint;
use crate::apl::zdo::config::ZbCapabilities;
use crate::apl::zdp::types::descriptors::{NodeDescriptor, NodePowerDescriptor, ServerMask, SimpleDescriptor, UserDescriptor};
use crate::common::bytes::WithLength;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

const CLUSTER_LIST_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum AddrRequestType {
    #[default]
    SingleDevice = 0x0,
    ExtendedResponse(u8) = 0x1,
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite)]
pub struct NwkAddrReq {
    pub ieee_address: ExtendedAddress,
    pub request_type: AddrRequestType,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct IeeeAddrReq {
    pub nwk_addr_of_interest: NwkAddress,
    pub request_type: AddrRequestType,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct NodeDescReq {
    pub nwk_addr_of_interest: NwkAddress,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct PowerDescReq {
    pub nwk_addr_of_interest: NwkAddress,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct SimpleDescReq {
    pub nwk_addr_of_interest: NwkAddress,
    pub endpoint: ApsEndpoint,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct ActiveEpReq {
    pub nwk_addr_of_interest: NwkAddress,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct MatchDescReq {
    pub nwk_addr_of_interest: NwkAddress,
    pub profile_id: u16,
    #[byte(len = u8)]
    pub in_cluster_list: zb_types::Vec<u16, CLUSTER_LIST_SIZE>,
    #[byte(len = u8)]
    pub out_cluster_list: zb_types::Vec<u16, CLUSTER_LIST_SIZE>,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct ComplexDescReq {
    nwk_addr_of_interest: NwkAddress,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct UserDescReq {
    nwk_addr_of_interest: NwkAddress,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct DeviceAnnce {
    pub nwk_addr: NwkAddress,
    pub ieee_addr: ExtendedAddress,
    pub capability: ZbCapabilities,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ParentAnnce {
    #[byte(len = u8)]
    pub children: zb_types::Vec<ExtendedAddress, 32>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct UserDescSet {
    nwk_addr_of_interest: NwkAddress,
    length: u8,
    user_description: UserDescriptor,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct SystemServerDiscoveryReq {
    pub server_mask: ServerMask,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoveryStoreReq {
    nwk_addr: NwkAddress,
    ieee_addr: ExtendedAddress,
    node_desc_size: u8,
    power_desc_size: u8,
    active_ep_size: u8,
    simple_desc_count: u8,
    simple_desc_size_list: zb_types::Vec<u8, 255>,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct NodeDescStoreReq {
    /// NWK Address for the Local Device.
    nwk_addr: NwkAddress,
    /// IEEE Address for the Local Device.
    ieee_addr: ExtendedAddress,
    // Node Descriptor
    node_descriptor: NodeDescriptor,
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite, PartialEq)]
#[repr(u8)]
pub enum AddrRspStatus {
    #[default]
    Success = 0x0,
    InvRequestType = 0x80,
    DeviceNotFound = 0x81,
}

#[derive(Clone, Debug, Default)]
pub struct AddrRsp {
    pub status: AddrRspStatus,
    pub ieee_addr: ExtendedAddress,
    pub nwk_addr: NwkAddress,
    pub num_assoc: Option<u16>,
    pub start_index: Option<u8>,
    pub nwk_addr_assoc_dev_list: Option<zb_types::Vec<u16, 255>>,
}

impl<'a, C> TryRead<'a, C> for AddrRsp {
    fn try_read(bytes: &'a [u8], _: C) -> byte::Result<(Self, usize)> {
        let mut rsp = AddrRsp {
            status: AddrRspStatus::Success,
            ieee_addr: Default::default(),
            nwk_addr: Default::default(),
            num_assoc: None,
            start_index: None,
            nwk_addr_assoc_dev_list: None,
        };

        let mut offset = 0;

        rsp.status = bytes.read_with(&mut offset, Endian::Little)?;
        rsp.ieee_addr = bytes.read_with(&mut offset, Endian::Little)?;
        rsp.nwk_addr = bytes.read_with(&mut offset, Endian::Little)?;

        if bytes[offset..].len() > 0 {
            rsp.num_assoc = Some(bytes.read_with(&mut offset, Endian::Little)?);
            rsp.start_index = Some(bytes.read_with(&mut offset, Endian::Little)?);
            // TODO: fix
            // rsp.nwk_addr_assoc_dev_list = Some(bytes.read_with(&mut offset,
            // Endian::Little)?);
        }

        Ok((rsp, offset))
    }
}

impl<'a, C> TryWrite<C> for &AddrRsp {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        let mut offset = 0;

        bytes.write_with(&mut offset, self.status, Endian::Little)?;
        bytes.write_with(&mut offset, self.ieee_addr, Endian::Little)?;
        bytes.write_with(&mut offset, self.nwk_addr, Endian::Little)?;

        if self.num_assoc.is_some() {
            bytes.write_with(&mut offset, self.num_assoc.unwrap(), Endian::Little)?;
            bytes.write_with(&mut offset, self.start_index.unwrap(), Endian::Little)?;
            // TODO: fix
            // bytes.write_with(&mut offset,
            // self.nwk_addr_assoc_dev_list.unwrap(), Endian::Little)?;
        }

        Ok(offset)
    }
}

impl<'a, C> TryWrite<C> for &mut AddrRsp {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        <&AddrRsp>::try_write(self, bytes, ())
    }
}

impl<'a, C> TryWrite<C> for AddrRsp {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        <&AddrRsp>::try_write(&self, bytes, ())
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug, Default, TryRead, TryWrite)]
#[repr(u8)]
pub enum DescRspStatus {
    #[default]
    Success = 0x0,
    InvRequestType = 0x80,
    DeviceNotFound = 0x81,
    NoDescriptor = 0x89,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, Default)]
pub struct NodeDescRsp {
    pub status: DescRspStatus,
    pub nwk_addr: NwkAddress,
    #[byte(parse_if = status == DescRspStatus::Success)]
    pub node_descriptor: Option<NodeDescriptor>,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct PowerDescRsp {
    pub status: DescRspStatus,
    pub nwk_addr: NwkAddress,
    #[byte(parse_if = status == DescRspStatus::Success)]
    pub power_descriptor: Option<NodePowerDescriptor>,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite, PartialEq)]
#[repr(u8)]
pub enum SimpleDescRspStatus {
    Success = 0x0,
    InvRequestType = 0x80,
    DeviceNotFound = 0x81,
    InvalidEp = 0x82,
    NotActive = 0x83,
    NoDescriptor = 0x89,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct SimpleDescRsp {
    pub status: SimpleDescRspStatus,
    pub nwk_addr: NwkAddress,
    pub simple_descriptor: WithLength<u8, SimpleDescriptor>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ActiveEpRsp {
    pub status: DescRspStatus,
    pub nwk_addr: NwkAddress,
    #[byte(len = u8)]
    pub active_ep_list: zb_types::Vec<ApsEndpoint, 32>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct MatchDescRsp {
    pub status: DescRspStatus,
    pub nwk_addr: NwkAddress,
    #[byte(len = u8)]
    pub match_list: zb_types::Vec<ApsEndpoint, 32>,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum ParentAnnceRspStatus {
    Success = 0x0,
    NotSupported = 0x84,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ParentAnnceRsp {
    pub status: ParentAnnceRspStatus,
    #[byte(len = u8)]
    pub children: zb_types::Vec<ExtendedAddress, 32>,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
pub struct SystemServerDiscoveryRsp {
    pub mask: ServerMask,
}
