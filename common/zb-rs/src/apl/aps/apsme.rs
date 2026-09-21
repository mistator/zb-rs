use crate::apl::aps::ctx::{Aps, Apsme, DeviceKeyPairDescriptorSet};
use crate::apl::aps::types::ApsAddress;
use crate::apl::aps::types::ApsEndpoint;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::common::security::SecurityNetworkParams;
use crate::nwk::ctx::{JoinedNwk, JoinedState, Nwk};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, TryRead, TryWrite)]
#[repr(u8)]
pub enum BindingAddress {
    Group(NwkAddress) = 0x1,
    Device(ExtendedAddress, ApsEndpoint) = 0x3,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, TryRead, TryWrite)]
pub struct Binding {
    pub src_address: ExtendedAddress,
    pub src_endpoint: ApsEndpoint,
    pub cluster_id: u16,
    pub dst_address: BindingAddress,
}

#[derive(Debug, Clone, Default, TryRead, TryWrite)]
pub struct ApsGroupEntry {
    pub group_addr: u16,
    pub endpoints: zb_types::Vec<u8, 32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApsmeBindRequest {
    pub src_address: ExtendedAddress,
    pub src_endpoint: ApsEndpoint,
    pub cluster_id: u16,
    pub dst_address: ApsAddress,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum BindStatus {
    Success = 0x0,
    InvalidEp = 0x82,
    NotSupported = 0x84,
    TableFull = 0x8c,
    NotAuthorized = 0x8d,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsmeBindError {
    // IllegalRequest,
    TableFull,
    // NotSupported,
}

#[derive(Clone, Copy, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum UnbindStatus {
    Success = 0x0,
    InvalidEp = 0x82,
    NotSupported = 0x84,
    NoEntry = 0x88,
    NotAuthorized = 0x8d,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsmeUnbindError {
    IllegalRequest,
    InvalidBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsmeAddGroupError {
    InvalidParameter,
    TableFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsmeRemoveGroupError {
    InvalidGroup,
    InvalidParameter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApsmeRemoveAllGroupsError {
    InvalidParameter,
}

pub struct ApsmeAddrGroupRequest {
    group_address: u16,
    endpoint: u8,
}

impl<T: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Apsme for Aps<T, D, S> {
    fn bind_request(&mut self, binding: Binding) -> Result<(), ApsmeBindError> {
        self.binding_table.insert(binding)
            .map(|_| ())
            .map_err(|_| {
                log::warn!("error inserting binding {:?}: table full", binding);
                ApsmeBindError::TableFull
            })
    }

    fn unbind_request(&mut self, binding: Binding) -> Result<(), ApsmeUnbindError> {
        if self.binding_table.remove(&binding) {
            Ok(())
        } else {
            log::warn!("error inserting binding {:?}: not found", binding);
            Err(ApsmeUnbindError::InvalidBinding)
        }
    }

    fn add_group(&mut self, group: u16, endpoint: u8) -> Result<(), ApsmeAddGroupError> {
        // TODO: check if endpoint is currently on device
        // if self.ib.aps_group_table.contains(&(group, endpoint)) {
        // return Ok(());
        // }
        //
        // TODO: update nwk table
        // self.ib.aps_group_table.push((group, endpoint)).map_err(|_|
        // ApsmeAddGroupError::TableFull)
        //
        todo!()
    }

    fn remove_group(&mut self, group: u16, endpoint: u8) -> Result<(), ApsmeRemoveGroupError> {
        // TODO: check if endpoint is currently on device
        //
        // let idx = match self.ib.aps_group_table
        // .iter()
        // .find_position(|entry| entry.0 == group && entry.1 == endpoint) {
        // Some((idx, _)) => idx,
        // None => return Err(ApsmeRemoveGroupError::InvalidGroup),
        // };
        //
        // self.ib.aps_group_table.remove(idx);
        // Ok(())
        //
        todo!()
    }

    fn remove_all_groups(&mut self, _endpoint: u8) -> Result<(), ApsmeRemoveAllGroupsError> {
        todo!()
    }

    fn is_authorized(&self) -> bool { self.is_authorized }
    fn set_authorized(&mut self) -> () { self.is_authorized = true}
    fn get_security_network_params(&self) -> SecurityNetworkParams { self.security_network_params }

    fn get_tc_addr(&self) -> Option<ExtendedAddress> {
        match self.security_network_params {
            SecurityNetworkParams::Centralized(addr) => Some(addr),
            SecurityNetworkParams::Distributed => None
        }
    }

    fn get_device_key_pair_set(&self) -> &DeviceKeyPairDescriptorSet { &self.device_key_pair_set }
    fn get_device_key_pair_set_mut(&mut self) -> &mut DeviceKeyPairDescriptorSet {
        &mut self.device_key_pair_set
    }

    fn set_parent_announce_timer(&mut self, timer: f32) -> () { self.parent_announce_timer = timer }
}

