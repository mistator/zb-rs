use byte::{BytesExt, TryRead, TryWrite, ctx};
use byte_derive::{TryRead, TryWrite};
use core::cmp::min;
use zb_macros::{try_write_impl, BitStruct};
use zb_types::common::DeviceType;
use zb_types::mac::MacCapabilities;

use crate::apl::aps::types::ApsEndpoint;

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite)]
pub struct NodeDescriptor {
    pub info: NodeDescriptorInfo,
    pub frequency_bands: FrequencyBands,
    pub mac_capabilities: MacCapabilities,
    pub manufacturer_code: u16,
    pub maximum_buffer_size: u8,
    pub maximum_incoming_transfer_size: u16,
    pub server_mask: ServerMask,
    pub maximum_outgoing_transfer_size: u16,
    pub descriptor_capabilities: DescriptorCapabilities,
}

impl NodeDescriptor {
    pub fn get_logical_type(&self) -> DeviceType { self.info.logical_type }

    pub fn is_complex_descriptor_available(&self) -> bool { self.info.complex_descriptor_available }

    pub fn is_user_descriptor_available(&self) -> bool { self.info.user_descriptor_available }
}

#[derive(BitStruct, Debug, Eq, PartialEq, Clone, Copy)]
#[bit_struct(repr = u8)]
pub struct FrequencyBands {
    #[bit_struct(skip = 3)]
    low: bool,
    #[bit_struct(skip = 1)]
    mid: bool,
    high: bool,
    european_fsk: bool
}

impl Default for FrequencyBands {
    fn default() -> Self {
        Self {
            low: false,
            mid: false,
            high: true,
            european_fsk: false,
        }
    }
}

impl Default for ServerMask {
    fn default() -> Self {
        Self {
            primary_trust_center: false,
            backup_trust_center: false,
            primary_binding_table_cache: false,
            backup_binding_table_cache: false,
            primary_discovery_cache: false,
            backup_discovery_cache: false,
            network_manager: false,
            stack_compliance_revision: 22,
        }
    }
}

#[derive(BitStruct, Clone, Copy, Debug, Default)]
#[bit_struct(repr = u8)]
pub struct NodeDescriptorInfo {
    #[bit_struct(len = 3)]
    pub logical_type: DeviceType,
    pub complex_descriptor_available: bool,
    pub user_descriptor_available: bool,
}

#[derive(BitStruct, Clone, Copy, Eq, PartialEq, Debug)]
#[bit_struct(repr = u16)]
pub struct ServerMask {
    pub primary_trust_center: bool,
    pub backup_trust_center: bool,
    pub primary_binding_table_cache: bool,
    pub backup_binding_table_cache: bool,
    pub primary_discovery_cache: bool,
    pub backup_discovery_cache: bool,
    pub network_manager: bool,
    #[bit_struct(len = 7)]
    #[bit_struct(skip = 2)]
    pub stack_compliance_revision: u8
}

#[derive(BitStruct, Copy, Clone, Debug, Default)]
#[bit_struct(repr = u8)]
pub struct DescriptorCapabilities {
    pub extended_active_endpoint_list_available: bool,
    pub extended_simple_descriptor_list_available: bool,
}

#[derive(BitStruct, Clone, Copy, Debug, Default)]
#[bit_struct(repr = u16)]
pub struct NodePowerDescriptor {
    #[bit_struct(len = 4)]
    pub current_power_mode: CurrentPowerMode,
    #[bit_struct(len = 4)]
    pub available_power_sources: AvailablePowerSources,
    #[bit_struct(len = 4)]
    pub current_power_source: CurrentPowerSource,
    #[bit_struct(len = 4)]
    pub current_power_source_level: CurrentPowerSourceLevel,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum CurrentPowerMode {
    // Receiver synchronized with the receiver on when idle subfield of the node descriptor.
    #[default]
    Synchronized = 0b0000,
    // Receiver comes on periodically as defined by the node power descriptor.
    Periodically = 0b0001,
    // Receiver comes on when stimulated, for example, by a user pressing a button.
    Stimulated = 0b0010,
}

#[derive(BitStruct, Clone, Copy, Debug, Default)]
#[bit_struct(repr = u8)]
pub struct AvailablePowerSources {
    pub mains_power: bool,
    pub rechargeable_battery: bool,
    pub disposable_battery: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum CurrentPowerSource {
    #[default]
    MainsPower = 0b000,
    RechargeableBattery = 0b010,
    DisposableBattery = 0b100,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum CurrentPowerSourceLevel {
    Critical = 0b0000,
    OneThird = 0b0100,
    TwoThirds = 0b1000,
    #[default]
    Full = 0b1100,
}

// Server clusters reside on the input list, and client clusters reside on the
// output list.
#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct SimpleDescriptor {
    pub endpoint: ApsEndpoint,
    pub application_profile_identifier: u16,
    pub application_device_identifier: u16,
    pub application_device_version: u8,
    #[byte(len = u8)] pub application_input_cluster_list: zb_types::Vec<u16, 32>,
    #[byte(len = u8)] pub application_output_cluster_list: zb_types::Vec<u16, 32>,
}

const USER_DESCRIPTOR_SIZE: usize = 16;

#[derive(Copy, Clone, Debug)]
pub struct UserDescriptor([u8; 16]);

impl<'a> TryRead<'a, ctx::Endian> for UserDescriptor {
    fn try_read(bytes: &'a [u8], _: ctx::Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let value: &'a [u8] = bytes.read_with(
            offset,
            ctx::Bytes::Len(min(bytes.len(), USER_DESCRIPTOR_SIZE)),
        )?;
        if value.iter().all(|&b| b > 0x1f && b < 0x80) {
            let mut dest = [0x20u8; 16];
            let dest_slice = &mut dest[..value.len()];
            dest_slice.copy_from_slice(&value);

            Ok((UserDescriptor(dest), *offset))
        } else {
            Err(byte::Error::BadInput {
                err: "InvalidUserDescriptor: Input is not valid ASCII",
            })
        }
    }
}

#[try_write_impl]
impl TryWrite<ctx::Endian> for &UserDescriptor {
    fn try_write(self, bytes: &mut [u8], __: ctx::Endian) -> byte::Result<usize> {
        Ok(self.0.try_write(bytes, ())?)
    }
}
