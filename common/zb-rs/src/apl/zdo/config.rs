use crate::apl::aps::constants::MAX_APS_FRAME_SIZE;
use crate::apl::zdp::types::descriptors::{AvailablePowerSources, CurrentPowerMode, CurrentPowerSource, CurrentPowerSourceLevel, DescriptorCapabilities, FrequencyBands, NodeDescriptor, NodeDescriptorInfo, NodePowerDescriptor, ServerMask, UserDescriptor};
use crate::nwk::constants::MAX_NWK_PAYLOAD_SIZE;
use crate::nwk::nlme::ScanDuration;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use core::num::NonZeroU8;
use embassy_time::Duration;
use zb_macros::try_write_impl;
use zb_types::common::DeviceType;
use zb_types::common::ExtendedAddress;
use zb_types::mac::{ChannelMask, MacCapabilities, MacCurrentSource, MacDeviceType};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZbCapabilities {
    pub device_type: MacDeviceType,
    pub current_source: MacCurrentSource,
    pub receiver_on_when_idle: bool,
    pub allocate_address: bool,
}

impl From<MacCapabilities> for ZbCapabilities {
    fn from(value: MacCapabilities) -> Self {
        Self {
            device_type: value.device_type,
            current_source: value.current_source,
            receiver_on_when_idle: value.rx_on_when_idle,
            allocate_address: value.allocate_address,
        }
    }
}

impl From<ZbCapabilities> for MacCapabilities {
    fn from(value: ZbCapabilities) -> Self {
        Self {
            alternate_pan_coordinator: false,
            device_type: value.device_type,
            current_source: value.current_source,
            rx_on_when_idle: value.receiver_on_when_idle,
            security: false,
            allocate_address: value.allocate_address,
        }
    }
}

impl TryRead<'_, Endian> for ZbCapabilities {
    fn try_read(bytes: &'_ [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let (value, size) = MacCapabilities::try_read(bytes, ctx)?;
        Ok((value.into(), size))
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &ZbCapabilities {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        MacCapabilities::from(*self).try_write(bytes, ctx)
    }
}

#[derive(bon::Builder, Copy, Clone, Debug)]
pub struct ZbConfig {
    #[builder(default = NonZeroU8::new(5).unwrap())]
    pub nwk_scan_attempts: NonZeroU8,
    #[builder(default = Duration::from_millis(100))]
    pub nwk_time_between_scans: Duration,
    pub user_descriptor: Option<UserDescriptor>,
    #[builder(default = ChannelMask::DEFAULT_PRIMARY_CHANNEL_SET)]
    pub primary_channel_set: ChannelMask,
    #[builder(default = ChannelMask::DEFAULT_SECONDARY_CHANNEL_SET)]
    pub secondary_channel_set: ChannelMask,
    #[builder(default = ScanDuration::new(0x03).unwrap())]
    pub scan_duration: ScanDuration,
    #[builder(default = false)]
    pub use_insecure_join: bool,
    pub use_extended_pan_id: Option<ExtendedAddress>,
    #[builder(default = false)]
    pub touchlink_supported: bool,

    pub device_type: DeviceType,
    pub manufacturer_code: u16,
    pub rx_on_when_idle: bool,
    #[builder(default)]
    pub frequency_bands: FrequencyBands,

    pub available_power_sources: AvailablePowerSources,
    #[builder(default)]
    pub current_power_mode: CurrentPowerMode
}

impl Default for ZbConfig {
    fn default() -> Self {
        Self::builder()
            .device_type(DeviceType::EndDevice)
            .rx_on_when_idle(true)
            .available_power_sources(AvailablePowerSources {
                mains_power: true,
                ..Default::default()
            })
            .manufacturer_code(0x1234)
            .build()
    }
}

impl ZbConfig {
    fn get_mac_device_type(&self) -> MacDeviceType {
        match self.device_type {
            DeviceType::Coordinator => MacDeviceType::FullFunctionDevice,
            DeviceType::Router => MacDeviceType::FullFunctionDevice,
            DeviceType::EndDevice => MacDeviceType::ReducedFunctionDevice,
        }
    }

    pub fn get_node_descriptor(&self) -> NodeDescriptor {
        NodeDescriptor {
            info: NodeDescriptorInfo {
                logical_type: self.device_type,
                complex_descriptor_available: false,
                user_descriptor_available: self.user_descriptor.is_some(),
            },
            frequency_bands: self.frequency_bands,
            mac_capabilities: MacCapabilities {
                alternate_pan_coordinator: false,
                device_type: self.get_mac_device_type(),
                current_source: MacCurrentSource::Mains,
                rx_on_when_idle: self.rx_on_when_idle,
                security: false,
                allocate_address: true,
            },
            manufacturer_code: self.manufacturer_code,
            maximum_buffer_size: MAX_NWK_PAYLOAD_SIZE as u8,
            maximum_incoming_transfer_size: MAX_APS_FRAME_SIZE as u16,
            server_mask: self.get_server_mask(),
            maximum_outgoing_transfer_size: MAX_APS_FRAME_SIZE as u16,
            descriptor_capabilities: DescriptorCapabilities {
                extended_active_endpoint_list_available: false,
                extended_simple_descriptor_list_available: false,
            },
        }
    }

    pub fn get_power_descriptor(&self) -> NodePowerDescriptor {
        NodePowerDescriptor {
            available_power_sources: self.available_power_sources,
            current_power_mode: self.current_power_mode,
            current_power_source: CurrentPowerSource::MainsPower,
            current_power_source_level: CurrentPowerSourceLevel::Full,
        }

        // TODO: make battery
    }

    pub fn is_end_device(&self) -> bool { self.device_type == DeviceType::EndDevice }

    pub fn is_router_or_coordinator(&self) -> bool {
        matches!(self.device_type, DeviceType::Router | DeviceType::Coordinator)
    }

    pub fn is_coordinator(&self) -> bool { self.device_type == DeviceType::Coordinator }

    pub fn get_capabilities(&self) -> ZbCapabilities {
        ZbCapabilities {
            device_type: self.get_mac_device_type(),
            current_source: MacCurrentSource::Mains,
            receiver_on_when_idle: self.rx_on_when_idle,
            allocate_address: true,
        }
    }

    pub fn get_server_mask(&self) -> ServerMask {
        ServerMask {
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DiscoveryType {
    #[default]
    IEEE,
    NWK,
}
