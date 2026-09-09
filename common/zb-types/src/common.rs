use core::fmt;

use crate::mac::MacDeviceType;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use ieee802154::mac;

pub type Key = [u8; 16];

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryRead, TryWrite)]
#[repr(u8)]
pub enum DeviceType {
    Coordinator = 0x00,
    Router = 0x01,
    EndDevice = 0x02,
}

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::EndDevice
    }
}

impl From<MacDeviceType> for DeviceType {
    fn from(value: MacDeviceType) -> Self {
        match value {
            MacDeviceType::ReducedFunctionDevice => Self::EndDevice,
            MacDeviceType::FullFunctionDevice => Self::Router,
        }
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, TryRead, TryWrite)]
pub struct PanId(pub u16);

impl From<u16> for PanId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<mac::PanId> for PanId {
    fn from(value: mac::PanId) -> Self {
        Self(value.0)
    }
}

impl From<PanId> for mac::PanId {
    fn from(value: PanId) -> Self {
        mac::PanId(value.0)
    }
}

impl fmt::Debug for PanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IeeePanId(0x{:04x})", self.0)
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, TryRead, TryWrite, PartialOrd, Ord)]
pub struct NwkAddress(pub u16);

impl From<u16> for NwkAddress {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<mac::ShortAddress> for NwkAddress {
    fn from(value: mac::ShortAddress) -> Self {
        Self(value.0)
    }
}

impl From<NwkAddress> for mac::ShortAddress {
    fn from(value: NwkAddress) -> Self {
        mac::ShortAddress(value.0)
    }
}

impl fmt::Debug for NwkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShortAddress(0x{:04x})", self.0)
    }
}

impl Default for NwkAddress {
    fn default() -> Self {
        Self(0xffff)
    }
}

impl NwkAddress {
    pub const BROADCAST_ALL: Self = Self(0xffff);
    pub const BROADCAST_LOW_POWER: Self = Self(0xfffb);
    pub const BROADCAST_ROUTERS: Self = Self(0xffc);
    pub const BROADCAST_RX_ON_IDLE: Self = Self(0xfffd);
    pub const MAX: Self = Self(0xffff);
    pub const MAX_NON_BROADCAST: Self = Self(0xfff6);
    pub const ZERO: Self = Self(0x0000);

    pub fn is_broadcast(&self) -> bool {
        self.0 > 0xfff7
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast()
    }

    pub fn get_value(&self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, TryRead, TryWrite)]
pub struct ExtendedAddress(pub u64);

impl From<u64> for ExtendedAddress {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<mac::ExtendedAddress> for ExtendedAddress {
    fn from(value: mac::ExtendedAddress) -> Self {
        Self(value.0)
    }
}

impl From<ExtendedAddress> for mac::ExtendedAddress {
    fn from(value: ExtendedAddress) -> Self {
        mac::ExtendedAddress(value.0)
    }
}

impl fmt::Debug for ExtendedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IeeeAddress(0x{:016x})", self.0)
    }
}

impl Default for ExtendedAddress {
    fn default() -> Self {
        Self::MAX
    }
}

impl ExtendedAddress {
    pub const MAX: ExtendedAddress = ExtendedAddress(0xffffffff);
    pub const ZERO: ExtendedAddress = ExtendedAddress(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn get_value(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceAddress {
    Short(Option<NwkAddress>),
    Extended(ExtendedAddress),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Address {
    Short(NwkAddress),
    Extended(ExtendedAddress),
}

impl From<NwkAddress> for Address {
    fn from(value: NwkAddress) -> Self {
        Self::Short(value)
    }
}

impl From<ExtendedAddress> for Address {
    fn from(value: ExtendedAddress) -> Self {
        Self::Extended(value)
    }
}
