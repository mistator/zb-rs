use crate::apl::aps::apsde::ApsdeDataIndication;
use crate::apl::aps::security::types::indications::ApsmeConfirmKeyIndication;
use crate::apl::aps::security::types::indications::ApsmeTransportKeyIndication;
use crate::apl::aps::security::types::indications::ApsmeUpdateDeviceIndication;
use bounded_integer::BoundedU8;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};
use zb_macros::try_write_impl;
use zb_types::common::NwkAddress;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SrcAddrMode {
    Reserved = 0x00,
    #[default]
    Short,
    Extended = 0x02,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApsAddress {
    Group(NwkAddress) = 0x01,
    Network(NwkAddress, ApsEndpoint) = 0x02,
}

impl Default for ApsAddress {
    fn default() -> Self { ApsAddress::Group(NwkAddress::default()) }
}

impl ApsAddress {
    pub fn get_nwk_address(&self) -> NwkAddress {
        match self {
            ApsAddress::Group(addr) => *addr,
            ApsAddress::Network(addr, _) => *addr,
        }
    }

    pub fn is_unicast(&self) -> bool { !self.is_broadcast() }

    pub fn is_broadcast(&self) -> bool {
        match self {
            ApsAddress::Group(addr) => addr.is_broadcast(),
            ApsAddress::Network(addr, _) => addr.is_broadcast(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxOptions {
    pub security_enabled: bool,
    pub use_network_key: bool,
    pub acknowledged: bool,
    pub fragmentation_permitted: bool,
    pub include_extended_nonce: bool,
}

impl TxOptions {
    pub const SECURE_CMD: TxOptions = TxOptions {
        security_enabled: true,
        use_network_key: false,
        acknowledged: false,
        fragmentation_permitted: false,
        include_extended_nonce: true,
    };
}

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ApsEndpoint(BoundedU8<0, 254>);

impl ApsEndpoint {
    pub const fn new(value: u8) -> Option<Self> {
        match BoundedU8::<0, 254>::new(value) {
            None => None,
            Some(value) => Some(Self(value))
        }
    }

    pub fn get(&self) -> u8 {
        self.0.get()
    }
}

impl<'a> TryRead<'a, Endian> for ApsEndpoint {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let (value, size) = u8::try_read(bytes, ctx)?;
        let slf = Self::new(value).ok_or_else(|| {
            log::warn!("invalid endpoint received for ApsSrcEndpoint: {:?}", value);
            byte::Error::BadInput {
                err: "invalid endpoint received for ApsSrcEndpoint",
            }
        })?;

        Ok((slf, size))
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &ApsEndpoint {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write_with(offset, self.0.get(), ctx)?;
        Ok(*offset)
    }
}

#[derive(Clone, Debug)]
pub enum ApsIndication {
    Data(ApsdeDataIndication),
    TransportKey(ApsmeTransportKeyIndication),
    UpdateDevice(ApsmeUpdateDeviceIndication),
    ConfirmKey(ApsmeConfirmKeyIndication),
}
