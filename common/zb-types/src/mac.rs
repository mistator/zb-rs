use byte::TryRead;
use crate::common::{ExtendedAddress, NwkAddress, PanId};
use byte_derive::{TryRead, TryWrite};
use ieee802154::mac;
use ieee802154::mac::command::CapabilityInformation;
use ieee802154::mac::FooterMode;
use zb_macros::BitStruct;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MacAddress {
    Short(PanId, NwkAddress),
    Extended(PanId, ExtendedAddress),
}

impl From<mac::Address> for MacAddress {
    fn from(value: mac::Address) -> Self {
        match value {
            mac::Address::Short(pan_id, short) => {
                MacAddress::Short(PanId(pan_id.0), NwkAddress(short.0))
            }
            mac::Address::Extended(pan_id, extended) => {
                MacAddress::Extended(PanId(pan_id.0), ExtendedAddress(extended.0))
            }
        }
    }
}

impl From<MacAddress> for mac::Address {
    fn from(value: MacAddress) -> Self {
        match value {
            MacAddress::Short(pan_id, short) => {
                mac::Address::Short(mac::PanId(pan_id.0), mac::ShortAddress(short.0))
            }
            MacAddress::Extended(pan_id, extended) => {
                mac::Address::Extended(mac::PanId(pan_id.0), mac::ExtendedAddress(extended.0))
            }
        }
    }
}

impl MacAddress {
    pub fn is_broadcast(&self) -> bool {
        match self {
            MacAddress::Short(_, addr) => addr.is_broadcast(),
            MacAddress::Extended(_, _) => false,
        }
    }
}

impl MacAddress {
    pub fn pan_id(&self) -> PanId {
        match *self {
            MacAddress::Short(pan_id, _) => pan_id,
            MacAddress::Extended(pan_id, _) => pan_id,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, TryRead, TryWrite)]
#[repr(u8)]
pub enum MacDeviceType {
    ReducedFunctionDevice = 0,
    FullFunctionDevice = 1,
}

impl Default for MacDeviceType {
    fn default() -> Self {
        MacDeviceType::ReducedFunctionDevice
    }
}

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy, TryRead, TryWrite)]
#[repr(u8)]
pub enum MacCurrentSource {
    Other = 0,
    #[default]
    Mains = 1,
}
#[derive(Clone, Copy, PartialEq)]
pub enum ChannelPage {
    ChannelPage0 = 0,
    ChannelPage1,
    ChannelPage2,
}

#[derive(Clone, Copy, Debug)]
pub enum Channel {
    Channel0 = 0,
    Channel1,
    Channel2,
    Channel3,
    Channel4,
    Channel5,
    Channel6,
    Channel7,
    Channel8,
    Channel9,
    Channel10,
    Channel11,
    Channel12,
    Channel13,
    Channel14,
    Channel15,
    Channel16,
    Channel17,
    Channel18,
    Channel19,
    Channel20,
    Channel21,
    Channel22,
    Channel23,
    Channel24,
    Channel25,
    Channel26,
}

impl From<u8> for Channel {
    fn from(value: u8) -> Self {
        match value {
            0 => Channel::Channel0,
            1 => Channel::Channel1,
            2 => Channel::Channel2,
            3 => Channel::Channel3,
            4 => Channel::Channel4,
            5 => Channel::Channel5,
            6 => Channel::Channel6,
            7 => Channel::Channel7,
            8 => Channel::Channel8,
            9 => Channel::Channel9,
            10 => Channel::Channel10,
            11 => Channel::Channel11,
            12 => Channel::Channel12,
            13 => Channel::Channel13,
            14 => Channel::Channel14,
            15 => Channel::Channel15,
            16 => Channel::Channel16,
            17 => Channel::Channel17,
            18 => Channel::Channel18,
            19 => Channel::Channel19,
            20 => Channel::Channel20,
            21 => Channel::Channel21,
            22 => Channel::Channel22,
            23 => Channel::Channel23,
            24 => Channel::Channel24,
            25 => Channel::Channel25,
            26 => Channel::Channel26,
            _ => { panic!("invalid channel received") }
        }
    }
}

impl Channel {
    pub const ALL: [Channel; 27] = [
        Channel::Channel0,
        Channel::Channel1,
        Channel::Channel2,
        Channel::Channel3,
        Channel::Channel4,
        Channel::Channel5,
        Channel::Channel6,
        Channel::Channel7,
        Channel::Channel8,
        Channel::Channel9,
        Channel::Channel10,
        Channel::Channel11,
        Channel::Channel12,
        Channel::Channel13,
        Channel::Channel14,
        Channel::Channel15,
        Channel::Channel16,
        Channel::Channel17,
        Channel::Channel18,
        Channel::Channel19,
        Channel::Channel20,
        Channel::Channel21,
        Channel::Channel22,
        Channel::Channel23,
        Channel::Channel24,
        Channel::Channel25,
        Channel::Channel26,
    ];

    pub fn as_channel_mask(&self) -> ChannelMask {
        ChannelMask::new(ChannelPage::ChannelPage0, &[*self])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, TryRead, TryWrite)]
pub struct ChannelMask(pub u32);

impl ChannelMask {
    pub const ZERO: ChannelMask = ChannelMask(0);

    pub const DEFAULT_PRIMARY_CHANNEL_SET: ChannelMask = ChannelMask(0x02108800);
    pub const DEFAULT_SECONDARY_CHANNEL_SET: ChannelMask = ChannelMask(0x07fff800 ^ 0x2108800);

    pub fn new(page: ChannelPage, channels: &[Channel]) -> ChannelMask {
        let mut mask = (page as u32) << 27;
        for channel in channels {
            let idx = *channel as u8;
            mask |= 1 << idx;
        }

        ChannelMask(mask)
    }

    pub fn get_page(&self) -> ChannelPage {
        let page = (self.0 & 0b11111000_00000000_00000000_00000000) >> 27;

        match page {
            0 => ChannelPage::ChannelPage0,
            1 => ChannelPage::ChannelPage1,
            2 => ChannelPage::ChannelPage2,
            _ => unreachable!(),
        }
    }

    pub fn channel_is_set(&self, channel: Channel) -> bool {
        let channel_n = channel as u8;
        (self.0 & (1u32 << channel_n)) != 0
    }

    pub fn intersect_with(&self, other: ChannelMask) -> ChannelMask {
        if self.get_page() != other.get_page() {
            return ChannelMask::ZERO;
        }

        ChannelMask(self.0 & other.0)
    }
}

impl Default for ChannelMask {
    fn default() -> Self {
        ChannelMask::new(
            ChannelPage::ChannelPage0,
            &[
                Channel::Channel11,
                Channel::Channel12,
                Channel::Channel13,
                Channel::Channel14,
                Channel::Channel15,
                Channel::Channel16,
                Channel::Channel17,
                Channel::Channel18,
                Channel::Channel19,
                Channel::Channel20,
                Channel::Channel21,
                Channel::Channel22,
                Channel::Channel23,
                Channel::Channel24,
                Channel::Channel25,
                Channel::Channel26,
            ],
        )
    }
}

pub const A_MAX_MPDU_UNSECURED_OVERHEAD: usize = 25;
pub const A_MAX_PHY_PACKET_SIZE: usize = 127;
pub const A_MAX_MAC_SAFE_PAYLOAD_SIZE: usize =
    A_MAX_PHY_PACKET_SIZE - A_MAX_MPDU_UNSECURED_OVERHEAD;
pub const A_MAX_MAC_PAYLOAD_SIZE: usize = A_MAX_PHY_PACKET_SIZE - A_MIN_MPDU_OVERHEAD;
pub const A_MIN_MPDU_OVERHEAD: usize = 11;

#[derive(Clone, Debug)]
pub struct MacFrame {
    pub header: mac::Header,
    pub content: mac::FrameContent,

    pub payload: crate::Vec<u8, A_MAX_MAC_PAYLOAD_SIZE>,

    pub footer: [u8; 2],
}

impl TryRead<'_> for MacFrame {
    fn try_read(bytes: &'_ [u8], _: ()) -> byte::Result<(Self, usize)> {
        let (frame, size) = mac::frame::Frame::try_read(bytes, FooterMode::Explicit)?;
        Ok((Self {
            header: frame.header,
            content: frame.content,
            payload: crate::Vec::<u8, A_MAX_MAC_PAYLOAD_SIZE>::from_slice(frame.payload)
                .map_err(|_| byte::Error::BadInput {err: "frame too long"})?,
            footer: frame.footer
        }, size))
    }
}

#[derive(BitStruct, Copy, Clone, Eq, PartialEq, Debug)]
#[bit_struct(repr = u8)]
pub struct MacCapabilities {
    pub alternate_pan_coordinator: bool,
    pub device_type: MacDeviceType,
    pub current_source: MacCurrentSource,
    pub rx_on_when_idle: bool,
    #[bit_struct(skip = 2)]
    pub security: bool,
    pub allocate_address: bool,
}

impl Default for MacCapabilities {
    fn default() -> Self {
        Self {
            alternate_pan_coordinator: false,
            device_type: MacDeviceType::ReducedFunctionDevice,
            current_source: MacCurrentSource::Mains,
            rx_on_when_idle: true,
            security: true,
            allocate_address: true,
        }
    }
}

impl MacCapabilities {
    pub fn is_reduced_function_device(&self) -> bool {
        self.device_type == MacDeviceType::ReducedFunctionDevice
    }

    pub fn is_full_function_device(&self) -> bool {
        self.device_type == MacDeviceType::FullFunctionDevice
    }
}

impl From<MacCapabilities> for CapabilityInformation {
    fn from(value: MacCapabilities) -> Self {
        CapabilityInformation::from(value.get_value())
    }
}