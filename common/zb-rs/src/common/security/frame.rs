use crate::common::security::SecurityError;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_macros::BitStruct;
use zb_types::common::ExtendedAddress;

#[derive(Debug, Clone, Copy, TryRead, TryWrite)]
pub struct AuxFrameHeader {
    pub security_control: SecurityControl,
    pub frame_counter: u32,
    #[byte(parse_if = security_control.extended_nonce)]
    pub source_address: Option<ExtendedAddress>,
    #[byte(parse_if = security_control.key_identifier == KeyIdentifier::Network)]
    pub key_sequence_number: Option<u8>,
}

impl AuxFrameHeader {
    pub fn create_nonce(&self) -> Result<[u8; 13], SecurityError> {
        let AuxFrameHeader {
            security_control,
            frame_counter,
            source_address: Some(ExtendedAddress(source_address)),
            ..
        } = self
        else {
            log::warn!("[CREATE-NONCE] error creating nonce, aux header does not contain source address");
            return Err(SecurityError::InvalidData);
        };

        let mut nonce = [0u8; 13];
        for i in 0..8 {
            nonce[i] = (source_address >> (8 * i) & 0xff) as u8;
        }

        for i in 0..4 {
            nonce[i + 8] = (frame_counter >> (8 * i) & 0xff) as u8;
        }
        nonce[12] = security_control.get_value();
        Ok(nonce)
    }
}

#[derive(BitStruct, Clone, Copy, Debug)]
#[bit_struct(repr = u8)]
pub struct SecurityControl {
    #[bit_struct(len = 3)]
    pub security_level: SecurityLevel,
    #[bit_struct(len = 2)]
    pub key_identifier: KeyIdentifier,
    pub extended_nonce: bool
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum SecurityLevel {
    None = 0b000,
    Mic32 = 0b001,
    Mic64 = 0b010,
    Mic128 = 0b011,
    Enc = 0b100,
    #[default]
    EncMic32 = 0b101,
    EncMic64 = 0b110,
    EncMic128 = 0b111,
}

impl SecurityLevel {
    pub fn is_secured(&self) -> bool { self != &SecurityLevel::None }

    pub fn mic_length(&self) -> usize {
        match self {
            Self::EncMic32 | Self::Mic32 => 4,
            Self::EncMic64 | Self::Mic64 => 8,
            Self::EncMic128 | Self::Mic128 => 16,
            Self::None | Self::Enc => 0,
        }
    }

    pub fn from_bits(bits: u8) -> Self {
        match bits {
            0b000 => Self::None,
            0b001 => Self::Mic32,
            0b010 => Self::Mic64,
            0b011 => Self::Mic128,
            0b100 => Self::Enc,
            0b101 => Self::EncMic32,
            0b110 => Self::EncMic64,
            0b111 => Self::EncMic128,
            _ => unreachable!(),
        }
    }

    pub fn as_bits(&self) -> u8 {
        match self {
            Self::None => 0b000,
            Self::Mic32 => 0b001,
            Self::Mic64 => 0b010,
            Self::Mic128 => 0b011,
            Self::Enc => 0b100,
            Self::EncMic32 => 0b101,
            Self::EncMic64 => 0b110,
            Self::EncMic128 => 0b111,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum KeyIdentifier {
    Data = 0b00,
    Network = 0b01,
    KeyTransport = 0b10,
    KeyLoad = 0b11,
}
