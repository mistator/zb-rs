use aes::Aes128;
use ccm::Ccm;
use ccm::consts::U13;
use ctr::Ctr64BE;
use thiserror::Error;

use zb_types::common::{ExtendedAddress, Key};

pub mod frame;
pub mod primitives;

pub const TRUST_CENTER_LINK_KEY: Key = [
    0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39,
];

// AES-128 CCM with MIC32
pub type Aes128Ccm<N> = Ccm<Aes128, N, U13>;
pub type Aes128Ctr = Ctr64BE<Aes128>;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum SecurityError {
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid data")]
    InvalidData,
    #[error("parse error")]
    ParseError(byte::Error),
    #[error("ccm error")]
    CcmError(ccm::Error),
    #[error("key not found")]
    KeyNotFound,
    #[error("frame security failed")]
    Unspecified,
}

impl From<byte::Error> for SecurityError {
    fn from(value: byte::Error) -> Self { Self::ParseError(value) }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum SecurityNetworkParams {
    Centralized(ExtendedAddress),
    #[default]
    Distributed,
}

