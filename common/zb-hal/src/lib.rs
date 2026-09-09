#![cfg_attr(not(test), no_std)]

use core::fmt::Debug;
use thiserror::Error;
use zb_types::common::{ExtendedAddress, NwkAddress, PanId};
use zb_types::mac::{Channel, ChannelMask, MacFrame};

#[trait_variant::make(Ieee802154Driver: Send)]
pub trait LocalIeee802154Driver {
    fn get_extended_address(&self) -> ExtendedAddress;
    fn get_channel_mask(&self) -> ChannelMask;
    fn is_rx_on_when_idle(&self) -> bool;

    fn get_pan_id(&self) -> Option<PanId>;
    async fn set_pan_id(&mut self, pan_id: Option<PanId>) -> ();
    fn get_short_address(&self) -> Option<NwkAddress>;
    async fn set_short_address(&mut self, short_addr: Option<NwkAddress>) -> ();

    async fn set_channel(&mut self, channel: Channel) -> ();

    async fn transmit(&mut self, frame: &[u8]) -> Result<(), byte::Error>;

    async fn flush(&mut self) -> ();
    async fn poll(&mut self) -> Option<MacFrame>;
    async fn wait_frame(&mut self) -> MacFrame;

    async fn reset(&mut self, set_default_pib: bool) -> ();
}

pub trait NwkMac: Ieee802154Driver + Clone + Debug {}

#[derive(Clone, Copy, Debug, Error)]
pub enum StorageError {
    #[error("nvs error")]
    NvsError,
    #[error("byte error, {}", 0)]
    ByteError(byte::Error),
}

impl From<byte::Error> for StorageError {
    fn from(e: byte::Error) -> Self {
        StorageError::ByteError(e)
    }
}

pub trait StoragePool {
    type S: StorageRegion;
    
    fn reserve_region(&mut self, size: u32) -> Result<Self::S, ()>;
}

#[trait_variant::make(StorageRegion: Send)]
pub trait LocalStorageRegion : Clone {
    async fn persist_with_offset(&mut self, offset: u32, buffer: &[u8]) -> Result<(), StorageError>;
    async fn load_with_offset(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), StorageError>;

    fn persist(&mut self, buffer: &[u8]) -> impl Future<Output=Result<(), StorageError>> {
        self.persist_with_offset(0, buffer)
    }

    fn load(&mut self, buffer: &mut [u8]) -> impl Future<Output=Result<(), StorageError>> {
        self.load_with_offset(0, buffer)
    }

    async fn clear(&mut self) -> Result<(), StorageError>;
}
