use byte_derive::TryRead;
use byte_derive::TryWrite;

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct NetworkUpdate {
    pub update_id: u8,
    pub channel: u8,
    pub pan_id: u16,
    pub network_address: u16,
}
