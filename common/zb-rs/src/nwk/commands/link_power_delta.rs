use byte_derive::TryRead;
use byte_derive::TryWrite;

use zb_types::common::NwkAddress;

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct LinkPowerDelta {
    pub command_options: CommandOptions,
    #[byte(len = u8)]
    pub power_list: zb_types::Vec<DeltaEntry, 32>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum CommandOptions {
    Notification = 0x00,
    Request = 0x01,
    Response = 0x02,
}

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct DeltaEntry {
    pub device_address: NwkAddress,
    pub delta: u8,
}
