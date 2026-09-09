use core::time::Duration;

pub const MAX_SAME_NETWORK_RETRY_ATTEMPTS: u8 = 10;
pub const MIN_COMMISSIONING_TIME: Duration = Duration::from_secs(180);
pub const REC_SAME_NETWORK_RETRY_ATTEMPTS: u8 = 3;
pub const TC_LINK_KEY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

// TOUCHLINK
pub const TL_INTERPAN_TRANSFER_ID_LIFETIME: Duration = Duration::from_secs(8);
pub const TL_MIN_STARTUP_DELAY_TIME: Duration = Duration::from_secs(2);
pub const TL_PRIMARY_CHANNEL_SET: u32 = 0x02108800;
pub const TL_RX_WINDOW_DURATION: Duration = Duration::from_secs(5);
pub const TL_SCAN_TIME_BASE_DURATION: Duration = Duration::from_millis(250);
pub const TL_SECONDARY_CHANNEL_SET: u32 = 0x07fff800 ^ TL_PRIMARY_CHANNEL_SET;
