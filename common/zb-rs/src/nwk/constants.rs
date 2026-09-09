use embassy_time::Duration;

use crate::common::security::frame::SecurityLevel;
use crate::common::utils::from_octets;
use crate::nwk::ctx::DeviceTimeout;
use zb_types::common::NwkAddress;
use zb_types::mac::A_MAX_MAC_PAYLOAD_SIZE;

pub const NWK_COORDINATOR_ADDRESS: NwkAddress = NwkAddress::ZERO;
pub const DEFAULT_SECURITY_LEVEL: SecurityLevel = SecurityLevel::EncMic32;
pub const MIN_HEADER_OVERHEAD: usize = 8;
pub const PROTOCOL_VERSION: u8 = 0x2;
pub const WAIT_BEFORE_VALIDATION: Duration = Duration::from_millis(0x500);
pub const ROUTE_DISCOVERY_TIME: Duration = Duration::from_millis(0x2710);
pub const MAX_BROADCAST_JITTER_OCTETS: u64 = 0x7d0;
pub const MAX_BROADCAST_JITTER: Duration = from_octets(MAX_BROADCAST_JITTER_OCTETS);
pub const INITIAL_ROUTE_REQUEST_RETRIES: u8 = 3;
pub const ROUTE_REQUEST_RETRIES: u8 = 2;
pub const ROUTE_REQUEST_RETRY_INTERVAL: Duration = Duration::from_millis(0xfe);
pub const MIN_ROUTE_REQUEST_JITTER: Duration = Duration::from_millis(2);
pub const MAX_ROUTE_REQUEST_JITTER: Duration = Duration::from_millis(128);
pub const MAC_FRAME_OVERHEAD: u8 = 0x0b;

pub const MAX_NWK_PAYLOAD_SIZE: usize = A_MAX_MAC_PAYLOAD_SIZE - MIN_HEADER_OVERHEAD;

// Actually NIB attributes, but not changed during execution
pub const NWK_MAX_SOURCE_ROUTE: u8 = 0x0c;
pub const NWK_USE_MULTICAST: bool = true;
pub const NWK_LINK_STATUS_PERIOD: u8 = 0x0f;
pub const NWK_ROUTER_AGE_LIMIT: u8 = 3;
pub const NWK_LEAVE_REQUEST_ALLOWED: bool = true;
pub const NWK_END_DEVICE_TIMEOUT_DEFAULT: DeviceTimeout = DeviceTimeout::Mins256;
pub const NWK_LEAVE_REQUEST_WITHOUT_REJOIN_ALLOWED: bool = true;
