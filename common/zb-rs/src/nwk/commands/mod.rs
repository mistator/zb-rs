pub mod end_device_timeout_request;
pub mod end_device_timeout_response;
pub mod leave;
pub mod link_power_delta;
pub mod link_status;
pub mod network_report;
pub mod network_status;
pub mod network_update;
pub mod rejoin_request;
pub mod rejoin_response;
pub mod route_reply;
pub mod route_request;

use crate::apl::zdo::config::ZbCapabilities;
use crate::nwk::commands::end_device_timeout_request::EndDeviceTimeoutRequest;
use crate::nwk::commands::end_device_timeout_response::EndDeviceTimeoutResponse;
use crate::nwk::commands::leave::Leave;
use crate::nwk::commands::link_power_delta::LinkPowerDelta;
use crate::nwk::commands::link_status::LinkStatusCmd;
use crate::nwk::commands::network_report::NetworkReport;
use crate::nwk::commands::network_status::NetworkStatus;
use crate::nwk::commands::network_update::NetworkUpdate;
use crate::nwk::commands::rejoin_response::RejoinResponse;
use crate::nwk::commands::route_reply::RouteReply;
use crate::nwk::commands::route_request::RouteRequest;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_types::common::NwkAddress;

#[derive(Debug, Clone, TryRead, TryWrite)]
#[repr(u8)]
#[byte(ctx = ())]
pub enum Command {
    RouteRequest(#[byte(ctx = byte::LE)] RouteRequest) = 0x01,
    RouteReply(#[byte(ctx = byte::LE)] RouteReply) = 0x02,
    NetworkStatus(#[byte(ctx = byte::LE)] NetworkStatus) = 0x03,
    Leave(#[byte(ctx = byte::LE)] Leave) = 0x04,
    RouteRecord(#[byte(len = u8, ctx = byte::LE)] zb_types::Vec<NwkAddress, 32>) = 0x05,
    RejoinRequest(#[byte(ctx = byte::LE)] ZbCapabilities) = 0x06,
    RejoinResponse(#[byte(ctx = byte::LE)] RejoinResponse) = 0x07,
    LinkStatus(#[byte(ctx = byte::LE)] LinkStatusCmd) = 0x08,
    NetworkReport(#[byte(ctx = byte::LE)] NetworkReport) = 0x09,
    NetworkUpdate(#[byte(ctx = byte::LE)] NetworkUpdate) = 0x0a,
    EndDeviceTimeoutRequest(#[byte(ctx = byte::LE)] EndDeviceTimeoutRequest) = 0x0b,
    EndDeviceTimeoutResponse(#[byte(ctx = byte::LE)] EndDeviceTimeoutResponse) = 0x0c,
    LinkPowerDelta(#[byte(ctx = byte::LE)] LinkPowerDelta) = 0x0d,
}
