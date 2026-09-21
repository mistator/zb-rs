use crate::nwk::commands::Command;
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::NldeTransferError;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::ctx::{JoinedState, Nwk};


#[derive(Debug, Clone, Copy, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum NetworkStatus {
    NoRouteAvailable(NwkAddress) = 0x00,
    TreeLinkFailure(NwkAddress) = 0x01,
    NonTreeLinkFailure(NwkAddress) = 0x02,
    LowBatteryLevel = 0x03,
    NoRoutingCapacity = 0x04,
    NoIndirectCapacity = 0x05,
    IndirectTransactionExpiry = 0x06,
    TargetDeviceUnavailable = 0x07,
    TargetAddressUnallocated = 0x08,
    ParentLinkFailure = 0x09,
    ValidateRoute = 0x0a,
    SourceRouteFailure(NwkAddress) = 0x0b,
    ManyToOneRouteFailure(NwkAddress) = 0x0c,
    AddressConflict(NwkAddress) = 0x0d,
    VerifyAddresses = 0x0e,
    PanIdentifierUpdate = 0x0f,
    NetworkAddressUpdate(NwkAddress) = 0x10,
    BadFrameCounter = 0x11,
    BadKeySequenceNumber = 0x12,
    UnknownCommand = 0x13,
}

pub struct NetworkStatusCmd {
    pub dest_short_addr: NwkAddress,
    pub dest_extended_addr: Option<ExtendedAddress>,
    pub status: NetworkStatus,
}

impl<T: JoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub async fn send_network_status_cmd(
        &mut self,
        config: NetworkStatusCmd,
    ) -> Result<(), NldeTransferError> {
        let hdr = NwkHeader::cmd(self)
            .destination(config.dest_short_addr)
            .maybe_destination_ieee(config.dest_extended_addr)
            .call();

        let cmd = Command::NetworkStatus(config.status);

        let frame = NwkFrame::new_cmd_frame(hdr, cmd);

        self.transmit_frame(&frame, config.dest_short_addr, !config.dest_short_addr.is_broadcast()).await
    }
}

