use crate::common::information_base::ParentInformation;
use crate::nwk::commands::Command;
use crate::nwk::ctx::{Initialized, Joined, JoinedDevice, Nwk};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::service::routing::ReceivedCommandFrame;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(Debug, Copy, Clone, TryRead, TryWrite)]
pub struct EndDeviceTimeoutResponse {
    pub status: EndDeviceTimeoutResponseStatus,
    pub parent_information: ParentInformation,
}

#[derive(Debug, Copy, Clone, TryRead, TryWrite)]
#[repr(u8)]
pub enum EndDeviceTimeoutResponseStatus {
    Success = 0,
    IncorrectValue = 1,
}

impl<T: JoinedDevice, D: NwkMac, S: StorageRegion>Nwk<Initialized<Joined<T>>, D, S> {
    pub async fn send_end_device_timeout_response_cmd(
        &mut self,
        end_device_short_addr: NwkAddress,
        end_device_extended_addr: ExtendedAddress,
        status: EndDeviceTimeoutResponseStatus,
    ) -> Result<(), NldeTransferError> {
        let hdr = NwkHeader::cmd(self)
            .destination(end_device_short_addr)
            .destination_ieee(end_device_extended_addr)
            .radius(1)
            .call();

        let cmd = Command::EndDeviceTimeoutResponse(EndDeviceTimeoutResponse {
            status,
            parent_information: ParentInformation {
                mac_data_poll_keepalive_supported: true,
                end_device_timeout_request_keepalive_supported: true,
                power_negotiation_supported: false,
            },
        });

        let cmd_frame = NwkFrame::new_cmd_frame(hdr, cmd);

        self.transmit_frame(&cmd_frame, end_device_short_addr, true).await
    }

    pub async fn handle_end_device_timeout_response_command(
        &mut self,
        frame: &ReceivedCommandFrame<'_, EndDeviceTimeoutResponse>,
    ) -> () {
        self.ctx.parent_information = frame.cmd.parent_information;
    }
}

