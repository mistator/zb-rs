use crate::common::information_base::ParentInformation;
use crate::nwk::commands::Command;
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::service::routing::ReceivedCommandFrame;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::ctx::{InitializedNwk, JoinedAsEndDevice, JoinedState, Nwk, RoutingState};

#[derive(Debug, Copy, Clone, TryRead, TryWrite)]
pub struct EndDeviceTimeoutResponse {
    pub status: EndDeviceTimeoutResponseStatus,
    pub parent_information: ParentInformation,
}

#[derive(Debug, Copy, Clone, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum EndDeviceTimeoutResponseStatus {
    Success = 0,
    IncorrectValue = 1,
}

impl<T: JoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    fn make_end_device_timeout_response_cmd(
        &mut self,
        short_addr: NwkAddress,
        ext_addr: ExtendedAddress,
        status: EndDeviceTimeoutResponseStatus
    ) -> NwkFrame {
        let hdr = NwkHeader::cmd(self)
            .destination(short_addr)
            .destination_ieee(ext_addr)
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

        NwkFrame::new_cmd_frame(hdr, cmd)
    }
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub async fn send_end_device_timeout_response_cmd(
        &mut self,
        end_device_short_addr: NwkAddress,
        end_device_extended_addr: ExtendedAddress,
        status: EndDeviceTimeoutResponseStatus,
    ) -> Result<(), NldeTransferError> {
        let cmd_frame = self.make_end_device_timeout_response_cmd(end_device_short_addr, end_device_extended_addr, status);
        self.transmit_frame(&cmd_frame, end_device_short_addr, true).await
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsEndDevice, D, S> {
    pub async fn handle_end_device_timeout_response_command(
        &mut self,
        frame: &ReceivedCommandFrame<'_, EndDeviceTimeoutResponse>,
    ) -> () {
        self.get_ctx_mut().parent_information = frame.cmd.parent_information;
    }
}

#[cfg(test)]
mod tests {
    use crate::nwk::commands::end_device_timeout_response::ParentInformation;
    use embassy_time::{Duration, WithTimeout};
    use zb_hal_test_mock::driver::{DEFAULT_EXT_ADDR, DEFAULT_NWK_ADDR};
    use crate::nwk::commands::end_device_timeout_response::EndDeviceTimeoutResponseStatus;
    use crate::nwk::ctx::{InitializedNwk, Nwk, NwkListen};

    #[futures_test::test]
    async fn end_device_updates_parent_information_on_successful_end_device_timeout_response_cmd() {
        let mut nwk = Nwk::end_device().call();

        let frame = nwk.make_end_device_timeout_response_cmd(
            DEFAULT_NWK_ADDR,
            DEFAULT_EXT_ADDR,
            EndDeviceTimeoutResponseStatus::Success,
        );
        nwk.add_received_frame(&frame);

        nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();

        assert_eq!(nwk.get_ctx().parent_information, ParentInformation {
            mac_data_poll_keepalive_supported: true,
            end_device_timeout_request_keepalive_supported: true,
            power_negotiation_supported: false,
        })
    }
}