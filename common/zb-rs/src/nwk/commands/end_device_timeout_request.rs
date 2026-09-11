use core::ops::Add;

use crate::nwk::commands::Command;
use crate::nwk::commands::end_device_timeout_response::EndDeviceTimeoutResponseStatus;
use crate::nwk::ctx::{EndDevice, Initialized, Joined, JoinedDevice, Nwk, Router};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::TransferResult;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::unwrap_or_return;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::{Duration, Instant};
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::{DeviceType, ExtendedAddress, NwkAddress};

#[derive(TryRead, TryWrite, Clone, Copy, Debug, Default, PartialEq)]
#[repr(u8)]
pub enum DeviceTimeout {
    #[default]
    Secs10 = 0,
    Mins2 = 1,
    Mins4 = 2,
    Mins8 = 3,
    Mins16 = 4,
    Mins32 = 5,
    Mins64 = 6,
    Mins128 = 7,
    Mins256 = 8,
    Mins512 = 9,
    Mins1024 = 10,
    Mins2048 = 11,
    Mins4096 = 12,
    Mins8192 = 13,
    Mins16384 = 14,
}

impl DeviceTimeout {
    pub fn get_duration(&self) -> Duration {
        let value = *self as u8;
        match value {
            0 => Duration::from_secs(10),
            _ => Duration::from_secs(2u64.pow(value as u32) * 60),
        }
    }
}

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct EndDeviceTimeoutRequest {
    pub requested_timeout: DeviceTimeout,
    pub end_device_configuration: u16,
}

impl<D: NwkMac, S: StorageRegion, T: JoinedDevice>Nwk<Initialized<Joined<T>>, D, S> {
    fn build_end_device_timeout_request_cmd_frame(
        &mut self,
        nwk_addr: NwkAddress,
        ext_addr: Option<ExtendedAddress>,
        requested_timeout: DeviceTimeout,
    ) -> NwkFrame {
        let hdr = NwkHeader::cmd(self)
            .destination(nwk_addr)
            .maybe_destination_ieee(ext_addr)
            .radius(1)
            .call();

        let cmd = Command::EndDeviceTimeoutRequest(EndDeviceTimeoutRequest {
            requested_timeout,
            // 3.4.11.3.2 End Device Configuration Field
            // This is a bitmask indicating the end device’s requested configuration. At this time there are no enumerated bits in
            // the configuration field. Devices adhering to this standard shall set the field to 0.
            end_device_configuration: 0,
        });

        NwkFrame::new_cmd_frame(hdr, cmd)
    }
}

// 3.4.11
// The End Device Timeout Request command is sent by an end device informing its parent of its timeout requirements.
// This allows the parent the ability to delete the child entry from the neighbor table if the child has not communicated
// with the parent in the specified amount of time.
impl<D: NwkMac, S: StorageRegion>Nwk<Initialized<Joined<EndDevice>>, D, S> {
    pub async fn send_end_device_timeout_request_cmd(&mut self, requested_timeout: DeviceTimeout) -> TransferResult {
        let nwk_addr = self.ctx.parent.nwk_addr;
        let ext_addr = self.ctx.parent.ext_addr;
        let dst_address = self.ctx.parent.nwk_addr;

        let frame = self.build_end_device_timeout_request_cmd_frame(
            nwk_addr, ext_addr, requested_timeout,
        );

        self.transmit_frame(&frame, dst_address, true).await
    }
}

// 3.4.12
// The End Device Timeout Response is sent by a router parent informing the end device whether it has accepted the
// timeout value that it was previously sent, and what its capabilities are.
impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    pub async fn handle_end_device_timeout_request_command(
        &mut self,
        frame: &ReceivedCommandFrame<'_, EndDeviceTimeoutRequest>,
    ) -> TransferResult {
        let cmd = &frame.cmd;
        let ext_addr = unwrap_or_return!(frame.header.source_ieee, Ok(()));

        // 3.4.11.3.2
        // Devices that receive the End Device Timeout Request message with an End Device
        // Configuration field set to anything other than 0 shall reject the message. The receiving device shall send an End
        // Device Timeout Response command with a status of 0x01 (INCORRECT_VALUE).
        if cmd.end_device_configuration != 0 {
            return self.send_end_device_timeout_response_cmd(
                frame.mac_src_addr,
                ext_addr,
                EndDeviceTimeoutResponseStatus::IncorrectValue,
            )
                .await;
        }

        let neighbor = unwrap_or_return!(
            self.get_router_ctx_mut().children
                .iter_mut()
                .find(|nb| nb.nwk_addr == frame.mac_src_addr
                    && nb.device_type == DeviceType::EndDevice),
            Ok(())
        );

        let duration = cmd.requested_timeout.get_duration();
        neighbor.expiration = Instant::now().add(duration);
        neighbor.device_timeout = cmd.requested_timeout;
        neighbor.end_device_configuration = cmd.end_device_configuration;

        self.send_end_device_timeout_response_cmd(
            frame.mac_src_addr,
            ext_addr,
            EndDeviceTimeoutResponseStatus::Success,
        )
            .await
    }
}

#[cfg(test)]
mod tests {
    use embassy_time::{Duration, Instant, WithTimeout};
    use zb_hal_test_mock::driver::{DEFAULT_EXT_ADDR, DEFAULT_NWK_ADDR};
    use zb_types::common::{ExtendedAddress, NwkAddress};
    use crate::nwk::commands::Command;
    use crate::nwk::commands::end_device_timeout_request::DeviceTimeout;
    use crate::nwk::commands::end_device_timeout_response::EndDeviceTimeoutResponseStatus;
    use crate::nwk::ctx::{LocalNwkListen, Nwk};
    use crate::nwk::ctx::tests::{DEFAULT_CHILD_EXT_ADDR, DEFAULT_CHILD_NWK_ADDR};
    use crate::nwk::frame::{CommandFrame, NwkFrame};

    macro_rules! assert_timeout {
        ($future:expr) => {
            assert_timeout!($future, 100);
        };
        ($future:expr, $timeout_millis:expr) => {
            let result = embassy_time::WithTimeout::with_timeout(
                $future, embassy_time::Duration::from_millis($timeout_millis)).await;
            core::assert_matches!(result, Err(embassy_time::TimeoutError));
        }
    }

    #[futures_test::test]
    async fn end_device_ignores_end_device_timeout_request_cmd() {
        let mut nwk = Nwk::end_device().call();

        let end_device_frame = nwk.build_end_device_timeout_request_cmd_frame(
            DEFAULT_NWK_ADDR,
            Some(DEFAULT_EXT_ADDR),
            DeviceTimeout::Mins2
        );

        nwk.add_received_frame(&end_device_frame);
        assert_timeout!(nwk.listen_nwk(true));
    }

    #[futures_test::test]
    async fn router_increases_child_timeout_on_valid_end_device_timeout_request() {
        let mut nwk = Nwk::router().call();
        let before_timeout = nwk.get_children().first().unwrap().expiration;

        let mut end_device_frame = nwk.build_end_device_timeout_request_cmd_frame(
            DEFAULT_CHILD_NWK_ADDR,
            Some(DEFAULT_CHILD_EXT_ADDR),
            DeviceTimeout::Mins8
        );
        end_device_frame.header_mut().source = DEFAULT_CHILD_NWK_ADDR;

        nwk.add_received_frame(&end_device_frame);
        nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();

        let after_timeout = nwk.get_children().first().unwrap().expiration;

        assert_ne!(before_timeout, after_timeout);
        let timeout_duration = DeviceTimeout::Mins8.get_duration();

        assert!(after_timeout - Instant::now() < timeout_duration);
        assert!(after_timeout - Instant::now() + Duration::from_millis(500) > timeout_duration);
    }

    #[futures_test::test]
    async fn router_returns_valid_end_device_timeout_response_on_valid_end_device_timeout_request() {
        let mut nwk = Nwk::router().call();

        let mut end_device_frame = nwk.build_end_device_timeout_request_cmd_frame(
            DEFAULT_CHILD_NWK_ADDR,
            Some(DEFAULT_CHILD_EXT_ADDR),
            DeviceTimeout::Mins8
        );
        end_device_frame.header_mut().source = DEFAULT_CHILD_NWK_ADDR;

        nwk.add_received_frame(&end_device_frame);
        nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();

        let sent_frame = nwk.get_last_transmitted_frame().expect("no frames sent");
        if let NwkFrame::NwkCommand(CommandFrame { header, command: Command::EndDeviceTimeoutResponse(cmd) }) = sent_frame {
            assert_eq!(header.source, nwk.ctx.addr);
            assert_eq!(header.destination, DEFAULT_CHILD_NWK_ADDR);
            assert_eq!(cmd.status, EndDeviceTimeoutResponseStatus::Success);
        } else {
            panic!("invalid frame type sent")
        };
    }

    #[futures_test::test]
    async fn router_returns_invalid_end_device_timeout_response_on_invalid_end_device_timeout_request() {
        let mut nwk = Nwk::router().call();

        let mut end_device_frame = nwk.build_end_device_timeout_request_cmd_frame(
            DEFAULT_CHILD_NWK_ADDR,
            Some(DEFAULT_CHILD_EXT_ADDR),
            DeviceTimeout::Mins8
        );
        end_device_frame.header_mut().source = DEFAULT_CHILD_NWK_ADDR;
        if let NwkFrame::NwkCommand(CommandFrame { command: Command::EndDeviceTimeoutRequest(ref mut cmd), .. }) = end_device_frame {
            cmd.end_device_configuration = 1;
        }

        nwk.add_received_frame(&end_device_frame);
        nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();

        let sent_frame = nwk.get_last_transmitted_frame().expect("no frames sent");
        if let NwkFrame::NwkCommand(CommandFrame { header, command: Command::EndDeviceTimeoutResponse(cmd) }) = sent_frame {
            assert_eq!(header.source, nwk.ctx.addr);
            assert_eq!(header.destination, DEFAULT_CHILD_NWK_ADDR);
            assert_eq!(cmd.status, EndDeviceTimeoutResponseStatus::IncorrectValue);
        } else {
            panic!("invalid frame type sent")
        };
    }

    #[futures_test::test]
    async fn router_ignores_end_device_request_for_non_child() {
        let mut nwk = Nwk::router().call();

        let end_device_frame = nwk.build_end_device_timeout_request_cmd_frame(
            NwkAddress(0x1111),
            Some(ExtendedAddress(0x1234123412341234)),
            DeviceTimeout::Mins2
        );

        nwk.add_received_frame(&end_device_frame);
        assert_timeout!(nwk.listen_nwk(true));
    }
}
