use core::ops::Add;

use crate::nwk::commands::Command;
use crate::nwk::commands::end_device_timeout_response::EndDeviceTimeoutResponseStatus;
use crate::nwk::ctx::DeviceTimeout;
use crate::nwk::ctx::{Initialized, Joined, JoinedDevice, Nwk, Router};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::TransferResult;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::unwrap_or_return;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Instant;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::DeviceType;

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct EndDeviceTimeoutRequest {
    pub requested_timeout: DeviceTimeout,
    pub end_device_configuration: u16,
}

impl<T: JoinedDevice, D: NwkMac, S: StorageRegion>Nwk<Initialized<Joined<T>>, D, S> {
    pub async fn send_end_device_timeout_request_cmd(&mut self, requested_timeout: DeviceTimeout) -> TransferResult {
        let nwk_addr = self.ctx.parent.nwk_addr;
        let ext_addr = self.ctx.parent.ext_addr;

        let hdr = NwkHeader::cmd(self)
            .destination(nwk_addr)
            .maybe_destination_ieee(ext_addr)
            .radius(1)
            .call();

        let cmd = Command::EndDeviceTimeoutRequest(EndDeviceTimeoutRequest {
            requested_timeout,
            end_device_configuration: 0,
        });
        let cmd_frame = NwkFrame::new_cmd_frame(hdr, cmd);

        let dst_address = self.ctx.parent.nwk_addr;
        self.transmit_frame(&cmd_frame, dst_address, true).await
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    pub async fn handle_end_device_timeout_request_command(
        &mut self,
        frame: &ReceivedCommandFrame<'_, EndDeviceTimeoutRequest>,
    ) -> TransferResult {
        let cmd = &frame.cmd;
        let ext_addr = unwrap_or_return!(frame.header.source_ieee, Ok(()));

        let neighbor = unwrap_or_return!(
            self.get_router_ctx_mut().children
                .iter_mut()
                .find(|nb| nb.nwk_addr == frame.mac_src_addr
                    && nb.device_type == DeviceType::EndDevice),
            Ok(())
        );

        if cmd.end_device_configuration != 0 {
            return self.send_end_device_timeout_response_cmd(
                frame.mac_src_addr,
                ext_addr,
                EndDeviceTimeoutResponseStatus::IncorrectValue,
            )
                .await;
        }

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
