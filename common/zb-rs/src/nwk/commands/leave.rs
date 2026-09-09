use crate::nwk::commands::Command;
use crate::nwk::ctx::{EndDevice, Initialized, Joined, JoinedDevice, Nwk, Router};
use crate::nwk::frame::CommandFrame;
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::TransferResult;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(BitStruct, Clone, Copy, Debug)]
#[bit_struct(repr = u8)]
pub struct Leave {
    #[bit_struct(skip = 5)]
    pub rejoin: bool,
    pub request: bool,
    pub remove_children: bool,
}

pub struct LeaveCmd {
    pub request: Option<(NwkAddress, Option<ExtendedAddress>)>,
    pub rejoin: bool,
    pub remove_children: bool,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<EndDevice>>, D, S> {
    pub async fn send_leave_cmd(&mut self, config: LeaveCmd) -> TransferResult {
        let dest = self.ctx.parent.nwk_addr;
        self.emit_leave_cmd(config, dest, true).await
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    pub async fn send_leave_cmd(&mut self, config: LeaveCmd) -> TransferResult {
        let dest = NwkAddress::MAX;
        self.emit_leave_cmd(config, dest, false).await
    }
}


impl<T: JoinedDevice, D: NwkMac, S: StorageRegion>Nwk<Initialized<Joined<T>>, D, S> {
    async fn emit_leave_cmd(&mut self, config: LeaveCmd, dest: NwkAddress, ack: bool) -> TransferResult {
        let cmd = Command::Leave(Leave {
            rejoin: false,
            request: config.request.is_some(),
            remove_children: false,
        });

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(self)
                .destination(
                    config
                        .request
                        .map(|o| o.0)
                        .unwrap_or(NwkAddress::BROADCAST_RX_ON_IDLE),
                )
                .maybe_destination_ieee(if let Some((_, Some(ext_addr))) = config.request {
                    ext_addr.into()
                } else {
                    None
                })
                .radius(1)
                .call(),
            command: cmd,
        });

        self.transmit_frame(&frame, dest, ack).await
    }
}
