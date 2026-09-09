use core::cmp::max;
use core::ops::Add;

use crate::nwk::commands::Command;
use crate::nwk::constants::NWK_ROUTER_AGE_LIMIT;
use crate::nwk::ctx::{Initialized, Joined, Nwk, Router};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::TransferResult;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::unwrap_or_return;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Duration;
use embassy_time::Instant;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::NwkAddress;

#[derive(Debug, Clone, TryRead, TryWrite)]
pub struct LinkStatusCmd {
    pub command_options: CommandOptions,
    pub entries: zb_types::Vec<LinkStatusEntry, 16>,
}

#[derive(BitStruct, Debug, Clone, Copy)]
#[bit_struct(repr = u8)]
pub struct CommandOptions {
    #[bit_struct(len = 5)]
    pub entry_count: u8,
    pub first_frame: bool,
    pub last_frame: bool,
}

#[derive(Debug, Clone, Copy, TryRead, TryWrite)]
pub struct LinkStatusEntry {
    pub neighbor_address: NwkAddress,
    pub link_status: LinkStatus,
}

#[derive(BitStruct, Debug, Clone, Copy)]
#[bit_struct(repr = u8)]
pub struct LinkStatus {
    #[bit_struct(len = 3)]
    pub incoming_cost: u8,
    #[bit_struct(len = 3)]
    #[bit_struct(skip = 1)]
    pub outgoing_cost: u8,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    pub async fn send_link_status_command(&mut self, n_frame: usize) -> TransferResult {
        let hdr = NwkHeader::cmd(self)
            .destination(NwkAddress::BROADCAST_ROUTERS)
            .radius(1)
            .call();

        self.get_router_ctx_mut().children.sort_by_key(|nb| nb.nwk_addr);
        let (len, entries) = {
            let entries = self.get_router_ctx()
                .children
                .iter()
                .skip(max(n_frame * 16 - 1, 0))
                .collect::<zb_types::Vec<_, 16>>();

            let len = entries.len();
            let entries = entries
                .iter()
                .take(16)
                .map(|nb| LinkStatusEntry {
                    neighbor_address: nb.nwk_addr,
                    link_status: LinkStatus {
                        incoming_cost: nb.incoming_cost,
                        outgoing_cost: nb.outgoing_cost,
                    },
                })
                .collect::<zb_types::Vec<_, 16>>();

            (len, entries)
        };

        let cmd = Command::LinkStatus(LinkStatusCmd {
            command_options: CommandOptions {
                entry_count: entries.len() as u8,
                first_frame: n_frame == 0,
                last_frame: len <= 16,
            },
            entries,
        });

        let cmd_frame = NwkFrame::new_cmd_frame(hdr, cmd);

        self.transmit_frame(&cmd_frame, NwkAddress::BROADCAST_ALL, false).await
    }

    // 3.6.3.4.2
    pub fn handle_link_status_command(
        &mut self,
        frame: &ReceivedCommandFrame<LinkStatusCmd>,
    ) {
        let slf = self.ctx.addr;
        // Upon receipt of a link status command frame by a ZigBee router or
        // coordinator, the age field of the neighbor table entry corresponding to
        // the transmitting device is reset to 0.
        let neighbor = unwrap_or_return!(
        self.get_router_ctx_mut().children
            .iter_mut()
            .find(|nb| nb.nwk_addr == frame.mac_src_addr)
    );

        neighbor.expiration = Instant::now().add(Duration::from_secs(NWK_ROUTER_AGE_LIMIT as u64));

        let entries = &frame.cmd.entries;
        let opt = frame.cmd.command_options;

        // The list of addresses covered by a frame is determined
        // from the first and last addresses in the link status list, and the first
        // frame and last frame bits of the command options field. If the receiver's
        // network address is outside the range covered by the frame, the frame is
        // discarded and pro- cessing is terminated.
        if entries.is_empty() {
            return;
        }

        if opt.first_frame && slf < entries.first().unwrap().neighbor_address {
            return;
        }

        if opt.last_frame && slf > entries.last().unwrap().neighbor_address {
            return;
        }

        // If the receiver's network address falls within the range covered by the
        // frame, then the link status list is searched. If the receiver's address
        // is found, the outgoing cost field of the neighbor table entry corre-
        // sponding to the sender is set to the incoming cost value of the link status
        // entry. If the receiver's address is not found, the outgoing cost field is
        // set to 0.
        neighbor.outgoing_cost = entries
            .iter()
            .find_map(|link| {
                if link.neighbor_address == slf {
                    Some(link.link_status.incoming_cost)
                } else {
                    None
                }
            })
            .unwrap_or_default();
    }
}
