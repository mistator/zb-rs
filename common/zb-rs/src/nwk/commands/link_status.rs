use alloc::sync::Arc;
use core::ops::{Add, Mul};
use core::sync::atomic::{AtomicU8, Ordering};
use bon::{Builder};
use crate::nwk::commands::Command;
use crate::nwk::constants::{MAX_ROUTE_REQUEST_JITTER_MILLIS,  MIN_ROUTE_REQUEST_JITTER_MILLIS, NWK_LINK_STATUS_PERIOD, NWK_ROUTER_AGE_LIMIT};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::{NldeTransferError};
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::{unwrap_or_return};
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Duration, Timer};
use embassy_time::Instant;
use zb_hal::{ NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::{ExtendedAddress, NwkAddress};
use zb_types::mac::A_MAX_MAC_PAYLOAD_SIZE;
use crate::common::security::frame::SecurityLevel;
use crate::mac::mlme::Mlme;
use crate::nwk::security::EncryptedFrameParams;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use crate::nwk::ctx::{InitializedNwk, Nwk, RoutingState};
use crate::nwk::nib::{NeighborTable, NEIGHBOR_TABLE_MAX_ENTRIES, NetworkSecurityMaterialDescriptorSet};
use crate::nwk::service::transmission::build_mac_payload;

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

#[derive(Debug, Default, Clone, Copy, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum LinkCost {
    #[default]
    Unknown = 0,
    _1 = 1,
    _2 = 2,
    _3 = 3,
    _4 = 4,
    _5 = 5,
    _6 = 6,
    _7 = 7,
}

#[derive(BitStruct, Debug, Clone, Copy)]
#[bit_struct(repr = u8)]
pub struct LinkStatus {
    #[bit_struct(len = 3)]
    pub incoming_cost: LinkCost,
    #[bit_struct(len = 3)]
    #[bit_struct(skip = 1)]
    pub outgoing_cost: LinkCost,
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // 3.6.3.4.2
    pub fn handle_link_status_command(
        &mut self,
        frame: &ReceivedCommandFrame<LinkStatusCmd>,
    ) {
        // Upon receipt of a link status command frame by a ZigBee router or
        // coordinator, the age field of the neighbor table entry corresponding to
        // the transmitting device is reset to 0.
        self.lock_neighbors_mut(|nbs| {
            let neighbor = unwrap_or_return!(
            nbs
                .children
                .iter_mut()
                .find(|nb| nb.nwk_addr == frame.mac_src_addr));

            neighbor.expiration = Instant::now()
                .add(Duration::from_secs(NWK_LINK_STATUS_PERIOD as u64).mul(NWK_ROUTER_AGE_LIMIT as u32));

            let slf = self.get_addr();

            let entries = &frame.cmd.entries;
            let opt = frame.cmd.command_options;

            if entries.is_empty() {
                return;
            }

            if opt.first_frame && slf < entries.first().unwrap().neighbor_address {
                return;
            }

            if opt.last_frame && slf > entries.last().unwrap().neighbor_address {
                return;
            }

            // The list of addresses covered by a frame is determined
            // from the first and last addresses in the link status list, and the first
            // frame and last frame bits of the command options field. If the receiver's
            // network address is outside the range covered by the frame, the frame is
            // discarded and processing is terminated.

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
        });
    }
}

pub const MAX_LINK_STATUS_COMMAND_FRAMES: usize = NEIGHBOR_TABLE_MAX_ENTRIES.div_ceil(2);

fn make_link_status_commands(
    children: Arc<Mutex<CriticalSectionRawMutex, NeighborTable>>,
) -> zb_types::Vec<Command, MAX_LINK_STATUS_COMMAND_FRAMES> {
    // Link status entries are sorted in ascending order by network address. If all router neighbors do not fit in a single
    // frame, multiple frames are sent. When sending multiple frames, the last network address in the link status list for
    // frame N is equal to the first network address in the link status list for frame N+1.

    unsafe {children.lock_mut(|nbs| {
        let len = nbs.children.len();

        // [0, 16) => 1
        // [16, 31) => 2
        // [31, 46) => 3

        // len:             [16 + 15n, 16 + 15(n+1)) => n + 1
        // len - 16:        [15n, 15(n+1)) => n + 1
        // (len - 16) / 15: [n, n + 1) => n + 1
        // floor(*):        n => n + 1
        let n_frames = if len <= 16 {
            1
        } else {
            let result = (len as f64 - 16.0) / 15.0;
            (result.floor() + 1.0) as usize
        };
        nbs.cleanup();
        nbs.children.sort_by_key(|nb| nb.nwk_addr);

        let mut commands = zb_types::Vec::<Command, MAX_LINK_STATUS_COMMAND_FRAMES>::new();
        for i in 0..n_frames {
            let entries = nbs.children.iter()
                .skip(i * 15)
                .take(16)
                .map(|nb| {
                    LinkStatusEntry {
                        neighbor_address: nb.nwk_addr,
                        link_status: LinkStatus {
                            incoming_cost: nb.incoming_cost,
                            outgoing_cost: nb.outgoing_cost,
                        },
                    }
                }).collect::<zb_types::Vec<_, MAX_LINK_STATUS_COMMAND_FRAMES>>();
            commands.push(Command::LinkStatus(LinkStatusCmd {
                command_options: CommandOptions {
                    entry_count: entries.len() as u8,
                    first_frame: true,
                    last_frame: len == 1
                },
                entries,
            })).ok();
        }

        commands
    })}
}


#[derive(Builder)]
pub struct LinkStatusTaskParams<D: NwkMac> {
    source: NwkAddress,
    source_ieee: ExtendedAddress,
    sequence_number: Arc<AtomicU8>,
    neighbors: Arc<Mutex<CriticalSectionRawMutex, NeighborTable>>,
    security_level: SecurityLevel,
    active_key_seq_number: Arc<AtomicU8>,
    keys: Arc<Mutex<CriticalSectionRawMutex, NetworkSecurityMaterialDescriptorSet>>,
    mac: Mlme<D>,
    rand_seed: u64,
}

pub async fn link_status_task<D: NwkMac>(mut params: LinkStatusTaskParams<D>) -> ! {
    let mut rand = SmallRng::seed_from_u64(params.rand_seed);
    let mut ticker = embassy_time::Ticker::every(Duration::from_secs(NWK_LINK_STATUS_PERIOD as u64));

    loop {
        let commands = make_link_status_commands(params.neighbors.clone());
        for command in commands {
            let hdr = NwkHeader::cmd_no_ctx()
                .source(params.source)
                .source_ieee(params.source_ieee)
                .destination(NwkAddress::BROADCAST_ROUTERS)
                .sequence_number(params.sequence_number.fetch_add(1, Ordering::Relaxed))
                .radius(1)
                .call();

            let frame = NwkFrame::new_cmd_frame(hdr, command);

            let mut buffer = [0u8; A_MAX_MAC_PAYLOAD_SIZE];
            let encrypted_frame_params = EncryptedFrameParams {
                ext_addr: params.source_ieee,
                security_level: params.security_level,
                active_key_seq_number: params.active_key_seq_number.clone(),
                keys: params.keys.clone(),
            };

            let size = build_mac_payload(&frame, &mut buffer, &encrypted_frame_params).unwrap(); // TODO

            let jitter = rand.random_range::<usize, _>(MIN_ROUTE_REQUEST_JITTER_MILLIS..MAX_ROUTE_REQUEST_JITTER_MILLIS);
            Timer::after_millis(jitter as u64).await;

            params.mac
                .data_transmit_request(NwkAddress::MAX, &mut buffer[..size], false)
                .await
                .map_err(|err| NldeTransferError::McpsDataError(err)).ok();
        }

        ticker.next().await;
    }
}

#[cfg(test)]
mod tests {
    use embassy_time::{Duration, Instant};
    use zb_types::common::NwkAddress;
    use crate::assert_timeout;
    use crate::nwk::commands::Command;
    use crate::nwk::commands::link_status::{CommandOptions, LinkCost, LinkStatus, LinkStatusCmd, LinkStatusEntry};
    use crate::nwk::constants::{NWK_LINK_STATUS_PERIOD, NWK_ROUTER_AGE_LIMIT};
    use crate::nwk::ctx::{InitializedNwk, Nwk, NwkListen};
    use crate::nwk::ctx::tests::{DEFAULT_CHILD_EXT_ADDR, DEFAULT_CHILD_NWK_ADDR};
    use crate::nwk::frame::{CommandFrame, NwkFrame};
    use crate::nwk::frame::header::NwkHeader;

    #[futures_test::test]
    async fn router_updates_device_expiration_on_received_link_status_command() {
        let mut nwk = Nwk::router().call();
        let addr = nwk.get_addr();
        nwk.lock_neighbors_mut(|nbs| {
            nbs.children.iter_mut().for_each(|child| {
                child.expiration = Instant::now() + Duration::from_secs(1);
                child.outgoing_cost = LinkCost::_7;
            })
        });

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd_no_ctx()
                .source(DEFAULT_CHILD_NWK_ADDR)
                .source_ieee(DEFAULT_CHILD_EXT_ADDR)
                .destination(NwkAddress::BROADCAST_ROUTERS)
                .radius(1)
                .sequence_number(0)
                .call(),
            command: Command::LinkStatus(LinkStatusCmd {
                command_options: CommandOptions {
                    entry_count: 1,
                    first_frame: true,
                    last_frame: true,
                },
                entries: zb_types::Vec::<LinkStatusEntry, 16>::from_slice(&[
                    LinkStatusEntry {
                        neighbor_address: addr,
                        link_status: LinkStatus {
                            incoming_cost: LinkCost::_3,
                            outgoing_cost: LinkCost::_5,
                        },
                    }
                ]).unwrap(),
            })
        });

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));

        let child = nwk.lock_neighbors(|children| {
            children.find_by_short_addr(DEFAULT_CHILD_NWK_ADDR).unwrap().clone()
        });

        assert!(child.expiration > Instant::now() + Duration::from_secs((NWK_LINK_STATUS_PERIOD * NWK_ROUTER_AGE_LIMIT - 1) as u64));
        assert!(child.expiration < Instant::now() + Duration::from_secs((NWK_LINK_STATUS_PERIOD * NWK_ROUTER_AGE_LIMIT + 1) as u64));
    }

    #[futures_test::test]
    async fn router_updates_outgoing_cost_if_address_in_cmd() {
        let mut nwk = Nwk::router().call();
        nwk.lock_neighbors_mut(|nbs| {
            nbs.children.iter_mut().for_each(|child| {
                child.expiration = Instant::now() + Duration::from_secs(1);
                child.outgoing_cost = LinkCost::_7;
            })
        });

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd_no_ctx()
                .source(DEFAULT_CHILD_NWK_ADDR)
                .source_ieee(DEFAULT_CHILD_EXT_ADDR)
                .destination(NwkAddress::BROADCAST_ROUTERS)
                .radius(1)
                .sequence_number(0)
                .call(),
            command: Command::LinkStatus(LinkStatusCmd {
                command_options: CommandOptions {
                    entry_count: 1,
                    first_frame: true,
                    last_frame: true,
                },
                entries: zb_types::Vec::<LinkStatusEntry, 16>::from_slice(&[
                    LinkStatusEntry {
                        neighbor_address: nwk.get_addr(),
                        link_status: LinkStatus {
                            incoming_cost: LinkCost::_3,
                            outgoing_cost: LinkCost::_5,
                        },
                    }
                ]).unwrap(),
            })
        });

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));

        let child = nwk.lock_neighbors(|children| {
            children.find_by_short_addr(DEFAULT_CHILD_NWK_ADDR).unwrap().clone()
        });

        assert_eq!(child.outgoing_cost, LinkCost::_3);
    }

    #[futures_test::test]
    async fn router_updates_outgoing_cost_if_address_in_cmd_range_but_not_found() {
        let mut nwk = Nwk::router().call();
        nwk.lock_neighbors_mut(|nbs| {
            nbs.children.iter_mut().for_each(|child| {
                child.expiration = Instant::now() + Duration::from_secs(1);
                child.outgoing_cost = LinkCost::_7;
            })
        });

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd_no_ctx()
                .source(DEFAULT_CHILD_NWK_ADDR)
                .source_ieee(DEFAULT_CHILD_EXT_ADDR)
                .destination(NwkAddress::BROADCAST_ROUTERS)
                .radius(1)
                .sequence_number(0)
                .call(),
            command: Command::LinkStatus(LinkStatusCmd {
                command_options: CommandOptions {
                    entry_count: 1,
                    first_frame: true,
                    last_frame: true,
                },
                entries: zb_types::Vec::<LinkStatusEntry, 16>::from_slice(&[
                    LinkStatusEntry {
                        neighbor_address: NwkAddress(*nwk.get_addr() - 2),
                        link_status: LinkStatus {
                            incoming_cost: LinkCost::_3,
                            outgoing_cost: LinkCost::_5,
                        },
                    },
                    LinkStatusEntry {
                        neighbor_address: NwkAddress(*nwk.get_addr() + 2),
                        link_status: LinkStatus {
                            incoming_cost: LinkCost::_3,
                            outgoing_cost: LinkCost::_5,
                        },
                    }
                ]).unwrap(),
            })
        });

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));

        let child = nwk.lock_neighbors(|children| {
            children.find_by_short_addr(DEFAULT_CHILD_NWK_ADDR).unwrap().clone()
        });

        assert_eq!(child.outgoing_cost, LinkCost::Unknown);
    }

    #[futures_test::test]
    async fn router_ignores_frame_if_address_not_in_range() {
        let mut nwk = Nwk::router().call();
        nwk.lock_neighbors_mut(|nbs| {
            nbs.children.iter_mut().for_each(|child| {
                child.expiration = Instant::now() + Duration::from_secs(1);
                child.outgoing_cost = LinkCost::_7;
            })
        });

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd_no_ctx()
                .source(DEFAULT_CHILD_NWK_ADDR)
                .source_ieee(DEFAULT_CHILD_EXT_ADDR)
                .destination(NwkAddress::BROADCAST_ROUTERS)
                .radius(1)
                .sequence_number(0)
                .call(),
            command: Command::LinkStatus(LinkStatusCmd {
                command_options: CommandOptions {
                    entry_count: 1,
                    first_frame: true,
                    last_frame: true,
                },
                entries: zb_types::Vec::<LinkStatusEntry, 16>::from_slice(&[
                    LinkStatusEntry {
                        neighbor_address: NwkAddress(*nwk.get_addr() - 4),
                        link_status: LinkStatus {
                            incoming_cost: LinkCost::_3,
                            outgoing_cost: LinkCost::_5,
                        },
                    },
                    LinkStatusEntry {
                        neighbor_address: NwkAddress(*nwk.get_addr() - 3),
                        link_status: LinkStatus {
                            incoming_cost: LinkCost::_3,
                            outgoing_cost: LinkCost::_5,
                        },
                    }
                ]).unwrap(),
            })
        });

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));

        let child = nwk.lock_neighbors(|children| {
            children.find_by_short_addr(DEFAULT_CHILD_NWK_ADDR).unwrap().clone()
        });

        assert_eq!(child.outgoing_cost, LinkCost::_7);
    }
}