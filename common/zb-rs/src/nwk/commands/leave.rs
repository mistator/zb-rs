use crate::nwk::commands::Command;
use crate::nwk::frame::CommandFrame;
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::{NlmeLeaveIndication, TransferResult};
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::constants::NWK_LEAVE_REQUEST_ALLOWED;
use crate::nwk::ctx::{InitializedNwk, JoinedAsEndDevice, JoinedNwk, JoinedState, Nwk, RoutingState};
use crate::nwk::service::routing::ReceivedCommandFrame;

#[derive(BitStruct, Clone, Copy, Debug)]
#[bit_struct(repr = u8)]
pub struct Leave {
    #[bit_struct(skip = 5)]
    pub rejoin: bool,
    pub request: bool,
    pub remove_children: bool,
}

impl<T: JoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub async fn emit_leave_cmd(&mut self, config: Leave, dest: NwkAddress, dest_ext: Option<ExtendedAddress>) -> TransferResult {
        let cmd = Command::Leave(config);

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(self)
                .destination(if config.request { dest } else { NwkAddress::BROADCAST_RX_ON_IDLE })
                .maybe_destination_ieee(dest_ext)
                .radius(1)
                .call(),
            command: cmd,
        });

        self.transmit_frame(&frame, dest, dest.is_unicast()).await
    }
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub async fn handle_leave_request(&mut self, frame: &ReceivedCommandFrame<'_, Leave>) -> Option<NlmeLeaveIndication> {
        if frame.cmd.request {
            self.handle_leave_request_request(frame).await
        } else {
            self.lock_neighbors_mut(|nbs|
                nbs.children.retain(|child| child.nwk_addr != frame.header.source));

            if frame.header.source == self.lock_parent(|parent| parent.nwk_addr) {
                if frame.cmd.remove_children {
                    self.emit_leave_cmd(Leave {
                        request: false,
                        rejoin: frame.cmd.rejoin,
                        remove_children: frame.cmd.remove_children,
                    }, NwkAddress::MAX, frame.header.source_ieee).await.ok();
                }

                Some(NlmeLeaveIndication::LeaveParent { rejoin: frame.cmd.rejoin })
            } else {
                None
            }
        }
    }

    pub async fn handle_leave_request_request(&mut self, frame: &ReceivedCommandFrame<'_, Leave>) -> Option<NlmeLeaveIndication> {
        if frame.header.destination.is_broadcast() || !NWK_LEAVE_REQUEST_ALLOWED {
            return None;
        }

        self.emit_leave_cmd(Leave {
            request: false,
            rejoin: frame.cmd.rejoin,
            remove_children: frame.cmd.remove_children,
        }, NwkAddress::MAX, None).await.ok();

        Some(NlmeLeaveIndication::LeaveSelf { rejoin: frame.cmd.rejoin })
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsEndDevice, D, S> {
    pub async fn handle_leave_request(&mut self, frame: &ReceivedCommandFrame<'_, Leave>) -> Option<NlmeLeaveIndication>{
        if frame.cmd.request {
            return self.handle_leave_request_request(frame).await;
        } else {
            if frame.header.source == self.lock_parent(|parent| parent.nwk_addr) {
                return Some(NlmeLeaveIndication::LeaveParent { rejoin: frame.cmd.rejoin });
            }
        }

        None
    }

    pub async fn handle_leave_request_request(&mut self, frame: &ReceivedCommandFrame<'_, Leave>) -> Option<NlmeLeaveIndication> {
        let (nwk_addr, ext_addr) = self.lock_parent(|parent| (parent.nwk_addr, parent.ext_addr));
        if frame.header.destination.is_broadcast() || nwk_addr != frame.header.source
        {
            return None
        }

        self.emit_leave_cmd(Leave {
            request: false,
            rejoin: frame.cmd.rejoin,
            remove_children: false,
        }, nwk_addr, ext_addr.into()).await.ok();

        Some(NlmeLeaveIndication::LeaveSelf { rejoin: frame.cmd.rejoin })
    }
}

#[cfg(test)]
mod tests {
    use core::assert_matches;
    use crate::nwk::nlde::NlmeLeaveIndication;
    use crate::nwk::nlde::NwkIndication;
    use embassy_time::{Duration, WithTimeout};
    use zb_types::common::NwkAddress;
    use crate::assert_timeout;
    use crate::nwk::commands::Command;
    use crate::nwk::commands::leave::{Leave};
    use crate::nwk::ctx::{BaseNwk, BaseNwkPrivate, InitializedNwk, Nwk, NwkListen};
    use crate::nwk::ctx::tests::{DEFAULT_CHILD_EXT_ADDR, DEFAULT_CHILD_NWK_ADDR, DEFAULT_PARENT_EXT_ADDR, DEFAULT_PARENT_NWK_ADDR};
    use crate::nwk::frame::{CommandFrame, NwkFrame};
    use crate::nwk::frame::header::NwkHeader;

    #[futures_test::test]
    async fn coordinator_drops_leave_request() {

    }

    #[futures_test::test]
    async fn leave_request_with_request_field_true_is_dropped_if_address_is_broadcast() {
        let mut nwk = Nwk::router().call();
        let ext_addr = nwk.get_ext_addr();

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(NwkAddress::BROADCAST_RX_ON_IDLE)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: false,
                request: true,
                remove_children: false,
            })
        });

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));
    }

    #[futures_test::test]
    async fn router_processes_leave_request_if_nwk_leave_request_allowed_is_true() {
        let mut nwk = Nwk::router().call();
        let addr = nwk.get_addr();
        let ext_addr = nwk.get_ext_addr();

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(addr)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: true,
                request: true,
                remove_children: false,
            })
        });

        nwk.add_received_frame(&frame);
        nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();
        let sent_frame = nwk.get_last_transmitted_frame().unwrap();

        assert_eq!(sent_frame.header().destination, NwkAddress::BROADCAST_RX_ON_IDLE);
        match sent_frame {
            NwkFrame::NwkCommand(CommandFrame { command: Command::Leave(leave), .. }) => {
                assert_eq!(leave.request, false);
                assert_eq!(leave.rejoin, true);
                assert_eq!(leave.remove_children, false);
            }
            _ => panic!("invalid frame sent")
        }
    }

    #[futures_test::test]
    async fn router_drops_leave_request_if_nwk_leave_request_allowed_is_false() {

    }

    #[futures_test::test]
    async fn router_leaves_if_parent_has_left_and_children_should_leave() {
        let mut nwk = Nwk::router().call();
        let addr = nwk.get_addr();
        let ext_addr = nwk.get_ext_addr();

        let mut frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(addr)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: true,
                request: false,
                remove_children: true,
            })
        });
        frame.header_mut().source = DEFAULT_PARENT_NWK_ADDR;
        frame.header_mut().source_ieee = Some(DEFAULT_PARENT_EXT_ADDR);

        nwk.add_received_frame(&frame);
        let indication = nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();

        assert_matches!(indication, Some(NwkIndication::Leave(NlmeLeaveIndication::LeaveParent {..})));
        let sent_frame = nwk.get_last_transmitted_frame().unwrap();

        assert_eq!(sent_frame.header().destination, NwkAddress::BROADCAST_RX_ON_IDLE);
        match sent_frame {
            NwkFrame::NwkCommand(CommandFrame { command: Command::Leave(leave), .. }) => {
                assert_eq!(leave.request, false);
                assert_eq!(leave.rejoin, true);
                assert_eq!(leave.remove_children, true);
            }
            _ => panic!("invalid frame sent")
        }
    }

    #[futures_test::test]
    async fn router_removes_child_on_child_leave() {
        let mut nwk = Nwk::router().call();
        let addr = nwk.get_addr();
        let ext_addr = nwk.get_ext_addr();

        let mut frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(addr)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: true,
                request: false,
                remove_children: true,
            })
        });
        frame.header_mut().source = DEFAULT_CHILD_NWK_ADDR;
        frame.header_mut().source_ieee = Some(DEFAULT_CHILD_EXT_ADDR);

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));

        let sent_frame = nwk.get_last_transmitted_frame();
        assert!(sent_frame.is_none());
        assert!(nwk.lock_neighbors(|nbs| nbs.children.is_empty()));
    }

    #[futures_test::test]
    async fn end_device_drops_leave_request_if_not_from_parent() {
        let mut nwk = Nwk::end_device().call();
        let addr = nwk.get_addr();
        let ext_addr = nwk.get_ext_addr();

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(addr)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: true,
                request: true,
                remove_children: false,
            })
        });

        nwk.add_received_frame(&frame);
        assert_timeout!(nwk.listen_nwk(true));
    }

    #[futures_test::test]
    async fn end_device_processes_leave_request_if_from_parent() {
        let mut nwk = Nwk::end_device().call();
        let addr = nwk.get_addr();
        let ext_addr = nwk.get_ext_addr();

        let mut frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(addr)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: true,
                request: true,
                remove_children: false,
            })
        });
        frame.header_mut().source = DEFAULT_PARENT_NWK_ADDR;
        frame.header_mut().source_ieee = Some(DEFAULT_PARENT_EXT_ADDR);

        nwk.add_received_frame(&frame);
        nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();
        let sent_frame = nwk.get_last_transmitted_frame().unwrap();

        assert_eq!(sent_frame.header().destination, NwkAddress::BROADCAST_RX_ON_IDLE);
        match sent_frame {
            NwkFrame::NwkCommand(CommandFrame { command: Command::Leave(leave), .. }) => {
                assert_eq!(leave.request, false);
                assert_eq!(leave.rejoin, true);
                assert_eq!(leave.remove_children, false);
            }
            _ => panic!("invalid frame sent")
        }
    }

    #[futures_test::test]
    async fn end_device_sends_leave_indication_if_parent_left() {
        let mut nwk = Nwk::end_device().call();
        let addr = nwk.get_addr();
        let ext_addr = nwk.get_ext_addr();

        let mut frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(&mut nwk)
                .destination(addr)
                .destination_ieee(ext_addr)
                .radius(1)
                .call(),
            command: Command::Leave(Leave {
                rejoin: true,
                request: false,
                remove_children: false,
            })
        });
        frame.header_mut().source = DEFAULT_PARENT_NWK_ADDR;
        frame.header_mut().source_ieee = Some(DEFAULT_PARENT_EXT_ADDR);

        nwk.add_received_frame(&frame);
        let indication = nwk.listen_nwk(true).with_timeout(Duration::from_millis(100)).await.ok();
        assert_matches!(indication, Some(NwkIndication::Leave(NlmeLeaveIndication::LeaveParent {..})));

        let sent_frame = nwk.get_last_transmitted_frame();
        assert!(sent_frame.is_none());
    }
}
