use crate::apl::zdo::config::ZbCapabilities;
use crate::nwk::commands::Command;
use crate::nwk::commands::rejoin_response::RejoinResponse;
use crate::nwk::commands::rejoin_response::RejoinResponseCmd;
use crate::nwk::ctx::{Initialized, Joined, Nwk, PendingRejoin, Router};
use crate::nwk::ctx::{NeighborRelationship, NewNwkNeighbour, NwkNeighbor};
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::JoinMethod;
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::nlde::NlmeJoinIndication;
use crate::nwk::nlme::NlmeJoinError;
use crate::nwk::service::routing::ReceivedCommandFrame;
use crate::stack_profile::AddrAllocMethod;
use crate::unwrap_or_return;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

pub struct RejoinRequestCmd {
    pub dest_short_addr: NwkAddress,
    pub dest_ext_addr: ExtendedAddress,
    pub capability_information: ZbCapabilities,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<PendingRejoin>, D, S> {
    pub async fn send_rejoin_request_cmd(
        &mut self,
        mut config: RejoinRequestCmd,
    ) -> Result<(), NlmeJoinError> {
        if self.ctx.get_profile().nwk_addr_alloc == AddrAllocMethod::Stochastic {
            config.capability_information.allocate_address = false;
        }

        let hdr = NwkHeader::cmd(self)
            .destination(config.dest_short_addr)
            .destination_ieee(config.dest_ext_addr)
            .radius(1)
            .call();

        self.mac.set_short_address(self.ctx.addr.into()).await;

        let frame = NwkFrame::new_cmd_frame(hdr, Command::RejoinRequest(config.capability_information));

        self.transmit_frame(&frame, config.dest_short_addr, true)
            .await
            .map_err(|e| NlmeJoinError::TransferError(e))
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    pub async fn handle_rejoin_request_command(
        &mut self,
        frame: &ReceivedCommandFrame<'_, ZbCapabilities>,
    ) -> Result<Option<NlmeJoinIndication>, NldeTransferError> {
        let cmd = &frame.cmd;
        let ext_addr = unwrap_or_return!(
        frame.header.source_ieee,
        Err(NldeTransferError::InvalidRequest(
            "missing extended address in header"
        ))
    );
        let mut nwk_addr = frame.header.source;

        if self.ctx.get_profile().nwk_addr_alloc == AddrAllocMethod::Distributed {
            // TODO: alloc addr
        } else {
            // self-assigned address
            if self.is_address_conflict(&nwk_addr, &ext_addr, true) {
                nwk_addr = self.assign_child_address();
            }
        }

        self.get_router_ctx_mut().children.cleanup();
        let child = self
            .get_router_ctx_mut()
            .children
            .find_by_ext_addr_and_type_mut(ext_addr, cmd.device_type.into());

        if let Some(child) = child {
            child.nwk_addr = nwk_addr;
        } else {
            self.get_router_ctx_mut().children
                .retain(|nb| nb.ext_addr != Option::from(ext_addr));
            let neighbor = NwkNeighbor::new(NewNwkNeighbour {
                ext_addr,
                nwk_addr,
                device_type: cmd.device_type.into(),
                rx_on_when_idle: cmd.receiver_on_when_idle,
                relationship: NeighborRelationship::Child,
            });
            match self.get_router_ctx_mut().children.push(neighbor) {
                Ok(_) => {}
                Err(_) => {
                    self.send_rejoin_response_cmd(
                        &RejoinResponseCmd {
                            dst_addr: frame.header.source,
                            ext_dst_addr: ext_addr,
                            rejoin_response: RejoinResponse::PanAtCapacity,
                        },
                    )
                        .await
                        .ok();

                    return Ok(None);
                }
            }
        }

        match self.send_rejoin_response_cmd(
            &RejoinResponseCmd {
                dst_addr: frame.header.source,
                ext_dst_addr: ext_addr,
                rejoin_response: RejoinResponse::Success(nwk_addr),
            },
        )
            .await
        {
            Ok(_) => {
                Ok(Some(NlmeJoinIndication {
                    nwk_addr,
                    ext_addr,
                    join_method: JoinMethod::Rejoin {
                        secure: true, // TODO
                    },
                }))
            }
            Err(_) => Ok(None),
        }
    }
}


