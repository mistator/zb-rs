use crate::apl::zdo::config::ZbCapabilities;
use crate::nwk::commands::Command;
use crate::nwk::commands::rejoin_response::RejoinResponse;
use crate::nwk::commands::rejoin_response::RejoinResponseCmd;
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
use crate::nwk::ctx::{BaseNwkPrivate, InitializedNwk, Nwk, PendingJoin, RoutingState};
use crate::nwk::nib::{NeighborRelationship, NewNwkNeighbour, NwkNeighbor};

pub struct RejoinRequestCmd {
    pub dest_short_addr: NwkAddress,
    pub dest_ext_addr: ExtendedAddress,
    pub capability_information: ZbCapabilities,
}

impl<D: NwkMac, S: StorageRegion> Nwk<PendingJoin, D, S> {
    pub async fn send_rejoin_request_cmd(
        &mut self,
        mut config: RejoinRequestCmd,
    ) -> Result<(), NlmeJoinError> {
        if self.get_profile().nwk_addr_alloc == AddrAllocMethod::Stochastic {
            config.capability_information.allocate_address = false;
        }

        let hdr = NwkHeader::cmd(self)
            .destination(config.dest_short_addr)
            .destination_ieee(config.dest_ext_addr)
            .radius(1)
            .call();

        let addr = self.get_addr();
        self.get_mac_mut().set_short_address(addr.into());

        let frame = NwkFrame::new_cmd_frame(hdr, Command::RejoinRequest(config.capability_information));

        self.transmit_frame(&frame, config.dest_short_addr, true)
            .await
            .map_err(|e| NlmeJoinError::TransferError(e))
    }
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
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

        if self.get_profile().nwk_addr_alloc == AddrAllocMethod::Distributed {
            // TODO: alloc addr
        } else {
            // self-assigned address
            if self.is_address_conflict(&nwk_addr, &ext_addr, true) {
                nwk_addr = self.assign_child_address();
            }
        }

       let success = self.lock_neighbors_mut(|nbs| {
            nbs.cleanup();
            let child = nbs
                .find_by_ext_addr_and_type_mut(ext_addr, cmd.device_type.into());
           
           if let Some(child) = child {
               child.nwk_addr = nwk_addr;
               return true;
           } else {
               nbs.children.retain(|nb| nb.ext_addr != Option::from(ext_addr));
               let neighbor = NwkNeighbor::new(NewNwkNeighbour {
                   ext_addr,
                   nwk_addr,
                   device_type: cmd.device_type.into(),
                   rx_on_when_idle: cmd.receiver_on_when_idle,
                   relationship: NeighborRelationship::Child,
               });
               nbs.children.push(neighbor).is_ok()
           }
       });
        
        match success {
            true => match self.send_rejoin_response_cmd(
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
            false => {
                self.send_rejoin_response_cmd(
                    &RejoinResponseCmd {
                        dst_addr: frame.header.source,
                        ext_dst_addr: ext_addr,
                        rejoin_response: RejoinResponse::PanAtCapacity,
                    },
                )
                    .await
                    .ok();
                
                Ok(None)
            }
        }


    }
}


