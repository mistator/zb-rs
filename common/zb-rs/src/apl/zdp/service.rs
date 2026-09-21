use byte::TryRead;
use embassy_time::Duration;
use rand::RngExt;

use crate::apl::aps::apsde::ApsdeAddress;
use crate::apl::aps::apsde::ApsdeDataIndication;
use crate::apl::aps::apsde::ApsdeError;
use crate::apl::aps::apsde::ApsdeRequest;
use crate::apl::aps::apsde::ApsdeSapConfirm;
use crate::apl::aps::apsme::{ApsmeBindError, ApsmeUnbindError, BindStatus, Binding, UnbindStatus};
use crate::apl::aps::constants::PARENT_ANNOUNCE_BASE_TIMER_SECONDS;
use crate::apl::aps::constants::PARENT_ANNOUNCE_JITTER_MAX_SECONDS;
use crate::apl::aps::types::{ApsEndpoint, ApsIndication};
use crate::apl::zb_application::{ZbApplication};
use crate::apl::zdo::{EndDeviceNodeCtx, ZbNode, ZbNodeJoinedStatus};
use crate::apl::zdp::ZDP_ENDPOINT;
use crate::apl::zdp::ZDP_PROFILE;
use crate::apl::zdp::types::TransactionData;
use crate::apl::zdp::types::ZdpClusterIds;
use crate::apl::zdp::types::ZdpCommand;
use crate::apl::zdp::types::descriptors::{ServerMask, SimpleDescriptor};
use crate::apl::zdp::types::discovery::ActiveEpReq;
use crate::apl::zdp::types::discovery::ActiveEpRsp;
use crate::apl::zdp::types::discovery::AddrRequestType;
use crate::apl::zdp::types::discovery::AddrRsp;
use crate::apl::zdp::types::discovery::AddrRspStatus;
use crate::apl::zdp::types::discovery::DescRspStatus;
use crate::apl::zdp::types::discovery::DeviceAnnce;
use crate::apl::zdp::types::discovery::IeeeAddrReq;
use crate::apl::zdp::types::discovery::MatchDescReq;
use crate::apl::zdp::types::discovery::MatchDescRsp;
use crate::apl::zdp::types::discovery::NodeDescReq;
use crate::apl::zdp::types::discovery::NodeDescRsp;
use crate::apl::zdp::types::discovery::NwkAddrReq;
use crate::apl::zdp::types::discovery::ParentAnnce;
use crate::apl::zdp::types::discovery::ParentAnnceRsp;
use crate::apl::zdp::types::discovery::ParentAnnceRspStatus;
use crate::apl::zdp::types::discovery::PowerDescReq;
use crate::apl::zdp::types::discovery::PowerDescRsp;
use crate::apl::zdp::types::discovery::SimpleDescReq;
use crate::apl::zdp::types::discovery::SimpleDescRsp;
use crate::apl::zdp::types::discovery::SimpleDescRspStatus;
use crate::apl::zdp::types::discovery::SystemServerDiscoveryReq;
use crate::apl::zdp::types::discovery::SystemServerDiscoveryRsp;
use crate::apl::zdp::types::network::MgmtPermitJoiningReq;
use crate::apl::zdp::types::network::MgmtPermitJoiningRsp;
use crate::common::bytes::WithLength;
use crate::zcl::cluster::types::ClusterType;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::DeviceType;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::apl::aps::ctx::{ApsListen, ApsTransmit, Apsme};
use crate::nwk::ctx::{BaseNwk, BaseNwkPrivate, InitializedNwk, JoinedNwk, JoinedState, Nwk};
use crate::nwk::nib::NwkNeighbor;

pub type ApsdeResult = Result<ApsdeSapConfirm, ApsdeError>;
pub type OptionalApsdeResult = Result<Option<ApsdeSapConfirm>, ApsdeError>;

pub fn to_optional(result: ApsdeResult) -> OptionalApsdeResult {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) => Err(err),
    }
}

enum StatusResult {
    ThisDevice(NwkAddress),
    Neighbour(NwkNeighbor),
    InvRequestType,
    DeviceNotFound,
}

async fn get_descriptor_for_endpoint(endpoint: ApsEndpoint, value: &ZbApplication) -> SimpleDescriptor {
    let value = value.lock().await;
    let (profile_id, device_id) = value.get_device().get_profile_and_device_ids();
    let input_clusters = value
        .get_clusters()
        .iter()
        .filter(|cluster| cluster.get_type() == ClusterType::Server)
        .map(|cluster| cluster.get_identifier())
        .collect::<zb_types::Vec<u16, 32>>();
    let output_clusters = value
        .get_clusters()
        .iter()
        .filter(|cluster| cluster.get_type() == ClusterType::Client)
        .map(|cluster| cluster.get_identifier())
        .collect::<zb_types::Vec<u16, 32>>();

    SimpleDescriptor {
        endpoint,
        application_profile_identifier: profile_id,
        application_device_identifier: device_id,
        application_device_version: value.get_version(),
        application_input_cluster_list: input_clusters,
        application_output_cluster_list: output_clusters,
    }
}

impl<J: ZbNodeJoinedStatus<D, S>, D: NwkMac, S: StorageRegion> ZbNode<J, D, S> {
    fn get_status_and_neighbours(
        &mut self,
        addr: NwkAddress,
    ) -> StatusResult {
        if addr == self.ctx.get_nwk().get_addr() {
            return StatusResult::ThisDevice(addr);
        }

        self.ctx.get_nwk().lock_neighbors(|nbs| {
            match nbs.children.iter().find(|item| item.nwk_addr == addr) {
                Some(neighbour) => StatusResult::Neighbour(neighbour.clone()),
                None => StatusResult::DeviceNotFound,
            }
        })
    }

    fn handle_extended_addr_request(
        &mut self,
        start_index: u8,
        rsp: &mut AddrRsp,
    ) -> () {
        let addr = self.ctx.get_nwk().get_addr();
        let ext_addr = self.ctx.get_nwk().get_ext_addr();

        let matches = self.ctx.get_nwk().lock_neighbors(|nbs| {
            nbs
                .children
                .iter()
                .filter(|item| item.device_type == DeviceType::EndDevice)
                .skip(start_index as usize)
                .map(|item| item.nwk_addr.get_value())
                .collect::<zb_types::Vec<u16, 255>>()
        });

        rsp.status = AddrRspStatus::Success;
        rsp.nwk_addr = addr;
        rsp.ieee_addr = ext_addr;
        rsp.num_assoc = Some(matches.len() as u16);
        rsp.start_index = Some(start_index);
        rsp.nwk_addr_assoc_dev_list = Some(matches);
    }

    async fn transmit_zdp_command(
        &mut self,
        dst: ApsdeAddress,
        transaction_data: TransactionData,
        sequence_number: Option<u8>,
    ) -> ApsdeResult {
        let cluster_id = transaction_data.discriminant();
        let sequence_number = sequence_number.unwrap_or(self.ctx.get_zcl_transaction_number());

        let cmd = ZdpCommand {
            transaction_sequence_number: sequence_number,
            transaction_data,
        };

        self.ctx.get_aps_mut().aps_data_request(
            ApsdeRequest {
                dst_address: dst,
                profile_id: ZDP_PROFILE,
                cluster_id,
                src_endpoint: ZDP_ENDPOINT,
                asdu: cmd,
                ..Default::default()
            },
        ).await
    }

    pub(crate) async fn handle_zdp_command(
        &mut self,
        indication: &ApsdeDataIndication,
    ) -> OptionalApsdeResult {
        let (cmd, _) = ZdpCommand::try_read(indication.asdu.as_slice(), indication.cluster_id)
            .map_err(|err| {
                log::warn!("[HANDLE-ZDP-CMD] couldn't parse zdp command for indication: {:?}", indication);
                ApsdeError::ByteError(err)
            })?;

        let seq = cmd.transaction_sequence_number;
        match cmd.transaction_data {
            TransactionData::NwkAddrReq(req) => {
                self.handle_nwk_addr_request(&req, indication, seq).await
            }
            TransactionData::IeeeAddrReq(req) => {
                self.handle_ieee_addr_request(&req, indication, seq).await
            }
            TransactionData::NodeDescReq(req) => {
                to_optional(self.handle_node_desc_request(&req, indication, seq).await)
            }
            TransactionData::PowerDescReq(req) => {
                to_optional(self.handle_power_desc_request(&req, indication, seq).await)
            }
            TransactionData::SimpleDescReq(req) => {
                to_optional(self.handle_simple_desc_request(&req, indication, seq).await)
            }
            TransactionData::ActiveEpReq(req) => {
                to_optional(self.handle_active_ep_request(&req, indication, seq).await)
            }
            TransactionData::MatchDescReq(req) => {
                self.handle_match_desc_request(&req, indication, seq).await
            }
            TransactionData::DeviceAnnce(req) => {
                self.handle_device_annce(&req, indication)
            }
            TransactionData::ParentAnnce(req) => self.handle_parent_annce(&req, indication, seq).await,
            TransactionData::SystemServerDiscoveryReq(req) => {
                self.handle_system_server_discovery_request(&req, indication, seq).await
            }
            TransactionData::BindReq(req) => self.handle_bind_request(&req, indication, seq).await,
            TransactionData::UnbindReq(req) => self.handle_unbind_request(&req, indication, seq).await,
            _ => {
                log::warn!(
                "ZDP command with cluster_id {:?} not implemented",
                indication.cluster_id
            );
                Err(ApsdeError::NotSupported(
                    "command not implemented for cluster",
                ))
            }
        }
    }

    async fn handle_addr_request_no_matches(
        &mut self,
        indication: &ApsdeDataIndication,
        transaction_data: TransactionData,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        match indication.dst.is_broadcast() {
            true => to_optional(
                self.transmit_zdp_command(indication.src, transaction_data, seq_number.into()).await,
            ),
            false => Ok(None),
        }
    }

    async fn handle_nwk_addr_request(
        &mut self,
        req: &NwkAddrReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        let mut rsp = AddrRsp {
            status: AddrRspStatus::DeviceNotFound,
            ieee_addr: req.ieee_address,
            nwk_addr: NwkAddress::MAX,
            ..Default::default()
        };

        match self.ctx.get_nwk().find_nwk_addr(req.ieee_address) {
            None => {
                self.handle_addr_request_no_matches(
                    indication,
                    TransactionData::NwkAddrRsp(rsp),
                    seq_number,
                )
                    .await
            }
            Some(addr) => {
                match req.request_type {
                    AddrRequestType::SingleDevice => {
                        rsp.status = AddrRspStatus::Success;
                        rsp.nwk_addr = addr;
                    }
                    AddrRequestType::ExtendedResponse(start_index) => {
                        self.handle_extended_addr_request(start_index, &mut rsp);
                    }
                };
                to_optional(
                    self.transmit_zdp_command(

                        indication.src,
                        TransactionData::NwkAddrRsp(rsp),
                        seq_number.into(),
                    )
                        .await,
                )
            }
        }
    }

    async fn handle_ieee_addr_request(
        &mut self,
        req: &IeeeAddrReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        let addr = req.nwk_addr_of_interest;
        let mut rsp = AddrRsp {
            status: AddrRspStatus::DeviceNotFound,
            ieee_addr: ExtendedAddress::MAX,
            nwk_addr: self.ctx.get_nwk().get_addr(),
            ..Default::default()
        };

        match self.ctx.get_nwk().find_ext_addr(addr) {
            None => {
                self.handle_addr_request_no_matches(
                    indication,
                    TransactionData::IeeeAddrRsp(rsp),
                    seq_number,
                )
                    .await
            }
            Some(addr) => {
                match req.request_type {
                    AddrRequestType::SingleDevice => {
                        rsp.status = AddrRspStatus::Success;
                        rsp.ieee_addr = addr;
                    }
                    AddrRequestType::ExtendedResponse(start_index) => {
                        self.handle_extended_addr_request(start_index, &mut rsp);
                    }
                }
                to_optional(
                    self.transmit_zdp_command(

                        indication.src,
                        TransactionData::IeeeAddrRsp(rsp),
                        seq_number.into(),
                    )
                        .await,
                )
            }
        }
    }

    pub(crate) async fn handle_node_desc_request(
        &mut self,
        req: &NodeDescReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> ApsdeResult {
        let mut rsp = NodeDescRsp {
            status: Default::default(),
            nwk_addr: req.nwk_addr_of_interest,
            node_descriptor: None,
        };

        match self.get_status_and_neighbours(req.nwk_addr_of_interest) {
            StatusResult::ThisDevice(_) => {
                rsp.status = DescRspStatus::Success;
                rsp.node_descriptor = self.config.get_node_descriptor().into();
            }
            StatusResult::Neighbour(_) => rsp.status = DescRspStatus::NoDescriptor, // TODO
            StatusResult::InvRequestType => rsp.status = DescRspStatus::InvRequestType,
            StatusResult::DeviceNotFound => rsp.status = DescRspStatus::DeviceNotFound,
        }

        self.transmit_zdp_command(
            indication.src,
            TransactionData::NodeDescRsp(rsp),
            seq_number.into(),
        )
            .await
    }

    pub(crate) async fn emit_node_desc_request(
        &mut self,
        nwk_addr_of_interest: NwkAddress,
        seq_number: u8,
    ) -> ApsdeResult {
        let node_desc_req = NodeDescReq {
            nwk_addr_of_interest,
        };

        self.transmit_zdp_command(
            ApsdeAddress::Network(nwk_addr_of_interest, ZDP_ENDPOINT),
            TransactionData::NodeDescReq(node_desc_req),
            seq_number.into(),
        )
            .await
    }

    // TODO: JOIN with upper func
    // async fn _node_descriptor_request(
    // &mut self
    // ) -> Result<(), ApsdeSapError>{
    // let timeout = Duration::from_secs(10);
    // let cmd = self._wait_for_indication(timeout, |indication| {
    // return match indication {
    // ApsIndication::Data(
    // ApsdeDataIndication {
    // profile_id: 0,
    // cluster_id: ZdpClusterIds::NODE_DESC_RSP,
    // asdu,
    // asdu_length,
    // ..
    // }) => {
    // log::info!("RECEIVED RESPONSE!");
    // Some(NodeDescRsp::try_read(&asdu[1..asdu_length], ()).unwrap().0)
    // }
    // _ => None,
    // }
    // }).await.map_err(|err| ApsdeSapError::NotSupported)?;
    //
    // log::info!("received node_desc_rsp: {:?}", cmd);
    //
    // Ok(())
    // }

    async fn handle_power_desc_request(
        &mut self,
        req: &PowerDescReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> ApsdeResult {
        let mut rsp = PowerDescRsp {
            status: Default::default(),
            nwk_addr: req.nwk_addr_of_interest,
            power_descriptor: None,
        };

        match self.get_status_and_neighbours(req.nwk_addr_of_interest) {
            StatusResult::ThisDevice(_) => {
                rsp.status = DescRspStatus::Success;
                rsp.power_descriptor = self.config.get_power_descriptor().into();
            }
            StatusResult::Neighbour(_) => rsp.status = DescRspStatus::NoDescriptor, // TODO
            StatusResult::InvRequestType => rsp.status = DescRspStatus::InvRequestType,
            StatusResult::DeviceNotFound => rsp.status = DescRspStatus::DeviceNotFound,
        }

        self.transmit_zdp_command(

            indication.src,
            TransactionData::PowerDescRsp(rsp),
            seq_number.into(),
        )
            .await
    }

    async fn handle_simple_desc_request(
        &mut self,
        req: &SimpleDescReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> ApsdeResult {
        let mut rsp = SimpleDescRsp {
            status: SimpleDescRspStatus::InvalidEp,
            nwk_addr: req.nwk_addr_of_interest,
            simple_descriptor: WithLength::NONE,
        };

        if req.endpoint.get() == 0 || req.endpoint.get() > 240 {
            return self.transmit_zdp_command(
                indication.src,
                TransactionData::SimpleDescRsp(rsp),
                seq_number.into(),
            ).await;
        }

        match self.get_status_and_neighbours(req.nwk_addr_of_interest) {
            StatusResult::ThisDevice(_) => match self.applications.get(&req.endpoint) {
                Some(value) => {
                    let desc = get_descriptor_for_endpoint(req.endpoint, value).await;

                    rsp.status = SimpleDescRspStatus::Success;
                    rsp.simple_descriptor = WithLength::new(desc);
                }
                None => {
                    rsp.status = SimpleDescRspStatus::InvalidEp;
                    rsp.simple_descriptor = WithLength::NONE;
                }
            },
            StatusResult::Neighbour(_) => rsp.status = SimpleDescRspStatus::NoDescriptor,
            StatusResult::InvRequestType => rsp.status = SimpleDescRspStatus::InvRequestType,
            StatusResult::DeviceNotFound => rsp.status = SimpleDescRspStatus::DeviceNotFound,
        }

        self.transmit_zdp_command(
            indication.src,
            TransactionData::SimpleDescRsp(rsp),
            seq_number.into(),
        ).await
    }

    async fn handle_active_ep_request(
        &mut self,
        req: &ActiveEpReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> ApsdeResult {
        let mut rsp = ActiveEpRsp {
            status: Default::default(),
            nwk_addr: req.nwk_addr_of_interest,
            active_ep_list: Default::default(),
        };

        match self.get_status_and_neighbours(req.nwk_addr_of_interest) {
            StatusResult::ThisDevice(_) => {
                rsp.status = DescRspStatus::Success;
                rsp.active_ep_list = self.applications
                    .keys()
                    .map(|key| *key)
                    .collect::<zb_types::Vec<_, _>>();
            }
            StatusResult::Neighbour(_) => rsp.status = DescRspStatus::NoDescriptor,
            StatusResult::InvRequestType => rsp.status = DescRspStatus::InvRequestType,
            StatusResult::DeviceNotFound => rsp.status = DescRspStatus::DeviceNotFound,
        }

        log::info!("handle_active_ep_request: {:?}", rsp);
        self.transmit_zdp_command(
            indication.src,
            TransactionData::ActiveEpRsp(rsp),
            seq_number.into(),
        ).await
    }

    async fn handle_match_desc_request(
        &mut self,
        req: &MatchDescReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        fn descriptor_matches_request(desc: &SimpleDescriptor, req: &MatchDescReq) -> bool {
            if desc.application_profile_identifier != req.profile_id && req.profile_id != u16::MAX {
                false
            } else if req
                .in_cluster_list
                .iter()
                .any(|item| desc.application_input_cluster_list.contains(item))
            {
                true
            } else if req
                .out_cluster_list
                .iter()
                .any(|item| desc.application_output_cluster_list.contains(item))
            {
                true
            } else {
                false
            }
        }

        let addr = req.nwk_addr_of_interest;
        let local_addr = self.ctx.get_nwk().get_addr();

        let mut rsp = MatchDescRsp {
            status: DescRspStatus::InvRequestType,
            nwk_addr: req.nwk_addr_of_interest,
            match_list: Default::default(),
        };

        if self.ctx.get_nwk().is_end_device() && addr != local_addr && !addr.is_broadcast() {
            return if indication.dst.is_broadcast() {
                Ok(None)
            } else {
                to_optional(
                    self.transmit_zdp_command(
                        indication.src,
                        TransactionData::MatchDescRsp(rsp),
                        seq_number.into(),
                    )
                        .await,
                )
            };
        }

        if addr == local_addr || addr.is_broadcast() {
            for (ep, cluster) in self.applications.clone() {
                let desc = get_descriptor_for_endpoint(ep, &cluster).await;
                if descriptor_matches_request(&desc, req) {
                    rsp.match_list.push(ep).unwrap();
                }
            }
        } else {
            self.ctx.get_nwk().lock_neighbors(|nbs| {
                match nbs
                    .children
                    .iter()
                    .find(|item| item.device_type == DeviceType::EndDevice && item.nwk_addr == addr)
                {
                    Some(child) => {
                        for (ep, desc) in &child.simple_descriptors {
                            if descriptor_matches_request(desc, req) {
                                rsp.match_list.push(*ep).unwrap();
                            }
                        }

                        rsp.status = if rsp.match_list.len() > 0 {
                            DescRspStatus::Success
                        } else {
                            DescRspStatus::NoDescriptor
                        };
                    }
                    None => {
                        rsp.status = DescRspStatus::DeviceNotFound;
                    }
                };
            });

            if self.ctx.get_nwk().is_router() {
                return to_optional(
                    self.transmit_zdp_command(
                        indication.src,
                        TransactionData::MatchDescRsp(rsp),
                        seq_number.into(),
                    )
                        .await,
                );
            }
        }

        if rsp.match_list.len() == 0 && addr.is_broadcast() {
            return Ok(None);
        }

        rsp.status = DescRspStatus::Success;
        to_optional(
            self.transmit_zdp_command(
                indication.src,
                TransactionData::MatchDescRsp(rsp),
                seq_number.into(),
            )
                .await,
        )
    }

    // 3.6.2.3
    // When an end device joins or rejoins it will broadcast a ZDO Device_annce,
    // which in turn will be processed as follows:
    // 1. Search the neighbor table for an entry where the IEEEAddr in the ZDO
    //    Device_annce command
    // frame matches the Extended Address field of the neighbor table entry and the
    // Device Type field in the neighbor table entry is equal to End Device (0x02).
    // 2. If no such entry is found, skip to step 4.
    // 3. If an entry is found and the Device_Annce was broadcast, examine the
    //    nwkBroadcastTransac-
    // tionTable. If there is no entry in the nwkBroadcastTransactionTable for this
    // message, this indicates the message was relayed by another device on the
    // network acting as the end device’s router parent.
    // a. Delete the neighbor table entry with the corresponding Extended Address
    // equal to the IEEEAddr in the Device_Annce command.
    // 4. Continue processing the Device_Annce message.
    pub(crate) fn handle_device_annce(
        &mut self,
        req: &DeviceAnnce,
        indication: &ApsdeDataIndication,
    ) -> OptionalApsdeResult {
        match self.ctx.get_nwk().lock_neighbors(|nbs| {
            nbs.find_by_ext_addr_and_type(req.ieee_addr, DeviceType::EndDevice).is_some() && indication.dst.is_broadcast()
        }) {
            true => {
                if let ApsdeAddress::Group(addr) = indication.src {
                    if self.ctx.get_nwk()
                        .get_broadcast_transaction_table()
                        .iter()
                        .find(|rec| rec.source_address == addr) // TODO: Check how to get the NKW frame's sequence number here
                        .is_none()
                    {
                        self.ctx.get_nwk_mut().lock_neighbors_mut(|nbs| {
                            nbs.children.retain(|nb| nb.ext_addr != Some(req.ieee_addr))
                        });
                    }
                }
            }
            false => self.ctx.get_nwk_mut().get_addr_map_mut().insert(req.nwk_addr, req.ieee_addr),
        };

        Ok(None)
    }

    pub(crate) async fn emit_device_annce(
        &mut self,
    ) -> ApsdeResult {
        let annce = DeviceAnnce {
            nwk_addr: self.ctx.get_nwk().get_addr(),
            ieee_addr: self.ctx.get_nwk().get_ext_addr(),
            capability: self.config.get_capabilities(),
        };

        self.transmit_zdp_command(

            ApsdeAddress::Network(NwkAddress::BROADCAST_RX_ON_IDLE, ZDP_ENDPOINT),
            TransactionData::DeviceAnnce(annce),
            None,
        )
            .await
    }

    async fn handle_parent_annce(
        &mut self,
        req: &ParentAnnce,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        let mut rsp = ParentAnnceRsp {
            status: ParentAnnceRspStatus::Success,
            children: Default::default(),
        };

        match self.ctx.get_nwk().lock_neighbors(|nbs| {
            rsp.children = nbs
                .children
                .iter()
                .filter(|item| item.ext_addr.is_some())
                .filter(|item| {
                    req.children.contains(&item.ext_addr.unwrap())
                        && item.device_type == DeviceType::EndDevice
                        && item.keepalive_received
                })
                .map(|item| item.ext_addr.unwrap())
                .collect::<zb_types::Vec<ExtendedAddress, 32>>();

            rsp.children.len()
        }) {
            0 => return Ok(None),
            _ => {}
        }

        let jitter = self.ctx.get_nwk_mut().get_rng().random_range(0.0..PARENT_ANNOUNCE_JITTER_MAX_SECONDS);
        self.ctx.get_aps_mut().set_parent_announce_timer(PARENT_ANNOUNCE_BASE_TIMER_SECONDS + jitter);

        to_optional(
            self.transmit_zdp_command(
                indication.src,
                TransactionData::ParentAnnceRsp(rsp),
                seq_number.into(),
            )
                .await,
        )
    }

    fn emit_parent_annce() -> () {
        todo!()
    }

    async fn handle_system_server_discovery_request(
        &mut self,
        req: &SystemServerDiscoveryReq,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        let value = self.config.get_server_mask().get_value() & req.server_mask.get_value();
        if value == 0 {
            Ok(None)
        } else {
            to_optional(
                self.transmit_zdp_command(
                    indication.src,
                    TransactionData::SystemServerDiscoveryRsp(SystemServerDiscoveryRsp {
                        mask: ServerMask::new(value),
                    }),
                    seq_number.into(),
                )
                    .await,
            )
        }
    }

    // NETWORK MANAGEMENT COMMANDS

    pub async fn emit_permit_joining_req(
        &mut self,
        req: MgmtPermitJoiningReq,
        destination: ApsdeAddress,
    ) -> Result<MgmtPermitJoiningRsp, ApsdeError> {
        self.transmit_zdp_command(
            destination,
            TransactionData::MgmtPermitJoiningReq(req),
            None,
        )
            .await?;

        let timeout = Duration::from_secs(1);
        self.ctx.get_aps_mut().wait_for_indication(timeout, |indication| {
            return match indication {
                ApsIndication::Data(ApsdeDataIndication {
                                        profile_id: 0,
                                        cluster_id: ZdpClusterIds::MGMT_PERMIT_JOINING_RSP,
                                        asdu,
                                        ..
                                    }) => Some(
                    MgmtPermitJoiningRsp::try_read(asdu.as_slice(), byte::LE)
                        .unwrap()
                        .0,
                ),
                _ => None,
            };
        })
            .await
            .map_err(|err| {
                log::warn!("unsuccessful mgmt_permit_joining_req: {:?}", err);
                ApsdeError::NotSupported("permit joining didn't succeed")
            })
    }

    // ---------------------------

    // BIND MANAGEMENT COMMANDS

    pub async fn handle_bind_request(
        &mut self,
        binding: &Binding,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        if indication.dst.is_broadcast() {
            return Ok(None);
        }

        let status = match self.ctx.get_aps_mut().bind_request(*binding) {
            Ok(_) => BindStatus::Success,
            Err(err) => match err {
                ApsmeBindError::TableFull => BindStatus::TableFull,
            }
        };

        to_optional(
            self.transmit_zdp_command(
                indication.src,
                TransactionData::BindRsp(status),
                seq_number.into(),
            )
                .await,
        )
    }

    pub async fn handle_unbind_request(
        &mut self,
        binding: &Binding,
        indication: &ApsdeDataIndication,
        seq_number: u8,
    ) -> OptionalApsdeResult {
        if indication.dst.is_broadcast() {
            return Ok(None);
        }

        let status = match self.ctx.get_aps_mut().unbind_request(*binding) {
            Ok(_) => UnbindStatus::Success,
            Err(err) => match err {
                ApsmeUnbindError::IllegalRequest => UnbindStatus::NotAuthorized,
                ApsmeUnbindError::InvalidBinding => UnbindStatus::NoEntry,
            }
        };

        to_optional(
            self.transmit_zdp_command(
                indication.src,
                TransactionData::UnbindRsp(status),
                seq_number.into(),
            )
                .await,
        )
    }

    // ---------------------------
}

