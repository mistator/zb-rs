use bounded_integer::BoundedU8;
use embassy_time::WithTimeout;
use embassy_time::{Duration, TimeoutError};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::apl::aps::apsde::{ApsdeAddress, ApsdeError};
use crate::apl::aps::ctx::{APS_STORAGE_SIZE, ApsContext};
use crate::apl::aps::security::sap::errors::ApsmeSecurityError;
use crate::apl::aps::security::sap::service::ApsSecurityResult;
use crate::apl::aps::security::types::commands::ConfirmKeyStatus;
use crate::apl::aps::security::types::common::{KeyAttribute, LinkKeyType, RequestKeyType, TransportKeyData};
use crate::apl::aps::security::types::indications::ApsmeTransportKeyIndication;
use crate::apl::aps::types::ApsIndication;
use crate::apl::aps::types::{ApsAddress, ApsEndpoint};
use crate::apl::zb_application::{APPLICATIONS_SR_SIZE, ZbApplications, ZbApplicationsDef, ZbApplicationsMap};
use crate::apl::zdo::config::ZbConfig;
use crate::apl::zdp::ZDP_ENDPOINT;
use crate::apl::zdp::types::network::MgmtPermitJoiningReq;
use crate::bdb::constants::{MIN_COMMISSIONING_TIME, REC_SAME_NETWORK_RETRY_ATTEMPTS};
use crate::common::security::SecurityNetworkParams;
use crate::mac::mlme::Mlme;
use crate::nwk::ctx;
use crate::nwk::ctx::{EndDevice, Initialized, NWK_STORAGE_SIZE, NetworkSecurityMaterialDescriptor, Nwk, NwkInitialized, NwkJoined, TransitionError, TransitionResult, Uninitialized};
use crate::nwk::nib::{NetworkKeyType};
use crate::nwk::nlme::{NlmeAssociationJoinRequest, NlmeRejoinRequest, PermitJoiningConfig, ScanDuration, ScanRequest};
use crate::zcl::cluster::types::MAX_ATTRIBUTES_PER_CLUSTER;
use crate::zcl::command::global::AttributeRecord;
use crate::zcl::command::global::ReportAttributesCommand;
use crate::zcl::frame::ZclDirection;
use crate::zcl::service::EmitCommandFrameCfg;
use crate::zcl::service::RequestCfg;
use crate::unwrap_or_return;
use zb_hal::{NwkMac, StoragePool, StorageRegion};
use zb_types::common::NwkAddress;
use zb_types::mac::ChannelMask;

pub struct ZbContext<N: NwkJoined, S: StorageRegion> {
    pub aps: Option<ApsContext<N, S>>,
    pub spawner: embassy_executor::Spawner,
    pub rng: SmallRng,
}

pub trait ZbNodeStatus {}

pub struct UnjoinedCtx<D: NwkMac, S: StorageRegion> {
    nwk: Nwk<Uninitialized, D, S>,
    aps_stg: S,
}
impl<D: NwkMac, S: StorageRegion> ZbNodeStatus for UnjoinedCtx<D, S> {}

trait Joined : ZbNodeStatus {}
pub struct JoinedCtx<N: NwkJoined, S: StorageRegion> {
    zcl_transaction_number: u8,
    pub aps: ApsContext<N, S>
}
impl<N: NwkJoined, S: StorageRegion> ZbNodeStatus for JoinedCtx<N, S> {}

pub struct ZbNode<C: ZbNodeStatus, S: StorageRegion> {
    pub config: ZbConfig,
    pub spawner: embassy_executor::Spawner,
    pub applications: ZbApplications<S>,

    pub ctx: C
}

pub enum InitializedNode<D, N, S>
where
    D: NwkMac,
    N: NwkJoined,
    S: StorageRegion,
{
    Unjoined(ZbNode<UnjoinedCtx<D, S>, S>),
    Joined(ZbNode<JoinedCtx<N, S>, S>)
}

pub async fn initialize<D, P, S>(
    config: ZbConfig,
    spawner: embassy_executor::Spawner,
    applications: ZbApplicationsDef,
    mac: Mlme<D>,
    mut pool: P,
) -> InitializedNode<D, Nwk<Initialized<ctx::Joined<EndDevice>>, D, S>, S>
where
    D: NwkMac + Sync,
    P: StoragePool<S = S>,
    S: StorageRegion + Sync,
{

    log::info!("initializing device...");

    let nwk_stg = pool.reserve_region(NWK_STORAGE_SIZE as u32).unwrap();
    let aps_stg = pool.reserve_region(APS_STORAGE_SIZE as u32).unwrap();
    let apps_stg = pool.reserve_region(APPLICATIONS_SR_SIZE as u32).unwrap();

    let mut apps = ZbApplicationsMap::new(applications, apps_stg);
    apps.load_all().await;

    match Nwk::<Uninitialized, _, _>::load(mac, nwk_stg).await {
        Ok(nwk) => {
            if config.is_end_device() {
                let request = NlmeRejoinRequest {
                    ext_pan_id: nwk.get_ext_pan_id(),
                    channels: &[config.primary_channel_set],
                    scan_duration: ScanDuration::new(8).unwrap(),
                    capability_information: Default::default(),
                };

                log::info!("device is already on a network, rejoining...");
                match nwk.rejoin(&request).await {
                    Ok(nwk) => {
                        let aps_ctx = ApsContext::load_or_default(nwk, aps_stg).await;
                        let mut node = ZbNode {
                            config,
                            spawner,
                            applications: apps,
                            ctx: JoinedCtx {
                                zcl_transaction_number: 0,
                                aps: aps_ctx,
                            },
                        };

                        node.emit_device_annce().await.ok();
                        node.ctx.aps.persist().await.ok();

                        InitializedNode::Joined(node)
                    }
                    Err(err) => {
                        InitializedNode::Unjoined(ZbNode::<UnjoinedCtx<D, S>, S> {
                            config,
                            spawner,
                            applications: apps,
                            ctx: UnjoinedCtx {
                                nwk: Nwk {
                                    mac: err.state.mac,
                                    stg: err.state.stg,
                                    rng: SmallRng::seed_from_u64(0),
                                    seq_number: 0,
                                    ctx: ctx::Uninitialized,
                                },
                                aps_stg,
                            },
                        })
                    }
                }
            } else {
                let aps = ApsContext::load_or_default(nwk.make_end_device(), aps_stg).await;

                InitializedNode::Joined(ZbNode {
                    config,
                    spawner,
                    applications: apps,
                    ctx: JoinedCtx {
                        zcl_transaction_number: 0,
                        aps,
                    },
                })
            }
        },
        Err(cfg) => {
            if config.is_router_or_coordinator() && config.touchlink_supported {
                // select a channel from bdbcTLPrimaryChannelSet
            }

            InitializedNode::Unjoined(ZbNode {
                config,
                spawner,
                applications: apps,
                ctx: UnjoinedCtx {
                    nwk: Nwk {
                        mac: cfg.mac,
                        stg: cfg.stg,
                        rng: SmallRng::seed_from_u64(0),
                        seq_number: 0,
                        ctx: ctx::Uninitialized,
                    },
                    aps_stg,
                },
            })
        }
    }
}

type ZbNodeTransition<D, N, S> =
    TransitionResult<
        ZbNode<UnjoinedCtx<D, S>, S>,
        ZbNode<JoinedCtx<N, S>, S>,
        ()>;

impl<D, S> ZbNode<UnjoinedCtx<D, S>, S>
where
    D: NwkMac + Sync,
    S: StorageRegion + Sync,
{
    pub async fn network_steering(mut self) -> ZbNodeTransition<D, Nwk<Initialized<ctx::Joined<EndDevice>>, D, S>, S> {
        let primary_channel_set = self.config.primary_channel_set;
        let secondary_channel_set = self.config.secondary_channel_set;

        match self.try_join_for_channels(primary_channel_set).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                self = err.state;
            }
        }

        match self.try_join_for_channels(secondary_channel_set).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                self = err.state;
            }
        }

        Err(TransitionError {
            state: self,
            error: (),
        })
    }

    async fn try_join_for_channels(mut self, scan_channels: ChannelMask) -> ZbNodeTransition<D, Nwk<Initialized<ctx::Joined<EndDevice>>, D, S>, S> {
        let request = ScanRequest {
            channel_masks: &[scan_channels],
            duration: self.config.scan_duration,
        };

        let result = match self.ctx.nwk.network_discovery(&request).await {
            Ok(value) => value,
            Err(_) => {
                return TransitionError::err(self, ())
            }
        };

        for nd in result.iter().filter(|nd| nd.is_permit_joining()) {
            let mut retry_counter = 0;
            while retry_counter < REC_SAME_NETWORK_RETRY_ATTEMPTS {
                let req = NlmeAssociationJoinRequest {
                    capability_information: self.config.get_capabilities()
                };

                log::warn!("trying to connect to nd: {:?}", nd);
                match self.ctx.nwk.association_join(nd, req).await {
                    Ok(value) => {
                        let ctx = ApsContext::load_or_default(value, self.ctx.aps_stg).await;

                        let mut node = ZbNode::<JoinedCtx<Nwk<Initialized<ctx::Joined<EndDevice>>, D, S>, S>, S> {
                            config: self.config,
                            spawner: self.spawner,
                            applications: self.applications,
                            ctx: JoinedCtx {
                                zcl_transaction_number: 0,
                                aps: ctx,
                            },
                        };

                        log::info!("NLME-JOIN successful, waiting for network key...");
                        let result = node.wait_for_nwk_key().await;
                        return if result.is_err() {
                            log::warn!("couldn't obtain network key, resetting...");
                            // nlme::reset(nwk_ctx, false).await;

                            TransitionError::err(ZbNode {
                                config: self.config,
                                spawner: self.spawner,
                                applications: node.applications,
                                ctx: UnjoinedCtx {
                                    nwk: node.ctx.aps.nwk.reset(),
                                    aps_stg: node.ctx.aps.stg,
                                },
                            }, ())
                        } else {
                            log::info!("obtained network key, we are authorized");
                            node.ctx.aps.is_authorized = true;
                            if node.emit_device_annce().await.is_err() {
                                log::warn!("couldn't emit device annce");
                                return TransitionError::err(node.to_unjoined(), ());
                            }

                            log::info!("security_network_params: {:?}", node.ctx.aps.security_network_params);
                            match node.ctx.aps.security_network_params {
                                SecurityNetworkParams::Centralized(_) => {
                                    log::info!("updating trust center link key");
                                    match node.update_trust_center_link_key().await {
                                        Ok(_) => {}
                                        Err(err) => {
                                            log::warn!("couldn't update trust center link key, got error: `{:?}`. Resetting...", err);
                                            let nwk = node.ctx.aps.nwk.leave(false).await;
                                            return TransitionError::err(ZbNode {
                                                config: node.config,
                                                spawner: node.spawner,
                                                applications: node.applications,
                                                ctx: UnjoinedCtx {
                                                    nwk,
                                                    aps_stg: node.ctx.aps.stg,
                                                },
                                            }, ());
                                        }
                                    }
                                }
                                SecurityNetworkParams::Distributed => {}
                            }

                            match node.emit_permit_joining_req(
                                MgmtPermitJoiningReq::Enable(MIN_COMMISSIONING_TIME.as_secs() as u8),
                                ApsdeAddress::Network(NwkAddress::BROADCAST_ALL, ZDP_ENDPOINT),
                            )
                                .await
                            {
                                Err(err) => log::warn!("error sending MgmtPermitJoiningReq: {:?}", err),
                                _ => {}
                            };

                            if node.ctx.aps.nwk.is_router() {
                                // Activate permit joining
                            }

                            Ok(node)
                        }
                    }
                    Err(err) => {
                        self.ctx.nwk = err.state;
                        retry_counter += 1;
                    }
                }
            }
        }

        TransitionError::err(self, ())
    }
}

impl<D, S> ZbNode<JoinedCtx<Nwk<Initialized<ctx::Joined<EndDevice>>, D, S>, S>, S>
where
    D: NwkMac + Sync,
    S: StorageRegion + Sync,
{
    fn to_unjoined(self) -> ZbNode<UnjoinedCtx<D, S>, S> {
        let nwk = self.ctx.aps.nwk;

        ZbNode {
            config: self.config,
            spawner: self.spawner,
            applications: self.applications,
            ctx: UnjoinedCtx {
                nwk: Nwk {
                    mac: nwk.mac,
                    stg: nwk.stg,
                    rng: nwk.rng,
                    seq_number: nwk.seq_number,
                    ctx: Uninitialized,
                },
                aps_stg: self.ctx.aps.stg,
            }
        }
    }
}

impl<N, S> ZbNode<JoinedCtx<N, S>, S>
where
    N: NwkJoined,
    S: StorageRegion,
{
    pub fn get_zcl_transaction_number(&mut self) -> u8 {
        self.ctx.zcl_transaction_number = self.ctx.zcl_transaction_number.wrapping_add(1);
        self.ctx.zcl_transaction_number
    }

    async fn wait_for_nwk_key(&mut self) -> Result<(), TimeoutError> {
        let timeout = self.ctx.aps.nwk.get_profile().aps_security_timeout_period;

        let (ext_src_addr, key_data) =
            self.ctx.aps.wait_for_indication(timeout, |indication| match indication {
                ApsIndication::TransportKey(ApsmeTransportKeyIndication {
                                                ext_src_addr,
                                                transport_key: TransportKeyData::StandardNetworkKey(key_data),
                                            }) => Some((*ext_src_addr, *key_data)),
                _ => None,
            })
                .await?;

        match self.ctx.aps
            .device_key_pair_set
            .iter_mut()
            .find(|ref key| key.link_key_type == LinkKeyType::GlobalLinkKey)
        {
            Some(key) => key.device_address = ext_src_addr,
            _ => {
                log::error!("could not find global link key");
            }
        }

        self.ctx.aps.nwk
            .get_security_material_set_mut()
            .push(NetworkSecurityMaterialDescriptor {
                key_seq_number: key_data.key_sequence,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: Default::default(),
                key: key_data.key,
                network_key_type: NetworkKeyType::Standard,
            }).unwrap();

        Ok(())
    }

    async fn update_trust_center_link_key(&mut self) -> ApsSecurityResult {
        let tc_addr = unwrap_or_return!(self.ctx.aps.get_tc_addr(), Ok(()));
        self.ctx.aps.request_key(tc_addr, RequestKeyType::TrustCenterLinkKey).await?;

        let timeout = self.ctx.aps.nwk.get_profile().aps_security_timeout_period;
        let (ext_src_addr, key_data) =
            self.ctx.aps.wait_for_indication(timeout, |indication| match indication {
                ApsIndication::TransportKey(
                    ApsmeTransportKeyIndication {
                        ext_src_addr,
                        transport_key: TransportKeyData::TrustCenterLinkKey(key_data),
                        ..
                    }
                ) => Some((*ext_src_addr, *key_data)),
                _ => None,
            }).await.map_err(|err| {
                log::warn!("error receiving transport_key: {:?}", err);
                ApsmeSecurityError::CommandValidationError
            })?;

        let desc = self.ctx.aps
            .device_key_pair_set
            .iter_mut()
            .find(|desc| desc.device_address == ext_src_addr)
            .unwrap();

        desc.key_attributes = KeyAttribute::UnverifiedKey;
        desc.link_key = key_data.key;
        desc.link_key_type = LinkKeyType::UniqueLinkKey;

        self.ctx.aps.verify_key().await?;

        let indication = self.ctx.aps.wait_for_indication(timeout, |indication| match indication {
            ApsIndication::ConfirmKey(indication) => Some(*indication),
            _ => None,
        })
            .await
            .map_err(|err| {
                log::warn!("error waiting for confirmation: {:?}", err);
                ApsmeSecurityError::CommandValidationError
            })?;

        if indication.status != ConfirmKeyStatus::Success {
            return Err(ApsmeSecurityError::CommandValidationError);
        }

        Ok(())
    }

    async fn network_steering(&mut self) -> Result<(), ApsdeError> {
        let req = MgmtPermitJoiningReq::Enable(MIN_COMMISSIONING_TIME.as_secs() as u8);
        let address = ApsdeAddress::Network(NwkAddress::BROADCAST_ALL, ZDP_ENDPOINT);
        self.emit_permit_joining_req(req, address).await?;

        if self.ctx.aps.nwk.is_router() {
            let period = BoundedU8::<1, 254>::new(MIN_COMMISSIONING_TIME.as_secs() as u8).unwrap();
            self.ctx.aps.nwk.permit_joining(PermitJoiningConfig::EnabledForPeriod(period)).ok();
        }

        Ok(())
    }

    pub async fn start(&mut self) -> ! {
        let applications = self.applications.clone();

        let listen = async {
            loop {
                _ = self.listen()
                    .with_timeout(Duration::from_secs(1))
                    .await;

                let reports = self.get_report().await;

                {
                    for ((src_endpoint, profile_id, cluster_id), cmd) in reports {
                        _ = self.emit_report_attributes(
                            cmd,
                            EmitCommandFrameCfg {
                                direction: ZclDirection::ClientToServer,
                                ..Default::default()
                            },
                            RequestCfg {
                                dst_address: Default::default(),
                                profile_id,
                                cluster_id,
                                src_endpoint,
                            },
                        )
                            .await;
                    }
                }
            }
        };

        let update_apps = async {
            let mut ticker = embassy_time::Ticker::every(Duration::from_millis(100));
            let mut counter = 0u64;

            loop {
                for application in applications.values() {
                    let mut application = application.lock().await;
                    application.update(counter);
                }

                counter += 1;
                ticker.next().await;
            }
        };

        embassy_futures::join::join(listen, update_apps).await;
        unreachable!();
    }

    async fn get_report(&self) -> zb_types::HashMap<(ApsEndpoint, u16, u16), ReportAttributesCommand, MAX_ATTRIBUTES_PER_CLUSTER> {
        let mut responses = zb_types::HashMap::new();

        for (ep, application) in self.applications.iter() {
            let mut application = application.lock().await;
            let profile = application.get_profile();

            for cluster in application.get_clusters_mut() {
                let cluster_identifier = cluster.get_identifier();
                let mut cmd = ReportAttributesCommand::default();

                let mut attributes = cluster.get_reportable_attributes_mut();
                attributes.values_mut().for_each(|attr| {
                    if attr.should_report() {
                        cmd.attributes
                            .push(AttributeRecord {
                                identifier: attr.get_identifier(),
                                data: attr.get_zcl_data(),
                            })
                            .ok();
                    }
                });

                if !cmd.attributes.is_empty() {
                    responses.insert((*ep, profile, cluster_identifier), cmd).unwrap();
                }
            }
        }

        responses
    }

    pub async fn listen(&mut self) -> ! {
        loop {
            let indication = self.ctx.aps.wait_for_indication_no_timeout(|ind| match ind {
                ApsIndication::Data(indication) => Some((*indication).clone()),
                _ => None,
            })
                .await;

            log::debug!("received indication: {:?}", indication);

            match indication.dst {
                ApsAddress::Network(_, endpoint) => {
                    if endpoint == ZDP_ENDPOINT {
                        _ = self.handle_zdp_command(&indication)
                            .await
                            .map_err(|err| log::warn!("error handling zdp_command: {:?}", err));
                    } else {
                        _ = self.handle_zcl_command(endpoint, &indication)
                            .await
                            .map_err(|err| log::warn!("error handling zcl_command: {:?}", err));
                    }

                }
                _ => {}
            };
        }
    }

}



pub mod config;
