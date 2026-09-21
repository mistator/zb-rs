use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::AtomicU8;
use embassy_futures::select::{select, Either, select3, Either3};
use embassy_time::{Timer, WithTimeout};
use embassy_time::{Duration, TimeoutError};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::apl::aps::apsde::{ApsdeAddress};
use crate::apl::aps::ctx::{Aps, APS_STORAGE_SIZE, ApsListen, Apsme, Apsde, ApsmeSecurity};
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
use crate::nwk::ctx::{BaseNwk, InitializedNwk, Nwk, NwkConfig, NwkContext, PendingJoin, RoutingState, Uninitialized, NWK_STORAGE_SIZE, JoinedState, JoinedAsRouter, BaseNwkPrivate};
use crate::nwk::nib::{NetworkKeyType, NetworkSecurityMaterialDescriptor};
use crate::nwk::nlme::{NlmeAssociationJoinRequest, NlmeRejoinRequest, ScanDuration, ScanRequest};
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
use zb_types::transitions::{TransitionError, TransitionResult};
use crate::nwk::commands::end_device_timeout_request::{end_device_keepalive_task, DeviceTimeout, EndDeviceKeepaliveTask};
use crate::nwk::commands::link_status::{link_status_task, LinkStatusTaskParams};
use crate::nwk::ctx::{JoinedAsEndDevice, JoinedNwk};
use crate::nwk::nlde::NlmeLeaveIndication;

pub trait ZbNodeStatus {}
pub trait ZbNodeJoinedStatus<D: NwkMac, S: StorageRegion> : ZbNodeStatus {
    fn get_aps(&self) -> &(impl Apsde + Apsme + ApsmeSecurity);
    fn get_aps_mut(&mut self) -> &mut (impl Apsde + Apsme + ApsmeSecurity);
    fn get_nwk(&self) -> &impl JoinedNwk<D, S>;
    fn get_nwk_mut(&mut self) -> &mut impl JoinedNwk<D, S>;
    fn get_zcl_transaction_number(&mut self) -> u8;
    fn to_unjoined_ctx(self) -> UnjoinedCtx<D, S>;
    fn to_pending_rejoin_ctx(self) -> PendingRejoinCtx<D, S>;
}

pub struct UnjoinedCtx<D: NwkMac, S: StorageRegion> {
    nwk: Nwk<Uninitialized, D, S>,
    aps_storage: S,
}
impl<D: NwkMac, S: StorageRegion> ZbNodeStatus for UnjoinedCtx<D, S> {}

pub struct PendingRejoinCtx<D: NwkMac, S: StorageRegion> {
    nwk: Nwk<PendingJoin, D, S>,
    aps_storage: S,
}
impl<D: NwkMac, S: StorageRegion> ZbNodeStatus for PendingRejoinCtx<D, S> {}

pub struct EndDeviceNodeCtx<D: NwkMac, S: StorageRegion> where Aps<Nwk<JoinedAsEndDevice, D, S>, D, S> : ApsListen {
    zcl_transaction_number: u8,
    pub aps: Aps<Nwk<JoinedAsEndDevice, D, S>, D, S>
}
impl<D: NwkMac, S: StorageRegion> ZbNodeStatus for EndDeviceNodeCtx<D, S> {}
impl<D: NwkMac, S: StorageRegion> ZbNodeJoinedStatus<D, S> for EndDeviceNodeCtx<D, S> {
    fn get_aps(&self) -> &(impl Apsde + Apsme + ApsmeSecurity) { &self.aps }
    fn get_aps_mut(&mut self) -> &mut (impl Apsde + Apsme + ApsmeSecurity) { &mut self.aps }
    fn get_nwk(&self) -> &impl JoinedNwk<D, S> { &self.aps.nwk }
    fn get_nwk_mut(&mut self) -> &mut impl JoinedNwk<D, S> { &mut self.aps.nwk }
    fn get_zcl_transaction_number(&mut self) -> u8 { self.zcl_transaction_number.wrapping_add(1) }

    fn to_unjoined_ctx(self) -> UnjoinedCtx<D, S> {
        UnjoinedCtx {
            nwk: self.aps.nwk.reset(),
            aps_storage: self.aps.stg,
        }
    }

    fn to_pending_rejoin_ctx(self) -> PendingRejoinCtx<D, S> {
        PendingRejoinCtx {
            nwk: self.aps.nwk.to_pending_rejoin(),
            aps_storage: self.aps.stg,
        }
    }
}

pub struct RouterNodeCtx<D: NwkMac, S: StorageRegion> where Aps<Nwk<JoinedAsRouter, D, S>, D, S>: ApsListen {
    zcl_transaction_number: u8,
    pub aps: Aps<Nwk<JoinedAsRouter, D, S>, D, S>
}
impl<D: NwkMac, S: StorageRegion> ZbNodeStatus for RouterNodeCtx<D, S> {}
impl<D: NwkMac, S: StorageRegion> ZbNodeJoinedStatus<D, S> for RouterNodeCtx<D, S> {
    fn get_aps(&self) -> &(impl Apsde + Apsme + ApsmeSecurity) { &self.aps }
    fn get_aps_mut(&mut self) -> &mut (impl Apsde + Apsme + ApsmeSecurity) { &mut self.aps }
    fn get_nwk(&self) -> &impl JoinedNwk<D, S> { &self.aps.nwk }
    fn get_nwk_mut(&mut self) -> &mut impl JoinedNwk<D, S> { &mut self.aps.nwk }
    fn get_zcl_transaction_number(&mut self) -> u8 { self.zcl_transaction_number.wrapping_add(1) }

    fn to_unjoined_ctx(self) -> UnjoinedCtx<D, S> {
        UnjoinedCtx {
            nwk: self.aps.nwk.reset(),
            aps_storage: self.aps.stg,
        }
    }

    fn to_pending_rejoin_ctx(self) -> PendingRejoinCtx<D, S> {
        PendingRejoinCtx {
            nwk: self.aps.nwk.to_pending_rejoin(),
            aps_storage: self.aps.stg,
        }
    }
}

pub struct ZbNode<C: ZbNodeStatus, D: NwkMac, S: StorageRegion> {
    _marker: PhantomData<D>,
    pub config: ZbConfig,
    pub spawner: embassy_executor::Spawner,
    pub applications: ZbApplications<S>,

    pub ctx: C
}

pub async fn run<D, P, S>(
    config: ZbConfig,
    spawner: embassy_executor::Spawner,
    map: ZbApplicationsDef,
    mac: Mlme<D>,
    pool: P,
) -> !
where
    D: NwkMac,
    P: StoragePool<S = S>,
    S: StorageRegion,
{
    async fn join<Dd, Ss>(
        mut unjoined: ZbNode<UnjoinedCtx<Dd, Ss>, Dd, Ss>
    ) -> Either<ZbNode<EndDeviceNodeCtx<Dd, Ss>, Dd, Ss>, ZbNode<RouterNodeCtx<Dd, Ss>, Dd, Ss>>
    where
        Dd: NwkMac,
        Ss: StorageRegion,
    {
        log::info!("node is not on a network, trying to connect...");

        loop {
            match unjoined.network_steering().await {
                Ok(joined) => return joined,
                Err(err) => unjoined = err.state,
            };

            log::warn!("couldn't connect to a network, retrying in 10 seconds...");
            Timer::after_secs(10).await;
        }
    }

    let mut joined = match initialize(config, spawner, map, mac, pool).await {
        InitializedNode::JoinedAsEndDevice(joined) => Either::First(joined),
        InitializedNode::JoinedAsRouter(joined) => Either::Second(joined),
        InitializedNode::Unjoined(unjoined) => join(unjoined).await,
    };

    loop {
        let unjoined = match joined {
            Either::First(joined) => joined.start().await,
            Either::Second(joined) => joined.start().await,
        };
        joined = match unjoined {
            Either::First(uninitialized) => join(uninitialized).await,
            Either::Second(pending_rejoin) => match try_rejoin(pending_rejoin, config).await {
                InitializedNode::Unjoined(unjoined) => join(unjoined).await,
                InitializedNode::JoinedAsEndDevice(joined) => Either::First(joined),
                InitializedNode::JoinedAsRouter(joined) => Either::Second(joined),
            }
        };
    }
}

async fn try_rejoin<D, S>(
    node: ZbNode<PendingRejoinCtx<D, S>, D, S>,
    config: ZbConfig
) -> InitializedNode<D, S>
where
    D: NwkMac,
    S: StorageRegion,
{
    log::info!("device is already on a network, rejoining...");

    let nwk = node.ctx.nwk;

    let request = NlmeRejoinRequest {
        ext_pan_id: nwk.get_ext_pan_id(),
        channels: &[config.primary_channel_set],
        scan_duration: ScanDuration::new(8).unwrap(),
        capability_information: Default::default(),
    };

    match nwk.rejoin(&request).await {
        Ok(nwk) => {
            match nwk {
                zb_types::transitions::Either::First(nwk) => {
                    let aps = Aps::load_or_default(nwk, node.ctx.aps_storage);

                    let mut node = ZbNode {
                        _marker: Default::default(),
                        config,
                        spawner: node.spawner,
                        applications: node.applications,
                        ctx: EndDeviceNodeCtx {
                            zcl_transaction_number: 0,
                            aps,
                        },
                    };

                    node.emit_device_annce().await.ok();
                    node.ctx.aps.persist().ok();

                    InitializedNode::JoinedAsEndDevice(node)
                },
                zb_types::transitions::Either::Second(nwk) => {
                    let aps = Aps::load_or_default(nwk, node.ctx.aps_storage);

                    let mut node = ZbNode {
                        _marker: Default::default(),
                        config,
                        spawner: node.spawner,
                        applications: node.applications,
                        ctx: RouterNodeCtx {
                            zcl_transaction_number: 0,
                            aps,
                        },
                    };

                    node.emit_device_annce().await.ok();
                    node.ctx.aps.persist().ok();

                    InitializedNode::JoinedAsRouter(node)
                }
            }
        }
        Err(err) => {
            InitializedNode::Unjoined(ZbNode::<UnjoinedCtx<D, S>, D, S> {
                _marker: Default::default(),
                config,
                spawner: node.spawner,
                applications: node.applications,
                ctx: UnjoinedCtx {
                    nwk: err.state.reset(),
                    aps_storage: node.ctx.aps_storage,
                },
            })
        }
    }
}

pub enum InitializedNode<D, S>
where
    D: NwkMac,
    S: StorageRegion,
{
    Unjoined(ZbNode<UnjoinedCtx<D, S>, D, S>),
    JoinedAsEndDevice(ZbNode<EndDeviceNodeCtx<D, S>, D, S>),
    JoinedAsRouter(ZbNode<RouterNodeCtx<D, S>, D, S>),
}

async fn initialize<D, P, S>(
    config: ZbConfig,
    spawner: embassy_executor::Spawner,
    applications: ZbApplicationsDef,
    mac: Mlme<D>,
    mut pool: P,
) -> InitializedNode<D, S>
where
    D: NwkMac,
    P: StoragePool<S = S>,
    S: StorageRegion,
{
    log::info!("initializing device...");

    let nwk_stg = pool.reserve_region(NWK_STORAGE_SIZE as u32).unwrap();
    let aps_stg = pool.reserve_region(APS_STORAGE_SIZE as u32).unwrap();
    let apps_stg = pool.reserve_region(APPLICATIONS_SR_SIZE as u32).unwrap();

    let mut apps = ZbApplicationsMap::new(applications, apps_stg);
    apps.load_all().await;

    match Nwk::<Uninitialized, _, _>::load(mac, nwk_stg) {
        Ok(nwk) => {
            if config.is_end_device() {
                let node = ZbNode {
                    _marker: Default::default(),
                    config,
                    spawner,
                    applications: apps,
                    ctx: PendingRejoinCtx {
                        nwk,
                        aps_storage: aps_stg,
                    },
                };

                try_rejoin(node, config).await
            } else {
                let aps = Aps::load_or_default(nwk.to_router(), aps_stg);

                InitializedNode::JoinedAsRouter(ZbNode {
                    _marker: Default::default(),
                    config,
                    spawner,
                    applications: apps,
                    ctx: RouterNodeCtx {
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
                _marker: Default::default(),
                config,
                spawner,
                applications: apps,
                ctx: UnjoinedCtx {
                    nwk: Nwk::new(NwkConfig {
                        mac: cfg.mac,
                        stg: cfg.stg,
                        rng: SmallRng::seed_from_u64(0),
                        seq_number: Arc::new(Default::default()),
                    }),
                    aps_storage: aps_stg,
                },
            })
        }
    }
}

type ZbNodeTransition<D, S> =
    TransitionResult<
        ZbNode<UnjoinedCtx<D, S>, D, S>,
        Either<ZbNode<EndDeviceNodeCtx<D, S>, D, S>, ZbNode<RouterNodeCtx<D, S>, D, S>>,
        ()>;

impl<D, S> ZbNode<UnjoinedCtx<D, S>, D, S>
where
    D: NwkMac,
    S: StorageRegion,
{
    pub async fn network_steering(mut self) -> ZbNodeTransition<D, S> {
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

    async fn try_join_for_channels(mut self, scan_channels: ChannelMask) -> ZbNodeTransition<D, S> {
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
                        return match value {
                            zb_types::transitions::Either::First(nwk) => {
                                let aps = Aps::load_or_default(nwk, self.ctx.aps_storage);

                                let node = ZbNode::<EndDeviceNodeCtx<D, S>, D, S> {
                                    _marker: Default::default(),
                                    config: self.config,
                                    spawner: self.spawner,
                                    applications: self.applications,
                                    ctx: EndDeviceNodeCtx {
                                        zcl_transaction_number: 0,
                                        aps,
                                    },
                                };

                                match node.try_authenticate().await {
                                    Ok(node) => Ok(Either::First(node)),
                                    Err(node) => TransitionError::err(node, ()),
                                }
                            }
                            zb_types::transitions::Either::Second(nwk) => {
                                let aps = Aps::load_or_default(nwk, self.ctx.aps_storage);

                                let node = ZbNode::<RouterNodeCtx<D, S>, D, S> {
                                    _marker: Default::default(),
                                    config: self.config,
                                    spawner: self.spawner,
                                    applications: self.applications,
                                    ctx: RouterNodeCtx {
                                        zcl_transaction_number: 0,
                                        aps,
                                    },
                                };

                                match node.try_authenticate().await {
                                    Ok(node) => {
                                        // Activate permit joining
                                        Ok(Either::Second(node))
                                    },
                                    Err(node) => TransitionError::err(node, ()),
                                }
                            }
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

impl<J: ZbNodeJoinedStatus<D, S>, D: NwkMac, S: StorageRegion> ZbNode<J, D, S> {
    fn to_unjoined(self) -> ZbNode<UnjoinedCtx<D, S>, D, S> {
        ZbNode {
            _marker: Default::default(),
            config: self.config,
            spawner: self.spawner,
            applications: self.applications,
            ctx: self.ctx.to_unjoined_ctx()
        }
    }

    fn to_pending_rejoin(self) -> ZbNode<PendingRejoinCtx<D, S>, D, S> {
        ZbNode {
            _marker: Default::default(),
            config: self.config,
            spawner: self.spawner,
            applications: self.applications,
            ctx: self.ctx.to_pending_rejoin_ctx()
        }
    }

    pub fn get_zcl_transaction_number(&mut self) -> u8 { self.ctx.get_zcl_transaction_number() }

    async fn try_authenticate(mut self) -> Result<Self, ZbNode<UnjoinedCtx<D, S>, D, S>> {
        log::info!("NLME-JOIN successful, waiting for network key...");
        let result = self.wait_for_nwk_key().await;
        return if result.is_err() {
            log::warn!("couldn't obtain network key, resetting...");
            // nlme::reset(nwk_ctx, false).await;

            Err(ZbNode {
                _marker: Default::default(),
                config: self.config,
                spawner: self.spawner,
                applications: self.applications,
                ctx: self.ctx.to_unjoined_ctx(),
            })
        } else {
            log::info!("obtained network key, we are authorized");
            self.ctx.get_aps_mut().set_authorized();
            if self.emit_device_annce().await.is_err() {
                log::warn!("couldn't emit device annce");
                return Err(self.to_unjoined());
            }

            log::info!("security_network_params: {:?}", self.ctx.get_aps().get_security_network_params());
            match self.ctx.get_aps().get_security_network_params() {
                SecurityNetworkParams::Centralized(_) => {
                    log::info!("updating trust center link key");
                    match self.update_trust_center_link_key().await {
                        Ok(_) => {}
                        Err(err) => {
                            log::warn!("couldn't update trust center link key, got error: `{:?}`. Resetting...", err);
                            self.ctx.get_nwk_mut().leave(false).await.ok();
                            return Err(ZbNode {
                                _marker: Default::default(),
                                config: self.config,
                                spawner: self.spawner,
                                applications: self.applications,
                                ctx: self.ctx.to_unjoined_ctx(),
                            });
                        }
                    }
                }
                SecurityNetworkParams::Distributed => {}
            }

            match self.emit_permit_joining_req(
                MgmtPermitJoiningReq::Enable(MIN_COMMISSIONING_TIME.as_secs() as u8),
                ApsdeAddress::Network(NwkAddress::BROADCAST_ALL, ZDP_ENDPOINT),
            )
                .await
            {
                Err(err) => log::warn!("error sending MgmtPermitJoiningReq: {:?}", err),
                _ => {}
            };

            Ok(self)
        }
    }

    async fn wait_for_nwk_key(&mut self) -> Result<(), TimeoutError> {
        let timeout = self.ctx.get_nwk().get_profile().aps_security_timeout_period;

        let (ext_src_addr, key_data) =
            self.ctx.get_aps_mut().wait_for_indication(timeout, |indication| match indication {
                ApsIndication::TransportKey(ApsmeTransportKeyIndication {
                                                ext_src_addr,
                                                transport_key: TransportKeyData::StandardNetworkKey(key_data),
                                            }) => Some((*ext_src_addr, *key_data)),
                _ => None,
            })
                .await?;

        match self.ctx
            .get_aps_mut()
            .get_device_key_pair_set_mut()
            .iter_mut()
            .find(|ref key| key.link_key_type == LinkKeyType::GlobalLinkKey)
        {
            Some(key) => key.device_address = ext_src_addr,
            _ => {
                log::error!("could not find global link key");
            }
        }

        unsafe {
            self.ctx.get_nwk_mut().get_security_material_set().lock_mut(|keys| {
                keys.push(NetworkSecurityMaterialDescriptor {
                    key_seq_number: key_data.key_sequence,
                    outgoing_frame_counter: 0,
                    incoming_frame_counter_set: Default::default(),
                    key: key_data.key,
                    network_key_type: NetworkKeyType::Standard,
                }).ok();
            });
        }

        Ok(())
    }

    async fn update_trust_center_link_key(&mut self) -> ApsSecurityResult {
        let tc_addr = unwrap_or_return!(self.ctx.get_aps().get_tc_addr(), Ok(()));
        self.ctx.get_aps_mut().request_key(tc_addr, RequestKeyType::TrustCenterLinkKey).await?;

        let timeout = self.ctx.get_nwk().get_profile().aps_security_timeout_period;
        let (ext_src_addr, key_data) =
            self.ctx.get_aps_mut().wait_for_indication(timeout, |indication| match indication {
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

        let desc = self.ctx
            .get_aps_mut()
            .get_device_key_pair_set_mut()
            .iter_mut()
            .find(|desc| desc.device_address == ext_src_addr)
            .unwrap();

        desc.key_attributes = KeyAttribute::UnverifiedKey;
        desc.link_key = key_data.key;
        desc.link_key_type = LinkKeyType::UniqueLinkKey;

        self.ctx.get_aps_mut().verify_key().await?;

        let indication = self.ctx.get_aps_mut().wait_for_indication(timeout, |indication| match indication {
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
}

impl<D: NwkMac, S: StorageRegion> ZbNode<EndDeviceNodeCtx<D, S>, D, S> {
    pub async fn start(self) -> Either<ZbNode<UnjoinedCtx<D, S>, D, S>, ZbNode<PendingRejoinCtx<D, S>, D, S>> {
        let source = self.ctx.aps.nwk.get_addr();
        let source_ieee = self.ctx.aps.nwk.get_ext_addr();
        let security_level = self.ctx.aps.nwk.get_profile().nwk_security_level;
        let sequence_number = self.ctx.aps.nwk.get_seq_number();
        let (parent_addr, parent_ext_addr) = self.ctx.aps.nwk.lock_neighbors(|nbs| {
            (nbs.parent.nwk_addr, nbs.parent.ext_addr)
        });
        let keys = self.ctx.aps.nwk.get_security_material_set();
        let active_key_seq_number = self.ctx.aps.nwk.get_active_key_seq_number();

        let applications = self.applications.clone();
        let mac = self.ctx.aps.nwk.get_mac().clone();

        let params = EndDeviceKeepaliveTask::builder()
            .source(source)
            .source_ieee(source_ieee)
            .security_level(security_level)
            .sequence_number(sequence_number)
            .keys(keys)
            .active_key_seq_number(active_key_seq_number)
            .rand_seed(0)
            .mac(mac)
            .timeout(DeviceTimeout::Mins8)
            .parent_addr(parent_addr)
            .maybe_parent_ext_addr(parent_ext_addr)
            .build();
        let keepalive_task = end_device_keepalive_task(params);
        let update_apps = update_apps_task::<S>(applications);
        let listen = listen_task(self);

        match select3(listen, update_apps, keepalive_task).await {
            Either3::First(unjoined) => unjoined,
            Either3::Second(_) => unreachable!(),
            Either3::Third(_) => unreachable!(),
        }
    }
}

impl<D: NwkMac, S: StorageRegion> ZbNode<RouterNodeCtx<D, S>, D, S> {
    pub async fn start(self) -> Either<ZbNode<UnjoinedCtx<D, S>, D, S>, ZbNode<PendingRejoinCtx<D, S>, D, S>> {
        let source = self.ctx.aps.nwk.get_addr();
        let source_ieee = self.ctx.aps.nwk.get_ext_addr();
        let security_level = self.ctx.aps.nwk.get_profile().nwk_security_level;
        let sequence_number = self.ctx.aps.nwk.get_seq_number();
        let keys = self.ctx.aps.nwk.get_security_material_set();
        let active_key_seq_number = self.ctx.aps.nwk.get_active_key_seq_number();
        let neighbors = self.ctx.aps.nwk.get_neighbors();

        let applications = self.applications.clone();
        let mac = self.ctx.aps.nwk.get_mac().clone();

        let params = LinkStatusTaskParams::builder()
            .source(source)
            .source_ieee(source_ieee)
            .security_level(security_level)
            .sequence_number(sequence_number)
            .keys(keys)
            .active_key_seq_number(active_key_seq_number)
            .rand_seed(0)
            .mac(mac)
            .neighbors(neighbors)
            .build();
        let keepalive_task = link_status_task(params);
        let update_apps = update_apps_task::<S>(applications);
        let listen = listen_task(self);

        match select3(listen, update_apps, keepalive_task).await {
            Either3::First(unjoined) => unjoined,
            Either3::Second(_) => unreachable!(),
            Either3::Third(_) => unreachable!(),
        }
    }
}



impl<J: ZbNodeJoinedStatus<D, S>, D: NwkMac, S: StorageRegion> ZbNode<J, D, S> {
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

    async fn listen(&mut self) -> NlmeLeaveIndication {
        loop {
            let indication = self.ctx.get_aps_mut().listen_aps().await;
            log::debug!("received indication: {:?}", indication);

            match indication {
                ApsIndication::Data(indication) => {
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
                ApsIndication::Leave(indication) => return indication,
                ApsIndication::TransportKey(_) => {}
                ApsIndication::UpdateDevice(_) => {}
                ApsIndication::ConfirmKey(_) => {}
                ApsIndication::RemoveDevice(_) => {}
            }
        }
    }

}

async fn listen_task<D: NwkMac, S: StorageRegion, C: ZbNodeJoinedStatus<D, S>>(
    mut node: ZbNode<C, D, S>
) -> Either<ZbNode<UnjoinedCtx<D, S>, D, S>, ZbNode<PendingRejoinCtx<D, S>, D, S>> {
    loop {
        let indication = node.listen()
            .with_timeout(Duration::from_secs(1))
            .await;
        match indication {
            Ok(indication) => return match indication {
                NlmeLeaveIndication::LeaveSelf { .. } => Either::First(node.to_unjoined()),
                NlmeLeaveIndication::LeaveChild { .. } => Either::Second(node.to_pending_rejoin()),
                _ => todo!()
            },
            Err(_) => {}
        };

        let reports = node.get_report().await;
        {
            for ((src_endpoint, profile_id, cluster_id), cmd) in reports {
                _ = node.emit_report_attributes(
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
}

async fn update_apps_task<S: StorageRegion>(applications: ZbApplicationsDef) {
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
}

pub mod config;
