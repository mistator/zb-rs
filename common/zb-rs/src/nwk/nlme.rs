use alloc::sync::Arc;
use crate::unwrap_or_return;
use core::ops::Add;
use core::sync::atomic::AtomicU8;
use crate::apl::zdo::config::{ZbCapabilities};
use crate::common::security::SecurityError;
use crate::mac;
use crate::mac::constants::A_RESPONSE_WAIT_TIME;
use crate::mac::mlme::Mlme;
use crate::mac::mlme::MlmeScanRequest;
use crate::mac::mlme::MlmeScanType;
use crate::mac::mlme::MlmeStartError;
use crate::mac::mlme::MlmeStartRequest;
use crate::mac::types::{MacError, MlmeAssociationError, PanDescriptorList, PollError, ScanError};
use crate::mac::utils::calculate_duration;
use crate::nwk::commands::Command;
use crate::nwk::commands::leave::{Leave};
use crate::nwk::commands::network_status::NetworkStatus;
use crate::nwk::commands::rejoin_request::RejoinRequestCmd;
use crate::nwk::commands::rejoin_response::RejoinResponse;
use crate::nwk::frame::CommandFrame;
use crate::nwk::frame::NwkFrame;
use crate::nwk::nlde::{NldeTransferError};
use crate::stack_profile::StackProfile;
use bounded_integer::BoundedU16;
use bounded_integer::BoundedU8;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::Duration;
use embassy_time::Instant;
use ieee802154::mac::beacon::SuperframeOrder;
use ieee802154::mac::beacon::{BeaconOrder};
use ieee802154::mac::command::CapabilityInformation;
use thiserror::Error;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::DeviceType;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::common::PanId;
use zb_types::mac::{Channel, ChannelMask, ChannelPage, MacAddress};
use zb_types::transitions::{Either, TransitionError, TransitionResult};
use crate::nwk::ctx::{BaseNwk, BaseNwkPrivate, InitializedNwk, JoinedAsEndDevice, JoinedAsRouter, Nwk, NwkTransitionResult, PendingJoin, RoutingState, Uninitialized, UnjoinedState};
use crate::nwk::nib::{NeighborRelationship, NewNwkNeighbour, NwkNeighbor};
use crate::nwk::service::routing::compute_routing_cost;

pub type ScanDuration = BoundedU8<0, 0x0e>;
pub type DistributedNwkAddress = BoundedU16<1, 0xfff7>;

pub struct ScanRequest<'a> {
    pub channel_masks: &'a [ChannelMask],
    pub duration: ScanDuration,
}

#[derive(Error, Debug)]
pub enum NetworkDiscoveryError {
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
}

fn get_intersections<D: NwkMac>(
    mac: &Mlme<D>,
    channel_masks: &[ChannelMask],
) -> Result<zb_types::Vec<ChannelMask, 32>, ()> {
    let intersections = channel_masks
        .iter()
        .map(|mask| mask.intersect_with(mac.get_channel_mask()))
        .filter(|mask| *mask != ChannelMask::ZERO)
        .collect::<zb_types::Vec<_, _>>();
    if intersections.is_empty() {
        return Err(());
    }

    Ok(intersections)
}

pub type NetworkDescriptorList =
    zb_types::Vec<NetworkDescriptor, { mac::constants::MAX_IEEE802154_CHANNELS }>;
pub type NlmeNetworkDiscoveryConfirm = NetworkDescriptorList;

#[derive(Debug)]
pub struct NetworkDescriptor {
    pub extended_pan_id: ExtendedAddress,
    pub pan_id: PanId,
    pub update_id: u8,
    pub logical_channel: Channel,
    pub stack_profile: StackProfile,
    pub zigbee_version: u8,
    pub beacon_order: BeaconOrder,
    pub superframe_order: SuperframeOrder,
    pub router_capacity: bool,
    pub end_device_capacity: bool,
    pub routers: PanDescriptorList,
}

impl NetworkDescriptor {
    pub fn is_permit_joining(&self) -> bool {
        self.routers
            .iter()
            .any(|router| router.superframe_spec.association_permit)
    }

    pub fn get_potential_parents(&self, require_permit_joining: bool) -> PanDescriptorList {
        let mut potential_parents = self
            .routers
            .iter()
            .filter(|pd| !require_permit_joining || pd.superframe_spec.association_permit)
            .map(|pd| *pd)
            .collect::<PanDescriptorList>();

        // unchecked conditions:
        // - The link quality for frames received from this device is such that a link
        //   cost of at most 3 is produce when calculated as described in section
        //   3.6.3.1.
        // - The device shall have the most recent update id, where the determination of
        //   most recent needs to take into account that the update id will wrap back to
        //   zero. In particular the update id given in the beacon payload of the device
        //   should be greater than or equal to — again, compensating for wrap — the
        //   nwkUpdateId attribute of the NIB.

        // Sort potential parents by depth if we are on a legacy Zigbee network
        if self.stack_profile == StackProfile::Zigbee {
            potential_parents
                .sort_by_key(|parent| parent.zigbee_beacon.network_parameters.device_depth);
        }

        potential_parents
    }
}

pub type NetworkDiscoveryResult = Result<NlmeNetworkDiscoveryConfirm, NetworkDiscoveryError>;

impl<T: UnjoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // 3.2.2.3
    pub async fn network_discovery(&mut self, req: &ScanRequest<'_>) -> NetworkDiscoveryResult {
        let pds = self
            .get_pan_descriptors(req.duration, req.channel_masks)
            .await
            .map_err(|_| {
                NetworkDiscoveryError::InvalidParameter(
                    "requested channels do not match any available channels",
                )
            })?;

        let mut nds = NetworkDescriptorList::new();
        for pd in pds {
            match nds
                .iter_mut()
                .find(|nd| nd.extended_pan_id == pd.zigbee_beacon.extended_pan_id)
            {
                None => {
                    let mut routers = PanDescriptorList::new();
                    routers.push(pd).unwrap();

                    nds.push(NetworkDescriptor {
                        extended_pan_id: pd.zigbee_beacon.extended_pan_id,
                        pan_id: pd.coord_pan_id,
                        update_id: pd.zigbee_beacon.update_id,
                        logical_channel: pd.channel,
                        stack_profile: pd.zigbee_beacon.network_parameters.stack_profile,
                        zigbee_version: pd.zigbee_beacon.network_parameters.protocol_version,
                        beacon_order: pd.superframe_spec.beacon_order,
                        superframe_order: pd.superframe_spec.superframe_order,
                        router_capacity: pd.zigbee_beacon.network_parameters.router_capacity,
                        end_device_capacity: pd
                            .zigbee_beacon
                            .network_parameters
                            .end_device_capacity,
                        routers,
                    })
                    .ok()
                }
                Some(nd) => nd.routers.push(pd).ok(),
            };
        }

        Ok(nds)
    }

    async fn get_pan_descriptors(
        &mut self,
        duration: ScanDuration,
        channel_masks: &[ChannelMask],
    ) -> Result<PanDescriptorList, ()> {
        let intersections = get_intersections(&mut self.get_mac(), channel_masks)?;

        let mut pds = PanDescriptorList::new();
        for intersection in intersections {
            match self
                .get_mac_mut()
                .scan(MlmeScanRequest {
                    scan_type: MlmeScanType::Active,
                    channel_mask: intersection,
                    duration,
                })
                .await
            {
                Ok(res) => pds.extend(res),
                Err(_) => {}
            }
        }

        Ok(pds)
    }
}

#[derive(PartialEq)]
pub enum NetworkTopology {
    Centralized,
    Distributed(DistributedNwkAddress),
}

pub struct NetworkFormationRequest<'a> {
    channel_masks: &'a [ChannelMask],
    duration: ScanDuration,
    beacon_order: BeaconOrder,
    superframe_order: SuperframeOrder,
    battery_life_extension: bool,
    network_topology: NetworkTopology,
}

#[derive(Error, Debug)]
pub enum NetworkFormationError {
    #[error("{0}")]
    InvalidRequest(&'static str),
    #[error("{0}")]
    StartupFailure(&'static str),
    #[error("{0}")]
    MacError(#[from] MacError),
}

/*
// 3.2.2.5
async fn network_formation<D: NwkMac, S: StorageRegion>(
    ctx: &mut RouterContext<'_, D, S>,
    req: &NetworkFormationRequest<'_>,
) -> Result<(), NetworkFormationError> {
    if !ctx.as_nwk_ctx().config.is_coordinator()
        && req.network_topology == NetworkTopology::Centralized
    {
        return Err(NetworkFormationError::StartupFailure(
            "only a coordinator can form a centralized network",
        ));
    }

    let mac = &mut ctx.as_nwk_ctx_mut().mac;
    let intersections = get_intersections(mac, req.channel_masks)
        .map_err(|_| NetworkFormationError::MacError(MacError::InvalidScanParams))?;

    todo!()
}

 */

pub enum PermitJoiningConfig {
    Disabled,
    EnabledForPeriod(BoundedU8<1, 254>),
    Enabled,
}

#[derive(Error, Debug)]
pub enum PermitJoiningError {
    #[error("{0}")]
    InvalidRequest(&'static str),
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // 3.2.2.7
    pub(crate) fn permit_joining(&mut self, cfg: PermitJoiningConfig) -> () {
        match cfg {
            PermitJoiningConfig::Disabled => self.get_mac_mut().set_association_permit_timeout(Instant::MIN),
            PermitJoiningConfig::EnabledForPeriod(secs) => self.get_mac_mut().set_association_permit_timeout(
                Instant::now().add(Duration::from_secs(secs.get() as u64)),
            ),
            PermitJoiningConfig::Enabled => self.get_mac_mut().set_association_permit_timeout(Instant::MAX),
        };
    }
}

pub struct StartRouterRequest {
    pub beacon_order: BeaconOrder,
    pub superframe_order: SuperframeOrder,
    pub battery_life_extension: bool,
}

#[derive(Error, Debug)]
pub enum StartRouterError {
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("MLME-START error: {0}")]
    MlmeStartError(#[from] MlmeStartError),
}

pub type StartRouterResult<D, S> =
    TransitionResult<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>, StartRouterError>;

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsEndDevice, D, S> {
    // 3.2.2.9
    async fn start_router(mut self, req: StartRouterRequest) -> StartRouterResult<D, S> {
        match self.get_mac_mut().start(MlmeStartRequest {
            beacon_order: req.beacon_order,
            superframe_order: req.superframe_order,
            battery_life_extension: req.battery_life_extension,
            pan_coordinator_update: None,
        }) {
            Ok(_) => Ok(self.to_router()),
            Err(err) => Err(TransitionError {
                state: self,
                error: StartRouterError::from(err),
            }),
        }
    }
}

#[derive(Error, Debug)]
pub enum EdScanError {
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    #[error("scan error: {0}")]
    ScanError(#[from] ScanError),
}

pub struct EdChannelInfo {
    pub channel_page: ChannelPage,
    pub channel: Channel,
    pub energy_detected: u8,
}

pub type NlmeEdScanConfirm = zb_types::Vec<EdChannelInfo, 64>;

impl<D: NwkMac, S: StorageRegion> Nwk<Uninitialized, D, S> {
    // 3.2.2.11
    async fn ed_scan(&mut self, req: &ScanRequest<'_>) -> Result<NlmeEdScanConfirm, EdScanError> {
        Ok(self
            .get_pan_descriptors(req.duration, req.channel_masks)
            .await
            .map_err(|_| {
                EdScanError::InvalidParameter(
                    "requested channels do not match any available channels",
                )
            })?
            .iter()
            .map(|pd| EdChannelInfo {
                channel_page: ChannelPage::ChannelPage0, // TODO:
                channel: pd.channel,
                energy_detected: pd.link_quality, // TODO: do actual ED Scan
            })
            .collect::<NlmeEdScanConfirm>())
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum NlmeJoinError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("not permitted: {}", 0)]
    NotPermitted(&'static str),
    #[error("no networks")]
    NoNetworks,
    #[error("association error")]
    AssociationError(MlmeAssociationError),
    #[error("scan error: {}", 0)]
    ScanError(#[from] ScanError),
    #[error("security error: {}", 0)]
    SecurityError(#[from] SecurityError),
    #[error("transfer error: {}", 0)]
    TransferError(#[from] NldeTransferError),
}

pub type JoinResult<D, S> = TransitionResult<Nwk<Uninitialized, D, S>, Either<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>>, NlmeJoinError>;

pub struct NlmeAssociationJoinRequest {
    pub capability_information: ZbCapabilities,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Uninitialized, D, S> {
    // 3.2.2.13
    pub async fn association_join(
        mut self,
        nd: &NetworkDescriptor,
        req: NlmeAssociationJoinRequest,
    ) -> JoinResult<D, S> {
        let extended_pan_id = nd.extended_pan_id;
        let capabilities = req.capability_information;

        log::info!("[NLME-JOIN] join procedure started");

        let potential_parents = nd.get_potential_parents(true);
        let mut err = NlmeJoinError::NotPermitted("no potential parent devices found");

        for parent in potential_parents {
            let parent_nwk_addr = if let MacAddress::Short(_, parent_nwk_addr) = parent.coord_address {
                parent_nwk_addr
            } else {
                continue;
            };

            let (_, ext_addr) = match self
                .get_mac_mut()
                .associate(parent.channel, parent.coord_address, capabilities.into())
                .await
                .map_err(|err| {
                    log::warn!(
                        "[NLME-JOIN] couldn't connect to network {:?}, {:?}",
                        extended_pan_id,
                        err
                    );
                    if matches!(
                        err,
                        MlmeAssociationError::PanAccessDenied | MlmeAssociationError::PanAtCapacity
                    ) {
                        // parent.potential_parent = false;
                    }
                    NlmeJoinError::AssociationError(err)
                }) {
                Ok(value) => value,
                Err(assoc_err) => {
                    err = assoc_err;
                    continue;
                }
            };


            let mut nb = NwkNeighbor::new(NewNwkNeighbour {
                ext_addr,
                nwk_addr: parent_nwk_addr,
                device_type: if parent.superframe_spec.pan_coordinator {
                    DeviceType::Coordinator
                } else {
                    DeviceType::Router
                },
                rx_on_when_idle: true, // TODO
                relationship: NeighborRelationship::Parent,
            });
            nb.incoming_cost = compute_routing_cost(/*parent.link_quality*/);

            log::info!("[NLME-JOIN] joined to network `{:?}` with parent: {:?}", extended_pan_id, nb);

            return Ok(self.to_joined(nb, parent.zigbee_beacon.network_parameters.stack_profile, capabilities));
        }

        Err(TransitionError {
            state: self,
            error: err,
        })
    }
}

pub struct NlmeRejoinRequest<'a> {
    pub ext_pan_id: ExtendedAddress,
    pub channels: &'a [ChannelMask],
    pub scan_duration: ScanDuration,
    pub capability_information: ZbCapabilities,
}

pub type RejoinResult<D, S> =
    TransitionResult<Nwk<PendingJoin, D, S>, Either<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>>, NlmeJoinError>;

impl<D: NwkMac, S: StorageRegion> Nwk<PendingJoin, D, S> {
    pub async fn rejoin(mut self, req: &NlmeRejoinRequest<'_>) -> RejoinResult<D, S> {
        let self_ieee_addr = self.get_ext_addr();

        log::info!(
            "[NLME-REJOIN] starting network rejoin on network: {:?}",
            req.ext_pan_id
        );

        let scan_req = ScanRequest {
            channel_masks: req.channels,
            duration: req.scan_duration,
        };

        let nd = match self.network_discovery(&scan_req).await {
            Ok(nd) => nd,
            Err(_) => return Err(TransitionError::new(self, NlmeJoinError::InvalidRequest)),
        };

        let nd = match nd.iter().find(|nd| nd.extended_pan_id == req.ext_pan_id) {
            Some(nd) => nd,
            None => return Err(TransitionError::new(self, NlmeJoinError::NoNetworks)),
        };

        log::info!("[NLME-REJOIN] pan descriptor identifier, rejoining network");

        let potential_parents = nd.get_potential_parents(false);
        log::info!("[NLME-REJOIN] identified {} potential parents", potential_parents.len());

        for parent in potential_parents {
            let (nwk_addr, ext_addr) =
                //unwrap_or!(ctx.find_addresses(parent.coord_address), continue);
                //TODO
                (NwkAddress::default(), ExtendedAddress::default());
            self.get_mac_mut().set_channel(parent.channel);
            self.get_mac_mut().set_pan_id(parent.coord_pan_id.into());

            log::info!("[NLME-REJOIN] sending rejoin command to parent: {:?}", parent);
            let rejoin_request = RejoinRequestCmd {
                dest_short_addr: nwk_addr,
                dest_ext_addr: ext_addr,
                capability_information: req.capability_information,
            };
            match self.send_rejoin_request_cmd(rejoin_request).await {
                Ok(_) => {}
                Err(err) => {
                    log::warn!("[NLME-REJOIN] error sending rejoin request: {:?}", err);
                    continue;
                }
            };

            log::info!("[NLME-REJOIN] waiting for rejoin response");
            let timeout = calculate_duration(A_RESPONSE_WAIT_TIME);
            let (hdr, rsp) = match self.wait_for_frame(timeout, |frame| {
                if let NwkFrame::NwkCommand(CommandFrame {
                    command: Command::RejoinResponse(rsp),
                    header,
                }) = frame
                {
                    return Some((header.clone(), *rsp));
                }

                return None;
            })
            .await
            {
                Ok(value) => value,
                Err(err) => {
                    log::warn!(
                        "[NLME-REJOIN] rejoin response not received within timeout: {:?}",
                        err
                    );
                    continue;
                }
            };

            if let (Some(ieee_dst), Some(ieee_src)) = (hdr.destination_ieee, hdr.source_ieee) {
                if ieee_dst != self_ieee_addr || ieee_src != ext_addr {
                    continue;
                }

                match rsp {
                    RejoinResponse::Success(nwk_addr) => {
                        let new_parent = NwkNeighbor::new(NewNwkNeighbour {
                            ext_addr: ieee_src,
                            nwk_addr: hdr.source,
                            device_type: DeviceType::Router, // TODO
                            rx_on_when_idle: false,          // TODO
                            relationship: NeighborRelationship::Parent,
                        });
                        // TODO: link cost
                        // TODO: NwkNeighbour builder

                        return Ok(self.to_joined(new_parent, req.capability_information));
                    }
                    _ => continue,
                }
            } else {
                continue;
            }
        }

        Err(TransitionError::new(self, NlmeJoinError::NoNetworks))
    }
}

// TODO: orphaning rejoin
// TODO: change channel procedure

// 3.2.2.16
pub struct DirectJoinReq {
    pub ext_addr: ExtendedAddress,
    pub capability_information: CapabilityInformation,
}

#[derive(Error, Debug)]
pub enum DirectJoinError {
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("device already present in the neighbor table")]
    AlreadyPresent,
    #[error("neighbor table full")]
    NeighborTableFull,
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsRouter, D, S> {
    pub fn direct_join(&mut self, req: DirectJoinReq) -> Result<(), DirectJoinError> {
        let nwk_addr = self.assign_child_address();

        let child = NwkNeighbor::new(NewNwkNeighbour {
            ext_addr: req.ext_addr,
            nwk_addr,
            device_type: match req.capability_information.full_function_device {
                true => DeviceType::Coordinator,
                false => DeviceType::EndDevice,
            },
            rx_on_when_idle: req.capability_information.idle_receive,
            relationship: NeighborRelationship::Child,
        });

        self.lock_neighbors_mut(|nbs| {
            if nbs.find_by_ext_addr(req.ext_addr).is_some() {
                return Err(DirectJoinError::AlreadyPresent);
            }

            nbs.cleanup();
            nbs.children.push(child).map_err(|_| DirectJoinError::NeighborTableFull)
        })
    }
}

// 3.2.2.18
#[derive(Error, Debug)]
pub enum NlmeLeaveError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("unknown device")]
    UnknownDevice,
    #[error("security error: {}", 0)]
    SecurityError(SecurityError),
    #[error("transfer error: {}", 0)]
    TransferError(#[from] NldeTransferError),
}

pub type LeaveResult = Result<(), NlmeLeaveError>;

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsEndDevice, D, S> {
    pub async fn leave(&mut self, rejoin: bool) -> LeaveResult {
        self.emit_leave_cmd(Leave {
            rejoin,
            request: false,
            remove_children: false,
        }, NwkAddress::BROADCAST_RX_ON_IDLE, None).await.map_err(NlmeLeaveError::from)
    }
}

pub enum RouterLeaveReq {
    RemoveSelf {
        remove_children: bool,
        rejoin: bool,
    },
    RemoveChild {
        ext_addr: ExtendedAddress,
        remove_children: bool,
        rejoin: bool,
    },
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsRouter, D, S> {
    pub async fn leave(&mut self, req: RouterLeaveReq) -> LeaveResult {
        match req {
            RouterLeaveReq::RemoveSelf {
                rejoin,
                remove_children,
            } => self.emit_leave_cmd(Leave {
                request: false,
                rejoin,
                remove_children
            }, NwkAddress::MAX, None).await,
            RouterLeaveReq::RemoveChild {
                ext_addr,
                rejoin,
                remove_children,
            } => {
                let nwk_addr = self.lock_neighbors(|children| {
                    children
                        .find_by_ext_addr(ext_addr)
                        .map(|nb| nb.nwk_addr)
                });
                let nwk_addr = unwrap_or_return!(nwk_addr, Err(NlmeLeaveError::UnknownDevice));

                self.emit_leave_cmd(Leave {
                    request: false,
                    rejoin,
                    remove_children,
                }, nwk_addr, Some(ext_addr)).await
            }
        }.map_err(|err| NlmeLeaveError::TransferError(err))
    }
}

// 3.2.2.21
/*
pub async fn reset<D: NwkJoined>(
    mut ctx: ApsContext<D>, /* , warm_start: bool */
) -> () {
    //ctx.get_nwk_mut().mac.reset(true);

    // if warm_start {
    // let router_ctx = unwrap_or_return!(ctx.as_router().ok());
    // TODO
    // ctx.ib.nwk_neighbor_table = Default::default();
    // ctx.ib.nwk_route_table = Default::default();
    // } else {
    //ctx.clear_persistence().await.ok();
    //}
}

 */

// 3.2.2.23
pub enum RouteDiscoveryAddress {
    ManyToOneRoute { no_route_cache: bool },
    Group(NwkAddress),
    Device(NwkAddress),
}

pub struct RouteDiscoveryReq {
    pub dst_addr: RouteDiscoveryAddress,
    pub radius: u8,
}

#[derive(Error, Debug)]
pub enum RouteError {
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("route error")]
    RouteError(NetworkStatus),
    #[error("transfer error: {}", 0)]
    TransferError(#[from] NldeTransferError),
}

pub type RouteDiscoveryResult = Result<(), RouteError>;

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsRouter, D, S> {
    pub async fn route_discovery(&mut self, req: RouteDiscoveryReq) -> RouteDiscoveryResult {
        if let RouteDiscoveryAddress::Group(addr) | RouteDiscoveryAddress::Device(addr) =
            req.dst_addr
        {
            if addr.is_broadcast() {
                return Err(RouteError::InvalidRequest("address must be unicast"));
            }

            self.get_route_table_mut().cleanup();
            if self.get_route_table().is_full() {
                return Err(RouteError::RouteError(NetworkStatus::NoRoutingCapacity));
            }
        }

        match req.dst_addr {
            RouteDiscoveryAddress::ManyToOneRoute { no_route_cache } => {
                self.initiate_unicast_discovery(NwkAddress::BROADCAST_RX_ON_IDLE, no_route_cache)
                    .await
            }
            RouteDiscoveryAddress::Group(addr) => {
                if self.get_group_table().contains(&addr) {
                    return Ok(());
                }

                self.initiate_unicast_discovery(addr, false).await
            }
            RouteDiscoveryAddress::Device(addr) => {
                self.initiate_unicast_discovery(addr, false).await
            }
        }
        .ok();

        Ok(())

        // TODO: wait for route discover response for multicast and unicast
        // addresses
    }
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("mac error")]
    MacError(#[from] MacError),
}

pub struct NlmePermitJoiningRequest {
    pub permit_duration: u8,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlmePermitJoiningConfirm {
    // pub status: NlmeJoinStatus,
}

pub enum RejoinNetworkMethod {
    Association,
    Direct,
    Rejoin,
    Network,
}
pub enum NlmeSyncError {
    SyncFailure,
    InvalidParameter,
    PollError(PollError),
}

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
pub struct ZigbeeBeacon {
    pub protocol_id: u8,
    pub network_parameters: NetworkParameters,
    pub extended_pan_id: ExtendedAddress,
    pub tx_offset: [u8; 3],
    pub update_id: u8,
}

#[derive(BitStruct, Clone, Copy, Debug)]
#[bit_struct(repr = u16)]
pub struct NetworkParameters {
    #[bit_struct(len = 5)]
    pub stack_profile: StackProfile,
    #[bit_struct(len = 4)]
    pub protocol_version: u8,
    #[bit_struct(skip = 2)]
    pub router_capacity: bool,
    #[bit_struct(len = 4)]
    pub device_depth: u8,
    pub end_device_capacity: bool,
}
