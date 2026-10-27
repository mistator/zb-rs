use crate::apl::zdo::config::ZbCapabilities;
use crate::common::security::SecurityError;
use crate::mac::constants::{A_RESPONSE_WAIT_TIME, MAX_IEEE802154_CHANNELS};
use crate::mac::mlme::MlmeScanRequest;
use crate::mac::mlme::MlmeScanType;
use crate::mac::types::{AssociationError, MacError, PanDescriptorList, PollError, ScanError};
use crate::mac::utils::calculate_duration;
use crate::nwk::commands::Command;
use crate::nwk::commands::leave::Leave;
use crate::nwk::commands::link_status::LinkCost;
use crate::nwk::commands::network_status::NetworkStatus;
use crate::nwk::commands::rejoin_request::RejoinRequestCmd;
use crate::nwk::commands::rejoin_response::RejoinResponse;
use crate::nwk::ctx::{
    BaseNwk, BaseNwkPrivate, InitializedNwk, JoinedAsEndDevice, JoinedAsRouter, Nwk, PendingJoin,
    RoutingState, Uninitialized, UnjoinedState,
};
use crate::nwk::frame::CommandFrame;
use crate::nwk::frame::NwkFrame;
use crate::nwk::nib::{NeighborRelationship, NewNwkNeighbour, NwkNeighbor};
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::service::routing::compute_routing_cost;
use crate::stack_profile::StackProfile;
use crate::{unwrap_or, unwrap_or_return};
use bounded_integer::BoundedU8;
use bounded_integer::BoundedU16;
use byte::TryRead;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use core::ops::Add;
use embassy_time::Duration;
use embassy_time::Instant;
use ieee802154::mac::beacon::BeaconOrder;
use ieee802154::mac::beacon::SuperframeOrder;
use ieee802154::mac::command::CapabilityInformation;
use thiserror::Error;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::Vec;
use zb_types::common::DeviceType;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::common::PanId;
use zb_types::mac::{Channel, ChannelMask, ChannelPage, MacAddress, MacDeviceType};
use zb_types::transitions::{Either, TransitionError, TransitionResult};

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

pub type NetworkDescriptorList = Vec<NetworkDescriptor, { MAX_IEEE802154_CHANNELS }>;

#[derive(Clone, Copy, Debug)]
pub struct NwkNeighborJoinData {
    pub depth: u8,
    pub beacon_order: BeaconOrder,
    pub permit_joining: bool,
    pub router_capacity: bool,
    pub end_device_capacity: bool,
    pub potential_parent: bool,
}

#[derive(Debug, Clone)]
pub struct PanDescriptorDevice {
    pub neighbor: NwkNeighbor,
    pub join_data: NwkNeighborJoinData,
}

#[derive(Debug)]
pub struct NetworkDescriptor {
    pub extended_pan_id: ExtendedAddress,
    pub pan_id: PanId,
    pub update_id: u8,
    pub logical_channel: Channel,
    pub stack_profile: StackProfile,
    pub zigbee_version: u8,
    pub superframe_order: SuperframeOrder,
    pub neighbors: Vec<PanDescriptorDevice, 32>,
}

impl NetworkDescriptor {
    pub fn is_permit_joining(&self) -> bool {
        self.neighbors.iter().any(|device| device.join_data.permit_joining)
    }

    pub fn get_potential_parents(
        &mut self,
        require_permit_joining: bool,
        join_as: MacDeviceType,
    ) -> Vec<&mut PanDescriptorDevice, 16> {
        let is_potential_parent = |device: &PanDescriptorDevice| -> bool {
            device.join_data.potential_parent
                && (!require_permit_joining || device.join_data.permit_joining)
                && match join_as {
                    MacDeviceType::ReducedFunctionDevice => device.join_data.end_device_capacity,
                    MacDeviceType::FullFunctionDevice => device.join_data.router_capacity,
                }
                && device.neighbor.incoming_cost <= LinkCost::_3
        };

        let mut potential_parents = self
            .neighbors
            .iter_mut()
            .filter(|device| is_potential_parent(device))
            .collect::<Vec<&mut PanDescriptorDevice, 16>>();

        // unchecked conditions:
        // - The device shall have the most recent update id, where the determination of
        //   most recent needs to take into account that the update id will wrap back to
        //   zero. In particular the update id given in the beacon payload of the device
        //   should be greater than or equal to — again, compensating for wrap — the
        //   nwkUpdateId attribute of the NIB.

        // Sort potential parents by depth if we are on a legacy Zigbee network
        if self.stack_profile == StackProfile::Zigbee {
            potential_parents.sort_by_key(|parent| parent.join_data.depth);
        } else {
            potential_parents.sort_by_key(|parent| parent.neighbor.incoming_cost);
        }

        potential_parents
    }
}

pub type NetworkDiscoveryResult = Result<NetworkDescriptorList, NetworkDiscoveryError>;

impl<T: UnjoinedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    // 3.2.2.3
    pub async fn network_discovery(&mut self, req: &ScanRequest<'_>) -> NetworkDiscoveryResult {
        let mac_channel_mask = self.mac.get_channel_mask();
        let intersections = req
            .channel_masks
            .iter()
            .map(|mask| mask.intersect_with(mac_channel_mask))
            .filter(|mask| *mask != ChannelMask::ZERO)
            .collect::<Vec<ChannelMask, 16>>();
        if intersections.is_empty() {
            log::warn!("[NWK_DISCOVERY] requested channels do not match any available channels");
            return Err(NetworkDiscoveryError::InvalidParameter(
                "requested channels do not match any available channels",
            ));
        }

        let mut nds = NetworkDescriptorList::new();
        let pds = self.get_pan_descriptors(req.duration, intersections.as_slice()).await;

        for pd in pds {
            let (pan_id, addr) = if let MacAddress::Short(pan_id, addr) = pd.coord_address {
                (pan_id, addr)
            } else {
                continue;
            };
            let (zigbee_beacon, _) =
                unwrap_or!(ZigbeeBeacon::try_read(pd.payload.as_slice(), byte::LE).ok(), continue);

            let device = PanDescriptorDevice {
                neighbor: NwkNeighbor {
                    nwk_addr: addr,
                    device_type: DeviceType::Router,
                    relationship: NeighborRelationship::Other,
                    incoming_cost: compute_routing_cost(pd.link_quality),
                    outgoing_cost: Default::default(),
                    ..Default::default()
                },
                join_data: NwkNeighborJoinData {
                    depth: zigbee_beacon.network_parameters.device_depth,
                    beacon_order: pd.superframe_spec.beacon_order,
                    permit_joining: pd.superframe_spec.association_permit,
                    router_capacity: zigbee_beacon.network_parameters.router_capacity,
                    end_device_capacity: zigbee_beacon.network_parameters.end_device_capacity,
                    potential_parent: true,
                },
            };

            match nds.iter_mut().find(|nd| nd.extended_pan_id == zigbee_beacon.extended_pan_id) {
                None => nds
                    .push(NetworkDescriptor {
                        extended_pan_id: zigbee_beacon.extended_pan_id,
                        pan_id,
                        update_id: zigbee_beacon.update_id,
                        logical_channel: pd.channel,
                        stack_profile: zigbee_beacon.network_parameters.stack_profile,
                        zigbee_version: zigbee_beacon.network_parameters.protocol_version,
                        superframe_order: pd.superframe_spec.superframe_order,
                        neighbors: Vec::from_slice(&[device]).unwrap(),
                    })
                    .ok(),
                Some(nd) => nd.neighbors.push(device).ok(),
            };
        }

        Ok(nds)
    }

    async fn get_pan_descriptors(
        &mut self,
        duration: ScanDuration,
        channel_masks: &[ChannelMask],
    ) -> PanDescriptorList {
        let mut pds = PanDescriptorList::new();
        for mask in channel_masks {
            match self
                .mac
                .scan(MlmeScanRequest {
                    scan_type: MlmeScanType::Active,
                    channel_mask: *mask,
                    duration,
                })
                .await
            {
                Ok(res) => pds.extend(res),
                Err(_) => {}
            }
        }

        pds
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
            PermitJoiningConfig::Disabled => {
                self.get_mac_mut().set_association_permit_timeout(Instant::MIN)
            }
            PermitJoiningConfig::EnabledForPeriod(secs) => {
                self.get_mac_mut().set_association_permit_timeout(
                    Instant::now().add(Duration::from_secs(secs.get() as u64)),
                )
            }
            PermitJoiningConfig::Enabled => {
                self.get_mac_mut().set_association_permit_timeout(Instant::MAX)
            }
        };
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
    /*
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
     */
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
    AssociationError(AssociationError),
    #[error("scan error: {}", 0)]
    ScanError(#[from] ScanError),
    #[error("security error: {}", 0)]
    SecurityError(#[from] SecurityError),
    #[error("transfer error: {}", 0)]
    TransferError(#[from] NldeTransferError),
}

pub type JoinResult<D, S> = TransitionResult<
    Nwk<Uninitialized, D, S>,
    Either<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>>,
    NlmeJoinError,
>;

pub struct NlmeAssociationJoinRequest {
    pub capability_information: ZbCapabilities,
}

impl<D: NwkMac, S: StorageRegion> Nwk<Uninitialized, D, S> {
    // 3.2.2.13
    pub async fn association_join(
        mut self,
        nd: &mut NetworkDescriptor,
        req: NlmeAssociationJoinRequest,
    ) -> JoinResult<D, S> {
        let capabilities = req.capability_information;
        let NetworkDescriptor { logical_channel, pan_id, stack_profile, extended_pan_id, .. } = *nd;
        let mut potential_parents = nd.get_potential_parents(true, capabilities.device_type);

        log::info!("[NLME-JOIN] join procedure started");

        let mut err = NlmeJoinError::NotPermitted("no potential parent devices found");
        let idx = {
            let mut result = None;
            for (idx, parent) in potential_parents.iter_mut().enumerate() {
                let nwk_addr = parent.neighbor.nwk_addr;
                let addr = MacAddress::Short(pan_id, nwk_addr);

                let (_, ext_addr) = match self
                    .get_mac_mut()
                    .associate(logical_channel, addr, capabilities.into())
                    .await
                    .map_err(|err| {
                        log::warn!(
                            "[NLME-JOIN] couldn't connect to network {:?}, {:?}",
                            extended_pan_id,
                            err
                        );
                        if matches!(
                            err,
                            AssociationError::PanAccessDenied | AssociationError::PanAtCapacity
                        ) {
                            parent.join_data.potential_parent = false;
                        }
                        NlmeJoinError::AssociationError(err)
                    }) {
                    Ok(value) => value,
                    Err(assoc_err) => {
                        err = assoc_err;
                        continue;
                    }
                };

                parent.neighbor.ext_addr = Some(ext_addr);
                parent.neighbor.relationship = NeighborRelationship::Parent;

                result = Some(idx);
                break;
            }

            result
        };

        if let Some(idx) = idx {
            let parent = potential_parents.remove(idx);
            let neighbors = potential_parents
                .into_iter()
                .map(|parent| &parent.neighbor)
                .cloned()
                .collect::<Vec<NwkNeighbor, 32>>();
            log::info!(
                "[NLME-JOIN] joined to network `{:?}` with parent: {:?}",
                extended_pan_id,
                parent
            );

            Ok(self.to_joined(parent, neighbors, stack_profile, capabilities))
        } else {
            TransitionError::err(self, err)
        }
    }
}

pub struct NlmeRejoinRequest<'a> {
    pub ext_pan_id: ExtendedAddress,
    pub channels: &'a [ChannelMask],
    pub scan_duration: ScanDuration,
    pub capability_information: ZbCapabilities,
}

pub type RejoinResult<D, S> = TransitionResult<
    Nwk<PendingJoin, D, S>,
    Either<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>>,
    NlmeJoinError,
>;

impl<D: NwkMac, S: StorageRegion> Nwk<PendingJoin, D, S> {
    pub async fn rejoin(mut self, req: &NlmeRejoinRequest<'_>) -> RejoinResult<D, S> {
        let self_ieee_addr = self.get_ext_addr();

        log::info!("[NLME-REJOIN] starting network rejoin on network: {:?}", req.ext_pan_id);

        let scan_req = ScanRequest { channel_masks: req.channels, duration: req.scan_duration };

        let mut nd = match self.network_discovery(&scan_req).await {
            Ok(value) => value,
            Err(_) => return Err(TransitionError::new(self, NlmeJoinError::InvalidRequest)),
        };
        let nd = match nd.iter_mut().find(|nd| nd.extended_pan_id == req.ext_pan_id) {
            Some(nd) => nd,
            None => return Err(TransitionError::new(self, NlmeJoinError::NoNetworks)),
        };
        let channel = nd.logical_channel;
        let pan_id = nd.pan_id;

        log::info!("[NLME-REJOIN] pan descriptor identifier, rejoining network");

        let potential_parents =
            nd.get_potential_parents(false, req.capability_information.device_type);
        log::info!("[NLME-REJOIN] identified {} potential parents", potential_parents.len());

        for parent in potential_parents {
            let (nwk_addr, ext_addr) =
                //unwrap_or!(ctx.find_addresses(parent.coord_address), continue);
                //TODO
                (NwkAddress::default(), ExtendedAddress::default());
            self.get_mac_mut().set_channel(channel);
            self.get_mac_mut().set_pan_id(pan_id.into());

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
            let (hdr, rsp) = match self
                .wait_for_frame(timeout, |frame| {
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

                        return Ok(self.to_joined(
                            new_parent,
                            parent.join_data.depth,
                            req.capability_information,
                        ));
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
            nbs.neighbors.push(child).map_err(|_| DirectJoinError::NeighborTableFull)
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
        self.emit_leave_cmd(
            Leave { rejoin, request: false, remove_children: false },
            NwkAddress::BROADCAST_RX_ON_IDLE,
            None,
        )
        .await
        .map_err(NlmeLeaveError::from)
    }
}

pub enum RouterLeaveReq {
    RemoveSelf { remove_children: bool, rejoin: bool },
    RemoveChild { ext_addr: ExtendedAddress, remove_children: bool, rejoin: bool },
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsRouter, D, S> {
    pub async fn leave(&mut self, req: RouterLeaveReq) -> LeaveResult {
        match req {
            RouterLeaveReq::RemoveSelf { rejoin, remove_children } => {
                self.emit_leave_cmd(
                    Leave { request: false, rejoin, remove_children },
                    NwkAddress::MAX,
                    None,
                )
                .await
            }
            RouterLeaveReq::RemoveChild { ext_addr, rejoin, remove_children } => {
                let nwk_addr = self.lock_neighbors(|children| {
                    children.find_by_ext_addr(ext_addr).map(|nb| nb.nwk_addr)
                });
                let nwk_addr = unwrap_or_return!(nwk_addr, Err(NlmeLeaveError::UnknownDevice));

                self.emit_leave_cmd(
                    Leave { request: false, rejoin, remove_children },
                    nwk_addr,
                    Some(ext_addr),
                )
                .await
            }
        }
        .map_err(|err| NlmeLeaveError::TransferError(err))
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

#[cfg(test)]
mod tests {
    use crate::apl::zdo::config::ZbCapabilities;
    use crate::nwk::commands::link_status::LinkCost;
    use crate::nwk::ctx::{InitializedNwk, Nwk};
    use crate::nwk::nib::NwkNeighbor;
    use crate::nwk::nlme::{
        NetworkDescriptor, NlmeAssociationJoinRequest, NlmeJoinError, NwkNeighborJoinData,
        PanDescriptorDevice,
    };
    use core::assert_matches;
    use ieee802154::mac::beacon::{BeaconOrder, SuperframeOrder};
    use ieee802154::mac::command::{AssociationStatus, Command};
    use ieee802154::mac::{Address, FrameContent, FrameType, FrameVersion, Header, ShortAddress};
    use zb_hal_test_mock::driver::MockDriver;
    use zb_types::Vec;
    use zb_types::common::{ExtendedAddress, NwkAddress, PanId};
    use zb_types::mac::{Channel, MacCurrentSource, MacDeviceType, MacFrame, ReceivedMacFrame};

    #[futures_test::test]
    async fn association_join_fails_if_no_potential_parents() {
        let driver = MockDriver::builder().build();
        let nwk = Nwk::uninitialized(driver);

        let mut nd = NetworkDescriptor {
            extended_pan_id: Default::default(),
            pan_id: Default::default(),
            update_id: 0,
            logical_channel: Channel::Channel0,
            stack_profile: Default::default(),
            zigbee_version: 0,
            superframe_order: SuperframeOrder::Inactive,
            neighbors: Vec::<PanDescriptorDevice, 32>::from_slice(&[
                PanDescriptorDevice {
                    // permit_joining = false
                    neighbor: Default::default(),
                    join_data: NwkNeighborJoinData {
                        depth: 0,
                        beacon_order: BeaconOrder::OnDemand,
                        permit_joining: false,
                        router_capacity: false,
                        end_device_capacity: false,
                        potential_parent: true,
                    },
                },
                PanDescriptorDevice {
                    // end_device_capacity = false
                    neighbor: Default::default(),
                    join_data: NwkNeighborJoinData {
                        depth: 0,
                        beacon_order: BeaconOrder::OnDemand,
                        permit_joining: true,
                        router_capacity: true,
                        end_device_capacity: false,
                        potential_parent: true,
                    },
                },
                PanDescriptorDevice {
                    // link_cost = > 3
                    neighbor: NwkNeighbor::builder().incoming_cost(LinkCost::_5).build(),
                    join_data: NwkNeighborJoinData {
                        depth: 0,
                        beacon_order: BeaconOrder::OnDemand,
                        permit_joining: true,
                        router_capacity: true,
                        end_device_capacity: true,
                        potential_parent: true,
                    },
                },
                PanDescriptorDevice {
                    // potential_parent = false
                    neighbor: NwkNeighbor::builder().incoming_cost(LinkCost::_3).build(),
                    join_data: NwkNeighborJoinData {
                        depth: 0,
                        beacon_order: BeaconOrder::OnDemand,
                        permit_joining: true,
                        router_capacity: true,
                        end_device_capacity: true,
                        potential_parent: false,
                    },
                },
            ])
            .unwrap(),
        };

        let result = nwk
            .association_join(
                &mut nd,
                NlmeAssociationJoinRequest {
                    capability_information: ZbCapabilities {
                        device_type: MacDeviceType::ReducedFunctionDevice,
                        current_source: MacCurrentSource::Mains,
                        receiver_on_when_idle: true,
                        allocate_address: true,
                    },
                },
            )
            .await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        let err = err.error;
        assert_matches!(err, NlmeJoinError::NotPermitted(_))
    }

    #[futures_test::test]
    async fn association_join_joins_potential_parent_with_smallest_link_cost() {
        let pan_id = PanId(0x1234);
        let ext_addr = ExtendedAddress(0x1234123412341234);
        let parent_ext_addr = ExtendedAddress(0x1234123412341235);

        let mut driver = MockDriver::builder().build();
        driver.add_received_frame(ReceivedMacFrame {
            channel: Channel::Channel0,
            frame: MacFrame {
                header: Header {
                    frame_type: FrameType::MacCommand,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compress: false,
                    seq_no_suppress: false,
                    ie_present: false,
                    version: FrameVersion::Ieee802154_2003,
                    seq: 0,
                    destination: Some(Address::Extended(pan_id.into(), ext_addr.into())),
                    source: Some(Address::Extended(pan_id.into(), parent_ext_addr.into())),
                    auxiliary_security_header: None,
                },
                content: FrameContent::Command(Command::AssociationResponse(
                    ShortAddress(0x1234),
                    AssociationStatus::Successful,
                )),
                payload: Default::default(),
                footer: [0, 0],
            },
            rssi: 0,
            lqi: 0,
        });

        let nwk = Nwk::uninitialized(driver);

        let mut nd = NetworkDescriptor {
            extended_pan_id: Default::default(),
            pan_id: Default::default(),
            update_id: 0,
            logical_channel: Channel::Channel0,
            stack_profile: Default::default(),
            zigbee_version: 0,
            superframe_order: SuperframeOrder::Inactive,
            neighbors: Vec::<PanDescriptorDevice, 32>::from_slice(&[
                PanDescriptorDevice {
                    neighbor: NwkNeighbor::builder()
                        .nwk_addr(NwkAddress(0x1000))
                        .incoming_cost(LinkCost::_3)
                        .build(),
                    join_data: NwkNeighborJoinData {
                        depth: 0,
                        beacon_order: BeaconOrder::OnDemand,
                        permit_joining: true,
                        router_capacity: true,
                        end_device_capacity: true,
                        potential_parent: true,
                    },
                },
                PanDescriptorDevice {
                    neighbor: NwkNeighbor::builder()
                        .nwk_addr(NwkAddress(0x2000))
                        .incoming_cost(LinkCost::_1)
                        .build(),
                    join_data: NwkNeighborJoinData {
                        depth: 0,
                        beacon_order: BeaconOrder::OnDemand,
                        permit_joining: true,
                        router_capacity: true,
                        end_device_capacity: true,
                        potential_parent: true,
                    },
                },
            ])
            .unwrap(),
        };

        let result = nwk
            .association_join(
                &mut nd,
                NlmeAssociationJoinRequest {
                    capability_information: ZbCapabilities {
                        device_type: MacDeviceType::ReducedFunctionDevice,
                        current_source: MacCurrentSource::Mains,
                        receiver_on_when_idle: true,
                        allocate_address: true,
                    },
                },
            )
            .await;

        assert!(result.is_ok());

        let ok = result.ok().unwrap();
        let ok = ok.first().unwrap();

        ok.lock_parent(|parent| {
            assert_eq!(parent.nwk_addr, NwkAddress(0x2000));
            assert_eq!(parent.ext_addr, Some(parent_ext_addr));
        });

        ok.lock_neighbors(|neighbors| {
            assert_eq!(neighbors.neighbors.len(), 1);
        })
    }
}
