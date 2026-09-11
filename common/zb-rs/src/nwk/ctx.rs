use crate::apl::aps::types::ApsEndpoint;
use crate::apl::zdp::types::descriptors::SimpleDescriptor;
use crate::apl::zdp::types::descriptors::{NodeDescriptor, NodePowerDescriptor};
use crate::common::information_base::{ParentInformation, RouteEntrySet};
use crate::common::utils::from_octets;
use crate::mac::mlme::Mlme;
use crate::mac::types::PanDescriptor;
use crate::nwk::constants::{MAX_BROADCAST_JITTER_OCTETS, NWK_COORDINATOR_ADDRESS, NWK_END_DEVICE_TIMEOUT_DEFAULT};
use crate::nwk::nib::{IncomingFrameCounterDescriptor, NetworkKeyType, RouteRecord, TransactionRecord};
use crate::nwk::nlde::{NldeTransferError, NwkIndication};
use crate::nwk::nlme::{PermitJoiningConfig, PermitJoiningError};
use crate::nwk::service::transmission::DataFrameConfig;
use crate::stack_profile::{StackProfile, StackProfileParams};
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};
use byte_derive::{TryRead, TryWrite};
use core::fmt::Debug;
use core::ops::{Add, Deref, DerefMut};
use derive_more::{Deref, DerefMut};
use embassy_time::{Duration, Instant};
use ieee802154::mac::beacon::BeaconOrder;
use rand::SeedableRng;
use rand::prelude::SmallRng;
use smart_default::SmartDefault;
use thiserror::Error;
use zb_hal::{NwkMac, StorageError, StorageRegion};
use zb_macros::try_write_impl;
use zb_types::common::{DeviceType, ExtendedAddress, Key, NwkAddress, PanId};
use zb_types::mac::{Channel, MacAddress};

#[derive(TryRead, TryWrite, Clone, Copy, Debug, Default, PartialEq)]
#[repr(u8)]
pub enum DeviceTimeout {
    #[default]
    Secs10 = 0,
    Mins2 = 1,
    Mins4 = 2,
    Mins8 = 3,
    Mins16 = 4,
    Mins32 = 5,
    Mins64 = 6,
    Mins128 = 7,
    Mins256 = 8,
    Mins512 = 9,
    Mins1024 = 10,
    Mins2048 = 11,
    Mins4096 = 12,
    Mins8192 = 13,
    Mins16384 = 14,
}

impl DeviceTimeout {
    pub fn get_duration(&self) -> Duration {
        let value = *self as u8;
        match value {
            0 => Duration::from_secs(10),
            _ => Duration::from_secs(2u64.pow(value as u32) * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum NeighborRelationship {
    Parent = 0,
    Child = 1,
    Sibling = 2,
    #[default]
    Other = 3,
    PreviousChild = 4,
    UnauthenticatedChild = 5,
}

#[derive(Clone, Copy, Debug)]
pub struct NwkNeighborJoinData {
    pub extended_pan_id: ExtendedAddress,
    pub pan_id: PanId,
    pub logical_channel: Channel,
    pub depth: u8,
    pub beacon_order: BeaconOrder,
    pub permit_joining: bool,
    pub potential_parent: bool,
}

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct NeighborTable(zb_types::Vec<NwkNeighbor, 32>);

impl Deref for NeighborTable {
    type Target = zb_types::Vec<NwkNeighbor, 32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NeighborTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<NwkNeighbor> for NeighborTable {
    fn from_iter<T: IntoIterator<Item = NwkNeighbor>>(iter: T) -> Self {
        Self(zb_types::Vec::from_iter(iter))
    }
}

impl NeighborTable {
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        (*self).retain(|nb| nb.expiration > now);
    }

    pub fn find_by_ext_addr(&self, addr: ExtendedAddress) -> Option<&NwkNeighbor> {
        (*self).iter().find(|nb| nb.ext_addr == Some(addr))
    }

    pub fn find_by_ext_addr_and_type(
        &self,
        addr: ExtendedAddress,
        type_: DeviceType,
    ) -> Option<&NwkNeighbor> {
        (*self)
            .iter()
            .find(|nb| nb.ext_addr == Some(addr) && type_ == nb.device_type)
    }

    pub fn find_by_ext_addr_and_type_mut(
        &mut self,
        addr: ExtendedAddress,
        type_: DeviceType,
    ) -> Option<&mut NwkNeighbor> {
        (*self)
            .iter_mut()
            .find(|nb| nb.ext_addr == Some(addr) && type_ == nb.device_type)
    }

    pub fn find_by_ext_addr_mut(&mut self, addr: ExtendedAddress) -> Option<&mut NwkNeighbor> {
        (*self).iter_mut().find(|nb| nb.ext_addr == Some(addr))
    }

    pub fn find_by_short_addr(&self, addr: NwkAddress) -> Option<&NwkNeighbor> {
        (*self).iter().find(|nb| nb.nwk_addr == addr)
    }

    pub fn find_by_short_addr_and_device_type(
        &self,
        addr: NwkAddress,
        device_type: DeviceType,
    ) -> Option<&NwkNeighbor> {
        (*self)
            .iter()
            .find(|nb| nb.nwk_addr == addr && nb.device_type == device_type)
    }

    pub fn find_by_short_addr_mut(&mut self, addr: NwkAddress) -> Option<&mut NwkNeighbor> {
        (*self).iter_mut().find(|nb| nb.nwk_addr == addr)
    }
}

#[derive(Clone, Debug, TryRead, TryWrite, SmartDefault)]
pub struct NwkNeighbor {
    pub ext_addr: Option<ExtendedAddress>,
    pub nwk_addr: NwkAddress,
    pub device_type: DeviceType,
    pub end_device_configuration: u16,
    pub device_timeout: DeviceTimeout,
    pub relationship: NeighborRelationship,

    #[byte(ignore = true)]
    pub rx_on_when_idle: bool,
    // unused
    // timeout_counter: u32,
    #[byte(ignore = true)]
    pub transmit_failure: u8,
    #[byte(ignore = true)]
    pub incoming_cost: u8,
    #[byte(ignore = true)]
    pub outgoing_cost: u8,
    #[default(Instant::now())]
    #[byte(ignore = true, default = Instant::now())]
    pub expiration: Instant,
    // optional
    // incoming_beacon_timestamp: u8,
    // beacon_transmission_time: u8,
    #[byte(ignore = true)]
    pub keepalive_received: bool,
    // we only support 1 MAC interface currently
    // mac_interface_index: u8,
    // optional
    // mac_unicast_bytes_transmitted: u32,
    // mac_unicast_bytes_received: u32,
    #[byte(ignore = true)]
    pub node_descriptor: Option<NodeDescriptor>,
    #[byte(ignore = true)]
    pub power_descriptor: Option<NodePowerDescriptor>,
    #[byte(ignore = true)]
    pub simple_descriptors: zb_types::HashMap<ApsEndpoint, SimpleDescriptor, 32>,
    #[byte(ignore = true)]
    pub join_data: Option<NwkNeighborJoinData>,
}

pub struct NewNwkNeighbour {
    pub(crate) ext_addr: ExtendedAddress,
    pub(crate) nwk_addr: NwkAddress,
    pub(crate) device_type: DeviceType,
    pub(crate) rx_on_when_idle: bool,
    pub(crate) relationship: NeighborRelationship,
}

impl NwkNeighbor {
    pub fn new(neighbor: NewNwkNeighbour) -> Self {
        let timeout = NWK_END_DEVICE_TIMEOUT_DEFAULT;

        NwkNeighbor {
            ext_addr: Some(neighbor.ext_addr),
            nwk_addr: neighbor.nwk_addr,
            device_type: neighbor.device_type,
            rx_on_when_idle: neighbor.rx_on_when_idle,
            device_timeout: timeout,
            relationship: neighbor.relationship,
            expiration: Instant::now().add(timeout.get_duration()),
            ..Default::default()
        }
    }

    pub fn is_child(&self) -> bool {
        self.relationship == NeighborRelationship::Child
    }

    pub fn is_parent(&self) -> bool {
        self.relationship == NeighborRelationship::Parent
    }

    pub fn is_end_device(&self) -> bool {
        self.device_type == DeviceType::EndDevice
    }

    pub fn is_router(&self) -> bool {
        self.device_type == DeviceType::Router || self.device_type == DeviceType::Coordinator
    }

    pub(crate) fn update_from_pd(&mut self, pd: &PanDescriptor) {
        if let MacAddress::Short(_, addr) = pd.coord_address {
            self.nwk_addr = addr;
            self.device_type = if addr == NWK_COORDINATOR_ADDRESS {
                DeviceType::Coordinator
            } else {
                DeviceType::Router
            };
        }

        self.relationship = NeighborRelationship::Parent; // beacon from parent
        self.incoming_cost = pd.link_quality;
    }
}

#[derive(Debug, Default, Clone, Deref, DerefMut)]
pub struct AddressMap(heapless::index_map::FnvIndexMap<NwkAddress, ExtendedAddress, 64>);
impl AddressMap {
    pub fn find_ext_addr(&self, addr: &NwkAddress) -> Option<ExtendedAddress> {
        self.0.get(addr).cloned()
    }

    pub fn find_nwk_addr(&self, addr: &ExtendedAddress) -> Option<NwkAddress> {
        self.0.iter().find(|(_, ext)| **ext == *addr).map(|(nwk, _)| *nwk)
    }

    pub fn insert(&mut self, nwk: NwkAddress, ext: ExtendedAddress) -> () {
        self.0.insert(nwk, ext).ok();
    }
}

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct NetworkSecurityMaterialDescriptorSet(
    zb_types::Vec<NetworkSecurityMaterialDescriptor, 4>,
);

impl Deref for NetworkSecurityMaterialDescriptorSet {
    type Target = zb_types::Vec<NetworkSecurityMaterialDescriptor, 4>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NetworkSecurityMaterialDescriptorSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Default, Debug)]
pub struct NetworkSecurityMaterialDescriptor {
    pub key_seq_number: u8,
    pub outgoing_frame_counter: u32,
    pub incoming_frame_counter_set: zb_types::Vec<IncomingFrameCounterDescriptor, 32>,
    pub key: Key,
    pub network_key_type: NetworkKeyType,
}

impl<'a> TryRead<'a, Endian> for NetworkSecurityMaterialDescriptor {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        let key_seq_number = bytes.read_with(offset, ctx)?;
        let outgoing_frame_counter = bytes.read_with(offset, ctx)?;

        byte::check_len(bytes, 16)?;
        let key: [u8; 16] = bytes[*offset..*offset + 16].try_into().unwrap();
        *offset += 16;

        let network_key_type = bytes.read_with(offset, ctx)?;

        Ok((
            NetworkSecurityMaterialDescriptor {
                key_seq_number,
                outgoing_frame_counter,
                key,
                network_key_type,
                ..Default::default()
            },
            *offset,
        ))
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &NetworkSecurityMaterialDescriptor {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;

        bytes.write_with(offset, self.key_seq_number, ctx)?;
        bytes.write_with(offset, self.outgoing_frame_counter, ctx)?;
        bytes.write_with(offset, self.key.as_slice(), ())?;
        bytes.write_with(offset, self.network_key_type, ctx)?;

        Ok(*offset)
    }
}

pub const NWK_STORAGE_SIZE: usize = 1024;
pub trait NwkStorage : StorageRegion {}

#[derive(Error)]
pub struct TransitionError<T, E> {
    pub state: T,
    pub error: E,
}

impl<T, E> TransitionError<T, E> {
    pub fn new(state: T, error: E) -> Self {
        Self { state, error }
    }

    pub fn err<Ok>(state: T, error: E) -> Result<Ok, Self> {
        Err(Self { state, error })
    }
}

pub type TransitionResult<TOld, TNew, E> = Result<TNew, TransitionError<TOld, E>>;
pub type NwkTransitionResult<D, S, TOld, TNew, E> =
    Result<Nwk<TNew, D, S>, TransitionError<Nwk<TOld, D, S>, E>>;

pub trait NwkState {}
pub trait Unjoined : NwkState {}

pub trait BaseNwk {
    fn get_ext_addr(&self) -> ExtendedAddress;
    fn get_seq_number(&mut self) -> u8;
    fn get_rng(&mut self) -> &mut SmallRng;
}

pub trait NwkInitialized : BaseNwk {
    fn get_profile(&self) -> &StackProfileParams;
    fn get_addr(&self) -> NwkAddress;
    fn find_nwk_addr(&self, ext_addr: &ExtendedAddress) -> Option<NwkAddress>;
    fn find_ext_addr(&self, nwk_addr: &NwkAddress) -> Option<ExtendedAddress>;
    fn get_ext_pan_id(&self) -> ExtendedAddress;
}

#[trait_variant::make(NwkListen: Send)]
pub trait LocalNwkListen : NwkInitialized {
    async fn listen_nwk(&mut self, is_authorized: bool) -> NwkIndication;
}

#[trait_variant::make(NwkTransmit: Send)]
pub trait LocalNwkTransmit : NwkInitialized {
    async fn transmit_data_frame(&mut self, nsdu: &[u8], config: &DataFrameConfig) -> Result<(), NldeTransferError>;
}

pub trait NwkJoined : NwkListen + NwkTransmit {
    fn persist(&mut self) -> Result<(), StorageError>;
    fn get_children(&self) -> Option<&NeighborTable>;

    fn get_children_mut(&mut self) -> Option<&mut NeighborTable> {
        None
    }

    fn get_broadcast_transaction_table(&mut self) -> Option<&BroadcastTransactionTable>;

    fn get_addr_map(&self) -> &AddressMap;
    fn get_addr_map_mut(&mut self) -> &mut AddressMap;

    fn is_router(&self) -> bool {
        self.get_children().is_some()
    }
    fn is_end_device(&self) -> bool {
        !self.is_router()
    }

    fn permit_joining(&mut self, cfg: PermitJoiningConfig) -> Result<(), PermitJoiningError>;

    fn get_security_material_set_mut(&mut self) -> &mut NetworkSecurityMaterialDescriptorSet;
}

pub trait NwkRouter : NwkJoined {}
pub trait NwkEndDevice : NwkJoined {}

pub struct Uninitialized;
impl NwkState for Uninitialized {}
impl Unjoined for Uninitialized {}

pub trait InitializedState {}
pub trait ED : InitializedState {}
pub struct Initialized<T: InitializedState> {
    pub addr: NwkAddress,
    pub addr_map: AddressMap,
    pub ext_pan_id: ExtendedAddress,
    pub group_table: zb_types::Vec<NwkAddress, 64>,
    pub pan_id: PanId,
    pub parent: NwkNeighbor,
    pub parent_information: ParentInformation,
    pub profile: StackProfile,
    pub update_id: u8,

    pub active_key_seq_number: u8,
    pub all_fresh: bool,
    pub security_material_set: NetworkSecurityMaterialDescriptorSet,

    pub route_request_counter: u8,

    pub ctx: T,
}
impl<T: InitializedState> NwkState for Initialized<T> {}

pub struct PendingRejoin {}
impl InitializedState for PendingRejoin {}
impl ED for PendingRejoin {}
impl Unjoined for Initialized<PendingRejoin> {}

pub trait JoinedDevice {}
pub struct Joined<T: JoinedDevice> {
    pub ctx: T,
}
impl<T: JoinedDevice> InitializedState for Joined<T> {}
impl ED for Joined<EndDevice> {}

pub struct EndDevice;
impl JoinedDevice for EndDevice {}

impl<T: ED, D: NwkMac, S: StorageRegion> NwkInitialized for Nwk<Initialized<T>, D, S> {
    fn get_profile(&self) -> &StackProfileParams {
        &self.ctx.get_profile()
    }

    fn get_addr(&self) -> NwkAddress {
        self.ctx.addr
    }

    fn find_nwk_addr(&self, ext_addr: &ExtendedAddress) -> Option<NwkAddress> {
        find_nwk_addr(&self.get_ext_addr(), &self.ctx, ext_addr)
    }

    fn find_ext_addr(&self, nwk_addr: &NwkAddress) -> Option<ExtendedAddress> {
        find_ext_addr(&self.get_ext_addr(), &self.ctx, nwk_addr)
    }

    fn get_ext_pan_id(&self) -> ExtendedAddress {
        self.ctx.ext_pan_id
    }
}

impl<D: NwkMac, S: StorageRegion> NwkInitialized for Nwk<Initialized<Joined<Router>>, D, S> {
    fn get_profile(&self) -> &StackProfileParams {
        &self.ctx.get_profile()
    }

    fn get_addr(&self) -> NwkAddress {
        self.ctx.addr
    }

    fn find_nwk_addr(&self, ext_addr: &ExtendedAddress) -> Option<NwkAddress> {
        find_nwk_addr(&self.get_ext_addr(), &self.ctx, ext_addr)
            .or(self.get_children().find_by_ext_addr(*ext_addr)?.nwk_addr.into())
    }

    fn find_ext_addr(&self, nwk_addr: &NwkAddress) -> Option<ExtendedAddress> {
        find_ext_addr(&self.get_ext_addr(), &self.ctx, nwk_addr)
            .or(self.get_children().find_by_short_addr(*nwk_addr)?.ext_addr.into())
    }

    fn get_ext_pan_id(&self) -> ExtendedAddress {
        self.ctx.ext_pan_id
    }
}

fn find_nwk_addr<T: InitializedState>(slf: &ExtendedAddress, ctx: &Initialized<T>, ext_addr: &ExtendedAddress) -> Option<NwkAddress> {
    if *ext_addr == *slf {
        return ctx.addr.into();
    }

    if ctx.parent.ext_addr == Some(*ext_addr) {
        return ctx.parent.nwk_addr.into();
    }

    ctx.addr_map.find_nwk_addr(ext_addr)
}

fn find_ext_addr<T: InitializedState>(slf: &ExtendedAddress, ctx: &Initialized<T>, nwk_addr: &NwkAddress) -> Option<ExtendedAddress> {
    if *nwk_addr == (*ctx).addr {
        return (*slf).into();
    }

    if ctx.parent.nwk_addr == *nwk_addr {
        return ctx.parent.ext_addr.into();
    }

    ctx.addr_map.find_ext_addr(nwk_addr)
}

pub type BroadcastTransactionTable = zb_types::Vec<TransactionRecord, 64>;

#[derive(Default)]
pub struct Router {
    pub broadcast_transaction_table: BroadcastTransactionTable,
    pub children: NeighborTable,
    pub concentrator_discovery_time: u8,
    pub concentrator_radius: u8,
    pub is_concentrator: bool,
    pub route_record_table: zb_types::Vec<RouteRecord, 64>,
    pub route_table: RouteEntrySet,
}

impl JoinedDevice for Router {}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<Joined<Router>>, D, S> {
    pub fn get_router_ctx(&self) -> &Router {
        &self.ctx.ctx.ctx
    }

    pub fn get_router_ctx_mut(&mut self) -> &mut Router {
        &mut self.ctx.ctx.ctx
    }

    pub fn has_routing_capacity(&self) -> bool {
        !self.get_router_ctx().route_table.is_full()
    }

    pub fn get_children(&self) -> &NeighborTable {
        &self.get_router_ctx().children
    }

    pub fn cleanup_route_table(&mut self) {
        self.get_router_ctx_mut().route_table.cleanup()
    }
}

impl<T: InitializedState> Initialized<T> {
    pub fn get_profile(&self) -> &StackProfileParams {
        self.profile.get_params()
    }

    pub fn get_nwk_broadcast_delivery_time(&self) -> Duration {
        let profile = self.get_profile();

        let octets = (2.0 * profile.nwk_max_depth as f64)
            * (0.05 + (MAX_BROADCAST_JITTER_OCTETS as f64 / 2.0))
            + (profile.nwk_passive_ack_timeout * (profile.nwk_max_broadcast_retries as u32)) as f64
            / 1000.0;
        from_octets(octets as u64)
    }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<Initialized<T>, D, S> {
    pub fn reset(self) -> Nwk<Uninitialized, D, S> {
        Nwk {
            mac: self.mac,
            stg: self.stg,
            rng: self.rng,
            seq_number: self.seq_number,
            ctx: Uninitialized,
        }
    }
}

impl<T: InitializedState> Initialized<T> {
    pub fn make_router(self) -> Initialized<Joined<Router>> {
        Initialized {
            addr: self.addr,
            addr_map: self.addr_map,
            ext_pan_id: self.ext_pan_id,
            group_table: self.group_table,
            pan_id: self.pan_id,
            parent: self.parent,
            parent_information: self.parent_information,
            profile: self.profile,
            update_id: self.update_id,
            active_key_seq_number: self.active_key_seq_number,
            all_fresh: self.all_fresh,
            security_material_set: self.security_material_set,
            route_request_counter: 0,
            ctx: Joined {
                ctx: Router::default(),
            }
        }
    }
}

impl Initialized<PendingRejoin> {
    pub fn make_end_device(self) -> Initialized<Joined<EndDevice>> {
        Initialized {
            addr: self.addr,
            addr_map: self.addr_map,
            ext_pan_id: self.ext_pan_id,
            group_table: self.group_table,
            pan_id: self.pan_id,
            parent: self.parent,
            parent_information: self.parent_information,
            profile: self.profile,
            update_id: self.update_id,
            active_key_seq_number: self.active_key_seq_number,
            all_fresh: self.all_fresh,
            security_material_set: self.security_material_set,
            route_request_counter: 0,
            ctx: Joined {
                ctx: EndDevice
            }
        }
    }
}

#[derive(Clone)]
pub struct Nwk<T: NwkState, D: NwkMac, S: StorageRegion> {
    pub mac: Mlme<D>,
    pub stg: S,
    pub rng: SmallRng,

    pub seq_number: u8,
    pub ctx: T,
}

impl<T: NwkState, D: NwkMac, S: StorageRegion> BaseNwk for Nwk<T, D, S> {
    fn get_ext_addr(&self) -> ExtendedAddress {
        self.mac.get_ext_addr()
    }

    fn get_seq_number(&mut self) -> u8 {
        self.seq_number = self.seq_number.wrapping_add(1);
        self.seq_number
    }

    fn get_rng(&mut self) -> &mut SmallRng {
        &mut self.rng
    }
}

impl<D: NwkMac + Sync + Send, S: StorageRegion + Sync + Send> NwkRouter for Nwk<Initialized<Joined<Router>>, D, S> {}
impl<D: NwkMac + Sync + Send, S: StorageRegion + Sync + Send> NwkEndDevice for Nwk<Initialized<Joined<EndDevice>>, D, S> {}

impl<D: NwkMac, S: StorageRegion> Nwk<Initialized<PendingRejoin>, D, S> {
    pub fn make_end_device(self) -> Nwk<Initialized<Joined<EndDevice>>, D, S> {
        Nwk {
            mac: self.mac,
            stg: self.stg,
            rng: self.rng,
            seq_number: self.seq_number,
            ctx: self.ctx.make_end_device()
        }
    }

    pub fn make_router(self) -> Nwk<Initialized<Joined<Router>>, D, S> {
        Nwk {
            mac: self.mac,
            stg: self.stg,
            rng: self.rng,
            seq_number: self.seq_number,
            ctx: self.ctx.make_router()
        }
    }
}

#[derive(TryRead, TryWrite)]
pub struct PersistentNwkContext {
    addr: NwkAddress, // 2
    ext_pan_id: ExtendedAddress, // 8
    pan_id: PanId, // 2
    parent: NwkNeighbor, // 15
    parent_information: ParentInformation, // 2
    profile: StackProfile, // 1
    active_key_seq_number: u8, // 1
    all_fresh: bool, // 1
    security_material_set: NetworkSecurityMaterialDescriptorSet, // 25*4
    neighbor_table: Option<NeighborTable>, // 32*15
}

#[derive(Error)]
pub struct LoadNwkError<D: NwkMac, S: StorageRegion> {
    pub mac: Mlme<D>,
    pub stg: S,
    pub err: StorageError,
}

impl<T: NwkState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub fn load(mac: Mlme<D>, mut stg: S) -> Result<Nwk<Initialized<PendingRejoin>, D, S>, LoadNwkError<D, S>> {
        let mut buffer = [0u8; NWK_STORAGE_SIZE];

        match stg.load(&mut buffer) {
            Ok(_) => {}
            Err(err) => {
                log::warn!("error loading ctx: {:?}", err);
                return Err(LoadNwkError {
                    mac,
                    stg,
                    err,
                });
            }
        };

        let persistent = match buffer.read_with::<PersistentNwkContext>(&mut 0, byte::LE)
        {
            Ok(persistent) => persistent,
            Err(err) => {
                log::warn!("error loading ctx: {:?}", err);
                return Err(LoadNwkError {
                    mac,
                    stg,
                    err: StorageError::ByteError(err),
                });
            }
        };

        Ok(Nwk {
            mac,
            stg,
            rng: SmallRng::seed_from_u64(0), // TODO
            seq_number: 0,
            ctx: Initialized::<PendingRejoin> {
                addr: persistent.addr,
                addr_map: Default::default(),
                ext_pan_id: persistent.ext_pan_id,
                group_table: Default::default(),
                pan_id: persistent.pan_id,
                parent: persistent.parent,
                parent_information: persistent.parent_information,
                profile: persistent.profile,
                update_id: 0,
                active_key_seq_number: persistent.active_key_seq_number,
                all_fresh: persistent.all_fresh,
                security_material_set: persistent.security_material_set,
                route_request_counter: 0,
                ctx: PendingRejoin {},
            },
        })
    }

}

impl<D: NwkMac + Sync + Send, S: StorageRegion + Sync + Send> NwkJoined for Nwk<Initialized<Joined<EndDevice>>, D, S> {
    fn persist(&mut self) -> Result<(), StorageError> {
        let persistent = make_persistence_end_device(&self.ctx);

        let mut buffer = [0u8; NWK_STORAGE_SIZE];
        buffer.write_with(&mut 0, persistent, byte::LE)?;

        self.stg.persist(&buffer)
    }

    fn get_children(&self) -> Option<&NeighborTable> {
        None
    }

    fn get_broadcast_transaction_table(&mut self) -> Option<&BroadcastTransactionTable> {
        None
    }

    fn get_addr_map(&self) -> &AddressMap {
        &self.ctx.addr_map
    }

    fn get_addr_map_mut(&mut self) -> &mut AddressMap {
        &mut self.ctx.addr_map
    }

    fn permit_joining(&mut self, _cfg: PermitJoiningConfig) -> Result<(), PermitJoiningError> {
        Err(PermitJoiningError::InvalidRequest("permit joining is only available in routers"))
    }

    fn get_security_material_set_mut(&mut self) -> &mut NetworkSecurityMaterialDescriptorSet {
        &mut self.ctx.security_material_set
    }
}

impl<D: NwkMac + Sync + Send, S: StorageRegion + Sync + Send> NwkJoined for Nwk<Initialized<Joined<Router>>, D, S> {
    fn persist(&mut self) -> Result<(), StorageError> {
        let mut persistent = make_persistence_end_device(&self.ctx);
        persistent.neighbor_table = Some(self.get_router_ctx().children.clone());

        let mut buffer = [0u8; 1024];
        buffer.write_with(&mut 0, persistent, byte::LE)?;

        self.stg.persist(&buffer)
    }

    fn get_children(&self) -> Option<&NeighborTable> {
        Some(&self.ctx.ctx.ctx.children)
    }

    fn get_children_mut(&mut self) -> Option<&mut NeighborTable> {
        Some(&mut self.ctx.ctx.ctx.children)
    }

    fn get_broadcast_transaction_table(&mut self) -> Option<&BroadcastTransactionTable> {
        Some(&self.ctx.ctx.ctx.broadcast_transaction_table)
    }

    fn get_addr_map(&self) -> &AddressMap {
        &self.ctx.addr_map
    }

    fn get_addr_map_mut(&mut self) -> &mut AddressMap {
        &mut self.ctx.addr_map
    }

    fn permit_joining(&mut self, cfg: PermitJoiningConfig) -> Result<(), PermitJoiningError> {
        Ok(self.permit_joining(cfg))
    }

    fn get_security_material_set_mut(&mut self) -> &mut NetworkSecurityMaterialDescriptorSet {
        &mut self.ctx.security_material_set
    }
}


fn make_persistence_end_device<T: JoinedDevice>(ctx: &Initialized<Joined<T>>) -> PersistentNwkContext {
    PersistentNwkContext {
        addr: ctx.addr,
        ext_pan_id: ctx.ext_pan_id,
        pan_id: ctx.pan_id,
        parent: ctx.parent.clone(),
        parent_information: ctx.parent_information,
        profile: ctx.profile,
        active_key_seq_number: ctx.active_key_seq_number,
        all_fresh: ctx.all_fresh,
        security_material_set: ctx.security_material_set.clone(),
        neighbor_table: None
    }
}

#[cfg(test)]
pub mod tests {
    use crate::common::information_base::ParentInformation;
    use crate::mac::mlme::Mlme;
    use crate::nwk::ctx::{EndDevice, Initialized, Joined, NetworkSecurityMaterialDescriptor, NetworkSecurityMaterialDescriptorSet, Nwk, NwkNeighbor};
    use crate::stack_profile::StackProfile;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use zb_hal_test_mock::driver::MockDriver;
    use zb_hal_test_mock::storage::MemoryStorage;
    use zb_types::common::{ExtendedAddress, Key, NwkAddress, PanId};
    use zb_types::mac::Channel;

    const DEFAULT_NWK_KEY: Key = [
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0d
    ];

    pub const DEFAULT_EXT_ADDR: ExtendedAddress = ExtendedAddress(0x1234_5678_90ab_cdef);
    pub const DEFAULT_NWK_ADDR: NwkAddress = NwkAddress(0x1234);
    pub const DEFAULT_NWK_PAN_ID: PanId = PanId(0x1234);

    #[bon::bon]
    impl Nwk<Initialized<Joined<EndDevice>>, MockDriver, MemoryStorage> {

        #[builder]
        pub fn end_device(
            #[builder(default = DEFAULT_NWK_ADDR)]
            addr: NwkAddress,
            #[builder(default = DEFAULT_EXT_ADDR)]
            ext_addr: ExtendedAddress,
            #[builder(default = DEFAULT_EXT_ADDR)]
            ext_pan_id: ExtendedAddress,
            #[builder(default = DEFAULT_NWK_PAN_ID)]
            pan_id: PanId,
            #[builder(default = NwkNeighbor::default())]
            parent: NwkNeighbor,
            #[builder(default = ParentInformation::default())]
            parent_information: ParentInformation,
            #[builder(default = StackProfile::ZigbeePro)]
            profile: StackProfile,
            #[builder(default = true)]
            rx_on_when_idle: bool,
            #[builder(default = Channel::Channel11)]
            channel: Channel,
            #[builder(default = DEFAULT_NWK_KEY)]
            key: Key,
            #[builder(default = 0)]
            outgoing_frame_counter: u32,
        ) -> Self {
            let driver = MockDriver::builder()
                .extended_address(ext_addr)
                .pan_id(pan_id)
                .short_addr(addr)
                .rx_on_when_idle(rx_on_when_idle)
                .channel(channel)
                .build();

            let mac = Mlme::new(driver);
            let mut security_material_set = NetworkSecurityMaterialDescriptorSet::default();
            security_material_set.push(NetworkSecurityMaterialDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter,
                incoming_frame_counter_set: Default::default(),
                key,
                network_key_type: Default::default(),
            });

            Nwk {
                mac,
                stg: MemoryStorage::new(),
                rng: SmallRng::seed_from_u64(0),
                seq_number: 0,
                ctx: Initialized {
                    addr,
                    addr_map: Default::default(),
                    ext_pan_id,
                    group_table: Default::default(),
                    pan_id,
                    parent,
                    parent_information,
                    profile,
                    update_id: 0,
                    active_key_seq_number: 0,
                    all_fresh: false,
                    security_material_set,
                    route_request_counter: 0,
                    ctx: Joined {
                        ctx: EndDevice
                    },
                },
            }
        }
    }
}