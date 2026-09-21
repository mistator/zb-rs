use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};
use byte::BytesExt;
use byte_derive::{TryRead, TryWrite};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::Duration;
use rand::prelude::SmallRng;
use rand::SeedableRng;
use smart_default::SmartDefault;
use thiserror::Error;
use zb_hal::{NwkMac, StorageError, StorageRegion};
use zb_types::common::{ExtendedAddress, NwkAddress, PanId};
use zb_types::mac::MacDeviceType;
use zb_types::transitions::{Either, TransitionError};
use crate::apl::zdo::config::ZbCapabilities;
use crate::common::information_base::{ParentInformation, RouteTable};
use crate::common::utils::from_octets;
use crate::mac::mlme::Mlme;
use crate::nwk::commands::leave::Leave;
use crate::nwk::constants::MAX_BROADCAST_JITTER_OCTETS;
use crate::nwk::nib::{AddressMap, BroadcastTransactionTable, NeighborTable, NetworkSecurityMaterialDescriptorSet, NwkNeighbor, RouteRecord, RouteRecordTable};
use crate::nwk::nlde::{NldeTransferError, NwkIndication};
use crate::nwk::nlme::NlmeLeaveError;
use crate::nwk::service::transmission::DataFrameConfig;
use crate::stack_profile::{StackProfile, StackProfileParams};

pub type NwkTransitionResult<D, S, TOld, TNew, E> =
    Result<Nwk<TNew, D, S>, TransitionError<Nwk<TOld, D, S>, E>>;

pub const NWK_STORAGE_SIZE: usize = 1024;

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

#[derive(Clone, SmartDefault)]
pub struct NwkContext {
    // INITIALIZED FIELDS
    pub addr_map: AddressMap,
    pub group_table: GroupTable,
    pub parent_information: ParentInformation,
    pub profile: StackProfile,
    pub update_id: u8,

    pub active_key_seq_number: Arc<AtomicU8>,
    pub all_fresh: bool,
    #[default(Arc::new(Mutex::new(NetworkSecurityMaterialDescriptorSet::default())))]
    pub security_material_set: Arc<Mutex<CriticalSectionRawMutex, NetworkSecurityMaterialDescriptorSet>>,

    pub route_request_counter: u8,
    #[default(Arc::new(Mutex::new(NeighborTable::default())))]
    pub neighbors: Arc<Mutex<CriticalSectionRawMutex, NeighborTable>>,

    // ROUTER FIELDS
    pub broadcast_transaction_table: BroadcastTransactionTable,
    pub concentrator_discovery_time: u8,
    pub concentrator_radius: u8,
    pub is_concentrator: bool,
    pub route_record_table: zb_types::Vec<RouteRecord, 64>,
    pub route_table: RouteTable,
}


pub trait NwkState {}
pub trait InitializedState : NwkState {}
pub trait UnjoinedState : NwkState {}
pub trait JoinedState : InitializedState {}
pub trait NonRoutingState: InitializedState {}
pub trait RoutingState : JoinedState {}

pub struct Uninitialized {}
pub struct PendingJoin {}
pub struct JoinedAsEndDevice {}
pub struct JoinedAsRouter {}
pub struct JoinedAsCoordinator {}

impl NwkState for Uninitialized {}
impl UnjoinedState for Uninitialized {}

impl NwkState for PendingJoin {}
impl InitializedState for PendingJoin {}
impl UnjoinedState for PendingJoin {}
impl NonRoutingState for PendingJoin {}

impl NwkState for JoinedAsEndDevice {}
impl InitializedState for JoinedAsEndDevice {}
impl JoinedState for JoinedAsEndDevice {}
impl NonRoutingState for JoinedAsEndDevice {}

impl NwkState for JoinedAsRouter {}
impl InitializedState for JoinedAsRouter {}
impl JoinedState for JoinedAsRouter {}
impl RoutingState for JoinedAsRouter {}

impl NwkState for JoinedAsCoordinator {}
impl InitializedState for JoinedAsCoordinator {}
impl JoinedState for JoinedAsCoordinator {}
impl RoutingState for JoinedAsCoordinator {}

pub type GroupTable = zb_types::Vec<NwkAddress, 64>;

#[derive(Clone)]
pub struct Nwk<T: NwkState, D: NwkMac, S: StorageRegion> {
    pub(crate) mac: Mlme<D>,
    pub(crate) stg: S,
    pub(crate) rng: SmallRng,

    pub(crate) seq_number: Arc<AtomicU8>,

    ctx: NwkContext,
    _marker: PhantomData<T>,
}

pub struct NwkConfig<D: NwkMac, S: StorageRegion> {
    pub mac: Mlme<D>,
    pub stg: S,
    pub rng: SmallRng,
    pub seq_number: Arc<AtomicU8>,
}

#[derive(Error)]
pub struct LoadNwkError<D: NwkMac, S: StorageRegion> {
    pub mac: Mlme<D>,
    pub stg: S,
    pub err: StorageError,
}

impl<T: NwkState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub fn new(cfg: NwkConfig<D, S>) -> Self {
        Nwk {
            mac: cfg.mac,
            stg: cfg.stg,
            rng: cfg.rng,
            seq_number: cfg.seq_number,
            ctx: Default::default(),
            _marker: PhantomData,
        }
    }

    pub fn load(mut mac: Mlme<D>, mut stg: S) -> Result<Nwk<PendingJoin, D, S>, LoadNwkError<D, S>> {
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

        mac.set_pan_id(persistent.pan_id.into());
        mac.set_short_address(persistent.addr.into());
        mac.set_extended_pan_id(persistent.ext_pan_id.into());

        let neighbors = NeighborTable::new(persistent.parent);

        Ok(Nwk {
            mac,
            stg,
            rng: SmallRng::seed_from_u64(0), // TODO
            seq_number: Arc::new(AtomicU8::new(0)),
            ctx: NwkContext {
                addr_map: Default::default(),
                group_table: Default::default(),
                neighbors: Arc::new(Mutex::new(neighbors)),
                parent_information: persistent.parent_information,
                profile: persistent.profile,
                update_id: 0,
                active_key_seq_number: Arc::new(AtomicU8::new(persistent.active_key_seq_number)),
                all_fresh: persistent.all_fresh,
                security_material_set: Arc::new(Mutex::new(persistent.security_material_set)),
                route_request_counter: 0,
                ..Default::default()
            },
            _marker: PhantomData,
        })
    }
}

pub(crate) trait BaseNwkPrivate<D: NwkMac, S: StorageRegion> {
    fn get_mac(&self) -> &Mlme<D>;
    fn get_mac_mut(&mut self) -> &mut Mlme<D>;
    fn get_stg(&self) -> &S;
    fn get_stg_mut(&mut self) -> &mut S;
    fn get_rng(&mut self) -> &mut SmallRng;
}

pub trait BaseNwk<D: NwkMac, S: StorageRegion> : BaseNwkPrivate<D, S> {
    fn get_ext_addr(&self) -> ExtendedAddress { self.get_mac().get_ext_addr() }
    fn get_seq_number(&self) -> Arc<AtomicU8>;
    fn get_next_seq_number(&self) -> u8;
}

pub trait InitializedNwk<D: NwkMac, S: StorageRegion> : BaseNwk<D, S> {
    fn get_ctx(&self) -> &NwkContext;
    fn get_ctx_mut(&mut self) -> &mut NwkContext;

    fn get_addr(&self) -> NwkAddress { self.get_mac().get_short_address().unwrap() }
    fn get_pan_id(&self) -> PanId { self.get_mac().get_pan_id().unwrap() }
    fn get_ext_pan_id(&self) -> ExtendedAddress { self.get_mac().get_extended_pan_id().unwrap() }
    fn get_profile(&self) -> &StackProfileParams { &self.get_ctx().profile.get_params() }
    fn get_group_table(&self) -> &GroupTable { &self.get_ctx().group_table }
    fn get_addr_map(&self) -> &AddressMap { &self.get_ctx().addr_map }
    fn get_addr_map_mut(&mut self) -> &mut AddressMap { &mut self.get_ctx_mut().addr_map }

    fn lock_parent<U>(&self, f: impl FnOnce(&NwkNeighbor) -> U) -> U {
        self.get_ctx().neighbors.lock(|nbs| f(&nbs.parent))
    }
    fn lock_parent_mut<U>(&self, f: impl FnOnce(&mut NwkNeighbor) -> U) -> U {
        unsafe { self.get_ctx().neighbors.lock_mut(|nbs| f(&mut nbs.parent)) }
    }

    fn get_neighbors(&self) -> Arc<Mutex<CriticalSectionRawMutex, NeighborTable>> { self.get_ctx().neighbors.clone() }
    fn lock_neighbors<U>(&self, f: impl FnOnce(&NeighborTable) -> U) -> U {
        self.get_ctx().neighbors.lock(|nbs| f(nbs))
    }
    fn lock_neighbors_mut<U>(&self, f: impl FnOnce(&mut NeighborTable) -> U) -> U {
        unsafe { self.get_ctx().neighbors.lock_mut(|nbs| f(nbs)) }
    }

    fn find_nwk_addr(&self, ext_addr: ExtendedAddress) -> Option<NwkAddress> {
        let slf = self.get_ext_addr();
        if ext_addr == slf {
            return self.get_addr().into();
        }

        self.get_ctx().addr_map.find_nwk_addr(&ext_addr)
            .or(self.get_ctx().neighbors.lock(|nbs| nbs.find_by_ext_addr(ext_addr)?.nwk_addr.into()))
    }

    fn find_ext_addr(&self, nwk_addr: NwkAddress) -> Option<ExtendedAddress> {
        if nwk_addr == self.get_addr() {
            return self.get_ext_addr().into();
        }

        self.get_ctx().addr_map.find_ext_addr(&nwk_addr)
            .or(self.get_ctx().neighbors.lock(|nbs| nbs.find_by_short_addr(nwk_addr)?.ext_addr.into()))
    }

    fn get_security_material_set(&self) -> Arc<Mutex<CriticalSectionRawMutex, NetworkSecurityMaterialDescriptorSet>> {
        self.get_ctx().security_material_set.clone()
    }

    fn get_active_key_seq_number(&self) -> Arc<AtomicU8> {
        self.get_ctx().active_key_seq_number.clone()
    }

    fn get_nwk_broadcast_delivery_time(&self) -> Duration {
        let profile = self.get_profile();

        let octets = (2.0 * profile.nwk_max_depth as f64)
            * (0.05 + (MAX_BROADCAST_JITTER_OCTETS as f64 / 2.0))
            + (profile.nwk_passive_ack_timeout * (profile.nwk_max_broadcast_retries as u32)) as f64
            / 1000.0;
        from_octets(octets as u64)
    }

    fn get_broadcast_transaction_table(&self) -> &BroadcastTransactionTable {
        &self.get_ctx().broadcast_transaction_table
    }

    fn persist(&mut self) -> Result<(), StorageError> {
        let persistent = PersistentNwkContext {
            addr: self.get_addr(),
            ext_pan_id: self.get_ext_pan_id(),
            pan_id: self.get_pan_id(),
            parent: self.get_ctx().neighbors.lock(|nbs| nbs.parent.clone()),
            parent_information: self.get_ctx().parent_information,
            profile: self.get_ctx().profile,
            active_key_seq_number: self.get_ctx().active_key_seq_number.load(Ordering::Relaxed),
            all_fresh: self.get_ctx().all_fresh,
            security_material_set: self.get_ctx().security_material_set.lock(|set| set.clone()),
            neighbor_table: self.get_ctx().neighbors.lock(|children| children.clone()).into()
        };

        let mut buffer = [0u8; NWK_STORAGE_SIZE];
        buffer.write_with(&mut 0, persistent, byte::LE)?;

        self.get_stg_mut().persist(&buffer)
    }

    fn reset(self) -> Nwk<Uninitialized, D, S>;
}

pub trait NwkListen<D: NwkMac, S: StorageRegion> : InitializedNwk<D, S> {
    async fn listen_nwk(&mut self, is_authorized: bool) -> NwkIndication;
}

pub trait NwkTransmit<D: NwkMac, S: StorageRegion> : InitializedNwk<D, S> {
    async fn transmit_data_frame(&mut self, nsdu: &[u8], config: &DataFrameConfig) -> Result<(), NldeTransferError>;
}

pub trait JoinedNwk<D: NwkMac, S: StorageRegion> : NwkListen<D, S> + NwkTransmit<D, S> {
    //fn get_parent(&self) -> &NwkNeighbor { &self.get_ctx().parent }
    fn to_pending_rejoin(self) -> Nwk<PendingJoin, D, S>;
    fn is_router(&self) -> bool;
    fn is_end_device(&self) -> bool { !self.is_router() }
    async fn leave(&mut self, rejoin: bool) -> Result<(), NlmeLeaveError>;
}

pub trait RoutingNwk<T: RoutingState, D: NwkMac, S: StorageRegion> : JoinedNwk<D, S> {}

impl<T: NwkState, D: NwkMac, S: StorageRegion> BaseNwkPrivate<D, S> for Nwk<T, D, S> {
    fn get_mac(&self) -> &Mlme<D> { &self.mac }
    fn get_mac_mut(&mut self) -> &mut Mlme<D> { &mut self.mac }
    fn get_stg(&self) -> &S { &self.stg }
    fn get_stg_mut(&mut self) -> &mut S { &mut self.stg }
    fn get_rng(&mut self) -> &mut SmallRng { &mut self.rng }
}

impl<T: NwkState, D: NwkMac, S: StorageRegion> BaseNwk<D, S> for Nwk<T, D, S> {
    fn get_seq_number(&self) -> Arc<AtomicU8> { self.seq_number.clone() }
    fn get_next_seq_number(&self) -> u8 { self.seq_number.fetch_add(1, Ordering::Relaxed) }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> InitializedNwk<D, S> for Nwk<T, D, S> {
    fn get_ctx(&self) -> &NwkContext { &self.ctx }
    fn get_ctx_mut(&mut self) -> &mut NwkContext { &mut self.ctx }

    fn reset(mut self) -> Nwk<Uninitialized, D, S>
    where
        Self: Sized
    {
        self.get_stg_mut().clear().ok();
        self.mac.reset(true);

        Nwk {
            mac: self.mac,
            stg: self.stg,
            rng: self.rng,
            seq_number: self.seq_number,
            ctx: NwkContext::default(),
            _marker: PhantomData
        }
    }
}

fn to_pending_rejoin<T: JoinedState, D: NwkMac, S: StorageRegion>(mut nwk: Nwk<T, D, S>) -> Nwk<PendingJoin, D, S> {
    nwk.get_ctx_mut().neighbors = Arc::new(Mutex::new(NeighborTable::new(nwk.lock_parent(|parent| parent.clone()))));
    let seq_number = nwk.get_seq_number();

    Nwk {
        mac: nwk.mac,
        stg: nwk.stg,
        rng: nwk.rng,
        ctx: nwk.ctx,
        seq_number,
        _marker: PhantomData,
    }
}

impl<D: NwkMac, S: StorageRegion> JoinedNwk<D, S> for Nwk<JoinedAsEndDevice, D, S> {
    fn to_pending_rejoin(self) -> Nwk<PendingJoin, D, S> { to_pending_rejoin(self) }
    fn is_router(&self) -> bool { false }

    async fn leave(&mut self, rejoin: bool) -> Result<(), NlmeLeaveError> {
        self.emit_leave_cmd(Leave {
            rejoin,
            request: false,
            remove_children: false,
        }, NwkAddress::BROADCAST_RX_ON_IDLE, None).await.map_err(NlmeLeaveError::from)
    }
}

impl<D: NwkMac, S: StorageRegion> JoinedNwk<D, S> for Nwk<JoinedAsRouter, D, S> {
    fn to_pending_rejoin(self) -> Nwk<PendingJoin, D, S> { to_pending_rejoin(self) }
    fn is_router(&self) -> bool { true }

    async fn leave(&mut self, rejoin: bool) -> Result<(), NlmeLeaveError> {
        self.emit_leave_cmd(Leave {
            rejoin,
            request: false,
            remove_children: false,
        }, NwkAddress::MAX, None).await.map_err(NlmeLeaveError::from)
    }
}

impl<D: NwkMac, S: StorageRegion> JoinedNwk<D, S> for Nwk<JoinedAsCoordinator, D, S> {
    fn to_pending_rejoin(self) -> Nwk<PendingJoin, D, S> { to_pending_rejoin(self) }
    fn is_router(&self) -> bool { true }

    async fn leave(&mut self, rejoin: bool) -> Result<(), NlmeLeaveError> {
        self.emit_leave_cmd(Leave {
            rejoin,
            request: false,
            remove_children: false,
        }, NwkAddress::MAX, None).await.map_err(NlmeLeaveError::from)
    }
}

impl<T: RoutingState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub fn get_route_table(&self) -> &RouteTable { &self.ctx.route_table }
    pub fn get_route_table_mut(&mut self) -> &mut RouteTable { &mut self.ctx.route_table }
    pub fn get_route_record_table(&self) -> &RouteRecordTable { &self.ctx.route_record_table }
    pub fn get_route_record_table_mut(&mut self) -> &mut RouteRecordTable { &mut self.ctx.route_record_table }
    pub fn get_broadcast_transaction_table(&self) -> &BroadcastTransactionTable { &self.ctx.broadcast_transaction_table }
    pub fn get_broadcast_transaction_table_mut(&mut self) -> &mut BroadcastTransactionTable { &mut self.ctx.broadcast_transaction_table }

    pub fn lock_neighbors<U>(&self, f: impl FnOnce(&NeighborTable) -> U) -> U { self.ctx.neighbors.lock(f) }
    pub fn lock_neighbors_mut<U>(&self, f: impl FnOnce(&mut NeighborTable) -> U) -> U {
        unsafe { self.ctx.neighbors.lock_mut(f) }
    }

    pub fn has_routing_capacity(&self) -> bool { !self.ctx.route_table.is_full() }
}

impl<D: NwkMac, S: StorageRegion> Nwk<Uninitialized, D, S> {
    pub fn to_joined(self, parent: NwkNeighbor, stack_profile: StackProfile, capability_information: ZbCapabilities) -> Either<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>> {
        let ctx = NwkContext {
            neighbors: Arc::new(Mutex::new(NeighborTable::new(parent))),
            profile: stack_profile,
            ..Default::default()
        };

        match capability_information.device_type {
            MacDeviceType::ReducedFunctionDevice => {
                Either::First(Nwk::<JoinedAsEndDevice, D, S> {
                    mac: self.mac,
                    stg: self.stg,
                    rng: self.rng,
                    seq_number: self.seq_number,
                    ctx,
                    _marker: PhantomData,
                })
            }
            MacDeviceType::FullFunctionDevice => {
                Either::Second(Nwk::<JoinedAsRouter, D, S> {
                    mac: self.mac,
                    stg: self.stg,
                    rng: self.rng,
                    seq_number: self.seq_number,
                    ctx,
                    _marker: PhantomData,
                })
            }
        }
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<PendingJoin, D, S> {
    pub fn to_router(self) -> Nwk<JoinedAsRouter, D, S> {
        Nwk::<JoinedAsRouter, D, S> {
            mac: self.mac,
            stg: self.stg,
            rng: self.rng,
            seq_number: self.seq_number,
            ctx: self.ctx,
            _marker: PhantomData,
        }
    }
    pub fn to_joined(mut self, parent: NwkNeighbor, capability_information: ZbCapabilities) -> Either<Nwk<JoinedAsEndDevice, D, S>, Nwk<JoinedAsRouter, D, S>> {
        self.ctx.neighbors = Arc::new(Mutex::new(NeighborTable::new(parent)));

        match capability_information.device_type {
            MacDeviceType::ReducedFunctionDevice => {
                Either::First(Nwk::<JoinedAsEndDevice, D, S> {
                    mac: self.mac,
                    stg: self.stg,
                    rng: self.rng,
                    seq_number: self.seq_number,
                    ctx: self.ctx,
                    _marker: PhantomData,
                })
            }
            MacDeviceType::FullFunctionDevice => {
                Either::Second(Nwk::<JoinedAsRouter, D, S> {
                    mac: self.mac,
                    stg: self.stg,
                    rng: self.rng,
                    seq_number: self.seq_number,
                    ctx: self.ctx,
                    _marker: PhantomData,
                })
            }
        }
    }
}

impl<D: NwkMac, S: StorageRegion> Nwk<JoinedAsEndDevice, D, S> {
    pub fn to_router(self) -> Nwk<JoinedAsRouter, D, S> {
        Nwk {
            mac: self.mac,
            stg: self.stg,
            rng: self.rng,
            seq_number: self.seq_number,
            ctx: self.ctx,
            _marker: PhantomData,
        }
    }
}



mod private {
    use crate::nwk::ctx::{JoinedAsCoordinator, JoinedAsEndDevice, JoinedAsRouter, PendingJoin, Uninitialized};

    pub trait Sealed {}

    impl Sealed for Uninitialized {}
    impl Sealed for PendingJoin {}
    impl Sealed for JoinedAsEndDevice {}
    impl Sealed for JoinedAsRouter {}
    impl Sealed for JoinedAsCoordinator {}
}


#[cfg(test)]
pub mod tests {
    use alloc::sync::Arc;
    use core::marker::PhantomData;
    use embassy_sync::blocking_mutex::Mutex;
    use core::sync::atomic::AtomicU8;
    use ieee802154::mac;
    use ieee802154::mac::{FrameContent, Header};
    use crate::common::information_base::ParentInformation;
    use crate::mac::mlme::Mlme;
    use crate::nwk::ctx::{InitializedNwk, JoinedAsEndDevice, JoinedAsRouter, JoinedState, NeighborTable, NetworkSecurityMaterialDescriptorSet, Nwk, NwkContext, NwkNeighbor};
    use crate::stack_profile::StackProfile;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use zb_hal_test_mock::driver::{MockDriver, DEFAULT_NWK_ADDR, DEFAULT_EXT_ADDR, DEFAULT_NWK_PAN_ID};
    use zb_hal_test_mock::storage::MemoryStorage;
    use zb_types::common::{DeviceType, ExtendedAddress, Key, NwkAddress, PanId};
    use zb_types::mac::{Channel, A_MAX_MAC_PAYLOAD_SIZE, MacFrame};
    use zb_types::Vec;
    use crate::nwk::frame::NwkFrame;
    use crate::nwk::nib::{NeighborRelationship, NewNwkNeighbour, NEIGHBOR_TABLE_MAX_ENTRIES, NetworkSecurityMaterialDescriptor};

    const DEFAULT_NWK_KEY: Key = Key::new([
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0d
    ]);

    impl<T: JoinedState> Nwk<T, MockDriver, MemoryStorage> {
        pub fn add_received_frame(&mut self, frame: &NwkFrame) -> () {
            let mut mac_payload = [0u8; A_MAX_MAC_PAYLOAD_SIZE];
            let length = self.build_mac_payload(frame, &mut mac_payload).unwrap();

            let mac_frame = MacFrame {
                header: Header {
                    frame_type: mac::FrameType::Data,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compress: true,
                    seq_no_suppress: false,
                    ie_present: false,
                    version: mac::FrameVersion::Ieee802154_2003,
                    seq: 1,
                    destination: mac::Address::Short(self.get_pan_id().into(), self.get_addr().into()).into(),
                    source: mac::Address::Short(self.get_pan_id().into(), frame.src_addr().into()).into(),
                    auxiliary_security_header: None,
                },
                content: FrameContent::Data,
                payload: zb_types::Vec::<u8, A_MAX_MAC_PAYLOAD_SIZE>::from_slice(&mac_payload[..length]).unwrap(),
                footer: [0, 0],
            };

            self.mac.get_driver_mut().add_received_frame(mac_frame);
        }

        pub fn get_last_transmitted_frame(&self) -> Option<NwkFrame> {
            let mut payload = self.mac.get_driver().get_last_transmitted_frame()?.payload.clone();
            let (frame, _) = self.decrypt_frame(payload.as_mut_slice()).unwrap();
            Some(frame)
        }
    }

    pub const DEFAULT_PARENT_EXT_ADDR: ExtendedAddress = ExtendedAddress(0x1233_5678_90ab_cdef);
    pub const DEFAULT_PARENT_NWK_ADDR: NwkAddress = NwkAddress(0x1233);

    pub fn make_default_parent() -> NwkNeighbor {
        NwkNeighbor::new(NewNwkNeighbour {
            ext_addr: DEFAULT_PARENT_EXT_ADDR,
            nwk_addr: DEFAULT_PARENT_NWK_ADDR,
            device_type: DeviceType::Router,
            rx_on_when_idle: true,
            relationship: NeighborRelationship::Parent
        })
    }

    #[bon::bon]
    impl Nwk<JoinedAsEndDevice, MockDriver, MemoryStorage> {
        #[builder]
        pub fn end_device(
            #[builder(default = DEFAULT_NWK_ADDR)]
            addr: NwkAddress,
            #[builder(default = DEFAULT_EXT_ADDR)]
            ext_addr: ExtendedAddress,
            #[builder(default = DEFAULT_NWK_PAN_ID)]
            pan_id: PanId,
            parent: Option<NwkNeighbor>,
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
            }).unwrap();

            Nwk {
                _marker: PhantomData,
                mac,
                stg: MemoryStorage::new(),
                rng: SmallRng::seed_from_u64(0),
                seq_number: Arc::new(AtomicU8::new(0)),
                ctx: NwkContext {
                    addr_map: Default::default(),
                    group_table: Default::default(),
                    neighbors: Arc::new(Mutex::new(NeighborTable::new(parent.unwrap_or_else(make_default_parent)))),
                    parent_information,
                    profile,
                    update_id: 0,
                    active_key_seq_number: Arc::new(AtomicU8::new(0)),
                    all_fresh: false,
                    security_material_set: Arc::new(Mutex::new(security_material_set)),
                    route_request_counter: 0,
                    ..Default::default()
                },
            }
        }
    }

    pub const DEFAULT_CHILD_EXT_ADDR: ExtendedAddress = ExtendedAddress(0x1235_5678_90ab_cdef);
    pub const DEFAULT_CHILD_NWK_ADDR: NwkAddress = NwkAddress(0x1235);

    fn make_default_children() -> Vec<NwkNeighbor, NEIGHBOR_TABLE_MAX_ENTRIES> {
        Vec::from_slice(&[
            NwkNeighbor::new(NewNwkNeighbour {
                ext_addr: DEFAULT_CHILD_EXT_ADDR,
                nwk_addr: DEFAULT_CHILD_NWK_ADDR,
                device_type: DeviceType::EndDevice,
                rx_on_when_idle: true,
                relationship: NeighborRelationship::Child,
            })
        ]).unwrap()
    }

    #[bon::bon]
    impl Nwk<JoinedAsRouter, MockDriver, MemoryStorage> {
        #[builder]
        pub fn router(
            #[builder(default = DEFAULT_NWK_ADDR)]
            addr: NwkAddress,
            #[builder(default = DEFAULT_EXT_ADDR)]
            ext_addr: ExtendedAddress,
            #[builder(default = DEFAULT_NWK_PAN_ID)]
            pan_id: PanId,
            parent: Option<NwkNeighbor>,
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
            children: Option<Vec<NwkNeighbor, NEIGHBOR_TABLE_MAX_ENTRIES>>,
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
            }).unwrap();

            let mut table = NeighborTable::new(parent.unwrap_or_else(make_default_parent));
            let children = children.unwrap_or_else(make_default_children);

            for child in children {
                table.children.push(child).unwrap();
            }

            Nwk {
                _marker: PhantomData,
                mac,
                stg: MemoryStorage::new(),
                rng: SmallRng::seed_from_u64(0),
                seq_number: Arc::new(AtomicU8::new(0)),
                ctx: NwkContext {
                    addr_map: Default::default(),
                    group_table: Default::default(),
                    parent_information,
                    profile,
                    update_id: 0,
                    active_key_seq_number: Arc::new(AtomicU8::new(0)),
                    all_fresh: false,
                    security_material_set: Arc::new(Mutex::new(security_material_set)),
                    route_request_counter: 0,
                    broadcast_transaction_table: Default::default(),
                    neighbors: Arc::new(Mutex::new(table)),
                    concentrator_discovery_time: 0,
                    concentrator_radius: 0,
                    is_concentrator: false,
                    route_record_table: Default::default(),
                    route_table: Default::default(),
                },
            }
        }
    }
}