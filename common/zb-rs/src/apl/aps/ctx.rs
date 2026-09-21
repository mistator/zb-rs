use core::marker::PhantomData;
use core::todo;
use crate::apl::aps::apsme::{ApsGroupEntry, ApsmeAddGroupError, ApsmeBindError, ApsmeRemoveAllGroupsError, ApsmeRemoveGroupError, ApsmeUnbindError, Binding};
use crate::apl::aps::security::types::common::{DeviceKeyPairDescriptor, KeyAttribute, LinkKeyType, RequestKeyType, StandardKeyType, TransportKeyData};
use crate::apl::aps::types::{ApsEndpoint, ApsIndication, TxOptions};
use crate::common::security::{SecurityNetworkParams, TRUST_CENTER_LINK_KEY};
use crate::stack_profile::{StackProfile};
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};
use byte_derive::{TryRead, TryWrite};
use derive_more::{Deref, DerefMut};
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, TimeoutError, Timer};
use heapless::storage::Storage;
use zb_hal::{NwkMac, StorageError, StorageRegion};
use zb_macros::try_write_impl;
use zb_types::common::{ExtendedAddress, NwkAddress};
use zb_types::{HashMap, HashSet};
use crate::apl::aps::apsde::{ApsdeError, ApsdeRequest, ApsdeResult};
use crate::apl::aps::frame::{ApsCommand, ApsCommandFrame, ApsCommandFrameCtr};
use crate::apl::aps::security::sap::errors::ApsmeSecurityError;
use crate::apl::aps::security::sap::service::{ApsSecurityResult, UpdateDeviceRequest};
use crate::apl::aps::security::types::commands::{ConfirmKeyCommand, ConfirmKeyStatus, RemoveDeviceCommand, RequestKeyCommand, SwitchKeyCommand, VerifyKeyCommand};
use crate::common::security::primitives::HmacAes128Mmo;
use crate::nwk::ctx;
use crate::nwk::ctx::{InitializedNwk, JoinedAsEndDevice, JoinedAsRouter, JoinedNwk, JoinedState, Nwk};

#[derive(Clone, Default, Deref, DerefMut, TryRead, TryWrite)]
pub struct BindingTable(HashSet<Binding, 64>);

pub const APS_STORAGE_SIZE: usize = 4096;

pub type DeviceKeyPairDescriptorSet = zb_types::Vec<DeviceKeyPairDescriptor, 64>;

#[derive(Default, TryRead, TryWrite)]
struct ApsPersistentData {
    pub binding_table: BindingTable,
    #[byte(len = u8)]
    pub group_table: zb_types::Vec<ApsGroupEntry, 32>,
}

pub trait Apsme {
    fn bind_request(&mut self, binding: Binding) -> Result<(), ApsmeBindError>;
    fn unbind_request(&mut self, binding: Binding) -> Result<(), ApsmeUnbindError>;
    fn add_group(&mut self, group: u16, endpoint: u8) -> Result<(), ApsmeAddGroupError>;
    fn remove_group(&mut self, group: u16, endpoint: u8) -> Result<(), ApsmeRemoveGroupError>;
    fn remove_all_groups(&mut self, _endpoint: u8) -> Result<(), ApsmeRemoveAllGroupsError>;
    fn is_authorized(&self) -> bool;
    fn set_authorized(&mut self) -> ();
    fn get_security_network_params(&self) -> SecurityNetworkParams;
    fn get_tc_addr(&self) -> Option<ExtendedAddress>;
    fn get_device_key_pair_set(&self) -> &DeviceKeyPairDescriptorSet;
    fn get_device_key_pair_set_mut(&mut self) -> &mut DeviceKeyPairDescriptorSet;
    fn set_parent_announce_timer(&mut self, timer: f32) -> ();
}

pub trait ApsmeSecurity {
    async fn transport_key(&mut self, dst_addr: ExtendedAddress, transport_key_data: TransportKeyData) -> ApsSecurityResult;
    async fn update_device(&mut self, dst_addr: ExtendedAddress, req: UpdateDeviceRequest) -> ApsSecurityResult;
    async fn remove_device(
        &mut self,
        parent_address: ExtendedAddress,
        target_address: ExtendedAddress,
    ) -> Result<(), ApsmeSecurityError>;
    async fn request_key(
        &mut self,
        dest_address: ExtendedAddress,
        key_type: RequestKeyType,
    ) -> Result<(), ApsmeSecurityError>;
    async fn switch_key(
        &mut self,
        dest_address: ExtendedAddress,
        key_sequence_number: u8,
    ) -> Result<(), ApsmeSecurityError>;
    async fn verify_key(&mut self) -> ApsSecurityResult;
    async fn confirm_key(
        &mut self,
        dest_address: ExtendedAddress,
        status: ConfirmKeyStatus,
    ) -> ApsSecurityResult;
}

pub trait ApsTransmit {
    async fn aps_data_request<T>(&mut self, request: ApsdeRequest<T>) -> ApsdeResult
    where
        T: TryWrite<Endian> + Clone;
}

pub trait ApsListen {
    async fn listen_aps(&mut self) -> ApsIndication;

    async fn wait_for_indication<T>(&mut self, timeout: Duration, eval: fn(&ApsIndication) -> Option<T>) -> Result<T, TimeoutError> {
        let timeout = Timer::after(timeout);

        let receive = self.wait_for_indication_no_timeout(eval);
        match select(timeout, receive).await {
            Either::First(_) => Err(TimeoutError),
            Either::Second(result) => Ok(result)
        }
    }

    async fn wait_for_indication_no_timeout<T>(&mut self,eval: fn(&ApsIndication) -> Option<T>) -> T {
        loop {
            let indication = self.listen_aps().await;
            if let Some(result) = eval(&indication) {
                return result;
            } else {
                log::info!("[APSDE-INDICATION] received other indication {:?}", indication);
                continue;
            }
        }
    }
}

pub trait Apsde : ApsTransmit + ApsListen {}

impl<D: NwkMac, S: StorageRegion,> Apsde for Aps<Nwk<JoinedAsEndDevice, D, S>, D, S> {}
impl<D: NwkMac, S: StorageRegion,> Apsde for Aps<Nwk<JoinedAsRouter, D, S>, D, S> {}

/*
pub trait ApsState {}

pub trait NonRoutingState : ApsState {}
pub trait RoutingState : ApsState {}

pub struct NonRouting;
impl ApsState for NonRouting {}
impl NonRoutingState for NonRouting {}

pub struct Routing;
impl ApsState for Routing {}
impl RoutingState for Routing {}
*/


pub struct Aps<N: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion,> {
    _marker: PhantomData<D>,
    pub(crate) nwk: N,
    pub(crate) stg: S,

    aps_counter: u8,

    pub binding_table: BindingTable,
    pub group_table: zb_types::Vec<ApsGroupEntry, 32>,
    pub non_member_radius: u8,
    pub interframe_delay: u8,
    pub last_channel_energy: u8,
    pub last_channel_failure_rate: u8,
    pub channel_timer: u8,
    pub max_window_size: heapless::index_map::FnvIndexMap<ApsEndpoint, u8, 64>,
    pub parent_announce_timer: f32,

    // SECURITY ATTRIBUTES
    pub device_key_pair_set: DeviceKeyPairDescriptorSet,
    pub security_network_params: SecurityNetworkParams,
    pub is_authorized: bool,

    pub profile: StackProfile,
}

impl<T: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Aps<T, D, S> {
    pub fn get_aps_counter(&mut self) -> u8 {
        self.aps_counter = self.aps_counter.wrapping_add(1);
        self.aps_counter
    }

}

impl<J: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Aps<J, D, S>  {
    pub fn new(
        nwk: J,
        stg: S,
        binding_table: BindingTable,
        group_table: zb_types::Vec<ApsGroupEntry, 32>,
    ) -> Self {
        Self {
            _marker: PhantomData,
            nwk,
            stg,
            aps_counter: 0,
            binding_table,
            group_table,
            non_member_radius: 0,
            interframe_delay: 0,
            last_channel_energy: 0,
            last_channel_failure_rate: 0,
            channel_timer: 0,
            max_window_size: Default::default(),
            parent_announce_timer: 0.0,
            device_key_pair_set: DeviceKeyPairDescriptorSet::from_iter([DeviceKeyPairDescriptor {
                device_address: ExtendedAddress::ZERO,
                key_attributes: KeyAttribute::ProvisionalKey,
                link_key: TRUST_CENTER_LINK_KEY,
                outgoing_frame_counter: 0,
                incoming_frame_counter: 0,
                link_key_type: LinkKeyType::GlobalLinkKey,
            }]),
            security_network_params: Default::default(),
            is_authorized: false,
            profile: Default::default(),
        }
    }

    pub fn load_or_default(nwk: J, mut stg: S) -> Aps<J, D, S> {
        let mut buffer = [0u8; APS_STORAGE_SIZE];

        stg.load(&mut buffer).ok();
        let persistent_data = buffer.read_with::<ApsPersistentData>(&mut 0, byte::LE)
            .map_err(|err| {
                log::warn!("failed to load persistent ApsContext data: {:?}, using default context", err);
                err
            })
            .unwrap_or_default();

        Self::new(nwk, stg, persistent_data.binding_table, persistent_data.group_table)
    }

    pub fn persist(&mut self) -> Result<(), StorageError> {
        self.nwk.persist()?;

        let persistent = ApsPersistentData {
            binding_table: self.binding_table.clone(),
            group_table: self.group_table.clone(),
        };
        let mut buffer = [0u8; APS_STORAGE_SIZE];
        buffer.write_with(&mut 0, persistent, byte::LE)?;

        self.stg.persist(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;
    use crate::apl::aps::ctx::{Aps, DeviceKeyPairDescriptorSet};
    use crate::apl::aps::security::types::common::DeviceKeyPairDescriptor;
    use crate::common::information_base::ParentInformation;
    use crate::stack_profile::StackProfile;
    use bon::bon;
    use zb_hal_test_mock::driver::MockDriver;
    use zb_hal_test_mock::storage::MemoryStorage;
    use zb_types::common::{ExtendedAddress, NwkAddress, PanId};
    use crate::nwk::ctx::{JoinedAsEndDevice, Nwk};
    use crate::nwk::nib::NwkNeighbor;

    #[bon]
    impl Aps<Nwk<JoinedAsEndDevice, MockDriver, MemoryStorage>, MockDriver, MemoryStorage> {
        #[builder]
        pub fn end_device(
            #[builder(default = NwkAddress::from(0x1234))] addr: NwkAddress,
            #[builder(default = ExtendedAddress::from(0x1234_5678_90ab_cdef))]
            ext_addr: ExtendedAddress,
            #[builder(default = PanId::from(0x1234))] pan_id: PanId,
            #[builder(default = NwkNeighbor::default())]
            parent: NwkNeighbor,
            parent_information: Option<ParentInformation>,
            #[builder(default = StackProfile::ZigbeePro)] profile: StackProfile,
            key_pair_desc: Option<DeviceKeyPairDescriptor>
        ) -> Self {
            let nwk = Nwk::end_device()
                .addr(addr)
                .ext_addr(ext_addr)
                .pan_id(pan_id)
                .parent(parent)
                .maybe_parent_information(parent_information)
                .profile(profile)
                .call();

            let mut keys = DeviceKeyPairDescriptorSet::new();
            if let Some(key) = key_pair_desc {
                keys.push(key).unwrap();
            };

            Self {
                _marker: PhantomData,
                aps_counter: 0,
                nwk,
                stg: MemoryStorage::new(),
                binding_table: Default::default(),
                group_table: Default::default(),
                non_member_radius: 0,
                interframe_delay: 0,
                last_channel_energy: 0,
                last_channel_failure_rate: 0,
                channel_timer: 0,
                max_window_size: Default::default(),
                parent_announce_timer: 0.0,
                device_key_pair_set: keys,
                security_network_params: Default::default(),
                is_authorized: false,
                profile,
            }
        }
    }
}

