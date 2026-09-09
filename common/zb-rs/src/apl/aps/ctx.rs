use crate::apl::aps::apsme::{ApsGroupEntry, Binding};
use crate::apl::aps::security::types::common::{
    DeviceKeyPairDescriptor, KeyAttribute, LinkKeyType,
};
use crate::apl::aps::types::ApsEndpoint;
use crate::common::security::{SecurityNetworkParams, TRUST_CENTER_LINK_KEY};
use crate::nwk::ctx::{NwkJoined};
use crate::stack_profile::{StackProfile};
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};
use byte_derive::{TryRead, TryWrite};
use derive_more::{Deref, DerefMut};
use zb_hal::{StorageError, StorageRegion};
use zb_macros::try_write_impl;
use zb_types::common::{ExtendedAddress};

#[derive(Clone, Default, Deref, DerefMut)]
pub struct BindingTable(heapless::index_set::FnvIndexSet<Binding, 64>);

impl<'a> TryRead<'a, Endian> for BindingTable {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let mut bindings = heapless::index_set::FnvIndexSet::<Binding, 64>::new();

        let n_items = bytes.read_with::<u8>(offset, ctx)?;
        for _ in 0..n_items {
            let binding = bytes.read_with::<Binding>(offset, ctx)?;
            bindings.insert(binding).ok();
        }

        Ok((Self(bindings), *offset))
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &BindingTable {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;

        bytes.write_with(offset, self.0.len() as u8, ctx)?;
        for item in self.0.into_iter() {
            bytes.write_with(offset, *item, ctx)?;
        }

        Ok(*offset)
    }
}

pub const APS_STORAGE_SIZE: usize = 4096;
pub trait ApsStorage : StorageRegion {}

pub type DeviceKeyPairDescriptorSet = zb_types::Vec<DeviceKeyPairDescriptor, 64>;

#[derive(Default, TryRead, TryWrite)]
struct ApsPersistentData {
    pub binding_table: BindingTable,
    #[byte(len = u8)]
    pub group_table: zb_types::Vec<ApsGroupEntry, 32>,
}

pub struct ApsContext<N: NwkJoined, S: StorageRegion> {
    aps_counter: u8,

    pub nwk: N,
    pub stg: S,

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

impl<N: NwkJoined, S: StorageRegion> ApsContext<N, S> {
    pub fn get_aps_counter(&mut self) -> u8 {
        self.aps_counter = self.aps_counter.wrapping_add(1);
        self.aps_counter
    }

    pub fn is_authorized(&self) -> bool {
        self.is_authorized
    }

    pub fn get_tc_addr(&self) -> Option<ExtendedAddress> {
        match self.security_network_params {
            SecurityNetworkParams::Centralized(addr) => Some(addr),
            SecurityNetworkParams::Distributed => None
        }
    }
}

impl<N: NwkJoined, S: StorageRegion> ApsContext<N, S> {
    pub fn new(
        nwk: N,
        stg: S,
        binding_table: BindingTable,
        group_table: zb_types::Vec<ApsGroupEntry, 32>,
    ) -> Self {
        Self {
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

    pub async fn load_or_default(nwk: N, mut stg: S) -> ApsContext<N, S> {
        let mut buffer = [0u8; APS_STORAGE_SIZE];

        stg.load(&mut buffer).await.ok();
        let persistent_data = buffer.read_with::<ApsPersistentData>(&mut 0, byte::LE)
            .map_err(|err| {
                log::warn!("failed to load persistent ApsContext data: {:?}, using default context", err);
                err
            })
            .unwrap_or_default();

        Self::new(nwk, stg, persistent_data.binding_table, persistent_data.group_table)
    }

    pub async fn persist(&mut self) -> Result<(), StorageError> {
        self.nwk.persist().await?;

        let persistent = ApsPersistentData {
            binding_table: self.binding_table.clone(),
            group_table: self.group_table.clone(),
        };
        let mut buffer = [0u8; APS_STORAGE_SIZE];
        buffer.write_with(&mut 0, persistent, byte::LE)?;

        self.stg.persist(&buffer).await?;
        self.nwk.persist().await
    }
}

#[cfg(test)]
mod tests {
    use crate::apl::aps::ctx::{ApsContext, DeviceKeyPairDescriptorSet};
    use crate::apl::aps::security::types::common::DeviceKeyPairDescriptor;
    use crate::common::information_base::ParentInformation;
    use crate::nwk::ctx::{EndDevice, Initialized, Joined, Nwk, NwkNeighbor};
    use crate::stack_profile::StackProfile;
    use bon::bon;
    use zb_hal_test_mock::driver::MockDriver;
    use zb_hal_test_mock::storage::MemoryStorage;
    use zb_types::common::{ExtendedAddress, NwkAddress, PanId};

    #[bon]
    impl ApsContext<Nwk<Initialized<Joined<EndDevice>>, MockDriver, MemoryStorage>, MemoryStorage> {
        #[builder]
        pub fn end_device(
            #[builder(default = NwkAddress::from(0x1234))] addr: NwkAddress,
            #[builder(default = ExtendedAddress::from(0x1234_5678_90ab_cdef))]
            ext_addr: ExtendedAddress,
            #[builder(default = ExtendedAddress::from(0x1234_5678_90ab_cdef))]
            ext_pan_id: ExtendedAddress,
            #[builder(default = PanId::from(0x1234))] pan_id: PanId,
            #[builder(default = NwkNeighbor::default())] parent: NwkNeighbor,
            parent_information: Option<ParentInformation>,
            #[builder(default = StackProfile::ZigbeePro)] profile: StackProfile,
            key_pair_desc: Option<DeviceKeyPairDescriptor>
        ) -> Self {
            let nwk = Nwk::end_device()
                .addr(addr)
                .ext_addr(ext_addr)
                .ext_pan_id(ext_pan_id)
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

