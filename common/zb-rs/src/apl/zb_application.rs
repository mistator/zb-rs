use crate::apl::application::types::BaseApplication;
use crate::apl::aps::types::ApsEndpoint;
use crate::zcl::cluster::types::ZclCluster;
use alloc::boxed::Box;
use alloc::sync::Arc;
use derive_more::{Deref, DerefMut, IntoIterator};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use thiserror::Error;
use zb_hal::{StorageError, StorageRegion};

pub trait ZigbeeApplication: BaseApplication {
    fn ctx_update(&mut self) -> () {}
}

pub const MAX_APPLICATIONS: usize = 16;
pub const APPLICATION_STORAGE_SIZE: usize = 1024;
pub const APPLICATIONS_SR_SIZE: usize = MAX_APPLICATIONS * APPLICATION_STORAGE_SIZE;

pub type ZbApplication = Arc<Mutex<CriticalSectionRawMutex, Box<dyn ZigbeeApplication>>>;
pub type ZbApplicationsDef = heapless::index_map::FnvIndexMap<ApsEndpoint, ZbApplication, MAX_APPLICATIONS>;
pub type ZbApplications<S> = ZbApplicationsMap<S>;

#[derive(Deref, DerefMut, IntoIterator)]
pub struct ZbApplicationsMap<S: StorageRegion> {
    #[deref]
    #[deref_mut]
    #[into_iterator(owned, ref, ref_mut)]
    applications: ZbApplicationsDef,
    stg: S,
}

#[derive(Debug, Error)]
pub enum UseAppError {
    #[error("application not found")]
    ApplicationNotFound,
    #[error("cluster not found")]
    ClusterNotFound,
    #[error("storage error: {}", 0)]
    Storage(#[from] StorageError),
    #[error("byte error: {}", 0)]
    ByteError(byte::Error),
}

impl<S: StorageRegion> ZbApplicationsMap<S> {
    pub fn new(applications: ZbApplicationsDef, stg: S) -> Self {
        Self { applications, stg }
    }

    pub fn get(&self, ep: &ApsEndpoint) -> Option<&ZbApplication> {
        self.applications.get(ep)
    }

    pub async fn load_all(&mut self) {
        let mut indices = self.applications.keys().collect::<zb_types::Vec<_, MAX_APPLICATIONS>>();
        indices.sort_by_key(|item| item.get());

        let mut bytes = [0u8; APPLICATION_STORAGE_SIZE];

        for (idx, app_idx) in indices.iter().enumerate() {
            let app = self.applications.get(&app_idx).unwrap();
            let offset = (APPLICATION_STORAGE_SIZE * idx) as u32;

            if let Ok(()) = self.stg.load_with_offset(offset, &mut bytes) {
                let mut guard = app.lock().await;
                guard.load(&bytes).map_err(|err| {
                    log::warn!("error loading app data from persistent storage: {:?}", err);
                }).ok();
            }
        }
    }

    pub async fn use_application_mut<T, F: FnOnce(&mut dyn ZclCluster) -> T>(
        &mut self,
        ep: ApsEndpoint,
        cluster_id: u16,
        cb: F
    ) -> Result<T, UseAppError> {
        let application = self.applications.get(&ep).ok_or_else(|| {
            log::warn!("could not find application in endpoint `{:?}`", ep);
            UseAppError::ApplicationNotFound
        })?;

        let mut buffer = [0u8; APPLICATION_STORAGE_SIZE];
        let result = {
            let mut application = application.lock().await;
            let cluster = application.get_cluster_by_id_mut(cluster_id).ok_or_else(|| {
                log::warn!("could not find cluster {:?} for application in endpoint `{:?}`", cluster_id, ep);
                UseAppError::ClusterNotFound
            })?;

            let result = cb(cluster);

            application.try_write(&mut buffer).map_err(|err| UseAppError::ByteError(err))?;
            result
        };

        self.stg.persist(buffer.as_slice()).map_err(UseAppError::from)?;
        Ok(result)
    }
}



