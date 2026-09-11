use embassy_sync::blocking_mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embedded_storage::ReadStorage;
use embedded_storage::Storage;
use esp_bootloader_esp_idf::partitions;
use esp_bootloader_esp_idf::partitions::PartitionEntry;
use esp_storage::FlashStorage;
use zb_hal;
use zb_hal::{StorageError, StoragePool, StorageRegion};

static mut PT_MEM: &'static mut [u8; partitions::PARTITION_TABLE_MAX_LEN] =
    &mut [0; partitions::PARTITION_TABLE_MAX_LEN];
static DRIVER: blocking_mutex::Mutex<
    CriticalSectionRawMutex,
    Option<(FlashStorage<'static>, PartitionEntry<'static>)>,
> = blocking_mutex::Mutex::new(None);

#[derive(Clone, Copy, Debug)]
pub struct EspStoragePool {
    total_size: u32,
    idx: u32,
}

impl<'a> EspStoragePool {
    #[allow(static_mut_refs)]
    pub async fn new(mut flash: FlashStorage<'static>) -> Self {
        let pt = unsafe { partitions::read_partition_table(&mut flash, PT_MEM.as_mut()).unwrap() };

        let nvs = pt
            .find_partition(partitions::PartitionType::Data(
                partitions::DataPartitionSubType::Nvs,
            ))
            .unwrap()
            .unwrap();

        // SAFETY: not called within another lock/lock_mut
        unsafe {
            DRIVER.lock_mut(|drv| {
                *drv = Some((flash, nvs))
            })
        };

        Self { total_size: nvs.len(), idx: 0 }
    }
}

impl StoragePool for EspStoragePool {
    type S = EspStorageRegion;

    fn reserve_region(&mut self, size: u32) -> Result<EspStorageRegion, ()> {
        if self.idx + size>= self.total_size {
            log::warn!(
                "couldn't reserve region, max size exceeded. total: {:?}, available: {:?}, requested: {:?}",
                self.total_size, self.total_size - self.idx, size
            );
            return Err(());
        }

        let region = EspStorageRegion(self.idx, size);
        self.idx += size as u32;

        Ok(region)
    }
}

#[derive(Clone)]
pub struct EspStorageRegion(u32, u32);

impl StorageRegion for EspStorageRegion {
    fn persist_with_offset(&mut self, offset: u32, buffer: &[u8]) -> Result<(), StorageError> {
        if buffer.len() > self.1 as usize {
            return Err(StorageError::ByteError(byte::Error::BadInput {
                err: "maximum length exceeded",
            }));
        }

        // SAFETY: not called within another lock/lock_mut
        unsafe {
            DRIVER.lock_mut(|drv| {
                let (flash, nvs) = drv.as_mut().unwrap();
                let mut nvs = nvs.as_embedded_storage(flash);
                nvs.write(self.0 + offset, buffer)
                    .map_err(|_| StorageError::NvsError)
            })
        }
    }

    fn load_with_offset(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), StorageError> {
        // SAFETY: not called within another lock/lock_mut
        unsafe {
            DRIVER.lock_mut(|drv| {
                let (flash, nvs) = drv.as_mut().unwrap();

                let mut nvs = nvs.as_embedded_storage(flash);
                nvs.read(self.0 + offset, buffer)
                    .map_err(|_| StorageError::NvsError)
            })
        }
    }

    fn clear(&mut self) -> Result<(), StorageError> {
        todo!()
    }
}
