use byte::BytesExt;
use zb_hal;
use zb_hal::StorageError;

#[derive(Clone, Debug)]
pub struct MemoryStorage {
    buffer: [u8; 1024 * 16],
}

impl MemoryStorage {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; 1024 * 16],
        }
    }
}

impl zb_hal::StorageRegion for MemoryStorage {
    fn persist_with_offset(&mut self, offset: u32, buffer: &[u8]) -> Result<(), StorageError> {
        self.buffer
            .write_with(&mut (offset as usize), buffer, ())
            .map_err(|err| StorageError::ByteError(err))
    }

    fn load_with_offset(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), StorageError> {
        let off = offset as usize;
        buffer.copy_from_slice(&self.buffer[off..off + buffer.len()]);
        Ok(())
    }

    fn clear(&mut self) -> Result<(), StorageError> {
        self.buffer = [0u8; 1024 * 16];
        Ok(())
    }
}
