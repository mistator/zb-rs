use core::cmp::min;
use aead::AeadInPlace;
use aead::generic_array::ArrayLength;
use aes::Aes128;
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit as AesKeyInit;
use aes::cipher::KeyIvInit;
use aes::cipher::StreamCipherSeek;
use aes::cipher::generic_array::GenericArray as AesGenericArray;
use byte::BytesExt;
use byte::TryWrite;
use byte::ctx::Endian;
use ccm::Ccm;
use ccm::TagSize;
use ccm::aead::generic_array::GenericArray;
use ccm::consts::U13;
use ccm::consts::U16;
use ccm::consts::U4;
use ccm::consts::U8;
use ctr::cipher::StreamCipher;
use ctr::Ctr32BE;
use crate::common::security::SecurityError;
use crate::common::security::SecurityError::CcmError;
use crate::common::security::frame::AuxFrameHeader;
use crate::common::security::frame::SecurityLevel;
use zb_types::common::Key;

pub struct Aes128Mmo {
    state: [u8; Self::BLOCK_SIZE], // 128-bit hash state
}

impl Aes128Mmo {
    const BLOCK_SIZE: usize = 16;
    const PADDING_THRESHOLD: usize = 2usize.pow(Self::BLOCK_SIZE as u32);

    pub fn new() -> Self {
        Self {
            state: [0u8; Self::BLOCK_SIZE],
        }
    }

    pub fn initialize(iv: &[u8]) -> Self {
        let mut mmo = Self::new();
        let length = min(Self::BLOCK_SIZE, iv.len());
        mmo.state[..length].copy_from_slice(&iv[..length]);
        mmo
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), SecurityError> {
        self.update_impl(data.iter().copied())
    }

    fn update_impl(&mut self, data: impl Iterator<Item = u8>) -> Result<(), SecurityError> {
        let data = data.into_iter();
        let (_, Some(length)) = data.size_hint() else {
            unreachable!("invalid unbounded data");
        };

        let (padded_data, pad_len) = if length < Self::PADDING_THRESHOLD {
            // l+1+k = 7n (mod 8n)
            let pad_len =
                ((14i32 - (length % Self::BLOCK_SIZE) as i32) % Self::BLOCK_SIZE as i32) as usize;
            let mut padded_data = [0u8; Self::BLOCK_SIZE + 2];
            padded_data[0] = 0x80;
            padded_data[pad_len..pad_len + 2].copy_from_slice(&((length * 8) as u16).to_be_bytes());
            (padded_data, pad_len + 2)
        } else {
            // other padding method not supported
            return Err(SecurityError::InvalidData);
        };

        let pad = &padded_data[..pad_len];
        let mut iter = data.chain(pad.iter().copied());
        let len = length + pad_len;
        let mut i = 0;
        while i < len {
            let mut block = [0u8; Self::BLOCK_SIZE];
            for b_i in 0..Self::BLOCK_SIZE {
                let b = iter.next();
                if let Some(b) = b {
                    i += 1;
                    block[b_i] = b;
                }
            }

            // E_i = E(H_{i-1}, X_i)
            let cipher = Aes128::new(&AesGenericArray::from(self.state));
            let mut encrypted_block = AesGenericArray::from(block);
            cipher.encrypt_block(&mut encrypted_block);

            // H_i = E_i ⊕ X_i (Matyas-Meyer-Oseas)
            for i in 0..Self::BLOCK_SIZE {
                self.state[i] = encrypted_block[i] ^ block[i];
            }
        }

        Ok(())
    }

    pub fn finalize(self) -> [u8; 16] { self.state }

    pub fn digest(data: &[u8]) -> Result<[u8; Self::BLOCK_SIZE], SecurityError> {
        Self::digest_impl(data.iter().copied())
    }

    pub fn digest_impl(
        data: impl Iterator<Item = u8>,
    ) -> Result<[u8; Self::BLOCK_SIZE], SecurityError> {
        let mut hasher = Self::new();
        hasher.update_impl(data)?;
        Ok(hasher.finalize())
    }

    pub fn digest_with_iv(iv: &[u8], data: &[u8]) -> Result<[u8; Self::BLOCK_SIZE], SecurityError> {
        let mut hasher = Self::initialize(iv);
        hasher.update(data)?;
        Ok(hasher.finalize())
    }
}

impl Default for Aes128Mmo {
    fn default() -> Self { Self::new() }
}

/// HMAC implementation using AES-MMO hash function
/// Follows RFC 2104 HMAC specification
pub struct HmacAes128Mmo;

impl HmacAes128Mmo {
    const IPAD: u8 = 0x36;
    // Inner padding byte
    const OPAD: u8 = 0x5c;

    // Outer padding byte

    /// Convenience method to compute HMAC in one step
    /// $\text{HMAC}(K, M) = H((K \oplus \text{opad}) || H((K \oplus
    /// \text{ipad}) || M))$
    pub fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; Aes128Mmo::BLOCK_SIZE], SecurityError> {
        if key.len() == Aes128Mmo::BLOCK_SIZE {
            return Self::hmac_impl(key, data);
        }

        let key = Aes128Mmo::digest(key)?;
        Self::hmac_impl(&key, data)
    }

    fn hmac_impl(key: &[u8], data: &[u8]) -> Result<[u8; Aes128Mmo::BLOCK_SIZE], SecurityError> {
        let mut ipad = [Self::IPAD; Aes128Mmo::BLOCK_SIZE];
        let mut opad = [Self::OPAD; Aes128Mmo::BLOCK_SIZE];

        for i in 0..Aes128Mmo::BLOCK_SIZE {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }

        let inner = ipad.iter().chain(data.iter());
        let inner_hash = Aes128Mmo::digest_impl(inner.copied())?;

        let outer = opad.iter().chain(inner_hash.iter());
        Aes128Mmo::digest_impl(outer.copied())
    }
}

type Aes128Ctr = Ctr32BE<Aes128>;
pub type Aes128Ccm<N> = Ccm<Aes128, N, U13>;

pub(crate) struct CcmZigbee {
    pub key: [u8; 16],
}

impl CcmZigbee {
    fn extend_nonce(&self, nonce: &[u8; 13]) -> [u8; 16] {
        let mut long_nonce = [0u8; 16];
        long_nonce[0] = 1; // CCM L parameter (nonce length = 15 - L - 1)
        long_nonce[1..][..13].copy_from_slice(nonce.as_slice());

        long_nonce
    }

    fn ccm_decrypt<T: ArrayLength<u8> + TagSize>(
        &self,
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8],
        nonce: &[u8; 13],
    ) -> Result<(), SecurityError> {
        let nonce: GenericArray<u8, U13> = GenericArray::clone_from_slice(nonce.as_slice());

        let tag: GenericArray<u8, T> = GenericArray::clone_from_slice(tag);
        let cipher = Aes128Ccm::<T>::new(&self.key.into());
        cipher
            .decrypt_in_place_detached(&nonce, aad, ciphertext, &tag)
            .map_err(|err| {
                log::warn!("[CCM-DECRYPT] error decrypting frame: {:?}", err);
                CcmError(err)
            })
    }

    fn ccm_encrypt<T: ArrayLength<u8> + TagSize>(
        &self,
        aad: &[u8],
        buffer: &mut [u8],
        nonce: &[u8; 13],
    ) -> Result<(), SecurityError> {
        let nonce: GenericArray<u8, U13> = GenericArray::clone_from_slice(nonce.as_slice());

        let buffer_len = buffer.len();
        let tag_len = T::to_usize();

        let cipher = Aes128Ccm::<T>::new(&self.key.into());
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buffer[..buffer_len - tag_len])
            .map_err(|err| {
                log::warn!("[CCM-ENCRYPT] error encrypting frame: {:?}", err);
                CcmError(err)
            })?;
        buffer[buffer_len - tag_len..].copy_from_slice(tag.as_slice());
        Ok(())
    }

    pub fn decrypt_in_place(
        &self,
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8],
        nonce: &[u8; 13],
    ) -> Result<(), SecurityError> {
        if tag.is_empty() {
            let long_nonce = self.extend_nonce(nonce);
            let mut cipher = Aes128Ctr::new(&self.key.into(), &long_nonce.into());
            cipher.seek(16); // AES128 block size
            cipher.apply_keystream(ciphertext);
            Ok(())
        } else {
            match tag.len() {
                4 => self.ccm_decrypt::<U4>(aad, ciphertext, tag, nonce),
                8 => self.ccm_decrypt::<U8>(aad, ciphertext, tag, nonce),
                16 => self.ccm_decrypt::<U16>(aad, ciphertext, tag, nonce),
                _ => {
                    log::warn!("[CCM-DECRYPT] invalid tag length: {:?}", tag.len());
                    Err(CcmError(ccm::Error))
                },
            }
        }
    }

    pub fn encrypt_in_place(
        &self,
        security_level: SecurityLevel,
        aad: &[u8],
        buffer: &mut [u8],
        nonce: &[u8; 13],
    ) -> Result<(), SecurityError> {
        let mic_length = security_level.mic_length();

        match mic_length {
            0 => {
                let long_nonce = self.extend_nonce(nonce);
                let mut cipher = Aes128Ctr::new(&self.key.into(), &long_nonce.into());
                cipher.seek(16);
                cipher.apply_keystream(buffer);
                Ok(())
            }
            4 => self.ccm_encrypt::<U4>(aad, buffer, nonce),
            8 => self.ccm_encrypt::<U8>(aad, buffer, nonce),
            16 => self.ccm_encrypt::<U16>(aad, buffer, nonce),
            _ => {
                log::warn!("[CCM-ENCRYPT] invalid tag length: {:?}", mic_length);
                Err(CcmError(ccm::Error))
            }
        }
    }
}

pub fn write_and_encrypt_in_place(
    security_level: SecurityLevel,
    frame_buffer: &mut [u8],
    aux_hdr: AuxFrameHeader,
    key: Key,
    hdr: impl TryWrite<Endian>,
    payload: impl TryWrite,
) -> Result<usize, SecurityError> {
    let mic_len = security_level.mic_length();
    let nonce = aux_hdr.create_nonce()?;

    let offset = &mut 0;
    frame_buffer.write_with(offset, hdr, byte::LE)?;

    let aux_hdr_offset = *offset;
    frame_buffer.write_with(offset, aux_hdr, byte::LE)?;

    let payload_offset = *offset;
    frame_buffer.write_with(offset, payload, ())?;

    let tag_offset = *offset;
    for _ in 0..mic_len {
        frame_buffer.write_with(offset, 0u8, Endian::Little)?;
    }

    let (aad, payload) = frame_buffer.split_at_mut(payload_offset);
    // let (payload, _) = payload.split_at_mut(tag_offset - payload_offset);
    let len = tag_offset + mic_len;

    let ccm = CcmZigbee {
        key: *key.as_array().unwrap(),
    };
    ccm.encrypt_in_place(
        security_level,
        aad,
        &mut payload[..len - payload_offset],
        &nonce,
    )?;

    // overwrite sec level in aux header with 000
    frame_buffer[aux_hdr_offset] &= 0b1111_1000;

    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::security::TRUST_CENTER_LINK_KEY;

    #[test]
    fn ccm_primitives_mic_8() {
        let key: [u8; 16] = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ];
        let nonce: [u8; 13] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0x03, 0x02, 0x01, 0x00, 0x06,
        ];
        let mut lc: [u8; 23] = [
            0x1a, 0x55, 0xa3, 0x6a, 0xbb, 0x6c, 0x61, 0x0d, 0x06, 0x6b, 0x33, 0x75, 0x64, 0x9c,
            0xef, 0x10, 0xd4, 0x66, 0x4e, 0xca, 0xd8, 0x54, 0xa8,
        ];
        let tag: [u8; 8] = [0x0a, 0x89, 0x5c, 0xc1, 0xd8, 0xff, 0x94, 0x69];
        let la: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let ccm = CcmZigbee { key };

        ccm.decrypt_in_place(&la, &mut lc, &tag, &nonce).unwrap();

        let result = [
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ];

        assert!(lc.iter().eq(result.iter()));
    }

    #[test]
    fn ccm_primitives_no_mic() {
        let key: [u8; 16] = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ];
        let nonce: [u8; 13] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0x03, 0x02, 0x01, 0x00, 0x06,
        ];
        let mut lc: [u8; 23] = [
            0x1a, 0x55, 0xa3, 0x6a, 0xbb, 0x6c, 0x61, 0x0d, 0x06, 0x6b, 0x33, 0x75, 0x64, 0x9c,
            0xef, 0x10, 0xd4, 0x66, 0x4e, 0xca, 0xd8, 0x54, 0xa8,
        ];
        let tag: [u8; 0] = [];
        let la: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let ccm = CcmZigbee { key };

        ccm.decrypt_in_place(&la, &mut lc, &tag, &nonce).unwrap();

        let result = [
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ];

        assert!(lc.iter().eq(result.iter()));
    }

    #[test]
    fn aes_mmo_test_vector() {
        let message = [0xc0];
        let want = [
            0xae, 0x3a, 0x10, 0x2a, 0x28, 0xd4, 0x3e, 0xe0, 0xd4, 0xa0, 0x9e, 0x22, 0x78, 0x8b,
            0x20, 0x6c,
        ];

        let result = Aes128Mmo::digest(&message).unwrap();

        assert_eq!(result, want);
    }

    #[test]
    fn aes_mmo_length_equal_block_size() {
        let message = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ];
        let want = [
            0xa7, 0x97, 0x7e, 0x88, 0xbc, 0x0b, 0x61, 0xe8, 0x21, 0x08, 0x27, 0x10, 0x9a, 0x22,
            0x8f, 0x2d,
        ];

        let result = Aes128Mmo::digest(&message).unwrap();

        assert_eq!(result, want);
    }

    #[test]
    fn hmac_aes_mmo_1() {
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ];
        let want = [
            0x45, 0x12, 0x80, 0x7b, 0xf9, 0x4c, 0xb3, 0x40, 0x0f, 0x0e, 0x2c, 0x25, 0xfb, 0x76,
            0xe9, 0x99,
        ];
        let message = [0xc0];

        let result = HmacAes128Mmo::hmac(&key, &message).unwrap();

        assert_eq!(result, want);
    }

    #[test]
    fn hmac_aes_mmo_2() {
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];
        let want = [
            0xa3, 0xb0, 0x07, 0x99, 0x84, 0xbf, 0x15, 0x57, 0xf7, 0x4a, 0x0d, 0x63, 0x87, 0xe0,
            0xa1, 0x1a,
        ];
        let message = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ];

        let result = HmacAes128Mmo::hmac(&key, &message).unwrap();

        assert_eq!(result, want);
    }

    #[test]
    fn cmc_mac() {
        let key = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ];
        let nonce = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0x03, 0x02, 0x01, 0x00, 0x06,
        ];
        let mut plaintext = [
            0x08u8, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ];
        let auth_data = [0x0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let cipher = Aes128Ccm::<U8>::new(&key.into());
        let nonce: GenericArray<u8, U13> = GenericArray::clone_from_slice(nonce.as_slice());

        let tag = cipher.encrypt_in_place_detached(&nonce, &auth_data, &mut plaintext);
    }
}
