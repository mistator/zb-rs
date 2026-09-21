use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};
use byte::BytesExt;
use byte::TryRead;

use crate::common::security::SecurityError;
use crate::common::security::frame::{AuxFrameHeader, SecurityLevel};
use crate::common::security::frame::KeyIdentifier;
use crate::common::security::frame::SecurityControl;
use crate::common::security::primitives::CcmZigbee;
use crate::common::security::primitives::write_and_encrypt_in_place;
use crate::nwk::frame::NwkFrame;
use crate::nwk::frame::header::NwkHeader;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::{ExtendedAddress, Key};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use crate::nwk::ctx::{BaseNwk, InitializedNwk, InitializedState, Nwk};
use crate::nwk::nib::NetworkSecurityMaterialDescriptorSet;

pub struct EncryptedFrameParams {
    pub ext_addr: ExtendedAddress,
    pub security_level: SecurityLevel,
    pub active_key_seq_number: Arc<AtomicU8>,
    pub keys: Arc<Mutex<CriticalSectionRawMutex, NetworkSecurityMaterialDescriptorSet>>
}

pub fn make_encrypted_frame(
    frame: &NwkFrame,
    buffer: &mut [u8],
    params: &EncryptedFrameParams,
) -> Result<usize, SecurityError> {
    // 1. obtain key material & key data
    // 2. Construct the auxiliary header
    let security_control = SecurityControl {
        security_level: params.security_level,
        key_identifier: KeyIdentifier::Network,
        extended_nonce: true,
    };

    let mut should_persist = false;
    let result = unsafe { params.keys.lock_mut(|keys| {
        let sec_material = keys
            .iter_mut()
            .find(|k| k.key_seq_number == params.active_key_seq_number.load(Ordering::Relaxed))
            .ok_or(SecurityError::KeyNotFound)?;

        if sec_material.outgoing_frame_counter == u32::MAX {
            return Err(SecurityError::InvalidData);
        }

        let aux_hdr = AuxFrameHeader {
            security_control,
            frame_counter: sec_material.outgoing_frame_counter,
            key_sequence_number: Some(sec_material.key_seq_number),
            source_address: Some(params.ext_addr),
        };

        let result = match frame {
            NwkFrame::Data(frame) => write_and_encrypt_in_place(
                params.security_level,
                buffer,
                aux_hdr,
                sec_material.key,
                frame.header.clone(),
                frame.payload.as_slice(),
            ),
            NwkFrame::NwkCommand(frame) => write_and_encrypt_in_place(
                params.security_level,
                buffer,
                aux_hdr,
                sec_material.key,
                frame.header.clone(),
                frame.command.clone(),
            ),
            _ => {
                return Err(SecurityError::InvalidData);
            }
        };

        if result.is_ok() {
            sec_material.outgoing_frame_counter += 1;
            should_persist = (sec_material.outgoing_frame_counter - 1) % 1024 == 0;
        }

        result
    })? };

    if should_persist {
        //ctx.persist().await.ok();
        // TODO
    }

    Ok(result)
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub fn encrypt_frame(
        &mut self,
        frame: &NwkFrame,
        buffer: &mut [u8],
    ) -> Result<usize, SecurityError> {
         make_encrypted_frame(frame, buffer, &EncryptedFrameParams {
            ext_addr: self.get_ext_addr(),
            security_level: self.get_profile().nwk_security_level,
            active_key_seq_number: self.get_active_key_seq_number().clone(),
            keys: self.get_security_material_set().clone()
        })
    }


    pub fn decrypt_frame(
        &self,
        frame_buffer: &mut [u8],
    ) -> Result<(NwkFrame, bool), SecurityError> {
        let (nwk_hdr, nwk_hdr_len) = NwkHeader::try_read(frame_buffer, byte::LE)?;
        if !nwk_hdr.control.security {
            return Ok((
                NwkFrame::try_read(&frame_buffer[nwk_hdr_len..], nwk_hdr)?.0,
                false,
            ));
        }

        // Sec 4.3.1.2: overwrite the security level with the value from the NIB
        // (default 0x05)
        let sec_level = self.get_profile().nwk_security_level;
        let mic_length = sec_level.mic_length();
        byte::check_len(frame_buffer, mic_length)?;

        let (mut aux_hdr, aux_hdr_len) =
            AuxFrameHeader::try_read(&frame_buffer[nwk_hdr_len..], byte::LE)?;

        if aux_hdr.frame_counter == u32::MAX {
            return Err(SecurityError::InvalidData);
        }

        // 2) select the key from NIB
        let sec_material = self
            .get_security_material_set()
            .lock(|items| {
                items
                    .iter()
                    .find(|k| {
                        aux_hdr
                            .key_sequence_number
                            .is_some_and(|ksn| ksn == k.key_seq_number)
                    })
                    .ok_or(SecurityError::Unspecified)
                    .cloned()
            })?;

        // 3) check if frame_counter is equal or greater of the NIB
        let Some(source_address) = aux_hdr.source_address else {
            return Err(SecurityError::InvalidData);
        };
        if let Some(inc_frame_counter) = sec_material
            .incoming_frame_counter_set
            .iter()
            .find(|i| source_address == i.sender_address)
        {
            if aux_hdr.frame_counter < inc_frame_counter.incoming_frame_counter {
                return Err(SecurityError::InvalidData);
            }
        }

        // write back the security level from NIB to aux header
        // the updated values is required as input to ccm
        aux_hdr.security_control.security_level = sec_level;
        let mut offset = nwk_hdr_len;
        frame_buffer.write_with(&mut offset, aux_hdr, byte::LE)?;

        let (aad, frame) = frame_buffer.split_at_mut(nwk_hdr_len + aux_hdr_len);
        let (data, tag) = frame.split_at_mut(frame.len() - mic_length);

        let ccm = CcmZigbee {
            key: sec_material.key,
        };

        ccm.decrypt_in_place(aad, data, tag, &aux_hdr.create_nonce().unwrap())?;

        Ok((NwkFrame::try_read(data, nwk_hdr)?.0, true))
    }
}

#[cfg(test)]
mod tests {
    use crate::nwk::ctx::Nwk;
    use crate::nwk::frame::NwkFrame;
    use crate::nwk::frame::header::{FrameType, NwkHeader};
    use zb_types::Vec;
    use zb_types::common::{ExtendedAddress, NwkAddress};

    const NWK_FRAME_PAYLOAD: [u8; 17] = [
        0x0, 0x1, 0x4, 0xb, 0x4, 0x1, 0x1, 0x56, 0x10, 0xae, 0x0, 0x5, 0x5, 0x8, 0x5, 0xb, 0x5
    ];
    const ENC_NWK_FRAME_FRAME_COUNTER: u32 = 6534680;
    const ENC_NWK_FRAME_SRC_ADDR: ExtendedAddress = ExtendedAddress(0x00124b002f8f7a60);
    const ENC_NWK_FRAME: [u8; 43] = [
        0x48, 0x2, 0x85, 0x3c, 0x0, 0x0, 0x1e, 0x10, 0x28, 0x18, 0xb6, 0x63, 0x0, 0x60, 0x7a,
        0x8f, 0x2f, 0x0, 0x4b, 0x12, 0x0, 0x0, 0x38, 0xd7, 0xb2, 0x1c, 0xa5, 0xc9, 0x44, 0x6e,
        0xef, 0xca, 0x8d, 0x96, 0xd5, 0x3e, 0xb2, 0x35, 0x8b, 0x8, 0x88, 0x17, 0xd4
    ];

    #[test]
    fn test_decrypt_nwk_frame() {
        let mut frame_buffer = ENC_NWK_FRAME;

        let nwk = Nwk::end_device().call();
        let (frame, _) = nwk.decrypt_frame(&mut frame_buffer).unwrap();

        assert!(matches!(frame, NwkFrame::Data(_)));
    }

    #[test]
    fn decrypt_and_encrypt_nwk_frame() {
        let mut frame_buffer = ENC_NWK_FRAME;
        let mut nwk = Nwk::end_device()
            .ext_addr(ENC_NWK_FRAME_SRC_ADDR)
            .outgoing_frame_counter(ENC_NWK_FRAME_FRAME_COUNTER)
            .call();

        let (frame, _) = nwk.decrypt_frame(&mut frame_buffer).unwrap();
        let offset = nwk.encrypt_frame(&frame, &mut frame_buffer).unwrap();

        assert_eq!(offset, ENC_NWK_FRAME.len());
        assert_eq!(frame_buffer, ENC_NWK_FRAME);
    }

    #[test]
    fn encrypt_nwk_frame() {
        let mut buffer = [0x0u8; 127];
        let payload = NWK_FRAME_PAYLOAD;

        let mut nwk = Nwk::end_device()
            .ext_addr(ENC_NWK_FRAME_SRC_ADDR)
            .outgoing_frame_counter(ENC_NWK_FRAME_FRAME_COUNTER)
            .call();

        let hdr = NwkHeader::builder(&mut nwk)
            .frame_type(FrameType::Data)
            .route_discovery(true)
            .destination(NwkAddress(0x3c85))
            .source(NwkAddress(0x0))
            .radius(30)
            .security(true)
            .sequence_number(16)
            .build();
        let frame = NwkFrame::new_data_frame(hdr, Vec::from_slice(payload.as_slice()).unwrap());

        let len = nwk.encrypt_frame(&frame, &mut buffer).unwrap();

        assert_eq!(len, ENC_NWK_FRAME.len());
        assert_eq!(buffer[..len], ENC_NWK_FRAME);
    }
}
