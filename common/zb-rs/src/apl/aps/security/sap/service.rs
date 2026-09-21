use core::slice;

use byte::BytesExt;
use byte::TryRead;

use crate::apl::aps::apsde::ApsdeError;
use crate::apl::aps::constants::MAX_APS_PAYLOAD_SIZE;
use crate::apl::aps::ctx::{Aps, Apsme, ApsmeSecurity};
use crate::apl::aps::frame::ApsCommand;
use crate::apl::aps::frame::ApsCommandFrame;
use crate::apl::aps::frame::ApsCommandFrameCtr;
use crate::apl::aps::frame::ApsFrame;
use crate::apl::aps::frame::ApsHeader;
use crate::apl::aps::security::sap::errors::ApsmeSecurityError;
use crate::apl::aps::security::types::commands::ConfirmKeyCommand;
use crate::apl::aps::security::types::commands::ConfirmKeyStatus;
use crate::apl::aps::security::types::commands::RemoveDeviceCommand;
use crate::apl::aps::security::types::commands::RequestKeyCommand;
use crate::apl::aps::security::types::commands::SwitchKeyCommand;
use crate::apl::aps::security::types::commands::TransportKeyCommand;
use crate::apl::aps::security::types::commands::UpdateDeviceCommand;
use crate::apl::aps::security::types::commands::VerifyKeyCommand;
use crate::apl::aps::security::types::common::ApplicationLinkKeyData;
use crate::apl::aps::security::types::common::ApplicationLinkKeyDescriptor;
use crate::apl::aps::security::types::common::DeviceKeyPairDescriptor;
use crate::apl::aps::security::types::common::KeyAttribute;
use crate::apl::aps::security::types::common::LinkKeyType;
use crate::apl::aps::security::types::common::RequestKeyType;
use crate::apl::aps::security::types::common::StandardKeyDescriptor;
use crate::apl::aps::security::types::common::StandardKeyType;
use crate::apl::aps::security::types::common::StandardNetworkKeyData;
use crate::apl::aps::security::types::common::StandardNetworkKeyDescriptor;
use crate::apl::aps::security::types::common::TransportKeyData;
use crate::apl::aps::security::types::common::TrustCenterLinkKeyData;
use crate::apl::aps::security::types::common::TrustCenterLinkKeyDescriptor;
use crate::apl::aps::security::types::indications::{ApsmeConfirmKeyIndication, ApsmeRemoveDeviceIndication};
use crate::apl::aps::security::types::indications::ApsmeTransportKeyIndication;
use crate::apl::aps::security::types::indications::ApsmeUpdateDeviceIndication;
use crate::apl::aps::types::ApsIndication;
use crate::apl::aps::types::TxOptions;
use crate::common::security::SecurityError;
use crate::common::security::SecurityNetworkParams;
use crate::common::security::frame::AuxFrameHeader;
use crate::common::security::frame::KeyIdentifier;
use crate::common::security::frame::SecurityControl;
use crate::common::security::primitives::CcmZigbee;
use crate::common::security::primitives::HmacAes128Mmo;
use crate::common::security::primitives::write_and_encrypt_in_place;
use crate::nwk::constants::NWK_COORDINATOR_ADDRESS;
use crate::nwk::nlde::NldeDataIndicationDstAddress;
use crate::unwrap_or_return;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::ctx::{BaseNwk, InitializedNwk, JoinedAsRouter, JoinedNwk, JoinedState, Nwk, RoutingNwk, RoutingState};

pub type UpdateDeviceRequest = UpdateDeviceCommand;
pub type ApsSecurityResult = Result<(), ApsmeSecurityError>;

impl<T: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> ApsmeSecurity for Aps<T, D, S> {
    async fn transport_key(
        &mut self,
        dst_addr: ExtendedAddress,
        transport_key_data: TransportKeyData,
    ) -> ApsSecurityResult {
        let (descriptor, dest_address) = match transport_key_data {
            TransportKeyData::StandardNetworkKey(tk_data) => (
                StandardKeyDescriptor::StandardNetworkKey(StandardNetworkKeyDescriptor {
                    key: tk_data.key,
                    sequence_number: tk_data.key_sequence,
                    destination_address: dst_addr,
                    source_address: self.nwk.get_ext_addr()
                }),
                tk_data.parent_address.unwrap_or(dst_addr),
            ),
            TransportKeyData::ApplicationLinkKey(tk_data) => (
                StandardKeyDescriptor::ApplicationLinkKey(ApplicationLinkKeyDescriptor {
                    key: tk_data.key,
                    partner_address: tk_data.partner_address,
                    initiation_flag: false,
                }),
                dst_addr,
            ),
            TransportKeyData::TrustCenterLinkKey(tk_data) => (
                StandardKeyDescriptor::TrustCenterLinkKey(TrustCenterLinkKeyDescriptor {
                    key: tk_data.key,
                    destination_address: dst_addr,
                    source_address: self.nwk.get_ext_addr(),
                }),
                dst_addr,
            ),
        };

        let command = ApsCommand::TransportKey(TransportKeyCommand {
            key_descriptor: descriptor,
        });

        self.send_apsme_security_command(dest_address, command).await
    }

    async fn update_device(&mut self, dst_addr: ExtendedAddress, req: UpdateDeviceRequest) -> ApsSecurityResult {
        let command = ApsCommand::UpdateDevice(req);
        self.send_apsme_security_command(dst_addr, command).await
    }

    async fn remove_device(
        &mut self,
        parent_address: ExtendedAddress,
        target_address: ExtendedAddress,
    ) -> Result<(), ApsmeSecurityError> {
        let command = ApsCommand::RemoveDevice(RemoveDeviceCommand { target_address });
        self.send_apsme_security_command(parent_address, command).await
    }

    async fn request_key(
        &mut self,
        dest_address: ExtendedAddress,
        key_type: RequestKeyType,
    ) -> Result<(), ApsmeSecurityError> {
        let cmd = ApsCommand::RequestKey(RequestKeyCommand { key_type });
        self.send_apsme_security_command(dest_address, cmd).await
    }

    async fn switch_key(
        &mut self,
        dest_address: ExtendedAddress,
        key_sequence_number: u8,
    ) -> Result<(), ApsmeSecurityError> {
        let cmd = ApsCommand::SwitchKey(SwitchKeyCommand {
            sequence_number: key_sequence_number,
        });

        if dest_address != ExtendedAddress::MAX {
            self.send_apsme_security_command(dest_address, cmd).await
        } else {
            let nwk_address = NwkAddress(0xfffd);

            let frame = ApsCommandFrame::new(ApsCommandFrameCtr {
                dst_addr: nwk_address,
                command: cmd,
            });

            self.aps_cmd_transfer(frame, nwk_address, TxOptions::default())
                .await
                .map_err(ApsmeSecurityError::from)
        }
    }

    async fn verify_key(&mut self) -> ApsSecurityResult {
        // TODO: check if we are the trust center and ignore if so
        let tc_addr = if let SecurityNetworkParams::Centralized(ext_addr) = self.security_network_params
        {
            ext_addr
        } else {
            log::warn!("[VERIFY-KEY] can't verify key, not in a centralized network");
            return Err(ApsmeSecurityError::CommandValidationError);
        };

        let key_descriptor = self
            .device_key_pair_set
            .iter()
            .find(|key| key.device_address == tc_addr)
            .ok_or_else(|| {
                log::warn!("[VERIFY-KEY] could not find key pair associated with trust center");
                ApsmeSecurityError::CommandValidationError
            })?;

        let initiator_verify_key_hash = HmacAes128Mmo::hmac(&key_descriptor.link_key.as_slice(), &[0x03])
            .map_err(|_| {
                log::warn!("[VERIFY-KEY] hmac verification failed");
                ApsmeSecurityError::CommandValidationError
            })?;

        let cmd = ApsCommand::VerifyKey(VerifyKeyCommand {
            key_type: StandardKeyType::TrustCenterLinkKey,
            source_address: self.nwk.get_ext_addr(),
            initiator_hash_value: *initiator_verify_key_hash.as_array(),
        });

        let nwk_address = self
            .nwk
            .find_nwk_addr(tc_addr)
            .ok_or_else(|| {
                log::warn!("[VERIFY-KEY] could not find network address associated with trust center");
                ApsmeSecurityError::ApsdeSapError(ApsdeError::NoShortAddress)
            })?;

        let frame = ApsCommandFrame::new(ApsCommandFrameCtr {
            dst_addr: nwk_address,
            command: cmd,
        });

        self.aps_cmd_transfer(frame, nwk_address, TxOptions::default())
            .await
            .map_err(ApsmeSecurityError::from)
    }

    async fn confirm_key(
        &mut self,
        dest_address: ExtendedAddress,
        status: ConfirmKeyStatus,
    ) -> ApsSecurityResult {
        // TODO: check if we are the trust center and ignore if so
        if self.security_network_params == SecurityNetworkParams::Distributed {
            log::warn!("[CONFIRM-KEY] can't verify key, not in a centralized network");
            return Err(ApsmeSecurityError::CommandValidationError);
        }

        let key_descriptor = match self
            .device_key_pair_set
            .iter_mut()
            .find(|key| key.device_address == dest_address)
        {
            Some(key_descriptor) => key_descriptor,
            None => {
                let cmd = ApsCommand::ConfirmKey(ConfirmKeyCommand {
                    status: ConfirmKeyStatus::Failure,
                    key_type: StandardKeyType::TrustCenterLinkKey,
                    destination_address: dest_address,
                });

                return self.send_apsme_security_command(dest_address, cmd).await;
            }
        };

        key_descriptor.incoming_frame_counter = 0;

        let cmd = ApsCommand::ConfirmKey(ConfirmKeyCommand {
            status,
            key_type: StandardKeyType::TrustCenterLinkKey,
            destination_address: dest_address,
        });

        self.send_apsme_security_command(dest_address, cmd).await
    }
}

impl<T: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Aps<T, D, S> {
    async fn send_apsme_security_command(
        &mut self,
        dest_address: ExtendedAddress,
        cmd: ApsCommand,
    ) -> Result<(), ApsmeSecurityError> {
        let nwk_address = self
            .nwk
            .find_nwk_addr(dest_address)
            .ok_or_else(|| {
                log::warn!("couldn't send APS security command: nwk address for extended address `{:?}` not found", dest_address);
                ApsmeSecurityError::ApsdeSapError(ApsdeError::NoShortAddress)
            })?;

        let frame = ApsCommandFrame::new(ApsCommandFrameCtr {
            dst_addr: nwk_address,
            command: cmd,
        });

        log::info!(
        "nwk_address: {:?}, dest_address: {:?}",
        nwk_address,
        dest_address
    );
        self.aps_cmd_transfer(frame, nwk_address, TxOptions::SECURE_CMD)
            .await
            .map_err(ApsmeSecurityError::from)
    }

    pub fn validate_incoming_apsme_command(
        &mut self,
        src_address: NwkAddress,
        frame: &ApsCommandFrame,
        key_pair: Option<DeviceKeyPairDescriptor>,
    ) -> Result<(), ApsmeSecurityError> {
        if !matches!(
        frame.command,
        ApsCommand::TransportKey(_) | ApsCommand::UpdateDevice(_) |
    ApsCommand::RemoveDevice(_) | ApsCommand::RequestKey(_) | ApsCommand::SwitchKey(_) |
    /*ApsCommand::TunnelData(_) | */ ApsCommand::VerifyKey(_) | ApsCommand::ConfirmKey(_)
    ) {
            // not a security command, ignore
            return Ok(());
        }

        // TODO
        /*
        if self.config.get_server_mask().primary_trust_center {
            return Ok(()); // we are the trust center, ignore validation
        }
        
         */

        let tc_addr = unwrap_or_return!(self.get_tc_addr(), Ok(()));
        if self.is_authorized() {
            return Ok(()); // initial nwk key exchange
        }

        // determine if command was sent by trust center
        if frame.header.frame_control.security {
            let key_pair = key_pair.unwrap();
            if key_pair.device_address != tc_addr {
                log::warn!(
                    "[VALIDATE-APSME-COMMAND] invalid command received: received command \
                    from {:?}, which is not the trust center",
                    key_pair.device_address);
                return Err(ApsmeSecurityError::CommandValidationError);
            }
        } else {
            if matches!(
            frame.command,
            ApsCommand::TransportKey(_)
                | ApsCommand::RemoveDevice(_)
                | ApsCommand::RequestKey(_)
                | ApsCommand::ConfirmKey(_)
        ) {
                log::warn!("[VALIDATE-APSME-COMMAND] encryption required for {:?}", frame.command);
                return Err(ApsmeSecurityError::CommandValidationError); // encryption required for these commands
            }

            // If unique trust center link key, also required for UpdateDevice
            // check aib.apsLinkKeyType
            match frame.command {
                ApsCommand::VerifyKey(VerifyKeyCommand { source_address, .. }) => {
                    if source_address != tc_addr {
                        log::warn!("[VALIDATE-APSME-COMMAND] verify key command received \
                            from {:?}, which is not the trust center", source_address);
                        return Err(ApsmeSecurityError::CommandValidationError);
                    }
                }
                _ => {
                    if src_address != NWK_COORDINATOR_ADDRESS {
                        return Err(ApsmeSecurityError::CommandValidationError);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn handle_transport_key_command(
        &mut self,
        src_address: NwkAddress,
        frame: &ApsCommandFrame,
        cmd: &TransportKeyCommand,
    ) -> Option<ApsIndication> {
        let hdr = &frame.header;
        let desc = cmd.key_descriptor;

        if matches!(
            desc,
            StandardKeyDescriptor::ApplicationLinkKey(_) | StandardKeyDescriptor::TrustCenterLinkKey(_)
        ) && self.is_authorized()
                && !hdr.frame_control.security
        {
            return None;
        }

        match desc {
            StandardKeyDescriptor::StandardNetworkKey(desc) => {
                if !hdr.frame_control.security {
                    return None;
                }

                let dest = desc.destination_address;
                if dest == self.nwk.get_ext_addr()
                    || dest == ExtendedAddress::ZERO
                    || dest == ExtendedAddress::MAX
                {
                    if dest == ExtendedAddress::MAX {
                        self.security_network_params = SecurityNetworkParams::Distributed;
                    } else {
                        self.security_network_params = SecurityNetworkParams::Centralized(desc.source_address);

                        self.nwk
                            .get_addr_map_mut()
                            .insert(src_address, desc.source_address);
                        log::info!("22: {:?}", self.nwk.get_addr_map());
                    }

                    return Some(ApsIndication::TransportKey(ApsmeTransportKeyIndication {
                        ext_src_addr: desc.source_address,
                        transport_key: TransportKeyData::StandardNetworkKey(StandardNetworkKeyData {
                            key: desc.key,
                            key_sequence: desc.sequence_number,
                            parent_address: None,
                        }),
                    }));
                }

                None
            }
            StandardKeyDescriptor::ApplicationLinkKey(desc) => {
                let addr = self.nwk.find_ext_addr(src_address)?;

                Some(ApsIndication::TransportKey(ApsmeTransportKeyIndication {
                    ext_src_addr: addr,
                    transport_key: TransportKeyData::ApplicationLinkKey(ApplicationLinkKeyData {
                        key: desc.key,
                        partner_address: desc.partner_address,
                        initiator: desc.initiation_flag,
                    }),
                }))
            }
            StandardKeyDescriptor::TrustCenterLinkKey(desc) => {
                if desc.destination_address == self.nwk.get_ext_addr() {
                    Some(ApsIndication::TransportKey(ApsmeTransportKeyIndication {
                        ext_src_addr: desc.source_address,
                        transport_key: TransportKeyData::TrustCenterLinkKey(TrustCenterLinkKeyData {
                            key: desc.key,
                        }),
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub fn handle_update_device_command(
        &self,
        src_address: NwkAddress,
        cmd: &UpdateDeviceCommand,
    ) -> Option<ApsIndication> {
        let src = self.nwk.find_ext_addr(src_address)?;

        Some(ApsIndication::UpdateDevice(ApsmeUpdateDeviceIndication {
            src_address: src,
            device_address: cmd.device_address,
            device_short_address: cmd.device_short_address,
            status: cmd.status,
        }))
    }

    pub fn handle_request_key_command(
        &self,
        src_addr: NwkAddress,
        cmd: &RequestKeyCommand,
    ) -> () {
        // TODO
    }

    pub fn handle_switch_key_command(
        &self,
        src_addr: NwkAddress,
        cmd: &SwitchKeyCommand,
    ) -> () {
        // TODO
    }

    pub fn handle_verify_key_command(
        &self,
        src_addr: NwkAddress,
        cmd: &VerifyKeyCommand,
    ) -> () {
        // TODO
    }

    pub fn handle_confirm_key_command(
        &mut self,
        src_address: NwkAddress,
        dst_address: NldeDataIndicationDstAddress,
        cmd: &ConfirmKeyCommand,
    ) -> Option<ApsIndication> {
        let indication = ApsmeConfirmKeyIndication {
            status: cmd.status,
            src_address: cmd.destination_address,
            key_type: cmd.key_type,
        };

        match dst_address {
            NldeDataIndicationDstAddress::Multicast(_) => return None,
            NldeDataIndicationDstAddress::UnicastOrBroadcast(addr) => {
                if addr.is_broadcast() {
                    return None;
                }
            }
        };

        let src_address = self.nwk.find_ext_addr(src_address)?;

        // TODO: check fi we are the trust center and drop indication if so

        let tc_addr = if let SecurityNetworkParams::Centralized(ext_addr) = self.security_network_params
        {
            ext_addr
        } else {
            return None;
        };

        if indication.status != ConfirmKeyStatus::Success
            || indication.key_type != StandardKeyType::TrustCenterLinkKey
            || self.security_network_params == SecurityNetworkParams::Distributed
            || src_address != tc_addr
        {
            return None;
        }

        let key_descriptor = self
            .device_key_pair_set
            .iter_mut()
            .find(|key| key.device_address == tc_addr)?;

        key_descriptor.key_attributes = KeyAttribute::VerifiedKey;
        key_descriptor.incoming_frame_counter = 0;

        Some(ApsIndication::ConfirmKey(indication))
    }

    // section 4.4.1.2
    pub fn decrypt_aps_frame(
        &mut self,
        frame_buffer: &mut [u8],
    ) -> Result<(ApsFrame, Option<DeviceKeyPairDescriptor>), SecurityError> {
        // 5) overwrite the security level with the value from the NIB
        // (default 0x05)
        let sec_level = self.nwk.get_profile().nwk_security_level;
        let mic_length = sec_level.mic_length();
        byte::check_len(frame_buffer, mic_length)?;

        let (_, aps_hdr_len) = ApsHeader::try_read(frame_buffer, byte::LE)?;
        // SAFETY: the buffer for the header is not mutated
        // we can safely remove the &mut to satisfy the
        // borrow checker when returning NwkFrame<'_>
        let hdr_buf = unsafe { slice::from_raw_parts(frame_buffer.as_ptr(), aps_hdr_len) };
        let (aps_hdr, _) = ApsHeader::try_read(hdr_buf, byte::LE)?;

        if !aps_hdr.frame_control.security {
            return Ok((
                ApsFrame::from_payload(aps_hdr, &frame_buffer[aps_hdr_len..])?,
                None,
            ));
        }

        let (mut aux_hdr, aux_hdr_len) =
            AuxFrameHeader::try_read(&frame_buffer[aps_hdr_len..], byte::LE)?;

        if aux_hdr.frame_counter == u32::MAX {
            return Err(SecurityError::InvalidData);
        }

        let Some(source_address) = aux_hdr.source_address else {
            return Err(SecurityError::Unspecified);
        };

        log::info!("authorized: {:?}", self.is_authorized());
        log::info!("{:?}", self.device_key_pair_set);

        // step 2: select the security material matching the source address
        let key_config = self
            .device_key_pair_set
            .iter()
            .find(|key| {
                if !self.is_authorized() {
                    // TODO: test decryption with all link key types (global, unique, distributed,
                    // install code)
                    key.link_key_type == LinkKeyType::GlobalLinkKey
                } else {
                    key.device_address == source_address
                }
            })
            .ok_or_else(|| {
                log::warn!("[APS-DECRYPTION] couldn't decrypt frame, key not found. source \
                    address: {:?}, key_pair_set: {:?}", source_address, self.device_key_pair_set);
                SecurityError::Unspecified
            })?;

        // step 3: obtain the key
        let key = match aux_hdr.security_control.key_identifier {
            KeyIdentifier::Data => key_config.link_key,
            KeyIdentifier::KeyTransport => {
                // Section 4.5.3: key-transport key uses 1-octet string '0x00'
                HmacAes128Mmo::hmac(key_config.link_key.as_slice(), &[0x00])?
            }
            KeyIdentifier::KeyLoad => {
                // Section 4.5.3: key-load key uses 1-octet string '0x02'
                HmacAes128Mmo::hmac(key_config.link_key.as_slice(), &[0x02])?
            }
            KeyIdentifier::Network => {
                log::warn!("[APS-DECRYPTION] couldn't decrypt frame, invalid identifier in \
                    aux header key identifier");
                return Err(SecurityError::InvalidData)
            },
        };

        // step 4
        if matches!(key_config.link_key_type, LinkKeyType::UniqueLinkKey)
            && aux_hdr.frame_counter < key_config.incoming_frame_counter
        {
            log::warn!("[APS-DECRYPTION] couldn't decrypt frame, frame counter in aux header is \
                    less than key incoming frame counter");
            return Err(SecurityError::Unspecified);
        }

        // write back the security level from NIB to aux header
        // the updated values is required as input to ccm
        aux_hdr.security_control.security_level = sec_level;
        let mut offset = aps_hdr_len;
        frame_buffer.write_with(&mut offset, aux_hdr, byte::LE)?;

        // TODO:verify the source address
        let Some(_source_address) = aux_hdr.source_address else {
            log::warn!("[APS-DECRYPTION] couldn't decrypt frame, aux header does not contain the \
                source address");
            return Err(SecurityError::InvalidData);
        };

        let (aad, frame) = frame_buffer.split_at_mut(aps_hdr_len + aux_hdr_len);
        let (data, tag) = frame.split_at_mut(frame.len() - mic_length);

        let ccm = CcmZigbee { key };
        ccm.decrypt_in_place(aad, data, tag, &aux_hdr.create_nonce()?)?;

        Ok((ApsFrame::from_payload(aps_hdr, data)?, Some(*key_config)))
    }

    pub fn encrypt_aps_frame(
        &mut self,
        mut frame: ApsFrame,
        dest: ExtendedAddress,
        tx_options: TxOptions,
        buffer: &mut [u8],
    ) -> Result<usize, SecurityError> {
        let ieee_address = self.nwk.get_ext_addr();
        let security_level = self.nwk.get_profile().nwk_security_level;
        frame.header_mut().frame_control.security = true;

        // get link key associated with destination from AIB
        let key_set = &mut self.device_key_pair_set;
        log::info!("key_set: {:?}", key_set);
        let key_config = key_set
            .iter_mut()
            .find(|k| {
                k.device_address == dest
                    && matches!(
                    k.key_attributes,
                    KeyAttribute::ProvisionalKey | KeyAttribute::VerifiedKey
                )
            })
            .ok_or_else(|| {
                log::warn!("[APS-ENCRYPTION] couldn't encrypt frame, key not found. dest address: {:?}", dest);
                SecurityError::Unspecified
            })?;
        let link_key = key_config.link_key.as_slice();

        // Step 1: Obtain security material and key identifier
        let (key, key_id) = match frame {
            ApsFrame::ApsCommand(ApsCommandFrame {
                                     command: ApsCommand::TransportKey(ref tk),
                                     ..
                                 }) => match tk.key_descriptor {
                StandardKeyDescriptor::StandardNetworkKey(_) => (
                    HmacAes128Mmo::hmac(link_key, &[0x00])?,
                    KeyIdentifier::KeyTransport,
                ),
                _ => (
                    HmacAes128Mmo::hmac(link_key, &[0x02])?,
                    KeyIdentifier::KeyLoad,
                ),
            },
            _ => (key_config.link_key, KeyIdentifier::Data),
        };

        // Step 2: Extract frame counter (and key sequence number if needed)
        let frame_counter = key_config.outgoing_frame_counter;
        if frame_counter == u32::MAX {
            log::warn!("[APS-ENCRYPTION] frame counter overflow");
            return Err(SecurityError::InvalidData);
        }

        // Step 3: Obtain security level from NIB
        // Step 4: Construct auxiliary header
        let security_control = SecurityControl {
            security_level,
            key_identifier: key_id,
            extended_nonce: tx_options.include_extended_nonce
                || matches!(frame, ApsFrame::ApsCommand(_)),
        };

        let aux_hdr = AuxFrameHeader {
            security_control,
            frame_counter,
            source_address: if security_control.extended_nonce {
                Some(ieee_address)
            } else {
                None
            },
            key_sequence_number: None, /* this is should be never set because key_id = 0x01
                                    * (NetworkKey) is invalid */
        };

        // Write APS header
        let offset = match frame {
            ApsFrame::Data(data_frame) => write_and_encrypt_in_place(
                security_level,
                buffer,
                aux_hdr,
                key,
                data_frame.header,
                data_frame.payload.as_slice(),
            ),
            ApsFrame::ApsCommand(command_frame) => {
                let mut bytes = [0u8; MAX_APS_PAYLOAD_SIZE];
                let mut offset = 0;
                bytes.write_with(&mut offset, command_frame.command, byte::LE)
                    .map_err(|err| {
                        log::warn!("[APS-ENCRYPTION] error writing command frame: {:?}", err);
                        err
                    })?;

                write_and_encrypt_in_place(
                    security_level,
                    buffer,
                    aux_hdr,
                    key,
                    command_frame.header,
                    &bytes[0..offset],
                )
            }
            // already covered
            ApsFrame::Acknowledgement(_) => unreachable!(),
        }?;

        // step 9:
        // increment and write back frame counter
        key_config.outgoing_frame_counter += 1;

        Ok(offset)
    }
}


impl<D: NwkMac, S: StorageRegion> Aps<Nwk<JoinedAsRouter, D, S>, D, S> {
    pub fn handle_remove_device_command(
        &self,
        src_address: NwkAddress,
        cmd: &RemoveDeviceCommand,
    ) -> Option<ApsIndication> {
        Some(ApsIndication::RemoveDevice(ApsmeRemoveDeviceIndication {
            src_address: self.nwk.find_ext_addr(src_address)?,
            target_address: cmd.target_address
        }))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::apl::aps::security::types::common::{DeviceKeyPairDescriptor, KeyAttribute, LinkKeyType};
    use crate::apl::aps::types::TxOptions;
    use crate::common::security::TRUST_CENTER_LINK_KEY;
    use crate::common::security::frame::SecurityLevel;

    const NETWORK_KEY: [u8; 16] = [
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    #[test]
    fn test_create_nonce() {
        let source_address = Some(ExtendedAddress(0xaaaa_bbbb_cccc_dddd));
        let frame_counter = 0x0;
        let security_control = SecurityControl {
            security_level: SecurityLevel::EncMic32,
            key_identifier: KeyIdentifier::Network,
            extended_nonce: true,
        };
        let aux_hdr = AuxFrameHeader {
            security_control,
            frame_counter,
            source_address,
            key_sequence_number: None,
        };
        let nonce = aux_hdr.create_nonce().unwrap();
        assert_eq!(nonce, [
            0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 45
        ]);
    }

    #[test]
    fn decrypt_encrypt_aps_frame_data() {
        // aps cmd request key
        let frame_buffer = [
            0x21, 0x66, // aps header
            0x20, 0x4, 0x0, 0x0, 0x0, 0xe5, 0x1, 0x30, 0x38, 0x9c, 0x38, 0xc1, 0xa4, // aux header
            0x1a, 0x31, // enc data
            0xa4, 0xd7, 0xf4, 0xd7, // mic
        ];
        let mut buf = frame_buffer.clone();
        let dest = ExtendedAddress(0x1234_5678_90ab_cdef);

        let key_desc = DeviceKeyPairDescriptor {
            device_address: dest,
            key_attributes: KeyAttribute::VerifiedKey,
            link_key: TRUST_CENTER_LINK_KEY,
            outgoing_frame_counter: 4,
            incoming_frame_counter: 0,
            link_key_type: LinkKeyType::GlobalLinkKey,
        };

        let mut aps = Aps::end_device()
            .key_pair_desc(key_desc)
            .call();

        let (frame, _) = aps.decrypt_aps_frame(&mut buf).unwrap();

        let mut aps = Aps::end_device()
            .ext_addr(ExtendedAddress(0xa4c1_389c_3830_01e5))
            .key_pair_desc(key_desc)
            .call();

        let mut got_buffer = [0u8; 21];

        let offset = aps.encrypt_aps_frame(frame, dest, TxOptions::default(), &mut got_buffer)
            .unwrap();

        assert_eq!(offset, frame_buffer.len());
        assert_eq!(frame_buffer, got_buffer);
    }

    #[test]
    fn decrypt_encrypt_aps_frame_key_transport() {
        let frame_buffer = [
            0x21, 0x95, // aps hdr
            0x30, 0x0, 0x0, 0x0, 0x0, 0xe1, 0x52, 0x38, 0x7d, 0xc1, 0x36, 0xce, // aux hdr
            0xf4, 0xcc, 0x56, 0x50, 0x5e, 0x7, 0x2d, 0xc5, 0xc1, 0xe8, 0x40, 0xf2, 0xd5, 0xce, 0xc,
            0xa9, 0x2d, 0x64, 0x23, 0xcc, 0xc, 0x56, 0xcc, 0xc4, 0xcc, 0xf, 0x18, 0xa2, 0xe4, 0x82,
            0x88, 0x58, 0x4a, 0x90, 0x3e, 0x0, // enc data
            0x47, 0x60, 0xf2, 0x5d, // mic
        ];

        let dest = ExtendedAddress(0xa4c1_389c_3830_01e5);
        let key_pair = DeviceKeyPairDescriptor {
            device_address: dest,
            key_attributes: KeyAttribute::VerifiedKey,
            link_key: TRUST_CENTER_LINK_KEY,
            outgoing_frame_counter: 0,
            incoming_frame_counter: 0,
            link_key_type: LinkKeyType::GlobalLinkKey,
        };

        let mut aps = Aps::end_device()
            .key_pair_desc(key_pair)
            .call();
        let mut buf = frame_buffer;

        let (frame, _) = aps.decrypt_aps_frame(&mut buf).unwrap();

        let mut aps = Aps::end_device()
            .ext_addr(ExtendedAddress(0xf4ce_36c1_7d38_52e1))
            .key_pair_desc(key_pair)
            .call();

        let mut got_buffer = [0u8; 54];
        let offset = aps.encrypt_aps_frame(frame, dest, TxOptions::default(), &mut got_buffer)
            .unwrap();

        assert_eq!(offset, frame_buffer.len());
        assert_eq!(frame_buffer, got_buffer);
    }

    #[test]
    fn decrypt_encrypt_aps_frame_key_load() {
        let frame_buffer = [
            0x21, 0x97, // aps hdr
            0x38, 0x1, 0x0, 0x0, 0x0, 0xe1, 0x52, 0x38, 0x7d, 0xc1, 0x36, 0xce, // aux hdr
            0xf4, 0xe0, 0x4b, 0x37, 0xdb, 0x35, 0xc7, 0x13, 0x41, 0x71, 0xf0, 0xdf, 0xdb, 0x22,
            0xa5, 0xa1, 0x65, 0xbf, 0xfe, 0x41, 0x5a, 0xb2, 0x5f, 0xd9, 0x85, 0x79, 0x92, 0x5a,
            0xd4, 0xe6, 0x48, 0xfa, 0x6, 0xfb, 0x11, // enc data
            0xb7, 0xc9, 0x4, 0x3e, // mic
        ];
        let dest = ExtendedAddress(0xa4c1_389c_3830_01e5);
        let key_pair = DeviceKeyPairDescriptor {
            device_address: dest,
            key_attributes: KeyAttribute::VerifiedKey,
            link_key: TRUST_CENTER_LINK_KEY,
            outgoing_frame_counter: 1,
            incoming_frame_counter: 0,
            link_key_type: LinkKeyType::GlobalLinkKey,
        };
        let mut buf = frame_buffer;

        let mut aps = Aps::end_device()
            .key_pair_desc(key_pair)
            .call();

        let (frame, _) = aps.decrypt_aps_frame(&mut buf).unwrap();

        let mut aps = Aps::end_device()
            .ext_addr(ExtendedAddress(0xf4ce_36c1_7d38_52e1))
            .key_pair_desc(key_pair)
            .call();

        let mut got_buffer = [0u8; 53];
        let offset = aps.encrypt_aps_frame(frame, dest, TxOptions::default(), &mut got_buffer)
            .unwrap();

        assert_eq!(offset, frame_buffer.len());
        assert_eq!(frame_buffer, got_buffer);
    }
}
