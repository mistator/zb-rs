#![allow(dead_code)]

use crate::apl::aps::apsme::Binding;
use crate::apl::aps::apsme::BindingAddress;
use crate::apl::aps::constants::MAX_APS_FRAME_SIZE;
use crate::apl::aps::constants::MAX_APS_PAYLOAD_SIZE;
use crate::apl::aps::constants::MAX_FRAME_RETRIES;
use crate::apl::aps::ctx::{Aps, ApsListen, ApsTransmit, Apsme};
use crate::apl::aps::frame::ApsCommand;
use crate::apl::aps::frame::ApsCommandFrame;
use crate::apl::aps::frame::ApsDataFrame;
use crate::apl::aps::frame::ApsFrame;
use crate::apl::aps::frame::ApsFrameControl;
use crate::apl::aps::frame::ApsFrameType;
use crate::apl::aps::frame::ApsHeader;
use crate::apl::aps::frame::DataFrameInit;
use crate::apl::aps::frame::DeliveryMode;
use crate::apl::aps::frame::ExtendedFrameControlField;
use crate::apl::aps::security::types::common::DeviceKeyPairDescriptor;
use crate::apl::aps::types::ApsAddress;
use crate::apl::aps::types::ApsEndpoint;
use crate::apl::aps::types::ApsIndication;
use crate::apl::aps::types::SrcAddrMode;
use crate::apl::aps::types::TxOptions;
use crate::common::security::SecurityError;
use crate::nwk::nlde::{NldeDataIndication, NlmeLeaveIndication};
use crate::nwk::nlde::NldeDataIndicationDstAddress;
use crate::nwk::nlde::NldeTransferError;
use crate::nwk::nlde::NwkIndication;
use crate::nwk::service::transmission::DataFrameConfig;
use byte::BytesExt;
use byte::Error;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use core::cmp::min;
use embassy_futures::select::{Either, select};
use embassy_time::Duration;
use embassy_time::TimeoutError;
use embassy_time::Timer;
use thiserror::Error;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use crate::nwk::ctx::{BaseNwk, InitializedNwk, JoinedAsEndDevice, JoinedAsRouter, JoinedNwk, JoinedState, NonRoutingState, Nwk, NwkListen, NwkTransmit, RoutingNwk, RoutingState};

#[derive(Clone, Copy, Default, Debug)]
pub enum ApsdeDataIndicationSecurityStatus {
    #[default]
    Unsecured,
    SecuredNwkKey,
    SecuredLinkKey,
}

#[derive(Clone, Debug)]
pub struct ApsdeDataIndication {
    pub dst: ApsAddress,
    pub src: ApsdeAddress,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub asdu: zb_types::Vec<u8, MAX_APS_PAYLOAD_SIZE>,
    // status
    pub security_status: ApsdeDataIndicationSecurityStatus,
    pub link_quality: u8,
    // rx_time
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum ApsdeAddress {
    #[default]
    None = 0x0,
    Group(NwkAddress) = 0x01,
    Network(NwkAddress, ApsEndpoint) = 0x02,
    Extended(ExtendedAddress, ApsEndpoint) = 0x03,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Alias {
    pub src_addr: NwkAddress,
    pub seq_number: u8,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApsdeRequest<T: TryWrite<Endian> + Clone> {
    pub dst_address: ApsdeAddress,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_endpoint: ApsEndpoint,
    pub asdu: T,
    pub tx_options: TxOptions,
    pub alias: Option<Alias>,
    pub radius: Option<u8>,
}

// 2.2.4.1.2
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApsdeSapConfirm {
    pub dst_address: ApsdeAddress,
    pub src_endpoint: ApsEndpoint,
    pub tx_time: u8,
}

#[derive(Debug, Clone, Error, PartialEq)]
pub enum ApsdeError {
    #[error("operation not supported: {0}")]
    NotSupported(&'static str),
    #[error("no corresponding 16-bit network address found")]
    NoShortAddress,
    #[error(
        "no binding table entries found with the given source endpoint and cluster id parameters"
    )]
    NoBoundDevice,
    #[error("asdu too long")]
    TooLong,
    #[error("ack required but not received")]
    NoAck,
    #[error("error transmitting data: {}", 0)]
    NldeDataError(#[from] NldeTransferError),
    #[error("byte error: {}", 0)]
    ByteError(byte::Error),
    #[error("security error: {}", 0)]
    SecurityError(#[from] SecurityError),
}

pub type ApsdeResult = Result<ApsdeSapConfirm, ApsdeError>;

// 2.2.4.1.1
impl<J: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> ApsTransmit for Aps<J, D, S> {
    async fn aps_data_request<T>(&mut self, request: ApsdeRequest<T>) -> ApsdeResult
    where
        T: TryWrite<Endian> + Clone,
    {
        match request.dst_address {
            // If the DstAddrMode parameter is set to 0x00 and this primitive was received by the APSDE
            // of a device supporting a binding table, a search is made in the binding table
            // with the endpoint and cluster identifiers specified in the SrcEnd-
            // point and ClusterId parameters, respectively, for associated binding table entries.
            //
            // If more than one binding table entry is present, then the APSDE processes each binding
            // table entry as described above; until no more binding table entries remain. If
            // this primitive was received by the APSDE of a device that does not support a
            // binding table, the APSDE issues the APSDE-DATA.confirm primitive with a status of
            // NOT_SUPPORTED.
            ApsdeAddress::None => {
                let bindings = (*self
                    .binding_table)
                    .iter()
                    .filter(|item| {
                        item.src_endpoint == request.src_endpoint
                            && item.cluster_id == request.cluster_id
                    })
                    .collect::<zb_types::Vec<&Binding, 64>>();

                // If no binding table entries are found,
                // the APSDE issues the APSDE-DATA.confirm primitive with a status of
                // NO_BOUND_DEVICE.
                if bindings.is_empty() {
                    return Err(ApsdeError::NoBoundDevice);
                }

                let mut destinations = zb_types::Vec::<ApsAddress, 128>::new();

                for binding in bindings {
                    // If one or more
                    // binding table entries are found, then the APSDE examines the destination
                    // address information in each binding table entry. If this
                    // indicates a device itself, then the APSDE shall issue an
                    // APSDE-DATA.indication primitive to the next higher layer with
                    // the DstEndpoint parameter set to the destination endpoint identifier in the
                    // binding table entry.
                    if match binding.dst_address {
                        BindingAddress::Group(_) => false,
                        BindingAddress::Device(addr, _) => addr == self.nwk.get_ext_addr(),
                    } {
                        // If UseAlias parameter has the value of TRUE, the supplied value of the
                        // AliasSrcAddr shall be used for the SrcAddress
                        // parameter of the APSDE-DATA.indication primitive.
                        let _src = match request.alias {
                            Some(ref value) => {
                                ApsdeAddress::Network(value.src_addr, request.src_endpoint)
                            }
                            None => ApsdeAddress::Extended(
                                self.nwk.get_ext_addr(),
                                request.src_endpoint,
                            ),
                        };
                        // TODO: emit indication
                    } else {
                        // Otherwise if the binding table entries do not indicate the
                        // device itself, the APSDE constructs the APDU with the endpoint information
                        // from the binding table entry, if present, and uses the
                        // destination address information from the binding table entry when
                        // transmitting the frame via the NWK layer.
                        let (_dst, data_frame_dest) = match binding.dst_address {
                            BindingAddress::Group(addr) => (addr, ApsAddress::Group(addr)),
                            BindingAddress::Device(ieee_addr, endpoint) => match self.get_short_address(
                                ApsdeAddress::Extended(ieee_addr, endpoint),
                            ) {
                                None => continue,
                                Some(addr) => (addr, ApsAddress::Network(addr, endpoint)),
                            },
                        };

                        destinations.push(data_frame_dest).unwrap();
                    }
                }

                for dest in destinations {
                    self.aps_data_transfer(&dest, &request).await?;
                }
            }
            // If the DstAddrMode parameter has a value of 0x01, indicating group addressing, the
            // DstAddress parameter will be interpreted as a 16-bit group address. This address
            // will be placed in the group address field of the APS header, the DstEndpoint
            // parameter will be ignored, and the destination endpoint field will be omitted from the
            // APS header. The delivery mode sub-field of the frame control field of the APS
            // header shall have a value of 0x03 in this case.
            ApsdeAddress::Group(addr) => {
                self.aps_data_transfer(&ApsAddress::Group(addr), &request).await?;
            }
            // If the DstAddrMode parameter is set to 0x02, the DstAddress parameter contains a 16-bit
            // NWK address, and the DstEndpoint parameter is supplied. The next higher layer
            // should only employ DstAddrMode of 0x02 in cases where the destination NWK address
            // is employed for immediate application responses and the NWK address is not retained
            // for later data transmission requests.
            ApsdeAddress::Network(addr, dst_endpoint) => {
                self.aps_data_transfer(&ApsAddress::Network(addr, dst_endpoint), &request).await?;
            }
            // If the DstAddrMode parameter is set to 0x03, the DstAddress parameter contains an
            // extended 64-bit IEEE address and must first be mapped to a corresponding 16-bit
            // NWK address by using the nwkAddressMap attribute of the NIB (see Table 3-58). If
            // a corresponding 16-bit NWK address could not be found, the APSDE issues the
            // APSDE-DATA.confirm primitive with a status of NO_SHORT_ADDRESS. If a corresponding 16-bit
            // NWK address is found, it will be used in the invocation of the NLDE-DATA.request
            // primitive and the value of the DstEndpoint parameter will be placed in the
            // resulting APDU.
            ApsdeAddress::Extended(addr, dst_endpoint) => {
                let addr = self
                    .nwk
                    .find_nwk_addr(addr)
                    .ok_or(ApsdeError::NoShortAddress)?;
                self.aps_data_transfer(&ApsAddress::Network(addr, dst_endpoint), &request).await?;
            }
        }

        Ok(ApsdeSapConfirm {
            dst_address: Default::default(),
            src_endpoint: Default::default(),
            tx_time: 0,
        })
    }
}

impl<J: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Aps<J, D, S> {
    fn get_short_address(&self, address: ApsdeAddress) -> Option<NwkAddress> {
        match address {
            ApsdeAddress::Network(addr, _) => Some(addr),
            ApsdeAddress::Extended(addr, _) => self.nwk.find_nwk_addr(addr),
            _ => None,
        }
    }

    // If the ASDU to be transmitted is larger than will fit in a single frame, an
    // acknowledged transmission is requested, and the fragmentation permitted flag
    // of the TxOptions field is set to 1, and the ASDU is not too large to be
    // handled by the APSDE, then the ASDU shall be fragmented across multiple
    // APDUs, as described in section 2.2.8.4.5. Transmission and security
    // processing where requested, shall be carried out for each individual APDU
    // independently. Note that fragmentation shall not be used unless relevant
    // higher-layer documentation and/or interactions explicitly indicate that
    // fragmentation is permitted for the frame being sent, and that the other end
    // is able to receive the fragmented trans- mission, both in terms of number of
    // blocks and total transmission size.
    async fn aps_data_transfer<T: TryWrite<Endian> + Clone>(
        &mut self,
        dst: &ApsAddress,
        request: &ApsdeRequest<T>,
    ) -> Result<(), ApsdeError> {
        let mut asdu = [0u8; MAX_APS_FRAME_SIZE];
        let mut size = 0;
        let tx_options = request.tx_options;

        asdu.write_with(&mut size, request.asdu.clone(), byte::LE)
            .map_err(|err| match err {
                Error::Incomplete => ApsdeError::TooLong,
                _ => ApsdeError::ByteError(err),
            })?;

        if size <= MAX_APS_PAYLOAD_SIZE {
            let data_frame = ApsDataFrame::new(DataFrameInit {
                dst: *dst,
                source_endpoint: request.src_endpoint,
                profile_id: request.profile_id,
                cluster_id: request.cluster_id,
                payload: zb_types::Vec::from_slice(&asdu[..size]).unwrap(),
                ack_request: request.tx_options.acknowledged,
                extended_header: None,
            });

            let counter = self.get_aps_counter();
            self.aps_transfer(
                ApsFrame::Data(data_frame),
                dst.get_nwk_address(),
                request.alias.clone(),
                request.radius,
                request.tx_options,
                counter,
            )
                .await?;

            if request.tx_options.acknowledged {
                self.wait_for_ack(counter)
                    .await
                    .map(|_| ())
                    .map_err(|_| ApsdeError::NoAck)
            } else {
                Ok(())
            }
        } else {
            // If the ASDU to be transmitted is larger than will fit in a single frame and
            // fragmentation is not possible, then the ASDU is not transmitted and
            // the APSDE shall issue the APSDE-DATA.confirm primitive with a status of AS-
            // DU_TOO_LONG. Fragmentation is not possible if either an acknowledged
            // transmission is not requested, or if the fragmentation permitted flag
            // in the TxOptions field is set to 0, or if the ASDU is too large to be handled
            // by the APSDE.
            let aps_window_size = match request.dst_address {
                ApsdeAddress::Network(addr, ep) => {
                    if addr.is_broadcast() {
                        None
                    } else {
                        self.max_window_size.get(&ep)
                    }
                }
                ApsdeAddress::Extended(_, ep) => self.max_window_size.get(&ep),
                _ => None,
            };
            let fragmentation_possible = tx_options.acknowledged
                && tx_options.fragmentation_permitted
                && aps_window_size.is_some();
            if !fragmentation_possible {
                return Err(ApsdeError::TooLong);
            }

            let aps_window_size = *aps_window_size.unwrap() as usize;
            let counter = self.get_aps_counter();

            let mut transfer_window = async |slice: &[u8], initial_block_number: usize| {
                let mut retry_count: u8 = 0;
                let mut ack_bitfield: u8 = 0;
                let remaining_blocks = (slice.len() - 1) / MAX_APS_PAYLOAD_SIZE + 1;
                let window_size = min(aps_window_size, remaining_blocks);

                while retry_count < MAX_FRAME_RETRIES {
                    for idx in 0..window_size {
                        if ack_bitfield & (0000_0001 << idx) != 0 {
                            continue;
                        }
                        let chunk =
                            &slice[idx * MAX_APS_PAYLOAD_SIZE..(idx + 1) * MAX_APS_PAYLOAD_SIZE];
                        let block_number = initial_block_number + idx;

                        let data_frame = ApsDataFrame::new(DataFrameInit {
                            dst: *dst,
                            source_endpoint: request.src_endpoint,
                            profile_id: request.profile_id,
                            cluster_id: request.cluster_id,
                            payload: zb_types::Vec::from_slice(chunk).unwrap(),
                            ack_request: request.tx_options.acknowledged,
                            extended_header: if block_number == 0 {
                                ExtendedFrameControlField::FragmentationFirst {
                                    block_number: remaining_blocks as u8,
                                    ack_bitfield: None,
                                }
                                    .into()
                            } else {
                                ExtendedFrameControlField::FragmentationNotFirst {
                                    block_number: block_number as u8,
                                    ack_bitfield: None,
                                }
                                    .into()
                            },
                        });

                        self.aps_transfer(
                            ApsFrame::Data(data_frame),
                            dst.get_nwk_address(),
                            request.alias.clone(),
                            request.radius,
                            request.tx_options,
                            counter,
                        )
                            .await?;

                        Timer::after_millis(self.interframe_delay as u64).await;
                    }

                    match self.wait_for_ack(counter).await {
                        Ok(ApsHeader {
                               extended_header:
                               Some(
                                   ExtendedFrameControlField::FragmentationFirst {
                                       block_number,
                                       ack_bitfield: Some(bf),
                                   }
                                   | ExtendedFrameControlField::FragmentationNotFirst {
                                       block_number,
                                       ack_bitfield: Some(bf),
                                   },
                               ),
                               ..
                           }) => {
                            if block_number as usize != initial_block_number || bf != u8::MAX {
                                retry_count = 0;
                                ack_bitfield = bf;
                                continue;
                            } else {
                                return Ok(());
                            }
                        }
                        _ => {
                            retry_count += 1;
                            ack_bitfield = 0;
                        }
                    }
                }

                Err(ApsdeError::NoAck)
            };

            let chunks = (size - 1) / MAX_APS_PAYLOAD_SIZE + 1;
            let n_windows = (chunks - 1) / aps_window_size + 1;

            for idx in 0..n_windows {
                let n_byte = idx * aps_window_size * MAX_APS_PAYLOAD_SIZE;
                transfer_window(&asdu[n_byte..], idx * aps_window_size).await?;
            }

            Ok(())
        }
    }

    pub async fn aps_cmd_transfer(
        &mut self,
        frame: ApsCommandFrame,
        dst: NwkAddress,
        options: TxOptions,
    ) -> Result<(), ApsdeError> {
        let frame = ApsFrame::ApsCommand(frame);
        let counter = self.get_aps_counter();

        self.aps_transfer(frame, dst, None, 15.into(), options, counter).await
    }

    pub async fn aps_transfer(
        &mut self,
        mut frame: ApsFrame,
        dst: NwkAddress,
        alias: Option<Alias>,
        radius: Option<u8>,
        options: TxOptions,
        counter: u8,
    ) -> Result<(), ApsdeError> {
        let mut buffer = [0u8; 127];

        // If the UseAlias parameter has the value of TRUE, and the Acknowledged
        // transmission field of the TxOptions pa- rameter is set to 0b1, then the
        // APSDE issues the APSDE-DATA.confirm primitive with a status of
        // NOT_SUPPORTED.
        if alias.is_some() && options.acknowledged {
            log::warn!("couldn't send APS frame: transferring a frame with alias and acknowledgement required is not supported");
            return Err(ApsdeError::NotSupported(
                "transferring a frame with alias and acknowledgement required is not supported",
            ));
        }

        // The parameters UseAlias, AliasSrcAddr and AliasSeqNumb shall be used in the
        // invocation of the NLDE-DATA.request primitive. If UseAlias is set to
        // TRUE, the AliasSeqNumb value shall be copied into the APS Counter field
        // instead of using the device’s own value.
        let counter = match alias {
            None => counter,
            Some(ref alias) => alias.seq_number,
        };
        frame.header_mut().counter = counter;

        // If the TxOptions parameter specifies that secured transmission is required,
        // the APS sub-layer shall use the security service provider (see section
        // 4.2.3) to secure the ASDU. The security processing shall always be performed
        // using device’s own extended 64-bit IEEE address and the
        // OutgoingFrameCounter attribute as stored in apsDeviceKey-
        // PairSet attribute of the AIB for the entity indicated by the DstAddress
        // parameter, and those values shall be put into the auxiliary APS header of
        // the frame, even if UseAlias parameter has a value of TRUE. If the security
        // processing fails, the APSDE shall issue the APSDE-DATA.confirm primitive
        // with a status of SECURITY_FAIL.
        let len = if options.security_enabled {
            let dst_addr = self.nwk.find_ext_addr(dst)
                .ok_or_else(|| {
                    log::warn!("couldn't encrypt APS frame: matching IEEE address not found for destination address");
                    ApsdeError::SecurityError(SecurityError::Unspecified)
                })?
                .clone();
            self.encrypt_aps_frame(frame, dst_addr, options, &mut buffer)?
        } else {
            frame
                .try_write(&mut buffer, byte::LE)
                .map_err(|err| ApsdeError::ByteError(err))?
        };

        let cfg = DataFrameConfig {
            dst_address: dst,
            alias,
            // The application may limit the number of hops a transmitted frame is allowed to travel
            // through the network by setting the RadiusCounter parameter of the
            // NLDE-DATA.request primitive to a non-zero value.
            radius,
            // The APSDE will ensure that route discovery is always enabled at the network layer by
            // setting the DiscoverRoute parameter of the NLDE-DATA.request primitive to 0x01,
            // each time it is issued.
            discover_route: true,
            ..Default::default()
        };

        // The APSDE transmits the constructed frame by issuing the NLDE-DATA.request
        // primitive to the NWK layer. When the APSDE has completed all operations
        // related to this transmission request, including transmitting frames as re-
        // quired, any retransmissions, and the receipt or timeout of any
        // acknowledgements, then the APSDE shall issue the APSDE-DATA.confirm
        // primitive (see section 2.2.4.1.2).
        self.nwk.transmit_data_frame(&buffer[..len], &cfg)
            .await
            .map_err(ApsdeError::from)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum ApsdeSapIndicationStatus {
    #[default]
    Success,
    DefragUnsupported,
    DefragDeferred,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum SecurityStatus {
    #[default]
    Unsecured,
    SecuredNwkKey,
    SecuredLinkKey,
}

// 2.2.4.1.3
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApsdeSapIndication {
    dst_address: ApsdeAddress,
    src_addr_mode: SrcAddrMode,
    src_address: u64,
    src_endpoint: ApsEndpoint,
    profile_id: u16,
    cluster_id: u16,
    asdulength: u8,
    status: ApsdeSapIndicationStatus,
    security_status: SecurityStatus,
    link_quality: u8,
    rx_time: u8,
}

impl<D: NwkMac, S: StorageRegion> ApsListen for Aps<Nwk<JoinedAsEndDevice, D, S>, D, S> {
    async fn listen_aps(&mut self) -> ApsIndication {
        loop {
            let is_authorized = self.is_authorized();
            let mut nwk_indication = self.nwk.listen_nwk(is_authorized).await;

            let result = if let NwkIndication::Data(mut indication) = nwk_indication {
                self.handle_data_indication(&mut indication).await
            } else {
                self.handle_indication_common(&mut nwk_indication).await
            };

            if let Some(aps_indication) = result {
                return aps_indication;
            }
        }
    }
}

impl<D: NwkMac, S: StorageRegion> Aps<Nwk<JoinedAsEndDevice, D, S>, D, S> {
    async fn handle_data_indication(
        &mut self,
        indication: &mut NldeDataIndication,
    ) -> Option<ApsIndication> {
        let (frame, key_descriptor) = self.decrypt_aps_frame(indication.nsdu.as_mut_slice()).ok()?;

        match frame {
            ApsFrame::Data(dataframe) => self.handle_data_frame(dataframe, indication, key_descriptor).await,
            ApsFrame::ApsCommand(ref cmd_frame) => {
                self.validate_incoming_apsme_command(indication.src_address, &cmd_frame, key_descriptor)
                    .map_err(|err| {
                        log::warn!("received invalid APS command: {:?}", err);
                    }).ok()?;

                self.handle_aps_command_common(
                    indication.src_address,
                    indication.dst_address,
                    cmd_frame,
                )
            },
            ApsFrame::Acknowledgement(_) => None,
        }
    }
}

impl<D: NwkMac, S: StorageRegion> ApsListen for Aps<Nwk<JoinedAsRouter, D, S>, D, S> {
    async fn listen_aps(&mut self) -> ApsIndication {
        loop {
            let is_authorized = self.is_authorized();
            let mut nwk_indication = self.nwk.listen_nwk(is_authorized).await;

            let result = if let NwkIndication::Data(mut indication) = nwk_indication {
                self.handle_data_indication(&mut indication).await
            } else {
                self.handle_indication_common(&mut nwk_indication).await
            };

            if let Some(aps_indication) = result {
                return aps_indication;
            }
        }
    }
}

impl<D: NwkMac, S: StorageRegion> Aps<Nwk<JoinedAsRouter, D, S>, D, S> {
    async fn handle_data_indication(
        &mut self,
        indication: &mut NldeDataIndication,
    ) -> Option<ApsIndication> {
        let (frame, key_descriptor) = self.decrypt_aps_frame(indication.nsdu.as_mut_slice()).ok()?;

        match frame {
            ApsFrame::Data(dataframe) => self.handle_data_frame(dataframe, indication, key_descriptor).await,
            ApsFrame::ApsCommand(ref cmd_frame) => {
                self.validate_incoming_apsme_command(indication.src_address, &cmd_frame, key_descriptor)
                    .map_err(|err| {
                        log::warn!("received invalid APS command: {:?}", err);
                    }).ok()?;
                
                let result = self.handle_aps_command_common(
                    indication.src_address,
                    indication.dst_address,
                    cmd_frame,
                );
                
                if result.is_some() {
                    return result;
                }
                
                match cmd_frame.command {
                    ApsCommand::RemoveDevice(ref cmd) => self.handle_remove_device_command(indication.src_address, cmd),
                    ApsCommand::RequestKey(_) => None, 
                    ApsCommand::SwitchKey(_) => None,
                    ApsCommand::VerifyKey(_) => None,
                    _ => None
                }
            },
            ApsFrame::Acknowledgement(_) => None,
        }
    }
}

impl<J: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Aps<J, D, S> {
    async fn handle_indication_common(&mut self, indication: &mut NwkIndication) -> Option<ApsIndication> {
         match indication {
             // TODO
             NwkIndication::Leave(leave_indication) => match leave_indication {
                 NlmeLeaveIndication::LeaveSelf { .. } => { Some(ApsIndication::Leave(*leave_indication)) }
                 NlmeLeaveIndication::LeaveChild { .. } => { None }
                 NlmeLeaveIndication::LeaveParent { .. } => { None }
             },
             NwkIndication::Join(_) => None,
             NwkIndication::Status(_) => None,
             NwkIndication::DutyCycle(_) => None,
             NwkIndication::SyncLoss => None,
             _ => None,
        }
    }


    async fn handle_data_frame(
        &mut self,
       dataframe: ApsDataFrame,
       indication: &NldeDataIndication,
       key_descriptor: Option<DeviceKeyPairDescriptor>
    ) -> Option<ApsIndication> {
        let security_status = if key_descriptor.is_some() {
            ApsdeDataIndicationSecurityStatus::SecuredLinkKey
        } else if indication.security_use {
            ApsdeDataIndicationSecurityStatus::SecuredNwkKey
        } else {
            ApsdeDataIndicationSecurityStatus::Unsecured
        };

        let hdr = dataframe.header;
        let src_endpoint = hdr.source_endpoint.unwrap();

        let src = match self.nwk.find_ext_addr(indication.src_address) {
            Some(addr) => ApsdeAddress::Extended(addr, src_endpoint),
            _ => ApsdeAddress::Network(indication.src_address, src_endpoint),
        };

        if hdr.frame_control.ack_request {
            self.send_ack(
                AckFormat::Data {
                    dst_endpoint: hdr.source_endpoint.unwrap(),
                    cluster_id: hdr.cluster_id.unwrap(),
                    profile_id: hdr.profile_id.unwrap(),
                    src_endpoint: hdr.destination_endpoint.unwrap(),
                },
                hdr.counter,
                indication.src_address,
            )
                .await
                .ok();
        }

        let indication = ApsdeDataIndication {
            src,
            dst: ApsAddress::Network(
                match indication.dst_address {
                    NldeDataIndicationDstAddress::Multicast(addr) => addr,
                    NldeDataIndicationDstAddress::UnicastOrBroadcast(addr) => addr,
                },
                hdr.destination_endpoint.unwrap(),
            ),
            profile_id: hdr.profile_id.unwrap(),
            cluster_id: hdr.cluster_id.unwrap(),
            asdu: dataframe.payload,
            link_quality: indication.link_quality,
            security_status,
        };

        Some(ApsIndication::Data(indication))
    }

    fn handle_aps_command_common(
        &mut self,
        src_address: NwkAddress,
        dst_address: NldeDataIndicationDstAddress,
        frame: &ApsCommandFrame,
    ) -> Option<ApsIndication> {
        match frame.command {
            ApsCommand::TransportKey(ref cmd) => {
                self.handle_transport_key_command(src_address, frame, &cmd)
            }
            ApsCommand::UpdateDevice(ref cmd) => self.handle_update_device_command(src_address, &cmd),
            // ApsCommand::RemoveDevice(ref cmd) => self.handle_remove_device_command(src_address,
            // &cmd), ApsCommand::RequestKey(ref cmd) =>
            // self.handle_request_key_command(src_address, &cmd), ApsCommand::SwitchKey(ref
            // cmd) => self.handle_switch_key_command(src_address, &cmd),
            // ApsCommand::TunnelData(ref cmd) => self.handle_tunnel_command
            // ApsCommand::VerifyKey(ref cmd) => self.handle_verify_key_command(src_address, &cmd),
            ApsCommand::ConfirmKey(ref cmd) => {
                self.handle_confirm_key_command(src_address, dst_address, &cmd)
            }
            _ => None,
        }
    }
}


#[derive(Clone, Copy)]
enum AckFormat {
    Command,
    Data {
        dst_endpoint: ApsEndpoint,
        cluster_id: u16,
        profile_id: u16,
        src_endpoint: ApsEndpoint,
    },
}

impl<T: JoinedNwk<D, S>, D: NwkMac, S: StorageRegion> Aps<T, D, S> {
    async fn send_ack(
        &mut self,
        ack_format: AckFormat,
        counter: u8,
        dst_addr: NwkAddress,
    ) -> Result<(), ApsdeError> {
        let mut header = ApsHeader {
            frame_control: ApsFrameControl {
                frame_type: ApsFrameType::Acknowledgement,
                delivery_mode: DeliveryMode::Unicast,
                ack_format: matches!(ack_format, AckFormat::Command { .. }),
                security: false,
                ack_request: false,
                extended_header: false,
            },
            destination_endpoint: None,
            group_address: None,
            cluster_id: None,
            profile_id: None,
            source_endpoint: None,
            counter,
            extended_header: None,
        };

        if let AckFormat::Data {
            dst_endpoint,
            cluster_id,
            profile_id,
            src_endpoint,
        } = ack_format
        {
            header.destination_endpoint = dst_endpoint.into();
            header.cluster_id = cluster_id.into();
            header.profile_id = profile_id.into();
            header.source_endpoint = src_endpoint.into();
        }

        let frame = ApsFrame::Acknowledgement(header);

        self.aps_transfer(
            frame,
            dst_addr,
            None,
            None,
            TxOptions::default(),
            counter,
        ).await
    }

    fn process_ack_header(&mut self, counter: u8, indication: &NwkIndication) -> Option<ApsHeader> {
        let indication = if let NwkIndication::Data(indication) = indication {
            indication
        } else {
            return None;
        };

        let header: ApsHeader = match ApsHeader::try_read(indication.nsdu.as_slice(), byte::LE) {
            Ok((header, _)) => header,
            Err(_) => return None,
        };

        if header.frame_control.frame_type == ApsFrameType::Acknowledgement
            && header.counter == counter
        {
            Some(header)
        } else {
            None
        }
    }

    async fn wait_for_ack(&mut self, counter: u8) -> Result<ApsHeader, TimeoutError> {
        let timeout = 50 * 2 * (self.nwk.get_profile().nwk_max_depth as u64) + 100;

        let listen = async {
            loop {
                let is_authorized = self.is_authorized();
                let indication = self.nwk.listen_nwk(is_authorized).await;



                if let Some(header) = self.process_ack_header(counter, &indication) {
                    return header;
                }

            }
        };
        let timeout = Timer::after_millis(timeout);

        match select(listen, timeout).await {
            Either::First(result) => Ok(result),
            Either::Second(_) => Err(TimeoutError),
        }
    }
}
