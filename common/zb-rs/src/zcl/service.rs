use byte::TryRead;

use crate::apl::aps::apsde::ApsdeError;
use crate::apl::aps::apsde::ApsdeRequest;
use crate::apl::aps::apsde::{ApsdeAddress, ApsdeDataIndication};
use crate::apl::aps::types::ApsEndpoint;
use crate::apl::zb_application::{ZigbeeApplication};
use crate::apl::zdo::{JoinedCtx, ZbNode};
use crate::apl::zdp::service::OptionalApsdeResult;
use crate::apl::zdp::service::to_optional;
use crate::nwk::ctx::NwkJoined;
use crate::zcl::cluster::types::ZclCluster;
use crate::zcl::command::global::ConfigureReportingResponseCommand;
use crate::zcl::command::global::DefaultResponseCommand;
use crate::zcl::command::global::DiscoverAttributesResponseCommand;
use crate::zcl::command::global::DiscoverCommandsReceivedResponseCommand;
use crate::zcl::command::global::GlobalZclCommand;
use crate::zcl::command::global::ReadAttributesResponseCommand;
use crate::zcl::command::global::ReadReportingConfigurationResponseCommand;
use crate::zcl::command::global::ReportAttributesCommand;
use crate::zcl::command::global::WriteAttributesResponseCommand;
use crate::zcl::frame::ZclDirection;
use crate::zcl::frame::ZclFrame;
use crate::zcl::frame::ZclFrameCommand;
use crate::zcl::frame::ZclFrameControl;
use crate::zcl::frame::ZclFrameType;
use crate::zcl::frame::ZclHeader;
use crate::zcl::types::ZclStatus;
use zb_hal::StorageRegion;

#[derive(Default)]
pub struct EmitCommandFrameCfg {
    pub direction: ZclDirection,
    pub manufacturer_specific: bool,
    pub sequence_number: Option<u8>,
    pub manufacturer_code: Option<u16>,
}

pub struct RequestCfg {
    pub dst_address: ApsdeAddress,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub src_endpoint: ApsEndpoint,
}

async fn persist_application<S: StorageRegion>(
    stg: &mut S,
    application: &dyn ZigbeeApplication,
) {
    let mut buffer = [0u8; 1024];
    let result = application.try_write(&mut buffer);

    if let Some(_) = result.ok() {
        stg.persist(buffer.as_slice()) // TODO
            .ok();
    } else {
        log::warn!("could not write application to storage");
    }
}

fn generate_default_response(command_identifier: u8, status: ZclStatus) -> ZclFrameCommand {
    ZclFrameCommand::Global(GlobalZclCommand::DefaultResponse(DefaultResponseCommand {
        command_identifier,
        status_code: status,
    }))
}

fn handle_global_command(cmd: &GlobalZclCommand, cluster: &mut dyn ZclCluster) -> Option<ZclFrameCommand> {
    let global_cmd = match cmd {
        GlobalZclCommand::ReadAttributes(attrs) => {
            log::info!("received read attributes command: {:?}", attrs);
            let rsp = cluster.read_attributes(attrs);
            log::info!("read attributes command response: {:?}", rsp);

            GlobalZclCommand::ReadAttributesResponse(ReadAttributesResponseCommand {
                attribute_statuses: zb_types::Vec::from_iter(rsp),
            })
                .into()
        }
        // GlobalZclCommand::ReadAttributesResponse(_) => {}
        GlobalZclCommand::WriteAttributes(attrs) => {
            let rsp = cluster.write_attributes(attrs);

            GlobalZclCommand::WriteAttributesResponse(WriteAttributesResponseCommand {
                attributes: zb_types::Vec::from_iter(rsp),
            })
                .into()
        }
        GlobalZclCommand::WriteAttributesUndivided(attrs) => {
            let rsp = cluster
                .write_attributes_undivided(attrs);

            GlobalZclCommand::WriteAttributesResponse(WriteAttributesResponseCommand {
                attributes: zb_types::Vec::from_iter(rsp),
            })
                .into()
        }
        // GlobalZclCommand::WriteAttributesResponse(attrs) => {}
        GlobalZclCommand::WriteAttributesNoResponse(attrs) => {
            let _ = cluster.write_attributes(attrs);
            None
        }
        GlobalZclCommand::ConfigureReporting(attrs) => {
            let rsp = cluster.configure_reporting(attrs);

            GlobalZclCommand::ConfigureReportingResponse(
                ConfigureReportingResponseCommand {
                    configuration_records: zb_types::Vec::from_iter(rsp),
                },
            )
                .into()
        }
        // GlobalZclCommand::ConfigureReportingResponse(_) => {}
        GlobalZclCommand::ReadReportingConfiguration(attrs) => {
            let rsp =
                cluster.read_reporting_config(attrs);

            GlobalZclCommand::ReadReportingConfigurationResponse(
                ReadReportingConfigurationResponseCommand {
                    attributes: zb_types::Vec::from_iter(rsp),
                },
            )
                .into()
        }

        // GlobalZclCommand::ReadReportingConfigurationResponse(_) => {}
        // GlobalZclCommand::ReportAttributes(_) => {}
        // GlobalZclCommand::DefaultResponse(_) => {}
        GlobalZclCommand::DiscoverAttributes(attrs) => {
            let rsp = cluster.discover_attributes(
                attrs.start_attribute_identifier,
                attrs.maximum_attribute_identifiers,
            );
            GlobalZclCommand::DiscoverAttributesResponse(
                DiscoverAttributesResponseCommand {
                    discovery_complete: true, // TODO
                    attributes: zb_types::Vec::from_iter(rsp),
                },
            )
                .into()
        }
        // GlobalZclCommand::DiscoverAttributesResponse(_) => {}
        // GlobalZclCommand::ReadAttributesStructured(_) => {}
        // GlobalZclCommand::WriteAttributesStructured(_) => {}
        // GlobalZclCommand::WriteAttributesStructuredResponse(_) => {}
        GlobalZclCommand::DiscoverCommandsReceived(_attrs) => {
            // TODO
            GlobalZclCommand::DiscoverCommandsReceivedResponse(
                DiscoverCommandsReceivedResponseCommand {
                    discovery_complete: false,
                    identifiers: Default::default(),
                },
            )
                .into()
        }
        // GlobalZclCommand::DiscoverCommandsReceivedResponse(_) => {}
        // GlobalZclCommand::DiscoverCommandsGenerated(_) => {}
        // GlobalZclCommand::DiscoverCommandsGeneratedResponse(_) => {}
        // GlobalZclCommand::DiscoverAttributesExtended(_) => {}
        // GlobalZclCommand::DiscoverAttributesExtendedResponse(_) => {}
        _ => {
            None
        }
    };

    global_cmd.map(|cmd| ZclFrameCommand::Global(cmd))
}



impl<N: NwkJoined, S: StorageRegion> ZbNode<JoinedCtx<N, S>, S> {
    pub async fn handle_zcl_command(
        &mut self,
        endpoint: ApsEndpoint,
        indication: &ApsdeDataIndication,
    ) -> OptionalApsdeResult {
        let (frame, _) =
            ZclFrame::try_read(&indication.asdu.as_slice(), byte::LE).map_err(|err| ApsdeError::ByteError(err))?;

        let response = self.applications.use_application_mut(endpoint, indication.cluster_id, |cluster| {
            match frame.command {
                ZclFrameCommand::Global(ref cmd) => handle_global_command(cmd, cluster),
                ZclFrameCommand::Specific(ref cmd) => cluster.handle_custom_command(cmd)
            }
        })
            .await
            .map_err(|_| ApsdeError::NotSupported("application and cluster not found"))?;

        let response = if response.is_none() {
            if indication.dst.is_unicast()
                && !matches!(
                frame.command,
                ZclFrameCommand::Global(GlobalZclCommand::DefaultResponse(_))
            )
                && !frame.header.frame_control.disable_default_response
            {
                generate_default_response(frame.header.sequence_number, ZclStatus::Success)
            } else {
                return Ok(None);
            }
        } else {
            response.unwrap()
        };

        let frame_control = frame.header.frame_control;
        let cfg = EmitCommandFrameCfg {
            direction: match frame_control.direction {
                ZclDirection::ClientToServer => ZclDirection::ServerToClient,
                ZclDirection::ServerToClient => ZclDirection::ClientToServer,
            },
            manufacturer_specific: frame_control.manufacturer_specific,
            sequence_number: Some(frame.header.sequence_number),
            manufacturer_code: frame.header.manufacturer_code,
        };

        let request_cfg = RequestCfg {
            dst_address: indication.src,
            profile_id: indication.profile_id,
            cluster_id: indication.cluster_id,
            src_endpoint: endpoint,
        };

        self.emit_zcl_command_frame(response, cfg, request_cfg).await
    }

    pub async fn emit_report_attributes(
        &mut self,
        cmd: ReportAttributesCommand,
        cfg: EmitCommandFrameCfg,
        request_cfg: RequestCfg,
    ) -> OptionalApsdeResult {
        let frame = ZclFrameCommand::Global(GlobalZclCommand::ReportAttributes(cmd));
        self.emit_zcl_command_frame(frame, cfg, request_cfg).await
    }

    async fn emit_zcl_command_frame(
        &mut self,
        cmd: ZclFrameCommand,
        cfg: EmitCommandFrameCfg,
        request_cfg: RequestCfg,
    ) -> OptionalApsdeResult {
        let frame_type = match cmd {
            ZclFrameCommand::Global(_) => ZclFrameType::Global,
            ZclFrameCommand::Specific(_) => ZclFrameType::Specific,
        };

        let frame = ZclFrame {
            header: ZclHeader {
                frame_control: ZclFrameControl {
                    frame_type,
                    manufacturer_specific: cfg.manufacturer_specific,
                    direction: cfg.direction,
                    disable_default_response: true,
                },
                manufacturer_code: cfg.manufacturer_code,
                sequence_number: cfg
                    .sequence_number
                    .unwrap_or_else(|| self.get_zcl_transaction_number()),
            },
            command: cmd,
        };

        let apsde_sap_request = ApsdeRequest {
            dst_address: request_cfg.dst_address,
            profile_id: request_cfg.profile_id,
            cluster_id: request_cfg.cluster_id,
            src_endpoint: request_cfg.src_endpoint,
            asdu: frame,
            tx_options: Default::default(),
            alias: None,
            radius: 0.into(),
        };

        to_optional(self.ctx.aps.aps_data_request(apsde_sap_request).await)
    }
}

