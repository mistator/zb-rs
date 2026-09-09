use crate::zcl::types::ZclData;
use crate::zcl::types::ZclStatus;
use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::check_len;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_macros::try_write_impl;

pub const MAX_COMMAND_ITEMS: usize = 64;

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct AttributeRecord {
    pub identifier: u16,
    #[byte(ctx = ())]
    pub data: ZclData,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum GlobalZclCommand {
    ReadAttributes(ReadAttributesCommand) = 0x0,
    ReadAttributesResponse(ReadAttributesResponseCommand) = 0x1,
    WriteAttributes(WriteAttributesCommand) = 0x2,
    WriteAttributesUndivided(WriteAttributesCommand) = 0x3,
    WriteAttributesResponse(WriteAttributesResponseCommand) = 0x4,
    WriteAttributesNoResponse(WriteAttributesCommand) = 0x5,
    ConfigureReporting(ConfigureReportingCommand) = 0x6,
    ConfigureReportingResponse(ConfigureReportingResponseCommand) = 0x7,
    ReadReportingConfiguration(ReadReportingConfigurationCommand) = 0x8,
    ReadReportingConfigurationResponse(ReadReportingConfigurationResponseCommand) = 0x9,
    ReportAttributes(ReportAttributesCommand) = 0xa,
    DefaultResponse(DefaultResponseCommand) = 0xb,
    DiscoverAttributes(DiscoverAttributesCommand) = 0xc,
    DiscoverAttributesResponse(DiscoverAttributesResponseCommand) = 0xd,
    ReadAttributesStructured(ReadAttributesStructuredCommand) = 0xe,
    WriteAttributesStructured(WriteAttributesStructuredCommand) = 0xf,
    WriteAttributesStructuredResponse(WriteAttributesStructuredResponseCommand) = 0x10,
    DiscoverCommandsReceived(DiscoverCommandsReceivedCommand) = 0x11,
    DiscoverCommandsReceivedResponse(DiscoverCommandsReceivedResponseCommand) = 0x12,
    DiscoverCommandsGenerated(DiscoverCommandsReceivedCommand) = 0x13,
    DiscoverCommandsGeneratedResponse(DiscoverCommandsReceivedResponseCommand) = 0x14,
    DiscoverAttributesExtended(DiscoverAttributesCommand) = 0x15,
    DiscoverAttributesExtendedResponse(DiscoverAttributesExtendedResponseCommand) = 0x16,
}

#[derive(Clone, Debug, TryRead, TryWrite, Default)]
pub struct ReadAttributesCommand {
    pub attributes: zb_types::Vec<u16, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ReadAttributesResponseCommand {
    pub attribute_statuses: zb_types::Vec<ReadAttributesStatusRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ReadAttributesStatusRecord {
    pub identifier: u16,
    pub status: ZclStatus,
    #[byte(ctx = (), parse_if = status == ZclStatus::Success)]
    pub data: Option<ZclData>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributesCommand {
    pub attributes: zb_types::Vec<AttributeRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributesResponseCommand {
    pub attributes: zb_types::Vec<WriteAttributeStatusRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributeStatusRecord {
    pub status: ZclStatus,
    pub identifier: u16,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ConfigureReportingCommand {
    pub configuration_records:
        zb_types::Vec<AttributeReportingConfigurationRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug)]
pub struct AttributeReportingConfigurationRecord {
    pub direction: AttributeReportingConfigurationDirection,
    pub identifier: u16,
    pub data_type: Option<u8>,
    pub minimum_reporting_interval: Option<u16>,
    pub maximum_reporting_interval: Option<u16>,
    pub reportable_change: Option<ZclData>,
    pub timeout_period: Option<u16>,
}

impl TryRead<'_, Endian> for AttributeReportingConfigurationRecord {
    fn try_read(bytes: &'_ [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        let direction = bytes.read_with(offset, ctx)?;
        let identifier = bytes.read_with(offset, ctx)?;

        if direction == AttributeReportingConfigurationDirection::Report {
            let data_type = bytes.read_with(offset, ctx)?;
            let minimum_reporting_interval = bytes.read_with(offset, ctx)?;
            let maximum_reporting_interval = bytes.read_with(offset, ctx)?;

            // TODO: Parse reportable_change when appropriate

            Ok((
                Self {
                    direction,
                    identifier,
                    data_type: Some(data_type),
                    minimum_reporting_interval: Some(minimum_reporting_interval),
                    maximum_reporting_interval: Some(maximum_reporting_interval),
                    reportable_change: None,
                    timeout_period: None,
                },
                *offset,
            ))
        } else {
            let timeout_period = bytes.read_with(offset, ctx)?;

            Ok((
                Self {
                    direction,
                    identifier,
                    data_type: None,
                    minimum_reporting_interval: None,
                    maximum_reporting_interval: None,
                    reportable_change: None,
                    timeout_period: Some(timeout_period),
                },
                *offset,
            ))
        }
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &AttributeReportingConfigurationRecord {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;

        bytes.write_with(offset, self.direction, ctx)?;
        bytes.write_with(offset, self.identifier, ctx)?;

        if let Some(data_type) = self.data_type {
            bytes.write_with(offset, data_type, ctx)?;
        }

        if let Some(minimum_reporting_interval) = self.minimum_reporting_interval {
            bytes.write_with(offset, minimum_reporting_interval, ctx)?;
        };

        if let Some(maximum_reporting_interval) = self.maximum_reporting_interval {
            bytes.write_with(offset, maximum_reporting_interval, ctx)?;
        }

        if let Some(ref reportable_change) = self.reportable_change {
            bytes.write_with(offset, reportable_change, ())?;
        }

        if let Some(timeout_period) = self.timeout_period {
            bytes.write_with(offset, timeout_period, ctx)?;
        }

        Ok(*offset)
    }
}

#[derive(Clone, Copy, Debug, Default, TryRead, TryWrite, PartialEq)]
#[repr(u8)]
pub enum AttributeReportingConfigurationDirection {
    #[default]
    Report = 0x0,
    Receive = 0x1,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ConfigureReportingResponseCommand {
    pub configuration_records: zb_types::Vec<AttributeStatusRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct AttributeStatusRecord {
    pub status: ZclStatus,
    pub direction: AttributeReportingConfigurationDirection,
    pub identifier: u16,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ReadReportingConfigurationCommand {
    pub attributes: zb_types::Vec<ReportingConfigurationAttributeStatus, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ReportingConfigurationAttributeStatus {
    pub direction: AttributeReportingConfigurationDirection,
    pub identifier: u16,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ReadReportingConfigurationResponseCommand {
    pub attributes: zb_types::Vec<AttributeReadReportingConfigurationRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite, Default)]
pub struct AttributeReadReportingConfigurationRecord {
    pub status: ZclStatus,
    pub direction: AttributeReportingConfigurationDirection,
    pub identifier: u16,
    #[byte(parse_if = direction == AttributeReportingConfigurationDirection::Report)]
    pub data_type: Option<u8>,
    #[byte(parse_if = direction == AttributeReportingConfigurationDirection::Report)]
    pub minimum_reporting_interval: Option<u16>,
    #[byte(parse_if = direction == AttributeReportingConfigurationDirection::Report)]
    pub maximum_reporting_interval: Option<u16>,
    #[byte(ctx = (), parse_if = direction == AttributeReportingConfigurationDirection::Report)]
    pub reportable_change: Option<ZclData>, // try_write/read shouldn't include the data_type byte
    #[byte(parse_if = direction == AttributeReportingConfigurationDirection::Receive)]
    pub timeout_period: Option<u16>,
}

#[derive(Default, Clone, Debug, TryRead, TryWrite)]
pub struct ReportAttributesCommand {
    pub attributes: zb_types::Vec<AttributeRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DefaultResponseCommand {
    pub command_identifier: u8,
    pub status_code: ZclStatus,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoverAttributesCommand {
    pub start_attribute_identifier: u16,
    pub maximum_attribute_identifiers: u8,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoverAttributesResponseCommand {
    #[byte(ctx = ())]
    pub discovery_complete: bool,
    pub attributes: zb_types::Vec<DiscoverAttributeRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoverAttributeRecord {
    pub identifier: u16,
    pub data_type: u8,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ReadAttributesStructuredCommand {
    pub attribute_selectors: zb_types::Vec<AttributeSelector, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug)]
pub struct AttributeSelector {
    pub identifier: u16,
    pub indices: zb_types::Vec<u16, 15>,
}

impl<C> TryRead<'_, C> for AttributeSelector {
    fn try_read(bytes: &[u8], _: C) -> byte::Result<(Self, usize)> {
        let identifier = u16::from_le_bytes([bytes[0], bytes[1]]);
        let len = bytes[3] as usize;
        check_len(&bytes[4..], len * 2)?;

        let mut vec = zb_types::Vec::<u16, 15>::new();

        for i in 0..len {
            let item = u16::from_le_bytes([bytes[4 + 2 * i], bytes[5 + 2 * i]]);
            vec.push(item).ok();
        }

        Ok((
            Self {
                identifier,
                indices: vec,
            },
            len * 2 + 1,
        ))
    }
}

impl<C> TryWrite<C> for &AttributeSelector {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        let mut offset = 0;
        bytes.write_with(&mut offset, self.identifier, Endian::Little)?;
        bytes.write_with(&mut offset, self.indices.len() as u8, Endian::Little)?;

        let len = self.indices.len();

        for item in &self.indices {
            bytes.write_with(&mut offset, *item, Endian::Little)?;
        }

        Ok(len * 2 + 1)
    }
}

impl<C> TryWrite<C> for &mut AttributeSelector {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        <&AttributeSelector>::try_write(self, bytes, ())
    }
}

impl<C> TryWrite<C> for AttributeSelector {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        <&AttributeSelector>::try_write(&self, bytes, ())
    }
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributesStructuredCommand {
    pub attributes: zb_types::Vec<WriteAttributeRecord, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributeRecord {
    pub selector: AttributeSelector,
    #[byte(ctx = ())]
    pub data: ZclData,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributesStructuredResponseCommand {
    pub attributes: zb_types::Vec<WriteAttributeStructuredStatus, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct WriteAttributeStructuredStatus {
    pub status: ZclStatus,
    pub selector: AttributeSelector,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoverCommandsReceivedCommand {
    pub start_command_identifier: u8,
    pub maximum_command_identifiers: u8,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoverCommandsReceivedResponseCommand {
    #[byte(ctx = ())]
    pub discovery_complete: bool,
    pub identifiers: zb_types::Vec<u8, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct DiscoverAttributesExtendedResponseCommand {
    #[byte(ctx = ())]
    pub discovery_complete: bool,
    pub attributes: zb_types::Vec<ExtendedAttributeInformation, MAX_COMMAND_ITEMS>,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct ExtendedAttributeInformation {
    pub identifier: u16,
    pub data_type: u8,
    pub access_control: u8,
}
