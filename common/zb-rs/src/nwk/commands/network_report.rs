use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::{BitStruct, try_write_impl};
use zb_types::Vec;
use zb_types::common::{ExtendedAddress, PanId};
use zb_types::common::NwkAddress;
use crate::nwk::commands::Command;
use crate::nwk::constants::NWK_COORDINATOR_ADDRESS;
use crate::nwk::ctx::{InitializedNwk, InitializedState, Nwk};
use crate::nwk::frame::{CommandFrame, NwkFrame};
use crate::nwk::frame::header::NwkHeader;
use crate::nwk::nlde::TransferResult;

#[derive(BitStruct, Debug, Clone, Copy)]
#[bit_struct(repr = u8)]
pub struct NetworkReportOptions {
    #[bit_struct(len = 5)]
    pub count: u8,
    #[bit_struct(len = 3)]
    pub command_identifier: ReportCommandIdentifier
}

#[derive(Debug, Clone, Copy, TryRead, TryWrite)]
#[repr(u8)]
pub enum ReportCommandIdentifier {
    PanIdentifierConflict = 0x0,
}

#[derive(Debug, Clone, TryRead, TryWrite)]
#[byte(no_tag = true)]
#[repr(u8)]
pub enum NetworkReportInformation {
    PanIdentifierConflict(Vec<PanId, 16>) = 0x0,
}

#[derive(Debug, Clone, TryWrite)]
pub struct NetworkReport {
    pub options: NetworkReportOptions,
    pub extended_pan_id: ExtendedAddress,
    pub report_information: NetworkReportInformation,
}

impl TryRead<'_, Endian> for NetworkReport {
    fn try_read(bytes: &'_ [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        let options: NetworkReportOptions = bytes.read_with(offset, ctx)?;
        let extended_pan_id = bytes.read_with(offset, ctx)?;
        let report_information = bytes.read_with(offset, options.command_identifier as u8)?;

        Ok((
            Self {
                options,
                extended_pan_id,
                report_information,
            },
            *offset,
        ))
    }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub async fn send_nwk_report_cmd(&mut self, pan_ids: Vec<PanId, 16>) -> TransferResult {
        //let destination_ieee = self.find_ext_addr()

        let frame = NwkFrame::NwkCommand(CommandFrame {
            header: NwkHeader::cmd(self)
                .destination(NWK_COORDINATOR_ADDRESS)
                .call(),
            command: Command::NetworkReport(NetworkReport {
                options: NetworkReportOptions {
                    count: pan_ids.len() as u8,
                    command_identifier: ReportCommandIdentifier::PanIdentifierConflict,
                },
                extended_pan_id: self.get_ext_pan_id(),
                report_information: NetworkReportInformation::PanIdentifierConflict(pan_ids),
            })
        });

        self.transmit_frame(&frame, NWK_COORDINATOR_ADDRESS, true).await
    }
}
