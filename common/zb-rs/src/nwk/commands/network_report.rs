use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_macros::{BitStruct, try_write_impl};
use zb_types::Vec;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(Debug, Clone)]
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

        match options.command_identifier {
            ReportCommandIdentifier::PanIdentifierConflict => {
                let mut vec = Vec::<NwkAddress, 16>::new();
                for _ in 0..options.count {
                    let item = bytes.read_with(offset, byte::LE)?;
                    vec.push(item).unwrap();
                }
                Ok((
                    Self {
                        options,
                        extended_pan_id,
                        report_information: NetworkReportInformation::PanIdentifierConflict(vec),
                    },
                    *offset,
                ))
            }
        }
    }
}

#[try_write_impl]
impl TryWrite<Endian> for &NetworkReport {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write_with(offset, self.options, ctx)?;
        bytes.write_with(offset, self.extended_pan_id, ctx)?;

        match self.report_information {
            NetworkReportInformation::PanIdentifierConflict(ref vec) => {
                for item in vec {
                    bytes.write_with(offset, item, ctx)?;
                }
            }
        }

        Ok(*offset)
    }
}

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

#[derive(Debug, Clone)]
pub enum NetworkReportInformation {
    PanIdentifierConflict(zb_types::Vec<NwkAddress, 16>),
}
