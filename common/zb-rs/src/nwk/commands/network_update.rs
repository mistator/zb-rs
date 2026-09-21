use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Timer;
use zb_hal::{NwkMac, StorageRegion};
use zb_types::common::{ExtendedAddress, PanId};
use zb_types::Vec;
use crate::nwk::commands::network_report::{NetworkReportOptions, ReportCommandIdentifier};
use crate::nwk::commands::network_status::NetworkStatus;
use crate::nwk::ctx::{InitializedNwk, InitializedState, Nwk};
use crate::nwk::nlde::NwkIndication;
use crate::nwk::nlme::NlmeNetworkDiscoveryConfirm;
use crate::nwk::service::routing::ReceivedCommandFrame;

#[derive(Debug, Clone, Copy, TryRead, TryWrite)]
#[repr(u8)]
pub enum UpdateCommandIdentifier {
    PanIdentifierUpdate = 0x0,
}

#[derive(Debug, Clone, TryRead, TryWrite)]
#[byte(no_tag = true)]
#[repr(u8)]
pub enum UpdateInformation {
    PanIdentifierUpdate(PanId) = 0x0,
}

#[derive(Debug, Clone, TryWrite)]
pub struct NetworkUpdate {
    pub options: NetworkReportOptions,
    pub ext_pan_id: ExtendedAddress,
    pub update_id: u8,
    pub update_information: UpdateInformation,
}

impl TryRead<'_, Endian> for NetworkUpdate {
    fn try_read(bytes: &'_ [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;

        let options: NetworkReportOptions = bytes.read_with(offset, ctx)?;
        let ext_pan_id = bytes.read_with(offset, ctx)?;
        let update_id = bytes.read_with(offset, ctx)?;
        let update_information = bytes.read_with(offset, options.command_identifier as u8)?;

        Ok((Self {
            options,
            ext_pan_id,
            update_id,
            update_information,
        }, *offset))
    }
}

impl<T: InitializedState, D: NwkMac, S: StorageRegion> Nwk<T, D, S> {
    pub async fn handle_network_update_cmd(&mut self, frame: &ReceivedCommandFrame<'_, NetworkUpdate>) -> Option<NwkIndication> {
        match frame.cmd.update_information {
            UpdateInformation::PanIdentifierUpdate(pan_id) => {
                self.get_ctx_mut().update_id = frame.cmd.update_id;
                Timer::after(self.get_nwk_broadcast_delivery_time()).await;

                self.mac.set_pan_id(pan_id.into());

                Some(NwkIndication::Status(NetworkStatus::PanIdentifierUpdate))
            }
        }
    }
}
