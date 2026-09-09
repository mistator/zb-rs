use crate::apl::aps::security::types::commands::ConfirmKeyStatus;
use crate::apl::aps::security::types::commands::UpdateDeviceStatus;
use crate::apl::aps::security::types::common::StandardKeyType;
use crate::apl::aps::security::types::common::TransportKeyData;
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;

#[derive(Clone, Copy, Debug)]
pub struct ApsmeTransportKeyIndication {
    pub ext_src_addr: ExtendedAddress,
    pub transport_key: TransportKeyData,
}

#[derive(Clone, Copy, Debug)]
pub struct ApsmeUpdateDeviceIndication {
    pub src_address: ExtendedAddress,
    pub device_address: ExtendedAddress,
    pub device_short_address: NwkAddress,
    pub status: UpdateDeviceStatus,
}

#[derive(Clone, Copy, Debug)]
pub struct ApsmeConfirmKeyIndication {
    pub status: ConfirmKeyStatus,
    pub src_address: ExtendedAddress,
    pub key_type: StandardKeyType,
}
