use alloc::vec::Vec;
use byte::{check_len, BytesExt, Error, TryRead, TryWrite};
use byte::ctx::Endian;
use zigbee_macros::{bit_struct};
use zb_types::common::{ByteArray, IeeeExtendedAddress};

pub struct TLVVec<'a>(Vec<TLVs<'a>>);

impl<'a> TryRead<'a, Endian> for TLVVec<'a> {
    fn try_read(bytes: &'a [u8], _: Endian) -> byte::Result<(Self, usize)> {
        Self::try_read(&bytes, false)
    }
}

impl<'a> TryRead<'a, bool> for TLVVec<'a> {
    fn try_read(bytes: &'a [u8], only_simple: bool) -> byte::Result<(Self, usize)> {
        let mut vec = Vec::<TLVs<'a>>::new();
        let mut seen_ids = HashSet::<u8>::new();

        let mut idx = 0;
        while bytes[idx..].len() > 0 {
            let tag = bytes[idx];
            if tag != 64 && seen_ids.contains(&tag) {
                return Err(Error::BadInput {err: "duplicate TLV tag"});
            }
            seen_ids.insert(tag);

            let (value, len) = TLVs::try_read(&bytes[idx..], only_simple)?;
            if value.is_some() {
                vec.push(value.unwrap());
            }

            idx += len;
        }

        Ok((Self(vec), idx))
    }
}

impl<'a, C> TryWrite<C> for TLVVec<'a> {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        let mut offset = 0;
        for item in self.0 {
            bytes.write_with(&mut offset, item, Endian::Little)?;
        }

        Ok(offset)
    }
}

macro_rules! read_variant {
    ($variant: expr, $obj: expr, $bytes: expr) => {
        {
            let (value, read) = $obj::try_read(&$bytes[2..], Endian::Little)?;
            ($variant(value), read)
        }
    };
}

#[repr(u8)]
pub enum TLVs<'a> {
    ManufacturerSpecific(ManufacturerSpecificGlobalTLV<'a>) = 64,
    SupportedKeyNegotiationMethods(SupportedKeyNegotiationMethodsGlobalTLV) = 65,
    PanIdConflictReport(PanIdConflictReportGlobalTLV) = 66,
    NextPanId(NextPanIdGlobalTLV) = 67,
    NextChannelChange(NextChannelChangeGlobalTLV) = 68,
    SymmetricPassphrase(SymmetricPassphraseGlobalTLV) = 69,
    RouterInformation(RouterInformationGlobalTLV) = 70,
    FragmentationParameters(FragmentationParametersGlobalTLV) = 71,
    JoinerEncapsulation(TLVVec<'a>) = 72,
    BeaconAppendixEncapsulation(TLVVec<'a>) = 73,
    ConfigurationParameters(ConfigurationParametersGlobalTLV) = 75,
    //DeviceCapabilityExtension(DeviceCapabilityExtensionGlobalTLV) = 76
}

impl<'a> TLVs<'a> {
    fn try_read(bytes: &'a [u8], only_simple: bool) -> byte::Result<(Option<Self>, usize)> {
        check_len(bytes, 2)?;
        let (tag, len) = (bytes[0], bytes[1] + 1);
        check_len(&bytes[2..], len as usize)?;

        let (result, read) = match tag {
            64 => read_variant!(TLVs::ManufacturerSpecific, ManufacturerSpecificGlobalTLV, bytes),
            65 => read_variant!(TLVs::SupportedKeyNegotiationMethods, SupportedKeyNegotiationMethodsGlobalTLV, bytes),
            66 => read_variant!(TLVs::PanIdConflictReport, PanIdConflictReportGlobalTLV, bytes),
            67 => read_variant!(TLVs::NextPanId, NextPanIdGlobalTLV, bytes),
            68 => read_variant!(TLVs::NextChannelChange, NextChannelChangeGlobalTLV, bytes),
            69 => read_variant!(TLVs::SymmetricPassphrase, SymmetricPassphraseGlobalTLV, bytes),
            70 => read_variant!(TLVs::RouterInformation, RouterInformationGlobalTLV, bytes),
            71 => read_variant!(TLVs::FragmentationParameters, FragmentationParametersGlobalTLV, bytes),
            72 => {
                if only_simple {
                    return Err(Error::BadInput {err: "found encapsulated TLVs in encapsulated TLV"})
                }

                let (result, len) = TLVVec::try_read(&bytes[2..], true)?;
                (TLVs::JoinerEncapsulation(result), len)
            },
            73 => {
                if only_simple {
                    return Err(Error::BadInput {err: "found encapsulated TLVs in encapsulated TLV"})
                }

                let (result, len) = TLVVec::try_read(&bytes[2..], true)?;
                (TLVs::BeaconAppendixEncapsulation(result), len)
            }
            75 => read_variant!(TLVs::ConfigurationParameters, ConfigurationParametersGlobalTLV, bytes),
            _ => return Ok((None, (len + 2) as usize))
        };

        Ok((Some(result), read + 2))
    }

    pub(crate) fn discriminant(&self) -> u8 {
        unsafe { *<*const _>::from(self).cast::<u8>() }
    }
}

impl<'a, C> TryWrite<C> for TLVs<'a> {
    fn try_write(self, bytes: &mut [u8], _: C) -> byte::Result<usize> {
        let mut offset = 0;

        bytes.write_with(&mut offset, self.discriminant(), Endian::Little)?;
        bytes.write_with(&mut offset, 0, Endian::Little)?;

        match self {
            TLVs::ManufacturerSpecific(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::SupportedKeyNegotiationMethods(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::PanIdConflictReport(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::NextPanId(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::NextChannelChange(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::SymmetricPassphrase(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::RouterInformation(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::FragmentationParameters(value) => bytes.write_with(&mut offset, value, Endian::Little)?,
            TLVs::JoinerEncapsulation(value) => bytes.write_with(&mut offset, value, ())?,
            TLVs::BeaconAppendixEncapsulation(value) => bytes.write_with(&mut offset, value, ())?,
            TLVs::ConfigurationParameters(value) =>bytes.write_with(&mut offset, value, Endian::Little)?,
        };

        bytes[1] = offset as u8 - 3;

        Ok(offset)
    }
}



#[derive(TryRead, TryWrite)]
pub struct ManufacturerSpecificGlobalTLV<'a> {
    pub manufacturer_id: u16,
    #[byte(ctx = ())]
    pub additional_data: &'a [u8]
}


#[derive(TryRead, TryWrite)]
pub struct SupportedKeyNegotiationMethodsGlobalTLV {
    pub key_negotiation_protocols: KeyNegotiationProtocols,
    pub preshared_secrets: PresharedSecrets,
    pub source_ieee_address: IeeeExtendedAddress
}

bit_struct! {
    #[repr(u8)]
    pub struct KeyNegotiationProtocols {
        pub static_request_key: bool,
        pub speke_curve25519_aes_mmo_128: bool,
        pub speke_curve25519_sha_256: bool,
    }
}

bit_struct! {
    #[repr(u8)]
    pub struct PresharedSecrets {
        pub symmetric_authentication_token: bool,
        pub install_code_key: bool,
        pub passcode_key: bool,
        pub basic_access_key: bool,
        pub administrative_access_key: bool,
    }
}


#[derive(TryRead, TryWrite)]
pub struct PanIdConflictReportGlobalTLV {
    pub conflict_count: u16,
}

#[derive(TryRead, TryWrite)]
pub struct NextPanIdGlobalTLV {
    pub next_channel: u16,
}

#[derive(TryRead, TryWrite)]
pub struct NextChannelChangeGlobalTLV {
    pub a: u8
}

#[derive(TryRead, TryWrite)]
pub struct SymmetricPassphraseGlobalTLV {
    pub key: ByteArray<16>,
}

bit_struct! {
    #[repr(u16)]
    pub struct RouterInformationGlobalTLV {
        pub hub_connectivity: bool,
        pub uptime: bool,
        pub preferred_parent: bool,
        pub battery_backup: bool,
        pub enhanced_beacon_request_support: bool,
        pub mac_data_poll_keepalive_support: bool,
        pub end_device_keepalive_support: bool,
        pub power_negotiation_support: bool,
    }
}


#[derive(TryRead, TryWrite)]
pub struct FragmentationParametersGlobalTLV {
    pub node_id: u16,
    pub fragmentation_options: FragmentationOptions,
    pub maximum_incoming_transfer_unit: u16,
}

bit_struct! {
    #[repr(u8)]
    pub struct FragmentationOptions {
        pub aps_fragmentation_supported: bool,
    }
}

bit_struct! {
    #[repr(u16)]
    pub struct ConfigurationParametersGlobalTLV {
        pub zdo_restricted_mode: bool,
        pub require_link_key_encryption_for_aps_transport_key: bool,
        pub nwk_leave_request_allowed: bool,
    }
}
