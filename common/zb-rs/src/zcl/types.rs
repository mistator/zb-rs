use alloc::string::String;
use alloc::vec::Vec;

use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::ctx::Endian;
use byte_derive::TryRead;
use byte_derive::TryWrite;

use zb_types::common::ExtendedAddress;

#[derive(Clone, Copy, Debug, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum ZclStatus {
    Success = 0x00,
    Failure = 0x01,
    NotAuthorized = 0x7e,
    ReservedFieldNotZero = 0x7f,
    MalformedCommand = 0x80,
    UnsupClusterCommand = 0x81,
    UnsupGeneralCommand = 0x82,
    UnsupManufClusterCommand = 0x83,
    UnsupManufGeneralCommand = 0x84,
    InvalidField = 0x85,
    UnsupportedAttribute = 0x86,
    InvalidValue = 0x87,
    ReadOnly = 0x88,
    InsufficientSpace = 0x89,
    DuplicateExists = 0x8a,
    NotFound = 0x8b,
    UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d,
    InvalidSelector = 0x8e,
    WriteOnly = 0x8f,
    InconsistentStartupState = 0x90,
    DefinedOutOfBand = 0x91,
    Inconsistent = 0x92,
    ActionDenied = 0x93,
    Timeout = 0x94,
    Abort = 0x95,
    InvalidImage = 0x96,
    WaitForData = 0x97,
    NoImageAvailable = 0x98,
    RequireMoreImage = 0x99,
    NotificationPending = 0x9a,
    HardwareFailure = 0xc0,
    SoftwareFailure = 0xc1,
    CalibrationError = 0xc2,
    UnsupportedCluster = 0xc3,
}

impl Default for ZclStatus {
    fn default() -> Self { ZclStatus::Success }
}

#[repr(u8)]
#[derive(Clone, Debug, Default, PartialEq)]
pub enum ZclData {
    #[default]
    Null = 0x00,
    Data8(u8) = 0x08,
    Data16(u16) = 0x09,
    Data24(u32) = 0x0a,
    Data32(u32) = 0x0b,
    Data40(u64) = 0x0c,
    Data48(u64) = 0x0d,
    Data56(u64) = 0x0e,
    Data64(u64) = 0x0f,
    Bool(bool) = 0x10,
    Bitmap8(u8) = 0x18,
    Bitmap16(u16) = 0x19,
    Bitmap24(u32) = 0x1a,
    Bitmap32(u32) = 0x1b,
    Bitmap40(u64) = 0x1c,
    Bitmap48(u64) = 0x1d,
    Bitmap56(u64) = 0x1e,
    Bitmap64(u64) = 0x1f,
    UInt8(u8) = 0x20,
    UInt16(u16) = 0x21,
    UInt24(u32) = 0x22,
    UInt32(u32) = 0x23,
    UInt40(u64) = 0x24,
    UInt48(u64) = 0x25,
    UInt56(u64) = 0x26,
    UInt64(u64) = 0x27,
    Int8(i8) = 0x28,
    Int16(i16) = 0x29,
    Int24(i32) = 0x2a,
    Int32(i32) = 0x2b,
    Int40(i64) = 0x2c,
    Int48(i64) = 0x2d,
    Int56(i64) = 0x2e,
    Int64(i64) = 0x2f,
    Enum8(u8) = 0x30,
    Enum16(u16) = 0x31,
    Float16(f32) = 0x38,
    Float(f32) = 0x39,
    Double(f64) = 0x3a,
    OctetString(Vec<u8>) = 0x41,
    String(String) = 0x42,
    LongOctetString(Vec<u8>) = 0x43,
    LongString(String) = 0x44,
    Array(u16, Vec<ZclData>) = 0x48,
    Structure(u16, Vec<ZclData>) = 0x4c,
    Set(u16, Vec<ZclData>) = 0x50,
    Bag(u16, Vec<ZclData>) = 0x51,
    Time(ZclTime) = 0xe0,
    Date(ZclDate) = 0xe1,
    Timestamp(u32) = 0xe2,
    ClusterId(u16) = 0xe8,
    AttributeId(u16) = 0xe9,
    BacNetOid(u16) = 0xea,
    IeeeAddress(ExtendedAddress) = 0xf0,
    SecurityKey([u8; 16]) = 0xf1,
}

impl ZclData {
    fn discriminant(&self) -> u8 { unsafe { *<*const _>::from(self).cast::<u8>() } }
}

impl<'a> TryRead<'a> for ZclData {
    fn try_read(bytes: &'a [u8], _: ()) -> byte::Result<(Self, usize)> { Self::try_read(bytes, 0) }
}

impl<'a> TryWrite for &ZclData {
    fn try_write(self, bytes: &mut [u8], _: ()) -> byte::Result<usize> {
        <&ZclData>::try_write(self, bytes, 0)
    }
}

impl<'a> TryWrite for &mut ZclData {
    fn try_write(self, bytes: &mut [u8], _: ()) -> byte::Result<usize> {
        <&ZclData>::try_write(self, bytes, 0)
    }
}

impl<'a> TryWrite for ZclData {
    fn try_write(self, bytes: &mut [u8], _: ()) -> byte::Result<usize> {
        <&ZclData>::try_write(&self, bytes, 0)
    }
}

macro_rules! read_zcl_data_bytes {
    ($n_bytes: tt, $ty: ty, $bytes: expr, $zcl_variant: expr) => {{
        byte::check_len(&$bytes, $n_bytes)?;

        let mut dst = [0u8; size_of::<$ty>()];
        dst[..$n_bytes].copy_from_slice(&$bytes[..$n_bytes]);

        let value = <$ty>::from_le_bytes(dst);

        ($zcl_variant(value), $n_bytes)
    }};
}

macro_rules! write_zcl_data_bytes {
    ($n_bytes: tt, $offset: expr, $bytes: expr, $value: expr) => {{
        byte::check_len(&$bytes, $n_bytes)?;
        let le_bytes = $value.to_le_bytes();

        $bytes.write_with(&mut $offset, &le_bytes[..$n_bytes], ())?;
    }};
}

macro_rules! read_zcl_struct {
    ($bytes: expr, $depth: expr, $zcl_variant: expr) => {{
        byte::check_len(&$bytes, 2)?;
        let n_items = u16::from_le_bytes([$bytes[0], $bytes[1]]);

        // if n_items > MAX_ZCL_STRUCT_ITEMS as u16 {
        // return Err(byte::Error::BadInput {
        // err: "MAX_ZCL_STRUCT_ITEMS exceeded"
        // })
        // }

        let mut idx = 2;
        let mut vec = Vec::<ZclData>::new();

        for _ in 0..n_items {
            let (data, len) = ZclData::try_read(&$bytes[idx..], $depth + 1)?;
            vec.push(data);
            idx += len;
        }

        ($zcl_variant(n_items, vec), idx)
    }};
}

impl<'a> TryRead<'a, u8> for ZclData {
    fn try_read(bytes: &'a [u8], depth: u8) -> byte::Result<(Self, usize)> {
        if depth > 15 {
            return Err(byte::Error::BadInput {
                err: "depth limit exceeded",
            });
        }

        let tag = bytes[0];
        let bytes = &bytes[1..];

        let (value, len) = match tag {
            0x00 => (ZclData::Null, 0),
            0x08 => read_zcl_data_bytes!(1, u8, bytes, ZclData::Data8),
            0x09 => read_zcl_data_bytes!(2, u16, bytes, ZclData::Data16),
            0x0a => read_zcl_data_bytes!(3, u32, bytes, ZclData::Data24),
            0x0b => read_zcl_data_bytes!(4, u32, bytes, ZclData::Data32),
            0x0c => read_zcl_data_bytes!(5, u64, bytes, ZclData::Data40),
            0x0d => read_zcl_data_bytes!(6, u64, bytes, ZclData::Data48),
            0x0e => read_zcl_data_bytes!(7, u64, bytes, ZclData::Data56),
            0x0f => read_zcl_data_bytes!(8, u64, bytes, ZclData::Data64),
            0x10 => (ZclData::Bool(bool::try_read(&bytes, ())?.0), 1),
            0x18 => read_zcl_data_bytes!(1, u8, bytes, ZclData::Bitmap8),
            0x19 => read_zcl_data_bytes!(2, u16, bytes, ZclData::Bitmap16),
            0x1a => read_zcl_data_bytes!(3, u32, bytes, ZclData::Bitmap24),
            0x1b => read_zcl_data_bytes!(4, u32, bytes, ZclData::Bitmap32),
            0x1c => read_zcl_data_bytes!(5, u64, bytes, ZclData::Bitmap40),
            0x1d => read_zcl_data_bytes!(6, u64, bytes, ZclData::Bitmap48),
            0x1e => read_zcl_data_bytes!(7, u64, bytes, ZclData::Bitmap56),
            0x1f => read_zcl_data_bytes!(8, u64, bytes, ZclData::Bitmap64),
            0x20 => read_zcl_data_bytes!(1, u8, bytes, ZclData::UInt8),
            0x21 => read_zcl_data_bytes!(2, u16, bytes, ZclData::UInt16),
            0x22 => read_zcl_data_bytes!(3, u32, bytes, ZclData::UInt24),
            0x23 => read_zcl_data_bytes!(4, u32, bytes, ZclData::UInt32),
            0x24 => read_zcl_data_bytes!(5, u64, bytes, ZclData::UInt40),
            0x25 => read_zcl_data_bytes!(6, u64, bytes, ZclData::UInt48),
            0x26 => read_zcl_data_bytes!(7, u64, bytes, ZclData::UInt56),
            0x27 => read_zcl_data_bytes!(8, u64, bytes, ZclData::UInt64),
            0x28 => read_zcl_data_bytes!(1, i8, bytes, ZclData::Int8),
            0x29 => read_zcl_data_bytes!(2, i16, bytes, ZclData::Int16),
            0x2a => read_zcl_data_bytes!(3, i32, bytes, ZclData::Int24),
            0x2b => read_zcl_data_bytes!(4, i32, bytes, ZclData::Int32),
            0x2c => read_zcl_data_bytes!(5, i64, bytes, ZclData::Int40),
            0x2d => read_zcl_data_bytes!(6, i64, bytes, ZclData::Int48),
            0x2e => read_zcl_data_bytes!(7, i64, bytes, ZclData::Int56),
            0x2f => read_zcl_data_bytes!(8, i64, bytes, ZclData::Int64),
            0x30 => read_zcl_data_bytes!(1, u8, bytes, ZclData::Enum8),
            0x31 => read_zcl_data_bytes!(2, u16, bytes, ZclData::Enum16),
            0x38 => read_zcl_data_bytes!(2, f32, bytes, ZclData::Float16),
            0x39 => read_zcl_data_bytes!(4, f32, bytes, ZclData::Float),
            0x3a => read_zcl_data_bytes!(8, f64, bytes, ZclData::Double),
            0x41 => {
                let len = bytes[0] as usize;
                byte::check_len(&bytes[1..], len)?;
                (ZclData::OctetString(Vec::from(&bytes[1..len + 1])), len + 1)
            }
            0x42 => {
                let len = bytes[0] as usize;
                byte::check_len(&bytes[1..], len)?;

                let value =
                    str::from_utf8(&bytes[1..len + 1]).map_err(|_| byte::Error::BadInput {
                        err: "invalid utf8 format",
                    })?;

                (ZclData::String(String::from(value)), len + 1)
            }
            0x43 => {
                let len = get_u16_len(&bytes)? as usize;
                byte::check_len(&bytes[2..], len)?;

                (
                    ZclData::LongOctetString(Vec::from(&bytes[2..len + 2])),
                    len + 2,
                )
            }
            0x44 => {
                let len = get_u16_len(&bytes)? as usize;
                byte::check_len(&bytes[2..], len)?;

                let value =
                    str::from_utf8(&bytes[2..len + 2]).map_err(|_| byte::Error::BadInput {
                        err: "invalid utf8 format",
                    })?;

                (ZclData::String(String::from(value)), len + 2)
            }
            0x48 => read_zcl_struct!(bytes, depth, ZclData::Array),
            0x4c => read_zcl_struct!(bytes, depth, ZclData::Structure),
            0x50 => read_zcl_struct!(bytes, depth, ZclData::Set),
            0x51 => read_zcl_struct!(bytes, depth, ZclData::Bag),
            0xe0 => (ZclData::Time(ZclTime::try_read(&bytes, ())?.0), 4),
            0xe1 => (ZclData::Date(ZclDate::try_read(&bytes, ())?.0), 4),
            0xe2 => read_zcl_data_bytes!(4, u32, bytes, ZclData::Timestamp),
            0xe8 => read_zcl_data_bytes!(2, u16, bytes, ZclData::ClusterId),
            0xe9 => read_zcl_data_bytes!(2, u16, bytes, ZclData::AttributeId),
            0xea => read_zcl_data_bytes!(2, u16, bytes, ZclData::BacNetOid),
            0xf0 => (
                ZclData::IeeeAddress(ExtendedAddress::try_read(&bytes, byte::LE)?.0),
                4,
            ),
            0xf1 => {
                byte::check_len(&bytes, 16)?;
                let mut key = [0u8; 16];
                key.clone_from_slice(&bytes[0..16]);

                (ZclData::SecurityKey(key), 16)
            }
            _ => {
                return Err(byte::Error::BadInput {
                    err: "invalid data type",
                });
            }
        };

        Ok((value, len + 1))
    }
}

impl<'a> TryWrite<u8> for &ZclData {
    fn try_write(self, bytes: &mut [u8], depth: u8) -> byte::Result<usize> {
        self.discriminant();

        if depth > 15 {
            return Err(byte::Error::BadInput {
                err: "depth limit exceeded",
            });
        }

        let mut offset = 0;
        bytes.write_with(&mut offset, self.discriminant(), Endian::Little)?;

        match self {
            ZclData::Null => {}
            ZclData::Data8(value) => write_zcl_data_bytes!(1, offset, bytes, value),
            ZclData::Data16(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::Data24(value) => write_zcl_data_bytes!(3, offset, bytes, value),
            ZclData::Data32(value) => write_zcl_data_bytes!(4, offset, bytes, value),
            ZclData::Data40(value) => write_zcl_data_bytes!(5, offset, bytes, value),
            ZclData::Data48(value) => write_zcl_data_bytes!(6, offset, bytes, value),
            ZclData::Data56(value) => write_zcl_data_bytes!(7, offset, bytes, value),
            ZclData::Data64(value) => write_zcl_data_bytes!(8, offset, bytes, value),
            ZclData::Bool(value) => write_zcl_data_bytes!(1, offset, bytes, *value as u8),
            ZclData::Bitmap8(value) => write_zcl_data_bytes!(1, offset, bytes, value),
            ZclData::Bitmap16(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::Bitmap24(value) => write_zcl_data_bytes!(3, offset, bytes, value),
            ZclData::Bitmap32(value) => write_zcl_data_bytes!(4, offset, bytes, value),
            ZclData::Bitmap40(value) => write_zcl_data_bytes!(5, offset, bytes, value),
            ZclData::Bitmap48(value) => write_zcl_data_bytes!(6, offset, bytes, value),
            ZclData::Bitmap56(value) => write_zcl_data_bytes!(7, offset, bytes, value),
            ZclData::Bitmap64(value) => write_zcl_data_bytes!(8, offset, bytes, value),
            ZclData::UInt8(value) => write_zcl_data_bytes!(1, offset, bytes, value),
            ZclData::UInt16(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::UInt24(value) => write_zcl_data_bytes!(3, offset, bytes, value),
            ZclData::UInt32(value) => write_zcl_data_bytes!(4, offset, bytes, value),
            ZclData::UInt40(value) => write_zcl_data_bytes!(5, offset, bytes, value),
            ZclData::UInt48(value) => write_zcl_data_bytes!(6, offset, bytes, value),
            ZclData::UInt56(value) => write_zcl_data_bytes!(7, offset, bytes, value),
            ZclData::UInt64(value) => write_zcl_data_bytes!(8, offset, bytes, value),
            ZclData::Int8(value) => write_zcl_data_bytes!(1, offset, bytes, value),
            ZclData::Int16(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::Int24(value) => write_zcl_data_bytes!(3, offset, bytes, value),
            ZclData::Int32(value) => write_zcl_data_bytes!(4, offset, bytes, value),
            ZclData::Int40(value) => write_zcl_data_bytes!(5, offset, bytes, value),
            ZclData::Int48(value) => write_zcl_data_bytes!(6, offset, bytes, value),
            ZclData::Int56(value) => write_zcl_data_bytes!(7, offset, bytes, value),
            ZclData::Int64(value) => write_zcl_data_bytes!(8, offset, bytes, value),
            ZclData::Enum8(value) => write_zcl_data_bytes!(1, offset, bytes, value),
            ZclData::Enum16(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::Float16(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::Float(value) => write_zcl_data_bytes!(4, offset, bytes, value),
            ZclData::Double(value) => write_zcl_data_bytes!(8, offset, bytes, value),
            ZclData::OctetString(value) => {
                bytes.write_with(&mut offset, value.len() as u8, Endian::Little)?;
                bytes.write_with(&mut offset, value.as_slice(), ())?;
            }
            ZclData::String(value) => {
                bytes.write_with(&mut offset, value.len() as u8, Endian::Little)?;
                bytes.write_with(&mut offset, value.as_str(), ())?;
            }
            ZclData::LongOctetString(value) => {
                bytes.write_with(&mut offset, value.len() as u16, Endian::Little)?;
                bytes.write_with(&mut offset, value.as_slice(), ())?;
            }
            ZclData::LongString(value) => {
                bytes.write_with(&mut offset, value.len() as u16, Endian::Little)?;
                bytes.write_with(&mut offset, value.as_str(), ())?;
            }
            ZclData::Array(_, value) => {
                bytes.write_with(&mut offset, value.len() as u16, Endian::Little)?;
                for item in value {
                    bytes.write_with(&mut offset, item, depth + 1)?;
                }
            }
            ZclData::Structure(_, value) => {
                bytes.write_with(&mut offset, value.len() as u16, Endian::Little)?;
                for item in value {
                    bytes.write_with(&mut offset, item, depth + 1)?;
                }
            }
            ZclData::Set(_, value) => {
                bytes.write_with(&mut offset, value.len() as u16, Endian::Little)?;
                for item in value {
                    bytes.write_with(&mut offset, item, depth + 1)?;
                }
            }
            ZclData::Bag(_, value) => {
                bytes.write_with(&mut offset, value.len() as u16, Endian::Little)?;
                for item in value {
                    bytes.write_with(&mut offset, item, depth + 1)?;
                }
            }
            ZclData::Time(value) => bytes.write_with(&mut offset, value, ())?,
            ZclData::Date(value) => bytes.write_with(&mut offset, value, ())?,
            ZclData::Timestamp(value) => write_zcl_data_bytes!(4, offset, bytes, value),
            ZclData::ClusterId(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::AttributeId(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::BacNetOid(value) => write_zcl_data_bytes!(2, offset, bytes, value),
            ZclData::IeeeAddress(value) => bytes.write_with(&mut offset, value, byte::LE)?,
            ZclData::SecurityKey(value) => bytes.write_with(&mut offset, value.as_slice(), ())?,
        }

        Ok(offset)
    }
}

impl<'a> TryWrite<u8> for &mut ZclData {
    fn try_write(self, bytes: &mut [u8], ctx: u8) -> byte::Result<usize> {
        <&ZclData>::try_write(self, bytes, ctx)
    }
}

impl<'a> TryWrite<u8> for ZclData {
    fn try_write(self, bytes: &mut [u8], ctx: u8) -> byte::Result<usize> {
        <&ZclData>::try_write(&self, bytes, ctx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ZclTime {
    pub hour: Option<u8>,
    pub minute: Option<u8>,
    pub second: Option<u8>,
    pub hundredth: Option<u8>,
}

impl TryRead<'_> for ZclTime {
    fn try_read(bytes: &[u8], _: ()) -> byte::Result<(Self, usize)> {
        byte::check_len(&bytes, 4)?;
        let (hours, minutes, seconds, hundredths) = (bytes[0], bytes[1], bytes[2], bytes[3]);

        if (hours > 24 && hours != 0xff)
            || (minutes > 60 && minutes != 0xff)
            || (seconds > 60 && seconds != 0xff)
            || (hundredths > 100 && hundredths != 0xff)
        {
            return Err(byte::Error::BadInput {
                err: "invalid range received for `ZclTime` value",
            });
        }

        let value = Self {
            hour: if hours != 0xff { Some(hours) } else { None },
            minute: if minutes != 0xff { Some(minutes) } else { None },
            second: if seconds != 0xff { Some(seconds) } else { None },
            hundredth: if hundredths != 0xff {
                Some(hundredths)
            } else {
                None
            },
        };

        Ok((value, 4))
    }
}

impl TryWrite for &ZclTime {
    fn try_write(self, bytes: &mut [u8], _: ()) -> byte::Result<usize> {
        let mut offset = 0;

        bytes.write_with(
            &mut offset,
            [
                if self.hour.is_none() {
                    0xff
                } else {
                    self.hour.unwrap()
                },
                if self.minute.is_none() {
                    0xff
                } else {
                    self.minute.unwrap()
                },
                if self.second.is_none() {
                    0xff
                } else {
                    self.second.unwrap()
                },
                if self.hundredth.is_none() {
                    0xff
                } else {
                    self.hundredth.unwrap()
                },
            ]
            .as_slice(),
            (),
        )?;

        Ok(offset)
    }
}

impl TryWrite for &mut ZclTime {
    fn try_write(self, bytes: &mut [u8], ctx: ()) -> byte::Result<usize> {
        <&ZclTime>::try_write(self, bytes, ctx)
    }
}

impl TryWrite for ZclTime {
    fn try_write(self, bytes: &mut [u8], ctx: ()) -> byte::Result<usize> {
        <&ZclTime>::try_write(&self, bytes, ctx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ZclDate {
    pub year: Option<u8>,
    pub month: Option<u8>,
    pub day: Option<u8>,
    pub weekday: Option<u8>,
}

impl TryRead<'_> for ZclDate {
    fn try_read(bytes: &[u8], _: ()) -> byte::Result<(Self, usize)> {
        byte::check_len(&bytes, 4)?;
        let (year, month, day, weekday) = (bytes[0], bytes[1], bytes[2], bytes[3]);

        // Year is a value in the range [0, 255] which is summed to 1900, giving a range
        // of years in [1900, 2155]. In this range, every year divisible by 4 is
        // a leap year, except 1900 and 2100, which correspond to 0 and 200.
        let is_leap_year = year % 4 == 0 && (year != 0 && year != 200);

        if (month > 12 && month != 0xff)
            || (day > 31 && day != 0xff)
            || (weekday > 7 && weekday != 0xff)
            || [2u8, 4, 6, 9, 11].contains(&month) && day > 30
            || (year != 0xff && !is_leap_year && month == 2 && day > 29)
        {
            return Err(byte::Error::BadInput {
                err: "invalid range received for `ZclTime` value",
            });
        }

        let value = Self {
            year: if year != 0xff { Some(year) } else { None },
            month: if month != 0xff { Some(month) } else { None },
            day: if day != 0xff { Some(day) } else { None },
            weekday: if weekday != 0xff { Some(weekday) } else { None },
        };

        Ok((value, 4))
    }
}

impl TryWrite for &ZclDate {
    fn try_write(self, bytes: &mut [u8], _: ()) -> byte::Result<usize> {
        let mut offset = 0;

        bytes.write_with(
            &mut offset,
            [
                if self.year.is_none() {
                    0xff
                } else {
                    self.year.unwrap()
                },
                if self.month.is_none() {
                    0xff
                } else {
                    self.month.unwrap()
                },
                if self.day.is_none() {
                    0xff
                } else {
                    self.day.unwrap()
                },
                if self.weekday.is_none() {
                    0xff
                } else {
                    self.weekday.unwrap()
                },
            ]
            .as_slice(),
            (),
        )?;

        Ok(offset)
    }
}

impl TryWrite for &mut ZclDate {
    fn try_write(self, bytes: &mut [u8], ctx: ()) -> byte::Result<usize> {
        <&ZclDate>::try_write(self, bytes, ctx)
    }
}

impl TryWrite for ZclDate {
    fn try_write(self, bytes: &mut [u8], ctx: ()) -> byte::Result<usize> {
        <&ZclDate>::try_write(&self, bytes, ctx)
    }
}


fn get_u16_len(bytes: &[u8]) -> byte::Result<u16> {
    byte::check_len(bytes, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}
