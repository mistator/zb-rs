use core::fmt::Debug;
use core::marker::PhantomData;

use byte::BytesExt;
use byte::TryRead;
use byte::TryWrite;
use byte::check_len;
use byte::ctx::Endian;
use derive_more::Deref;

pub trait Integer: Clone + Debug {
    const SIZE: usize;
    const ZERO: Self;

    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn to_le_bytes(&self, result: &mut [u8]) -> ();
    fn as_usize(&self) -> usize;
    fn from_usize(value: usize) -> Self;
}

impl Integer for u8 {
    const SIZE: usize = 1;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        u8::from_le_bytes([bytes[0]])
    }

    fn to_le_bytes(&self, result: &mut [u8]) -> () {
        result.copy_from_slice(u8::to_le_bytes(*self).as_slice())
    }

    fn as_usize(&self) -> usize {
        *self as usize
    }

    fn from_usize(value: usize) -> Self {
        value as u8
    }
}

impl Integer for u16 {
    const SIZE: usize = 2;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    fn to_le_bytes(&self, result: &mut [u8]) -> () {
        result.copy_from_slice(u16::to_le_bytes(*self).as_slice())
    }

    fn as_usize(&self) -> usize {
        *self as usize
    }

    fn from_usize(value: usize) -> Self {
        value as u16
    }
}

impl Integer for u32 {
    const SIZE: usize = 4;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn to_le_bytes(&self, result: &mut [u8]) -> () {
        result.copy_from_slice(u32::to_le_bytes(*self).as_slice())
    }

    fn as_usize(&self) -> usize {
        *self as usize
    }

    fn from_usize(value: usize) -> Self {
        value as u32
    }
}

impl Integer for u64 {
    const SIZE: usize = 8;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Self {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    fn to_le_bytes(&self, result: &mut [u8]) -> () {
        result.copy_from_slice(u64::to_le_bytes(*self).as_slice())
    }

    fn as_usize(&self) -> usize {
        *self as usize
    }

    fn from_usize(value: usize) -> Self {
        value as u64
    }
}

#[derive(Copy, Clone, Debug, Deref, Default)]
pub struct WithLength<L: Integer, T: Clone>(#[deref] Option<T>, PhantomData<L>);

impl<L: Integer, T: Clone> WithLength<L, T> {
    pub const NONE: WithLength<L, T> = WithLength(None, PhantomData);

    pub fn new(value: T) -> Self {
        Self(Some(value), PhantomData)
    }
}

impl<'a, L: Integer, T: TryRead<'a, Endian> + Clone> TryRead<'a, Endian> for WithLength<L, T> {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        check_len(&bytes, L::SIZE)?;
        let (result, _) = T::try_read(&bytes[L::SIZE..], ctx)?;
        let size = L::from_le_bytes(&bytes).as_usize();

        if size == 0 {
            return Ok((WithLength::<L, T>::NONE, L::SIZE));
        }

        Ok((WithLength::<L, T>::new(result), L::SIZE + size))
    }
}

impl<L: Integer, T: TryWrite<Endian> + Clone> TryWrite<Endian> for &WithLength<L, T> {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        let num_size = size_of::<L>();
        check_len(bytes, num_size)?;

        let mut offset = num_size;
        
        match **self {
            None => {
                L::ZERO.to_le_bytes(&mut bytes[..num_size]);
            }
            Some(ref value) => {
                bytes.write_with(&mut offset, value.clone(), ctx)?;

                let len = L::from_usize(offset - num_size);
                len.to_le_bytes(&mut bytes[..num_size]);
            }
        }

        Ok(offset)
    }
}

impl<L: Integer, T: TryWrite<Endian> + Clone> TryWrite<Endian> for &mut WithLength<L, T> {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        <&WithLength<L, T>>::try_write(self, bytes, ctx)
    }
}

impl<L: Integer, T: TryWrite<Endian> + Clone> TryWrite<Endian> for WithLength<L, T> {
    fn try_write(self, bytes: &mut [u8], ctx: Endian) -> byte::Result<usize> {
        <&WithLength<L, T>>::try_write(&self, bytes, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_empty_with_length() {
        let empty = WithLength::<u8, u16>::default();
        let mut bytes = [0u8; 20];

        let size = empty.try_write(&mut bytes, Endian::Little).unwrap();
        assert_eq!(size, 1);
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn write_with_length() {
        let empty = WithLength::<u8, u16>::new(12);
        let mut bytes = [0u8; 20];

        let size = empty.try_write(&mut bytes, Endian::Little).unwrap();
        assert_eq!(size, 3);
        assert_eq!(bytes[1..size], [12, 0]);
    }

    #[test]
    fn read_empty_with_length() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let (value, size) = WithLength::<u8, u16>::try_read(&bytes[..], Endian::Little).unwrap();
        assert_eq!(size, 1);
        assert_eq!(*value, None)
    }

    #[test]
    fn read_with_length() {
        let bytes = [3u8, 1, 0, 3, 4, 5, 6, 7, 8, 9];

        let (value, size) = WithLength::<u8, u16>::try_read(&bytes[..], Endian::Little).unwrap();
        assert_eq!(size, 4);
        assert_eq!(*value, Some(1))
    }
}
