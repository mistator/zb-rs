#![cfg_attr(not(test), no_std)]
pub mod common;
pub mod mac;

use cfg_if::cfg_if;
use core::hash::Hash;
use derive_more::{Deref, DerefMut, IntoIterator};

cfg_if! {
    if #[cfg(feature = "alloc")] {
        use core::convert::Infallible;

        extern crate alloc;

        macro_rules! call {
            ($call: expr) => {
                return Ok($call)
            };
        }

        macro_rules! result {
            ($ok: ty, $err: ty) => {
                Result<$ok, Infallible>
            };
        }

        type InnerVec<T, const N: usize> = alloc::vec::Vec<T>;
        type InnerHashMap<K, V, const N: usize> = hashbrown::HashMap<K, V>;
        type InnerHashSet<K, V, const N: usize> = hashbrown::HashSet<K, V>;
    } else {
        use heapless::CapacityError;

        macro_rules! call {
            ($call: expr) => {
                return $call;
            };
        }

        macro_rules! result {
            ($ok: ty, $err: ty) => {
                Result<$ok, $err>
            };
        }

        type InnerVec<T, const N: usize> = heapless::Vec<T, N>;
        type InnerHashMap<K, V, const N: usize> = heapless::index_map::FnvIndexMap<K, V, N>;
        type InnerHashSet<K, V, const N: usize> = heapless::index_set::FnvIndexSet<T, N>;
    }
}

#[derive(Debug, Clone, Default, Deref, DerefMut, IntoIterator)]
pub struct Vec<T, const N: usize>(#[into_iterator(owned, ref, ref_mut)] InnerVec<T, N>);

impl<T, const N: usize> Vec<T, N> {
    pub fn new() -> Self { Self(InnerVec::<T, N>::default()) }

    pub fn push(&mut self, value: T) -> result!((), T) {
        call!(self.0.push(value))
    }
}

impl<T, const N: usize> FromIterator<T> for Vec<T, N> {
    fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self {
        Self(InnerVec::<T, N>::from_iter(iter))
    }
}

impl<T: Clone, const N: usize> Vec<T, N> {
    pub fn from_slice(slice: &[T]) -> result!(Self, CapacityError) {
        Ok(Self(InnerVec::<T, N>::from(slice)))
    }
}

impl<T: Clone, const N: usize> From<&[T]> for Vec<T, N> {
    fn from(value: &[T]) -> Self {
        Self(InnerVec::from(value))
    }
}

#[derive(Debug, Clone, Deref, DerefMut, IntoIterator, Default)]
pub struct HashMap<K, V, const N: usize>(#[into_iterator(owned, ref, ref_mut)] InnerHashMap<K, V, N>);

impl<K, V, const N: usize> HashMap<K, V, N> {
    pub fn new() -> Self { Self(InnerHashMap::<K, V, N>::default()) }
}

impl<K: Eq + Hash, V, const N: usize> HashMap<K, V, N>
{
    pub fn insert(&mut self, key: K, value: V) -> result!(Option<V>, (K, V)) {
        call!(self.0.insert(key, value))
    }
}

#[derive(Debug, Clone, Deref, DerefMut, IntoIterator)]
pub struct HashSet<K, V, const N: usize>(InnerHashSet<K, V, N>);

