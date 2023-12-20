use core::mem::size_of;

use super::types::State;

pub(crate) trait UnsignedInteger {
    const BITS: u32;
}

impl UnsignedInteger for u32 {
    const BITS: u32 = Self::BITS;
}

impl UnsignedInteger for u64 {
    const BITS: u32 = Self::BITS;
}

pub(crate) trait Zero: Sized {
    const ZERO: Self;
}

impl Zero for u8 {
    const ZERO: Self = 0;
}

impl Zero for u32 {
    const ZERO: Self = 0;
}

impl Zero for u64 {
    const ZERO: Self = 0;
}

impl Zero for usize {
    const ZERO: Self = 0;
}

impl<T, const LENGTH: usize> Zero for [T; LENGTH]
where
    T: Zero,
{
    const ZERO: Self = [T::ZERO; LENGTH];
}

pub(crate) trait Array {
    type ElementsType;

    const LENGTH: usize;
}

impl<T, const LENGTH: usize> Array for [T; LENGTH] {
    type ElementsType = T;

    const LENGTH: usize = LENGTH;
}

pub(crate) trait BytesRepresentation: Zero {
    type ByteArray: Array<ElementsType = u8>;
}

impl BytesRepresentation for u32 {
    type ByteArray = [u8; size_of::<Self>()];
}

impl BytesRepresentation for u64 {
    type ByteArray = [u8; size_of::<Self>()];
}

impl BytesRepresentation for usize {
    type ByteArray = [u8; size_of::<Self>()];
}

pub trait Sha2Algorithm {
    type Output;
}

pub(crate) trait Sha2AlgorithmInternal: Sha2Algorithm
where
    Self::Output: Array<ElementsType = u8>,
{
    type WorkingVariableT: BytesRepresentation + UnsignedInteger + Zero;

    type RoundKeys;

    const INITIAL_STATE: State<Self>;

    const ROUND_KEYS: Self::RoundKeys;

    const MESSAGE_SCHEDULE_W_MINUS_2_SHT: u32;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT1: u32;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT2: u32;

    const MESSAGE_SCHEDULE_W_MINUS_15_SHT: u32;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT1: u32;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT2: u32;

    const DIGEST_CHUNK_VARIABLE_0_ROT1: u32;
    const DIGEST_CHUNK_VARIABLE_0_ROT2: u32;
    const DIGEST_CHUNK_VARIABLE_0_ROT3: u32;

    const DIGEST_CHUNK_VARIABLE_4_ROT1: u32;
    const DIGEST_CHUNK_VARIABLE_4_ROT2: u32;
    const DIGEST_CHUNK_VARIABLE_4_ROT3: u32;
}
