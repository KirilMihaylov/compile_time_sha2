use super::{
    consts::{CHUNK_LENGTH, STATE_LENGTH},
    traits::{Array, BytesRepresentation, Sha2AlgorithmInternal, Zero},
};

/// Type representing the length field in the final block of the digest.
///
/// It is always twice as big as the working variables in the algorithms of the SHA2 family.
pub(crate) type MessageLength<ShaAlg> = [<ShaAlg as Sha2AlgorithmInternal>::WorkingVariableT; 2];

pub(crate) type Buffer<ShaAlg> =
    [<<ShaAlg as Sha2AlgorithmInternal>::WorkingVariableT as BytesRepresentation>::ByteArray;
        CHUNK_LENGTH];

#[must_use]
pub(crate) struct Chunk<ShaAlg>(pub(super) [ShaAlg::WorkingVariableT; CHUNK_LENGTH])
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>;

impl<ShaAlg> Chunk<ShaAlg>
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>,
{
    pub(crate) const INITIAL: Self = Self([<ShaAlg::WorkingVariableT as Zero>::ZERO; CHUNK_LENGTH]);
}

#[must_use]
#[repr(transparent)]
pub(crate) struct State<ShaAlg>(pub(super) [ShaAlg::WorkingVariableT; STATE_LENGTH])
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>;

impl<ShaAlg> State<ShaAlg>
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>,
{
    pub(crate) const fn new(values: [ShaAlg::WorkingVariableT; STATE_LENGTH]) -> Self {
        Self(values)
    }
}

#[must_use]
#[repr(transparent)]
pub(crate) struct DigestedChunk<ShaAlg>(pub(super) [ShaAlg::WorkingVariableT; STATE_LENGTH])
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>;

#[must_use]
#[repr(transparent)]
pub(crate) struct MessageSchedule<ShaAlg, const ROUND_COUNT: usize>(
    pub(super) [ShaAlg::WorkingVariableT; ROUND_COUNT],
)
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>;

#[must_use]
#[repr(transparent)]
pub struct RoundKeys<ShaAlg, const ROUND_COUNT: usize>(
    pub(super) [ShaAlg::WorkingVariableT; ROUND_COUNT],
)
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>;

impl<ShaAlg, const ROUND_COUNT: usize> RoundKeys<ShaAlg, ROUND_COUNT>
where
    ShaAlg: Sha2AlgorithmInternal + ?Sized,
    ShaAlg::Output: Array<ElementsType = u8>,
{
    pub(crate) const fn new(values: [ShaAlg::WorkingVariableT; ROUND_COUNT]) -> Self {
        Self(values)
    }
}
