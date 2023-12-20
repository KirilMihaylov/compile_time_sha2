use super::{
    consts::STATE_LENGTH,
    traits::{Array, Sha2AlgorithmInternal},
    types::{DigestedChunk, State},
};

macro_rules! prepare_state_for_next_chunk {
    ($($fn: ident: $type: ty),+ $(,)?) => {
        $(
            pub(crate) const fn $fn<ShaAlg>(
                mut state: State<ShaAlg>,
                digested_chunk: &DigestedChunk<ShaAlg>,
            ) -> State<ShaAlg>
            where
                ShaAlg: Sha2AlgorithmInternal<WorkingVariableT = $type> + ?Sized,
                ShaAlg::Output: Array<ElementsType = u8>,
            {
                let mut index = 0;

                while index < STATE_LENGTH {
                    state.0[index] = state.0[index].wrapping_add(digested_chunk.0[index]);

                    index += 1;
                }

                state
            }
        )+
    };
}

prepare_state_for_next_chunk![
    u32_impl: u32,
    u64_impl: u64,
];
