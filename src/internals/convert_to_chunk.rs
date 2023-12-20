use super::{
    consts::CHUNK_LENGTH,
    traits::{Array, BytesRepresentation, Sha2AlgorithmInternal},
    types::{Chunk, RoundKeys},
};

macro_rules! convert_to_chunk {
    ($($fn: ident: $type: ty),+ $(,)?) => {
        $(
            pub(crate) const fn $fn<ShaAlg, const ROUND_COUNT: usize>(
                source_buffer: &[<ShaAlg::WorkingVariableT as BytesRepresentation>::ByteArray; CHUNK_LENGTH],
            ) -> Chunk<ShaAlg>
            where
                ShaAlg:
                    Sha2AlgorithmInternal<WorkingVariableT = $type, RoundKeys = RoundKeys<ShaAlg, ROUND_COUNT>> + ?Sized,
                    ShaAlg::Output: Array<ElementsType = u8>,
            {
                let mut chunk = Chunk::INITIAL;

                let mut buffer_index = 0;

                while buffer_index < CHUNK_LENGTH {
                    chunk.0[buffer_index] =
                        ShaAlg::WorkingVariableT::from_be_bytes(source_buffer[buffer_index]);

                    buffer_index += 1;
                }

                chunk
            }
        )+
    };
}

convert_to_chunk![
    u32_impl: u32,
    u64_impl: u64,
];
