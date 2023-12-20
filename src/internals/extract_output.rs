use super::{
    traits::{Array, BytesRepresentation, Sha2AlgorithmInternal, Zero},
    types::State,
};

macro_rules! extract_output {
    ($($fn: ident: $type: ty),+ $(,)?) => {
        $(
            pub(crate) const fn $fn<ShaAlg, const OUTPUT_LENGTH: usize>(state: &State<ShaAlg>) -> ShaAlg::Output
            where
                ShaAlg: Sha2AlgorithmInternal<WorkingVariableT = $type, Output = [u8; OUTPUT_LENGTH]> + ?Sized,
            {
                let mut output: [u8; OUTPUT_LENGTH] = Zero::ZERO;

                {
                    let mut index = 0;

                    let mut output_chunk_start_index = 0;

                    while output_chunk_start_index < OUTPUT_LENGTH {
                        let bytes = state.0[index].to_be_bytes();

                        {
                            let mut byte_index = 0;

                            while byte_index < <<ShaAlg::WorkingVariableT as BytesRepresentation>::ByteArray as Array>::LENGTH {
                                output[output_chunk_start_index + byte_index] = bytes[byte_index];

                                byte_index += 1;
                            }
                        }

                        index += 1;

                        output_chunk_start_index +=
                            <<ShaAlg::WorkingVariableT as BytesRepresentation>::ByteArray as Array>::LENGTH;
                    }
                }

                output
            }
        )+
    };
}

extract_output![
    u32_impl: u32,
    u64_impl: u64,
];
