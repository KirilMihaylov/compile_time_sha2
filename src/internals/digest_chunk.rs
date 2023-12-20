use super::{
    consts::STATE_LENGTH,
    traits::{Array, Sha2AlgorithmInternal},
    types::{DigestedChunk, MessageSchedule, RoundKeys, State},
};

macro_rules! digest_chunk {
    ($($fn: ident: $type: ty),+ $(,)?) => {
        $(
            pub(crate) const fn $fn<ShaAlg, const ROUND_COUNT: usize>(
                state: &State<ShaAlg>,
                message_schedule: &MessageSchedule<ShaAlg, ROUND_COUNT>,
            ) -> DigestedChunk<ShaAlg>
            where
                ShaAlg:
                    Sha2AlgorithmInternal<WorkingVariableT = $type, RoundKeys = RoundKeys<ShaAlg, ROUND_COUNT>> + ?Sized,
                    ShaAlg::Output: Array<ElementsType = u8>,
            {
                let mut digested_chunk: DigestedChunk<ShaAlg> = DigestedChunk(state.0);

                let mut round = 0;

                while round < ROUND_COUNT {
                    let temp1 = (digested_chunk.0[4].rotate_right(ShaAlg::DIGEST_CHUNK_VARIABLE_4_ROT1)
                        ^ digested_chunk.0[4].rotate_right(ShaAlg::DIGEST_CHUNK_VARIABLE_4_ROT2)
                        ^ digested_chunk.0[4].rotate_right(ShaAlg::DIGEST_CHUNK_VARIABLE_4_ROT3))
                    .wrapping_add(
                        (digested_chunk.0[4] & digested_chunk.0[5])
                            ^ ((!digested_chunk.0[4]) & digested_chunk.0[6]),
                    )
                    .wrapping_add(digested_chunk.0[7])
                    .wrapping_add(message_schedule.0[round])
                    .wrapping_add(ShaAlg::ROUND_KEYS.0[round]);

                    let temp2 = temp1.wrapping_add(
                        (digested_chunk.0[0] & digested_chunk.0[1])
                            ^ (digested_chunk.0[0] & digested_chunk.0[2])
                            ^ (digested_chunk.0[1] & digested_chunk.0[2]),
                    );

                    {
                        let mut index = STATE_LENGTH - 1;

                        while index != 0 {
                            digested_chunk.0[index] = digested_chunk.0[index - 1];

                            index -= 1;
                        }
                    }

                    digested_chunk.0[0] = temp2.wrapping_add(
                        digested_chunk.0[0].rotate_right(ShaAlg::DIGEST_CHUNK_VARIABLE_0_ROT1)
                            ^ digested_chunk.0[0].rotate_right(ShaAlg::DIGEST_CHUNK_VARIABLE_0_ROT2)
                            ^ digested_chunk.0[0].rotate_right(ShaAlg::DIGEST_CHUNK_VARIABLE_0_ROT3),
                    );

                    digested_chunk.0[4] = digested_chunk.0[4].wrapping_add(temp1);

                    round += 1;
                }

                DigestedChunk(digested_chunk.0)
            }
        )+
    };
}

digest_chunk![
    u32_impl: u32,
    u64_impl: u64,
];
