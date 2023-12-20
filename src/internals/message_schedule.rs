use super::{
    consts::CHUNK_LENGTH,
    traits::{Array, Sha2AlgorithmInternal},
    types::{Chunk, MessageSchedule, RoundKeys},
};

macro_rules! message_schedule {
    ($($fn: ident: $type: ty),+ $(,)?) => {
        $(
            pub(crate) const fn $fn<ShaAlg, const ROUND_COUNT: usize>(
                chunk: &Chunk<ShaAlg>,
            ) -> MessageSchedule<ShaAlg, ROUND_COUNT>
            where
                ShaAlg:
                    Sha2AlgorithmInternal<WorkingVariableT = $type, RoundKeys = RoundKeys<ShaAlg, ROUND_COUNT>> + ?Sized,
                    ShaAlg::Output: Array<ElementsType = u8>,
            {
                let mut w: MessageSchedule<ShaAlg, ROUND_COUNT> = MessageSchedule([0; ROUND_COUNT]);

                let mut index = 0;

                while index < CHUNK_LENGTH {
                    w.0[index] = chunk.0[index];

                    index += 1;
                }

                while index < ROUND_COUNT {
                    w.0[index] = ((w.0[index - 2] >> ShaAlg::MESSAGE_SCHEDULE_W_MINUS_2_SHT)
                        ^ w.0[index - 2].rotate_right(ShaAlg::MESSAGE_SCHEDULE_W_MINUS_2_ROT1)
                        ^ w.0[index - 2].rotate_right(ShaAlg::MESSAGE_SCHEDULE_W_MINUS_2_ROT2))
                    .wrapping_add(w.0[index - 7])
                    .wrapping_add(
                        (w.0[index - 15] >> ShaAlg::MESSAGE_SCHEDULE_W_MINUS_15_SHT)
                            ^ w.0[index - 15].rotate_right(ShaAlg::MESSAGE_SCHEDULE_W_MINUS_15_ROT1)
                            ^ w.0[index - 15].rotate_right(ShaAlg::MESSAGE_SCHEDULE_W_MINUS_15_ROT2),
                    )
                    .wrapping_add(w.0[index - 16]);

                    index += 1;
                }

                w
            }
        )+
    };
}

message_schedule![
    u32_impl: u32,
    u64_impl: u64,
];
