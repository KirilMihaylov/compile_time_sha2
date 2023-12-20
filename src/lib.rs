#![forbid(warnings, unsafe_code, clippy::pedantic)]
#![cfg_attr(not(feature = "std"), no_std)]

use self::{
    consts::{
        SHA2_224_256_ROUND_COUNT, SHA2_224_256_ROUND_KEYS, SHA2_224_OUTPUT_LENGTH,
        SHA2_256_OUTPUT_LENGTH, SHA2_384_512_ROUND_COUNT, SHA2_384_512_ROUND_KEYS,
        SHA2_384_OUTPUT_LENGTH, SHA2_512_OUTPUT_LENGTH,
    },
    error::MessageTooLong,
    internals::{
        const_conversion::{usize_to_message_length_le_u32, usize_to_message_length_le_u64},
        consts::CHUNK_LENGTH,
        convert_to_chunk::{u32_impl as convert_to_chunk_u32, u64_impl as convert_to_chunk_u64},
        digest_chunk::{u32_impl as digest_chunk_u32, u64_impl as digest_chunk_u64},
        extract_output::{u32_impl as extract_output_u32, u64_impl as extract_output_u64},
        message_schedule::{u32_impl as message_schedule_u32, u64_impl as message_schedule_u64},
        prepare_state_for_next_chunk::{
            u32_impl as prepare_state_for_next_chunk_u32,
            u64_impl as prepare_state_for_next_chunk_u64,
        },
        traits::{Array, BytesRepresentation, Sha2Algorithm, Sha2AlgorithmInternal, Zero},
        types::{Buffer, Chunk, MessageLength, RoundKeys, State},
    },
};

pub mod consts;
pub mod error;
mod internals;

macro_rules! sha2 {
    (
        $(
            $sha_type: ident {
                usize_to_message_length_le: $usize_to_message_length_le: expr,
                convert_to_chunk: $convert_to_chunk: ident,
                message_schedule: $message_schedule: ident,
                digest_chunk: $digest_chunk: ident,
                prepare_state_for_next_chunk: $prepare_state_for_next_chunk: ident,
                extract_output: $extract_output: ident
                $(,)?
            }
        ),+
        $(,)?
    ) => {
        $(
            #[must_use]
            pub struct $sha_type {
                message_length: MessageLength<Self>,
                buffer_position: usize,
                buffer: Buffer<Self>,
                state: State<Self>,
            }

            impl $sha_type {
                const WORKING_VARIABLE_SIZE: usize =
                    <<<Self as Sha2AlgorithmInternal>::WorkingVariableT as BytesRepresentation>::ByteArray as Array>::LENGTH;

                const CHUNK_SIZE: usize = CHUNK_LENGTH * Self::WORKING_VARIABLE_SIZE;

                /// Constant representing the size in bytes of the length field in the final block of the digest.
                const LENGTH_FIELD_SIZE: usize =
                    <<<MessageLength<Self> as Array>::ElementsType as BytesRepresentation>::ByteArray as Array>::LENGTH
                        * <MessageLength<Self> as Array>::LENGTH;

                const LENGTH_FIELD_START: usize = Self::CHUNK_SIZE - Self::LENGTH_FIELD_SIZE;

                pub const fn new() -> Self {
                    Self {
                        message_length: Zero::ZERO,
                        buffer_position: 0,
                        buffer: [Zero::ZERO; CHUNK_LENGTH],
                        state: <Self as Sha2AlgorithmInternal>::INITIAL_STATE,
                    }
                }

                /// Appends the message in chunks, processing them when the internal buffer is full,
                /// thus the chunk is ready to be digested by the hashing function.
                ///
                /// # Errors
                ///
                /// This function will return an error if the cumulative message length goes above or
                /// gets equal to the limits of the selected hashing function.
                ///
                /// The limit for SHA224/-256 is: 2^61.
                ///
                /// The limit for SHA384/-512 is: 2^125.
                pub const fn update(mut self, message: &[u8]) -> Result<Self, MessageTooLong> {
                    Ok(if message.is_empty() {
                        self
                    } else {
                        self.message_length = match self.calculate_new_message_length(message) {
                            Ok(new_message_length) => new_message_length,
                            Err(error) => return Err(error),
                        };

                        self.update_buffer(message)
                    })
                }

                #[must_use]
                pub const fn finalize(mut self) -> <Self as Sha2Algorithm>::Output {
                    self.buffer[(self.buffer_position / Self::WORKING_VARIABLE_SIZE) % CHUNK_LENGTH]
                        [self.buffer_position % Self::WORKING_VARIABLE_SIZE] = 0x80;

                    self.buffer_position += 1;

                    if self.buffer_position == Self::CHUNK_SIZE {
                        self.state = Self::convert_and_process_chunk(self.state, &self.buffer);

                        self.buffer_position = 0;
                    }

                    let mut zero_until = if self.buffer_position <= Self::LENGTH_FIELD_START {
                        Self::LENGTH_FIELD_START
                    } else {
                        Self::CHUNK_SIZE
                    };

                    let mut zero_from = self.buffer_position;

                    loop {
                        self.buffer = Self::partially_zero_buffer(self.buffer, zero_from, zero_until);

                        if zero_until != Self::CHUNK_SIZE {
                            let [lower_half, higher_half] = self.message_length;

                            self.buffer[CHUNK_LENGTH - 2] = (higher_half << 3
                                | lower_half >> (<Self as Sha2AlgorithmInternal>::WorkingVariableT::BITS - 3))
                                .to_be_bytes();

                            self.buffer[CHUNK_LENGTH - 1] = (lower_half << 3).to_be_bytes();
                        }

                        self.state = Self::convert_and_process_chunk(self.state, &self.buffer);

                        if zero_until != Self::CHUNK_SIZE {
                            break $extract_output(&self.state);
                        }

                        zero_until = self.buffer_position;

                        zero_from = 0;
                    }
                }

                #[inline]
                const fn calculate_new_message_length(
                    &self,
                    message: &[u8],
                ) -> Result<[<Self as Sha2AlgorithmInternal>::WorkingVariableT; 2], MessageTooLong> {
                    let Some(appending_length) = $usize_to_message_length_le(message.len()) else {
                        return Err(MessageTooLong);
                    };

                    let (
                        [committed_lower_half, committed_higher_half],
                        [appending_lower_half, appending_higher_half],
                    ) = (self.message_length, appending_length);

                    let (new_lower_half, overflow) = committed_lower_half.overflowing_add(appending_lower_half);

                    let Some(intermediate_higher_half) =
                        committed_higher_half.checked_add(appending_higher_half)
                    else {
                        return Err(MessageTooLong);
                    };

                    let new_higher_half = if overflow {
                        if let Some(new_higher_half) = intermediate_higher_half.checked_add(1) {
                            new_higher_half
                        } else {
                            return Err(MessageTooLong);
                        }
                    } else {
                        intermediate_higher_half
                    };

                    // Three most-significant bits are zeroes, allowing safe multiplication by 8,
                    // which in turn represent the number of bits in the digested message.
                    if new_higher_half.leading_zeros() < 3 {
                        return Err(MessageTooLong);
                    }

                    Ok([new_lower_half, new_higher_half])
                }

                #[inline]
                /// # Assumptions
                /// This method assumes, and is optimized for, the case of a non-empty message.
                const fn update_buffer(mut self, message: &[u8]) -> Self {
                    let mut source_index = 0;

                    let mut outer_buffer_index = self.buffer_position / Self::WORKING_VARIABLE_SIZE;

                    let mut inner_buffer_index = self.buffer_position % Self::WORKING_VARIABLE_SIZE;

                    'outmost_loop: loop {
                        while outer_buffer_index < CHUNK_LENGTH {
                            while inner_buffer_index < Self::WORKING_VARIABLE_SIZE {
                                if source_index == message.len() {
                                    break 'outmost_loop;
                                }

                                self.buffer[outer_buffer_index][inner_buffer_index] = message[source_index];

                                self.buffer_position += 1;

                                source_index += 1;

                                inner_buffer_index += 1;
                            }

                            inner_buffer_index = 0;

                            outer_buffer_index += 1;
                        }

                        if outer_buffer_index == CHUNK_LENGTH {
                            self.state = Self::convert_and_process_chunk(self.state, &self.buffer);

                            self.buffer_position = 0;

                            outer_buffer_index = 0;
                        }
                    }

                    self
                }

                #[inline]
                const fn partially_zero_buffer(
                    mut buffer: Buffer<Self>,
                    zero_from: usize,
                    zero_until: usize,
                ) -> Buffer<Self> {
                    let mut outer_buffer_index;

                    if zero_from == 0 {
                        outer_buffer_index = 0;
                    } else {
                        outer_buffer_index = zero_from / Self::WORKING_VARIABLE_SIZE;

                        let mut inner_buffer_index = zero_from % Self::WORKING_VARIABLE_SIZE;

                        if inner_buffer_index != 0 {
                            while inner_buffer_index != Self::WORKING_VARIABLE_SIZE {
                                buffer[outer_buffer_index][inner_buffer_index] = 0;

                                inner_buffer_index += 1;
                            }

                            outer_buffer_index += 1;
                        }
                    }

                    let zero_outer_buffers_until = zero_until / Self::WORKING_VARIABLE_SIZE;

                    while outer_buffer_index < zero_outer_buffers_until {
                        buffer[outer_buffer_index] = Zero::ZERO;

                        outer_buffer_index += 1;
                    }

                    buffer
                }

                #[inline]
                const fn convert_and_process_chunk(
                    state: State<Self>,
                    buffer: &[<<Self as Sha2AlgorithmInternal>::WorkingVariableT as BytesRepresentation>::ByteArray; CHUNK_LENGTH],
                ) -> State<Self> {
                    Self::process_chunk(
                        state,
                        &$convert_to_chunk(buffer),
                    )
                }

                #[inline]
                const fn process_chunk(state: State<Self>, chunk: &Chunk<Self>) -> State<Self> {
                    let digested_chunk = $digest_chunk(
                        &state,
                        &$message_schedule(chunk),
                    );

                    $prepare_state_for_next_chunk(state, &digested_chunk)
                }
            }
        )+
    };
}

sha2![
    Sha224 {
        usize_to_message_length_le: usize_to_message_length_le_u32,
        convert_to_chunk: convert_to_chunk_u32,
        message_schedule: message_schedule_u32,
        digest_chunk: digest_chunk_u32,
        prepare_state_for_next_chunk: prepare_state_for_next_chunk_u32,
        extract_output: extract_output_u32,
    },
    Sha256 {
        usize_to_message_length_le: usize_to_message_length_le_u32,
        convert_to_chunk: convert_to_chunk_u32,
        message_schedule: message_schedule_u32,
        digest_chunk: digest_chunk_u32,
        prepare_state_for_next_chunk: prepare_state_for_next_chunk_u32,
        extract_output: extract_output_u32,
    },
    Sha384 {
        usize_to_message_length_le: usize_to_message_length_le_u64,
        convert_to_chunk: convert_to_chunk_u64,
        message_schedule: message_schedule_u64,
        digest_chunk: digest_chunk_u64,
        prepare_state_for_next_chunk: prepare_state_for_next_chunk_u64,
        extract_output: extract_output_u64,
    },
    Sha512 {
        usize_to_message_length_le: usize_to_message_length_le_u64,
        convert_to_chunk: convert_to_chunk_u64,
        message_schedule: message_schedule_u64,
        digest_chunk: digest_chunk_u64,
        prepare_state_for_next_chunk: prepare_state_for_next_chunk_u64,
        extract_output: extract_output_u64,
    },
];

impl Sha2Algorithm for Sha224 {
    type Output = [u8; SHA2_224_OUTPUT_LENGTH];
}

impl Sha2AlgorithmInternal for Sha224 {
    type WorkingVariableT = <Sha256 as Sha2AlgorithmInternal>::WorkingVariableT;

    type RoundKeys = RoundKeys<Self, SHA2_224_256_ROUND_COUNT>;

    const INITIAL_STATE: State<Self> = State::new([
        0xC105_9ED8,
        0x367C_D507,
        0x3070_DD17,
        0xF70E_5939,
        0xFFC0_0B31,
        0x6858_1511,
        0x64F9_8FA7,
        0xBEFA_4FA4,
    ]);

    const ROUND_KEYS: Self::RoundKeys = RoundKeys::new(SHA2_224_256_ROUND_KEYS);

    const MESSAGE_SCHEDULE_W_MINUS_2_SHT: u32 =
        <Sha256 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_2_SHT;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT1: u32 =
        <Sha256 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_2_ROT1;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT2: u32 =
        <Sha256 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_2_ROT2;

    const MESSAGE_SCHEDULE_W_MINUS_15_SHT: u32 =
        <Sha256 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_15_SHT;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT1: u32 =
        <Sha256 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_15_ROT1;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT2: u32 =
        <Sha256 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_15_ROT2;

    const DIGEST_CHUNK_VARIABLE_0_ROT1: u32 =
        <Sha256 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_0_ROT1;
    const DIGEST_CHUNK_VARIABLE_0_ROT2: u32 =
        <Sha256 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_0_ROT2;
    const DIGEST_CHUNK_VARIABLE_0_ROT3: u32 =
        <Sha256 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_0_ROT3;

    const DIGEST_CHUNK_VARIABLE_4_ROT1: u32 =
        <Sha256 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_4_ROT1;
    const DIGEST_CHUNK_VARIABLE_4_ROT2: u32 =
        <Sha256 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_4_ROT2;
    const DIGEST_CHUNK_VARIABLE_4_ROT3: u32 =
        <Sha256 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_4_ROT3;
}

impl Sha2Algorithm for Sha256 {
    type Output = [u8; SHA2_256_OUTPUT_LENGTH];
}

impl Sha2AlgorithmInternal for Sha256 {
    type WorkingVariableT = u32;

    type RoundKeys = RoundKeys<Self, SHA2_224_256_ROUND_COUNT>;

    const INITIAL_STATE: State<Self> = State::new([
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ]);

    const ROUND_KEYS: Self::RoundKeys = RoundKeys::new(SHA2_224_256_ROUND_KEYS);

    const MESSAGE_SCHEDULE_W_MINUS_2_SHT: u32 = 10;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT1: u32 = 17;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT2: u32 = 19;

    const MESSAGE_SCHEDULE_W_MINUS_15_SHT: u32 = 3;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT1: u32 = 7;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT2: u32 = 18;

    const DIGEST_CHUNK_VARIABLE_0_ROT1: u32 = 2;
    const DIGEST_CHUNK_VARIABLE_0_ROT2: u32 = 13;
    const DIGEST_CHUNK_VARIABLE_0_ROT3: u32 = 22;

    const DIGEST_CHUNK_VARIABLE_4_ROT1: u32 = 6;
    const DIGEST_CHUNK_VARIABLE_4_ROT2: u32 = 11;
    const DIGEST_CHUNK_VARIABLE_4_ROT3: u32 = 25;
}

impl Sha2Algorithm for Sha384 {
    type Output = [u8; SHA2_384_OUTPUT_LENGTH];
}

impl Sha2AlgorithmInternal for Sha384 {
    type WorkingVariableT = <Sha512 as Sha2AlgorithmInternal>::WorkingVariableT;

    type RoundKeys = RoundKeys<Self, SHA2_384_512_ROUND_COUNT>;

    const INITIAL_STATE: State<Self> = State::new([
        0xCBBB_9D5D_C105_9ED8,
        0x629A_292A_367C_D507,
        0x9159_015A_3070_DD17,
        0x152F_ECD8_F70E_5939,
        0x6733_2667_FFC0_0B31,
        0x8EB4_4A87_6858_1511,
        0xDB0C_2E0D_64F9_8FA7,
        0x47B5_481D_BEFA_4FA4,
    ]);

    const ROUND_KEYS: Self::RoundKeys = RoundKeys::new(SHA2_384_512_ROUND_KEYS);

    const MESSAGE_SCHEDULE_W_MINUS_2_SHT: u32 =
        <Sha512 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_2_SHT;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT1: u32 =
        <Sha512 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_2_ROT1;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT2: u32 =
        <Sha512 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_2_ROT2;

    const MESSAGE_SCHEDULE_W_MINUS_15_SHT: u32 =
        <Sha512 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_15_SHT;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT1: u32 =
        <Sha512 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_15_ROT1;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT2: u32 =
        <Sha512 as Sha2AlgorithmInternal>::MESSAGE_SCHEDULE_W_MINUS_15_ROT2;

    const DIGEST_CHUNK_VARIABLE_0_ROT1: u32 =
        <Sha512 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_0_ROT1;
    const DIGEST_CHUNK_VARIABLE_0_ROT2: u32 =
        <Sha512 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_0_ROT2;
    const DIGEST_CHUNK_VARIABLE_0_ROT3: u32 =
        <Sha512 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_0_ROT3;

    const DIGEST_CHUNK_VARIABLE_4_ROT1: u32 =
        <Sha512 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_4_ROT1;
    const DIGEST_CHUNK_VARIABLE_4_ROT2: u32 =
        <Sha512 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_4_ROT2;
    const DIGEST_CHUNK_VARIABLE_4_ROT3: u32 =
        <Sha512 as Sha2AlgorithmInternal>::DIGEST_CHUNK_VARIABLE_4_ROT3;
}

impl Sha2Algorithm for Sha512 {
    type Output = [u8; SHA2_512_OUTPUT_LENGTH];
}

impl Sha2AlgorithmInternal for Sha512 {
    type WorkingVariableT = u64;

    type RoundKeys = RoundKeys<Self, SHA2_384_512_ROUND_COUNT>;

    const INITIAL_STATE: State<Self> = State::new([
        0x6A09_E667_F3BC_C908,
        0xBB67_AE85_84CA_A73B,
        0x3C6E_F372_FE94_F82B,
        0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1,
        0x9B05_688C_2B3E_6C1F,
        0x1F83_D9AB_FB41_BD6B,
        0x5BE0_CD19_137E_2179,
    ]);

    const ROUND_KEYS: Self::RoundKeys = RoundKeys::new(SHA2_384_512_ROUND_KEYS);

    const MESSAGE_SCHEDULE_W_MINUS_2_SHT: u32 = 6;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT1: u32 = 19;
    const MESSAGE_SCHEDULE_W_MINUS_2_ROT2: u32 = 61;

    const MESSAGE_SCHEDULE_W_MINUS_15_SHT: u32 = 7;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT1: u32 = 1;
    const MESSAGE_SCHEDULE_W_MINUS_15_ROT2: u32 = 8;

    const DIGEST_CHUNK_VARIABLE_0_ROT1: u32 = 28;
    const DIGEST_CHUNK_VARIABLE_0_ROT2: u32 = 34;
    const DIGEST_CHUNK_VARIABLE_0_ROT3: u32 = 39;

    const DIGEST_CHUNK_VARIABLE_4_ROT1: u32 = 14;
    const DIGEST_CHUNK_VARIABLE_4_ROT2: u32 = 18;
    const DIGEST_CHUNK_VARIABLE_4_ROT3: u32 = 41;
}
