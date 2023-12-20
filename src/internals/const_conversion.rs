use super::traits::{Array, BytesRepresentation, Zero};

macro_rules! const_conversion_to_pack {
($($fn: ident: ($from: ty) -> ([$to: ty; $length: expr])),+ $(,)?) => {
    $(
        pub(crate) const fn $fn(x: $from) -> Option<[$to; 2]> {
            let source_bytes: <$from as BytesRepresentation>::ByteArray = x.to_le_bytes();

            let mut output_bytes: [<$to as BytesRepresentation>::ByteArray; $length] = Zero::ZERO;

            let mut source_index = 0;
            let mut buffer_index = 0;

            'outmost_loop: while buffer_index < $length {
                let mut inner_buffer_index = 0;

                while inner_buffer_index < <<$to as BytesRepresentation>::ByteArray as Array>::LENGTH {
                    if source_index < <<$from as BytesRepresentation>::ByteArray as Array>::LENGTH {
                        output_bytes[buffer_index][inner_buffer_index] = source_bytes[source_index];

                        source_index += 1;

                        inner_buffer_index += 1;
                    } else {
                        break 'outmost_loop;
                    }
                }

                buffer_index += 1;
            }

            while source_index < source_bytes.len() {
                if source_bytes[source_index] != 0 {
                    return None;
                }

                source_index += 1;
            }

            match output_bytes {
                [least_significant_bytes, most_significant_bytes] => Some([
                    <$to>::from_le_bytes(least_significant_bytes),
                    <$to>::from_le_bytes(most_significant_bytes),
                ]),
            }
        }
    )+
};
}

const_conversion_to_pack![
    usize_to_message_length_le_u32: (usize) -> ([u32; 2]),
    usize_to_message_length_le_u64: (usize) -> ([u64; 2]),
];

#[cfg(test)]
#[test]
fn test_conversions() {
    use core::mem::size_of;

    impl Zero for u128 {
        const ZERO: Self = 0;
    }

    impl BytesRepresentation for u128 {
        type ByteArray = [u8; size_of::<Self>()];
    }

    const_conversion_to_pack![
        test_u128_to_u32_2: (u128) -> ([u32; 2]),
        test_u32_to_u64_2: (u32) -> ([u64; 2]),
    ];

    assert_eq!(test_u128_to_u32_2(u64::MAX.into()), Some([u32::MAX; 2]));

    assert_eq!(test_u128_to_u32_2(u128::MAX), None);

    assert_eq!(test_u128_to_u32_2(u128::from(u32::MAX) + 1), Some([0, 1]));

    assert_eq!(test_u32_to_u64_2(u32::MAX), Some([u32::MAX.into(), 0]));
}
