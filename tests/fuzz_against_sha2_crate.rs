use std::{fmt::Debug, num::NonZeroUsize};

#[cfg(not(miri))]
use proptest::proptest;
#[cfg(miri)]
use quickcheck_macros::quickcheck;
use sha2::Digest;

use compile_time_sha2::{Sha224, Sha256, Sha384, Sha512};

fn test_against_sha2_crate<OwnSha, CrateSha>(input: &[u8], parts: NonZeroUsize)
where
    OwnSha: Sha2,
    OwnSha::Output: Debug + Eq,
    CrateSha: Sha2<Output = OwnSha::Output>,
{
    let own_hash = {
        let mut sha2 = OwnSha::new();

        let chunk_size = input.len() / parts;

        for chunk in input.chunks(chunk_size.max(1)) {
            if chunk_size == 0 {
                sha2 = sha2.update(&[]);
            }

            sha2 = sha2.update(chunk);

            if chunk_size == 0 {
                sha2 = sha2.update(&[]);
            }
        }

        sha2.finalize()
    };

    let expected_hash = {
        let mut digest = CrateSha::new();

        digest = digest.update(input);

        digest.finalize()
    };

    assert!(
        own_hash == expected_hash,
        "input: {input:02X?}\n  own: {own_hash:02X?}\ncrate: {expected_hash:02X?}"
    );
}

#[cfg(miri)]
#[quickcheck]
fn fuzz_against_sha2_crate_sha224_via_quickcheck(input: Vec<u8>, parts: NonZeroUsize) {
    test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
}

#[cfg(miri)]
#[quickcheck]
fn fuzz_against_sha2_crate_sha256_via_quickcheck(input: Vec<u8>, parts: NonZeroUsize) {
    test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
}

#[cfg(miri)]
#[quickcheck]
fn fuzz_against_sha2_crate_sha384_via_quickcheck(input: Vec<u8>, parts: NonZeroUsize) {
    test_against_sha2_crate::<Sha384, sha2::Sha384>(&input, parts);
}

#[cfg(miri)]
#[quickcheck]
fn fuzz_against_sha2_crate_sha512_via_quickcheck(input: Vec<u8>, parts: NonZeroUsize) {
    test_against_sha2_crate::<Sha512, sha2::Sha512>(&input, parts);
}

#[cfg(not(miri))]
proptest! {
    #[test]
    fn fuzz_against_sha2_crate_sha224(input: Vec<u8>, parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_against_sha2_crate_sha256(input: Vec<u8>, parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_against_sha2_crate_sha384(input: Vec<u8>, parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha384, sha2::Sha384>(&input, parts);
    }

    #[test]
    fn fuzz_against_sha2_crate_sha512(input: Vec<u8>, parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha512, sha2::Sha512>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_54(input: [u8; 54], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_55(input: [u8; 55], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_56(input: [u8; 56], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_57(input: [u8; 57], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_63(input: [u8; 63], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_64(input: [u8; 64], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_65(input: [u8; 65], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_118(input: [u8; 118], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_119(input: [u8; 119], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_120(input: [u8; 120], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_121(input: [u8; 121], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_127(input: [u8; 127], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_128(input: [u8; 128], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha224_len_129(input: [u8; 129], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha224, sha2::Sha224>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_54(input: [u8; 54], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_55(input: [u8; 55], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_56(input: [u8; 56], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_57(input: [u8; 57], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_63(input: [u8; 63], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_64(input: [u8; 64], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_65(input: [u8; 65], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_118(input: [u8; 118], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_119(input: [u8; 119], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_120(input: [u8; 120], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_121(input: [u8; 121], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_127(input: [u8; 127], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_128(input: [u8; 128], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }

    #[test]
    fn fuzz_bounds_against_sha2_crate_sha256_len_129(input: [u8; 129], parts: NonZeroUsize) {
        test_against_sha2_crate::<Sha256, sha2::Sha256>(&input, parts);
    }
}

trait Sha2 {
    type Output;

    fn new() -> Self;

    fn update(self, message: &[u8]) -> Self;

    fn finalize(self) -> Self::Output;
}

impl Sha2 for Sha224 {
    type Output = [u8; 28];

    fn new() -> Self {
        Self::new()
    }

    fn update(self, message: &[u8]) -> Self {
        self.update(message).unwrap()
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }
}

impl Sha2 for sha2::Sha224 {
    type Output = <Sha224 as Sha2>::Output;

    fn new() -> Self {
        Digest::new()
    }

    fn update(mut self, message: &[u8]) -> Self {
        Digest::update(&mut self, message);

        self
    }

    fn finalize(self) -> Self::Output {
        Digest::finalize(self).into()
    }
}

impl Sha2 for Sha256 {
    type Output = [u8; 32];

    fn new() -> Self {
        Self::new()
    }

    fn update(self, message: &[u8]) -> Self {
        self.update(message).unwrap()
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }
}

impl Sha2 for sha2::Sha256 {
    type Output = <Sha256 as Sha2>::Output;

    fn new() -> Self {
        Digest::new()
    }

    fn update(mut self, message: &[u8]) -> Self {
        Digest::update(&mut self, message);

        self
    }

    fn finalize(self) -> Self::Output {
        Digest::finalize(self).into()
    }
}

impl Sha2 for Sha384 {
    type Output = [u8; 48];

    fn new() -> Self {
        Self::new()
    }

    fn update(self, message: &[u8]) -> Self {
        self.update(message).unwrap()
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }
}

impl Sha2 for sha2::Sha384 {
    type Output = <Sha384 as Sha2>::Output;

    fn new() -> Self {
        Digest::new()
    }

    fn update(mut self, message: &[u8]) -> Self {
        Digest::update(&mut self, message);

        self
    }

    fn finalize(self) -> Self::Output {
        Digest::finalize(self).into()
    }
}

impl Sha2 for Sha512 {
    type Output = [u8; 64];

    fn new() -> Self {
        Self::new()
    }

    fn update(self, message: &[u8]) -> Self {
        self.update(message).unwrap()
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }
}

impl Sha2 for sha2::Sha512 {
    type Output = <Sha512 as Sha2>::Output;

    fn new() -> Self {
        Digest::new()
    }

    fn update(mut self, message: &[u8]) -> Self {
        Digest::update(&mut self, message);

        self
    }

    fn finalize(self) -> Self::Output {
        Digest::finalize(self).into()
    }
}
