use sha2::Digest as _;

use compile_time_sha2::{Sha224, Sha256, Sha384, Sha512};

use self::precomputed::PRECOMPUTED;

mod precomputed;

#[test]
fn test_against_sha2_crate_sha224() {
    for (index, input) in PRECOMPUTED
        .iter()
        .map(|precomputed| precomputed.input)
        .enumerate()
    {
        let hash = Sha224::new().update(input).unwrap().finalize();

        let expected_hash: [u8; 28] = {
            let mut digest = sha2::Sha224::new();

            digest.update(input);

            digest.finalize().into()
        };

        assert!(
            hash == expected_hash,
            "input index: {index}\n     actual: {hash:02X?}\n   expected: {expected_hash:02X?}"
        );
    }
}

#[test]
fn test_against_sha2_crate_sha256() {
    for (index, input) in PRECOMPUTED
        .iter()
        .map(|precomputed| precomputed.input)
        .enumerate()
    {
        let hash = Sha256::new().update(input).unwrap().finalize();

        let expected_hash: [u8; 32] = {
            let mut digest = sha2::Sha256::new();

            digest.update(input);

            digest.finalize().into()
        };

        assert!(
            hash == expected_hash,
            "input index: {index}\n     actual: {hash:02X?}\n   expected: {expected_hash:02X?}"
        );
    }
}

#[test]
fn test_against_sha2_crate_sha384() {
    for (index, input) in PRECOMPUTED
        .iter()
        .map(|precomputed| precomputed.input)
        .enumerate()
    {
        let hash = Sha384::new().update(input).unwrap().finalize();

        let expected_hash: [u8; 48] = {
            let mut digest = sha2::Sha384::new();

            digest.update(input);

            digest.finalize().into()
        };

        assert!(
            hash == expected_hash,
            "input index: {index}\n     actual: {hash:02X?}\n   expected: {expected_hash:02X?}"
        );
    }
}

#[test]
fn test_against_sha2_crate_sha512() {
    for (index, input) in PRECOMPUTED
        .iter()
        .map(|precomputed| precomputed.input)
        .enumerate()
    {
        let hash = Sha512::new().update(input).unwrap().finalize();

        let expected_hash: [u8; 64] = {
            let mut digest = sha2::Sha512::new();

            digest.update(input);

            digest.finalize().into()
        };

        assert!(
            hash == expected_hash,
            "input index: {index}\n     actual: {hash:02X?}\n   expected: {expected_hash:02X?}"
        );
    }
}
