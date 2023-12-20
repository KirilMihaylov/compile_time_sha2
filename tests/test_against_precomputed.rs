use compile_time_sha2::{Sha224, Sha256, Sha384, Sha512};

use self::precomputed::PRECOMPUTED;

mod precomputed;

#[test]
fn test_against_precomputed() {
    for (index, precomputed) in PRECOMPUTED.iter().enumerate() {
        let hash = Sha224::new().update(precomputed.input).unwrap().finalize();

        assert!(
            hash == precomputed.sha224,
            "algorithm: SHA224\ninput index: {index}\n  actual: {hash:02X?}\nexpected: {expected_hash:02X?}",
            expected_hash = precomputed.sha224,
        );

        let hash = Sha256::new().update(precomputed.input).unwrap().finalize();

        assert!(
            hash == precomputed.sha256,
            "algorithm: SHA256\ninput index: {index}\n  actual: {hash:02X?}\nexpected: {expected_hash:02X?}",
            expected_hash = precomputed.sha256,
        );

        let hash = Sha384::new().update(precomputed.input).unwrap().finalize();

        assert!(
            hash == precomputed.sha384,
            "algorithm: SHA384\ninput index: {index}\n  actual: {hash:02X?}\nexpected: {expected_hash:02X?}",
            expected_hash = precomputed.sha384,
        );

        let hash = Sha512::new().update(precomputed.input).unwrap().finalize();

        assert!(
            hash == precomputed.sha512,
            "algorithm: SHA512\ninput index: {index}\n  actual: {hash:02X?}\nexpected: {expected_hash:02X?}",
            expected_hash = precomputed.sha512,
        );
    }
}
