//! Hash verification with constant-time comparison.

use subtle::ConstantTimeEq;

use crate::hash::{hash_blake3, hash_sha256, ContentHash, HashAlgorithm};

/// Recompute the hash of `data` using the same algorithm stored in `expected`,
/// then compare digests in constant time.
pub fn verify_hash(data: &[u8], expected: &ContentHash) -> bool {
    let computed = match expected.algorithm {
        HashAlgorithm::Blake3 => hash_blake3(data),
        HashAlgorithm::Sha256 => hash_sha256(data),
    };
    constant_time_eq(
        computed.hex_digest.as_bytes(),
        expected.hex_digest.as_bytes(),
    )
}

/// Verify that `data` hashes to `expected_hex` under BLAKE3.
pub fn verify_blake3(data: &[u8], expected_hex: &str) -> bool {
    let computed = hash_blake3(data);
    constant_time_eq(computed.hex_digest.as_bytes(), expected_hex.as_bytes())
}

/// Verify that `data` hashes to `expected_hex` under SHA-256.
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> bool {
    let computed = hash_sha256(data);
    constant_time_eq(computed.hex_digest.as_bytes(), expected_hex.as_bytes())
}

/// Constant-time byte comparison using the `subtle` crate.
/// Handles length differences without leaking length via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_blake3, hash_content, hash_sha256};

    // --- Round-trip: hash then verify returns true ---

    #[test]
    fn round_trip_blake3() {
        let data = b"round trip blake3";
        let h = hash_blake3(data);
        assert!(verify_hash(data, &h));
    }

    #[test]
    fn round_trip_sha256() {
        let data = b"round trip sha256";
        let h = hash_sha256(data);
        assert!(verify_hash(data, &h));
    }

    #[test]
    fn round_trip_default() {
        let data = b"round trip default";
        let h = hash_content(data);
        assert!(verify_hash(data, &h));
    }

    #[test]
    fn round_trip_verify_blake3_fn() {
        let data = b"verify_blake3 round trip";
        let h = hash_blake3(data);
        assert!(verify_blake3(data, &h.hex_digest));
    }

    #[test]
    fn round_trip_verify_sha256_fn() {
        let data = b"verify_sha256 round trip";
        let h = hash_sha256(data);
        assert!(verify_sha256(data, &h.hex_digest));
    }

    // --- Tampered data ---

    #[test]
    fn tampered_data_blake3() {
        let data = b"original data";
        let h = hash_blake3(data);
        let mut tampered = data.to_vec();
        tampered[0] ^= 0x01; // flip one bit
        assert!(!verify_hash(&tampered, &h));
    }

    #[test]
    fn tampered_data_sha256() {
        let data = b"original data";
        let h = hash_sha256(data);
        let mut tampered = data.to_vec();
        tampered[data.len() - 1] ^= 0xFF;
        assert!(!verify_hash(&tampered, &h));
    }

    #[test]
    fn tampered_hash_rejected() {
        let data = b"authentic content";
        let mut h = hash_blake3(data);
        // Corrupt one character of the digest
        let mut chars: Vec<u8> = h.hex_digest.into_bytes();
        chars[0] ^= 0x01;
        h.hex_digest = String::from_utf8(chars).unwrap();
        assert!(!verify_hash(data, &h));
    }

    // --- Empty input ---

    #[test]
    fn verify_empty_input() {
        let h = hash_blake3(b"");
        assert!(verify_hash(b"", &h));
        assert!(!verify_hash(b"\x00", &h));
    }

    // --- Large input ---

    #[test]
    fn verify_large_input() {
        let data = vec![0x42u8; 1_000_000];
        let h = hash_blake3(&data);
        assert!(verify_hash(&data, &h));
    }

    // --- Constant-time comparison unit tests ---

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // --- Wrong algorithm digest should fail ---

    #[test]
    fn cross_algorithm_mismatch() {
        let data = b"cross algo test";
        let blake3_hash = hash_blake3(data);
        let sha256_hash = hash_sha256(data);
        // The digests from different algorithms should differ
        assert_ne!(blake3_hash.hex_digest, sha256_hash.hex_digest);
        // Verify with wrong algorithm embedded should still fail
        // because the recomputed hash uses the algorithm from the ContentHash
        let fake = ContentHash {
            algorithm: HashAlgorithm::Blake3,
            hex_digest: sha256_hash.hex_digest.clone(),
        };
        assert!(!verify_hash(data, &fake));
    }

    // --- Property tests ---

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn blake3_hash_then_verify(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let h = hash_blake3(&data);
                prop_assert!(verify_hash(&data, &h));
            }

            #[test]
            fn sha256_hash_then_verify(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let h = hash_sha256(&data);
                prop_assert!(verify_hash(&data, &h));
            }

            #[test]
            fn default_hash_then_verify(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let h = hash_content(&data);
                prop_assert!(verify_hash(&data, &h));
            }

            #[test]
            fn blake3_digest_is_valid_hex(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let h = hash_blake3(&data);
                prop_assert!(hex::decode(&h.hex_digest).is_ok());
                prop_assert_eq!(h.hex_digest.len(), 64);
            }

            #[test]
            fn sha256_digest_is_valid_hex(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let h = hash_sha256(&data);
                prop_assert!(hex::decode(&h.hex_digest).is_ok());
                prop_assert_eq!(h.hex_digest.len(), 64);
            }
        }
    }
}
