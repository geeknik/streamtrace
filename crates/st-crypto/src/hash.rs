//! Content hashing using BLAKE3 (default) and SHA-256.

use sha2::Digest;

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
}

/// A computed content hash: algorithm identifier plus hex-encoded digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHash {
    pub algorithm: HashAlgorithm,
    pub hex_digest: String,
}

/// Compute the BLAKE3 hash of `data` and return the hex-encoded digest.
pub fn hash_blake3(data: &[u8]) -> ContentHash {
    let hash = blake3::hash(data);
    ContentHash {
        algorithm: HashAlgorithm::Blake3,
        hex_digest: hash.to_hex().to_string(),
    }
}

/// Compute the SHA-256 hash of `data` and return the hex-encoded digest.
pub fn hash_sha256(data: &[u8]) -> ContentHash {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    ContentHash {
        algorithm: HashAlgorithm::Sha256,
        hex_digest: hex::encode(result),
    }
}

/// Hash content using the default algorithm (BLAKE3).
pub fn hash_content(data: &[u8]) -> ContentHash {
    hash_blake3(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Known-answer tests ---

    #[test]
    fn sha256_known_answer_empty() {
        let h = hash_sha256(b"");
        assert_eq!(
            h.hex_digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn sha256_known_answer_streamtrace() {
        let h = hash_sha256(b"streamtrace");
        assert_eq!(
            h.hex_digest,
            "b0e2fe83c1a9f10adfcc8e70bb50d0990392019a3012534a60db7bc2cfdc2dc0"
        );
    }

    #[test]
    fn blake3_known_answer_empty() {
        // BLAKE3 reference: hash of empty input
        let h = hash_blake3(b"");
        assert_eq!(
            h.hex_digest,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(h.algorithm, HashAlgorithm::Blake3);
    }

    // --- Empty input ---

    #[test]
    fn hash_empty_produces_valid_hex() {
        let h = hash_content(b"");
        assert!(!h.hex_digest.is_empty());
        // Must be valid hex
        assert!(hex::decode(&h.hex_digest).is_ok());
    }

    // --- Determinism ---

    #[test]
    fn blake3_deterministic() {
        let a = hash_blake3(b"determinism test");
        let b = hash_blake3(b"determinism test");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_deterministic() {
        let a = hash_sha256(b"determinism test");
        let b = hash_sha256(b"determinism test");
        assert_eq!(a, b);
    }

    // --- hash_content defaults to BLAKE3 ---

    #[test]
    fn hash_content_uses_blake3() {
        let default = hash_content(b"test data");
        let explicit = hash_blake3(b"test data");
        assert_eq!(default, explicit);
    }

    // --- Large input ---

    #[test]
    fn hash_large_input() {
        let data = vec![0xABu8; 1_000_000]; // 1 MB
        let h = hash_blake3(&data);
        assert_eq!(h.hex_digest.len(), 64); // BLAKE3 produces 32 bytes = 64 hex chars
        let h2 = hash_sha256(&data);
        assert_eq!(h2.hex_digest.len(), 64); // SHA-256 also 32 bytes
    }

    // --- Different inputs produce different hashes ---

    #[test]
    fn different_inputs_different_hashes() {
        let a = hash_blake3(b"alpha");
        let b = hash_blake3(b"bravo");
        assert_ne!(a.hex_digest, b.hex_digest);
    }
}
