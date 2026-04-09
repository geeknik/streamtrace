//! Cryptographic operations for StreamTrace.
//!
//! Provides content hashing (BLAKE3, SHA-256), integrity verification,
//! and Ed25519 signing for evidence bundles.

pub mod hash;
pub mod sign;
pub mod verify;

pub use hash::{hash_blake3, hash_sha256, ContentHash, HashAlgorithm};
pub use sign::{verify_signature, DetachedSignature, PublicKeyInfo, SigningKeyPair};
pub use verify::{verify_blake3, verify_hash, verify_sha256};
