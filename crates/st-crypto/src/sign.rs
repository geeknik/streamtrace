//! Ed25519 signing and signature verification for evidence bundles.
//!
//! Uses `ed25519-dalek` for signing operations. Keys are generated using
//! OS-provided randomness via `rand::rngs::OsRng`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// An Ed25519 key pair for signing evidence bundles.
///
/// The signing key is held in memory. For persistent storage, use
/// [`SigningKeyPair::secret_key_bytes`] and encrypt the output before
/// writing to disk.
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

/// Public key metadata for export and verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Algorithm identifier, always "Ed25519".
    pub algorithm: String,
    /// Hex-encoded 32-byte public key.
    pub public_key_hex: String,
}

/// A detached signature with enough metadata for independent verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetachedSignature {
    /// Algorithm identifier, always "Ed25519".
    pub algorithm: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub signature_hex: String,
    /// Hex-encoded 32-byte public key of the signer.
    pub public_key_hex: String,
    /// ISO 8601 timestamp of when the signature was created.
    pub signed_at: String,
}

impl SigningKeyPair {
    /// Generate a new random key pair using OS-provided randomness.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Reconstruct a key pair from a 32-byte secret key.
    ///
    /// Use this after decrypting a stored secret key.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Returns the public key info for export or embedding in bundles.
    pub fn public_key_info(&self) -> PublicKeyInfo {
        let verifying_key = self.signing_key.verifying_key();
        PublicKeyInfo {
            algorithm: "Ed25519".to_string(),
            public_key_hex: hex::encode(verifying_key.as_bytes()),
        }
    }

    /// Sign `data` and return a detached signature with metadata.
    ///
    /// The signature covers the raw bytes of `data`. The caller is
    /// responsible for ensuring `data` is the canonical serialization
    /// of whatever is being signed (e.g., the integrity chain JSON).
    pub fn sign(&self, data: &[u8]) -> DetachedSignature {
        let signature = self.signing_key.sign(data);
        let verifying_key = self.signing_key.verifying_key();

        DetachedSignature {
            algorithm: "Ed25519".to_string(),
            signature_hex: hex::encode(signature.to_bytes()),
            public_key_hex: hex::encode(verifying_key.as_bytes()),
            signed_at: chrono_now_iso8601(),
        }
    }

    /// Export the 32-byte secret key for encrypted storage.
    ///
    /// The caller MUST encrypt these bytes before persisting them.
    /// Never log or transmit the return value in plaintext.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Verify a detached Ed25519 signature against `data`.
///
/// Decodes the public key and signature from hex, then verifies.
/// Returns `Ok(true)` if valid, `Ok(false)` if the signature does not
/// match, or `Err` if the hex encoding or key format is invalid.
pub fn verify_signature(data: &[u8], signature: &DetachedSignature) -> Result<bool, String> {
    if signature.algorithm != "Ed25519" {
        return Err(format!("unsupported algorithm: {}", signature.algorithm));
    }

    let pub_bytes = hex::decode(&signature.public_key_hex)
        .map_err(|e| format!("invalid public key hex: {e}"))?;

    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes".to_string())?;

    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).map_err(|e| format!("invalid public key: {e}"))?;

    let sig_bytes =
        hex::decode(&signature.signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be exactly 64 bytes".to_string())?;

    let sig = Signature::from_bytes(&sig_array);

    match verifying_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Returns the current UTC time as an ISO 8601 string.
///
/// Uses a standalone function to keep signing logic testable without
/// mocking time.
fn chrono_now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify_round_trip() {
        let kp = SigningKeyPair::generate();
        let data = b"evidence bundle integrity chain";
        let sig = kp.sign(data);

        let result = verify_signature(data, &sig).expect("verification should not error");
        assert!(result, "valid signature should verify");
    }

    #[test]
    fn tampered_data_fails_verification() {
        let kp = SigningKeyPair::generate();
        let data = b"original data";
        let sig = kp.sign(data);

        let tampered = b"tampered data";
        let result = verify_signature(tampered, &sig).expect("verification should not error");
        assert!(!result, "tampered data should not verify");
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let kp = SigningKeyPair::generate();
        let data = b"authentic data";
        let mut sig = kp.sign(data);

        // Flip a byte in the signature hex
        let mut sig_bytes = hex::decode(&sig.signature_hex).unwrap();
        sig_bytes[0] ^= 0xFF;
        sig.signature_hex = hex::encode(&sig_bytes);

        let result = verify_signature(data, &sig).expect("verification should not error");
        assert!(!result, "tampered signature should not verify");
    }

    #[test]
    fn signature_serialization_round_trip() {
        let kp = SigningKeyPair::generate();
        let sig = kp.sign(b"test data");

        let json = serde_json::to_string(&sig).expect("serialize");
        let deserialized: DetachedSignature = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(sig, deserialized);
    }

    #[test]
    fn public_key_serialization_round_trip() {
        let kp = SigningKeyPair::generate();
        let pk = kp.public_key_info();

        let json = serde_json::to_string(&pk).expect("serialize");
        let deserialized: PublicKeyInfo = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(pk, deserialized);
        assert_eq!(pk.algorithm, "Ed25519");
        assert_eq!(pk.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn from_bytes_round_trip() {
        let kp = SigningKeyPair::generate();
        let secret = kp.secret_key_bytes();

        let kp2 = SigningKeyPair::from_bytes(&secret);

        // Same key should produce same public key
        assert_eq!(kp.public_key_info(), kp2.public_key_info());

        // Signature from restored key should verify
        let data = b"round trip test";
        let sig = kp2.sign(data);
        let result = verify_signature(data, &sig).expect("should not error");
        assert!(result);
    }

    #[test]
    fn wrong_public_key_fails() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();

        let data = b"signed by kp1";
        let mut sig = kp1.sign(data);

        // Replace public key with kp2's key
        sig.public_key_hex = kp2.public_key_info().public_key_hex;

        let result = verify_signature(data, &sig).expect("should not error");
        assert!(!result, "wrong public key should not verify");
    }

    #[test]
    fn invalid_hex_returns_error() {
        let sig = DetachedSignature {
            algorithm: "Ed25519".to_string(),
            signature_hex: "not_valid_hex!".to_string(),
            public_key_hex: "also_invalid".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let result = verify_signature(b"data", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_algorithm_returns_error() {
        let sig = DetachedSignature {
            algorithm: "RSA-2048".to_string(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
            signed_at: String::new(),
        };

        let result = verify_signature(b"data", &sig);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported algorithm"));
    }

    #[test]
    fn empty_data_sign_verify() {
        let kp = SigningKeyPair::generate();
        let sig = kp.sign(b"");
        let result = verify_signature(b"", &sig).expect("should not error");
        assert!(result);
    }

    #[test]
    fn large_data_sign_verify() {
        let kp = SigningKeyPair::generate();
        let data = vec![0xABu8; 1_000_000];
        let sig = kp.sign(&data);
        let result = verify_signature(&data, &sig).expect("should not error");
        assert!(result);
    }

    #[test]
    fn detached_signature_fields_populated() {
        let kp = SigningKeyPair::generate();
        let sig = kp.sign(b"test");

        assert_eq!(sig.algorithm, "Ed25519");
        assert_eq!(sig.signature_hex.len(), 128); // 64 bytes = 128 hex chars
        assert_eq!(sig.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(!sig.signed_at.is_empty());
    }
}
