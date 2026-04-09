//! Signed evidence bundle generation and verification.
//!
//! An evidence bundle is a self-contained, cryptographically signed
//! package of case data suitable for legal proceedings. It includes:
//!
//! - A manifest describing the case and generation metadata
//! - Normalized forensic events as JSON
//! - Raw event content (base64-encoded)
//! - Per-file BLAKE3 integrity hashes
//! - A linear hash chain (simplified Merkle) for tamper detection
//! - An Ed25519 detached signature over the chain
//!
//! Verification recomputes all hashes and checks the signature,
//! providing a clear pass/fail for each integrity layer.
//!
//! All database reads during bundle generation execute within a single
//! REPEATABLE READ transaction to guarantee snapshot consistency. This
//! ensures the bundle reflects a consistent point-in-time view of the
//! case data, even if concurrent ingestion or case updates are occurring.

use base64::Engine;
use serde::{Deserialize, Serialize};
use st_common::error::{StError, StResult};
use st_common::types::CaseId;
use st_crypto::{hash_blake3, verify_signature, DetachedSignature, PublicKeyInfo, SigningKeyPair};
use st_store::cases::{case_event_from_row, case_from_row};
use st_store::events::forensic_event_from_row;
use st_store::raw_events::raw_event_from_row;
use st_store::Database;

// ---------------------------------------------------------------------------
// Bundle data structures
// ---------------------------------------------------------------------------

/// Top-level manifest embedded in every evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Schema version of the bundle format.
    pub bundle_version: String,
    /// UUID of the investigation case.
    pub case_id: String,
    /// Human-readable case name.
    pub case_name: String,
    /// Number of forensic events included.
    pub event_count: usize,
    /// Time range spanned by the included events, if any.
    pub time_range: Option<TimeRange>,
    /// ISO 8601 timestamp of bundle generation.
    pub generated_at: String,
    /// Identifier of the software that produced this bundle.
    pub generator: String,
}

/// Inclusive time range for events in a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// ISO 8601 start timestamp.
    pub start: String,
    /// ISO 8601 end timestamp.
    pub end: String,
}

/// Per-file integrity record (one per logical file in the bundle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrity {
    /// Relative path within the bundle (logical, not filesystem).
    pub path: String,
    /// Hash algorithm used, always "BLAKE3".
    pub hash_algorithm: String,
    /// Hex-encoded hash digest.
    pub hash_hex: String,
    /// Size of the content in bytes.
    pub size_bytes: usize,
}

/// Linear hash chain over all file hashes for tamper detection.
///
/// The root hash is BLAKE3(concatenation of all file hash hex strings).
/// A full Merkle tree is not needed here because the file count is
/// bounded by case event limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityChain {
    /// Hash algorithm, always "BLAKE3".
    pub algorithm: String,
    /// Ordered hex hashes of all files in the bundle.
    pub file_hashes: Vec<String>,
    /// BLAKE3 hash of the concatenated file hashes.
    pub root_hash: String,
}

/// A raw event entry within an evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBundleEntry {
    /// Identifier of the raw event.
    pub raw_event_id: String,
    /// BLAKE3 hash of the raw content.
    pub content_hash: String,
    /// MIME type of the raw content.
    pub content_type: String,
    /// Base64-encoded raw bytes.
    pub content_base64: String,
}

/// A complete signed evidence bundle (in-memory representation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Bundle manifest with case metadata.
    pub manifest: BundleManifest,
    /// Normalized forensic events as JSON values.
    pub events: Vec<serde_json::Value>,
    /// Raw event content entries.
    pub raw_events: Vec<RawBundleEntry>,
    /// Per-file integrity records.
    pub integrity: Vec<FileIntegrity>,
    /// Hash chain over all integrity records.
    pub chain: IntegrityChain,
    /// Ed25519 signature over the serialized chain.
    pub signature: DetachedSignature,
    /// Public key of the signer.
    pub public_key: PublicKeyInfo,
}

/// Result of verifying an evidence bundle.
#[derive(Debug, Clone, Serialize)]
pub struct BundleVerification {
    /// Whether all per-file hashes match recomputed values.
    pub integrity_valid: bool,
    /// Whether the root hash matches the recomputed chain.
    pub chain_valid: bool,
    /// Whether the Ed25519 signature is valid.
    pub signature_valid: bool,
    /// Human-readable explanations for each check.
    pub details: Vec<String>,
}

// ---------------------------------------------------------------------------
// Bundle building
// ---------------------------------------------------------------------------

/// Map a sqlx error to `StError::Database` (local helper to avoid
/// depending on the crate-private `map_sqlx_err` in st-store).
fn map_sqlx_err(e: sqlx::Error) -> StError {
    tracing::error!(error = %e, "database query failed (bundle)");
    StError::Database(e.to_string())
}

/// Build a signed evidence bundle for the given case.
///
/// All database reads execute within a single REPEATABLE READ transaction
/// to guarantee snapshot consistency. This ensures the bundle reflects a
/// consistent point-in-time view of the case data.
///
/// Fetches all case events and their raw events from the database,
/// computes integrity hashes, builds a hash chain, and signs it.
pub async fn build_evidence_bundle(
    db: &Database,
    signing_key: &SigningKeyPair,
    case_id: CaseId,
) -> StResult<EvidenceBundle> {
    // Begin a REPEATABLE READ transaction for snapshot-consistent reads.
    let mut tx = db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

    // 1. Fetch the case
    let case_row = sqlx::query(
        r#"
        SELECT id, name, description, status, created_by, created_at, updated_at
        FROM cases
        WHERE id = $1
        "#,
    )
    .bind(case_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx_err)?;

    let case = match case_row {
        Some(row) => case_from_row(&row),
        None => return Err(StError::NotFound(format!("case {case_id} not found"))),
    };

    // 2. Fetch all case events
    let case_event_rows = sqlx::query(
        r#"
        SELECT id, case_id, event_id, pinned, annotation, added_at, added_by
        FROM case_events
        WHERE case_id = $1
        ORDER BY added_at ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_sqlx_err)?;

    let case_events: Vec<_> = case_event_rows.iter().map(case_event_from_row).collect();

    let mut events_json: Vec<serde_json::Value> = Vec::with_capacity(case_events.len());
    let mut raw_entries: Vec<RawBundleEntry> = Vec::with_capacity(case_events.len());
    let mut integrity: Vec<FileIntegrity> = Vec::new();
    let mut earliest: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut latest: Option<chrono::DateTime<chrono::Utc>> = None;

    for ce in &case_events {
        // Fetch the normalized event within the transaction.
        let event_row = sqlx::query(
            r#"
            SELECT id, raw_event_id, event_type, severity,
                   occurred_at, observed_at, received_at,
                   actor_id, actor_name, actor_type,
                   subject_id, subject_name, subject_type,
                   object_id, object_name, object_type,
                   host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
                   src_port, dst_port, protocol,
                   device_id, device_name, device_type, hostname,
                   source_id, source_type, source_name,
                   tags, custom_fields
            FROM events
            WHERE id = $1
            "#,
        )
        .bind(ce.event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

        let event = match event_row {
            Some(row) => forensic_event_from_row(&row),
            None => {
                return Err(StError::NotFound(format!(
                    "event {} not found",
                    ce.event_id
                )))
            }
        };

        // Track time range
        match earliest {
            None => earliest = Some(event.occurred_at),
            Some(e) if event.occurred_at < e => earliest = Some(event.occurred_at),
            _ => {}
        }
        match latest {
            None => latest = Some(event.occurred_at),
            Some(l) if event.occurred_at > l => latest = Some(event.occurred_at),
            _ => {}
        }

        // Serialize event to JSON
        let event_json = serde_json::to_value(&event)
            .map_err(|e| StError::Internal(format!("failed to serialize event: {e}")))?;
        let event_bytes = serde_json::to_vec(&event_json)
            .map_err(|e| StError::Internal(format!("failed to serialize event bytes: {e}")))?;

        // File integrity for this event
        let event_hash = hash_blake3(&event_bytes);
        let event_path = format!("events/{}.json", event.id);
        integrity.push(FileIntegrity {
            path: event_path,
            hash_algorithm: "BLAKE3".to_string(),
            hash_hex: event_hash.hex_digest.clone(),
            size_bytes: event_bytes.len(),
        });

        events_json.push(event_json);

        // Fetch raw event within the transaction
        let raw_row = sqlx::query(
            r#"
            SELECT id, content, content_hash, content_type, source_id, source_type,
                   source_name, received_at, parser_id, byte_size
            FROM raw_events
            WHERE id = $1
            "#,
        )
        .bind(event.raw_event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

        let raw_event = match raw_row {
            Some(row) => raw_event_from_row(&row),
            None => {
                return Err(StError::NotFound(format!(
                    "raw event {} not found",
                    event.raw_event_id
                )))
            }
        };

        let raw_hash = hash_blake3(&raw_event.content);
        let raw_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_event.content);

        let raw_path = format!("raw/{}.bin", raw_event.id);
        integrity.push(FileIntegrity {
            path: raw_path,
            hash_algorithm: "BLAKE3".to_string(),
            hash_hex: raw_hash.hex_digest.clone(),
            size_bytes: raw_event.content.len(),
        });

        raw_entries.push(RawBundleEntry {
            raw_event_id: raw_event.id.to_string(),
            content_hash: raw_hash.hex_digest,
            content_type: raw_event.content_type.clone(),
            content_base64: raw_b64,
        });
    }

    // Commit the read-only transaction (releases the snapshot).
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit bundle read transaction");
        StError::Database(format!("commit failed: {e}"))
    })?;

    // 3. Build manifest
    let time_range = match (earliest, latest) {
        (Some(start), Some(end)) => Some(TimeRange {
            start: start.to_rfc3339(),
            end: end.to_rfc3339(),
        }),
        _ => None,
    };

    let manifest = BundleManifest {
        bundle_version: "1.0".to_string(),
        case_id: case.id.to_string(),
        case_name: case.name.clone(),
        event_count: events_json.len(),
        time_range,
        generated_at: chrono::Utc::now().to_rfc3339(),
        generator: format!("StreamTrace v{}", env!("CARGO_PKG_VERSION")),
    };

    // 4. Manifest integrity
    let manifest_bytes = serde_json::to_vec(&manifest)
        .map_err(|e| StError::Internal(format!("failed to serialize manifest: {e}")))?;
    let manifest_hash = hash_blake3(&manifest_bytes);
    integrity.push(FileIntegrity {
        path: "manifest.json".to_string(),
        hash_algorithm: "BLAKE3".to_string(),
        hash_hex: manifest_hash.hex_digest.clone(),
        size_bytes: manifest_bytes.len(),
    });

    // 5. Build integrity chain
    let file_hashes: Vec<String> = integrity.iter().map(|fi| fi.hash_hex.clone()).collect();
    let concatenated = file_hashes.join("");
    let root = hash_blake3(concatenated.as_bytes());

    let chain = IntegrityChain {
        algorithm: "BLAKE3".to_string(),
        file_hashes,
        root_hash: root.hex_digest,
    };

    // 6. Sign the chain
    let chain_json = serde_json::to_vec(&chain)
        .map_err(|e| StError::Internal(format!("failed to serialize chain: {e}")))?;
    let signature = signing_key.sign(&chain_json);
    let public_key = signing_key.public_key_info();

    Ok(EvidenceBundle {
        manifest,
        events: events_json,
        raw_events: raw_entries,
        integrity,
        chain,
        signature,
        public_key,
    })
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

/// Verify an evidence bundle's integrity, chain, and signature.
///
/// Returns a detailed verification result indicating which checks
/// passed and which failed.
pub fn verify_bundle(bundle: &EvidenceBundle) -> BundleVerification {
    let mut details = Vec::new();
    let mut integrity_valid = true;
    let mut chain_valid = true;

    // 1. Verify the integrity chain: recompute root hash from file_hashes
    let concatenated = bundle.chain.file_hashes.join("");
    let recomputed_root = hash_blake3(concatenated.as_bytes());

    if recomputed_root.hex_digest != bundle.chain.root_hash {
        chain_valid = false;
        details.push(format!(
            "chain root hash mismatch: expected {}, got {}",
            bundle.chain.root_hash, recomputed_root.hex_digest
        ));
    } else {
        details.push("chain root hash verified".to_string());
    }

    // 2. Verify that the integrity file_hashes match the chain's file_hashes
    let integrity_hashes: Vec<&str> = bundle
        .integrity
        .iter()
        .map(|fi| fi.hash_hex.as_str())
        .collect();
    let chain_hashes: Vec<&str> = bundle
        .chain
        .file_hashes
        .iter()
        .map(|h| h.as_str())
        .collect();

    if integrity_hashes != chain_hashes {
        integrity_valid = false;
        details.push("integrity hashes do not match chain file_hashes".to_string());
    } else {
        details.push(format!(
            "all {} file integrity records match chain",
            bundle.integrity.len()
        ));
    }

    // 3. Verify that event content hashes match their integrity records
    for (i, event_json) in bundle.events.iter().enumerate() {
        let event_bytes = match serde_json::to_vec(event_json) {
            Ok(b) => b,
            Err(e) => {
                integrity_valid = false;
                details.push(format!("failed to serialize event {i}: {e}"));
                continue;
            }
        };

        let computed = hash_blake3(&event_bytes);
        // Find corresponding integrity record
        if let Some(fi) = bundle.integrity.get(i * 2) {
            // Events are at even indices (event, raw, event, raw, ..., manifest)
            if computed.hex_digest != fi.hash_hex {
                integrity_valid = false;
                details.push(format!(
                    "event hash mismatch at {}: expected {}, got {}",
                    fi.path, fi.hash_hex, computed.hex_digest
                ));
            }
        }
    }

    // 4. Verify raw event content hashes
    for (i, raw_entry) in bundle.raw_events.iter().enumerate() {
        let raw_bytes =
            match base64::engine::general_purpose::STANDARD.decode(&raw_entry.content_base64) {
                Ok(b) => b,
                Err(e) => {
                    integrity_valid = false;
                    details.push(format!("failed to decode raw event {i} base64: {e}"));
                    continue;
                }
            };

        let computed = hash_blake3(&raw_bytes);
        if computed.hex_digest != raw_entry.content_hash {
            integrity_valid = false;
            details.push(format!(
                "raw event {} hash mismatch: expected {}, got {}",
                raw_entry.raw_event_id, raw_entry.content_hash, computed.hex_digest
            ));
        }
    }

    // 5. Verify the signature over the chain
    let chain_json = match serde_json::to_vec(&bundle.chain) {
        Ok(b) => b,
        Err(e) => {
            details.push(format!("failed to serialize chain for verification: {e}"));
            return BundleVerification {
                integrity_valid,
                chain_valid,
                signature_valid: false,
                details,
            };
        }
    };

    let signature_valid = match verify_signature(&chain_json, &bundle.signature) {
        Ok(valid) => {
            if valid {
                details.push("Ed25519 signature verified".to_string());
            } else {
                details.push("Ed25519 signature INVALID".to_string());
            }
            valid
        }
        Err(e) => {
            details.push(format!("signature verification error: {e}"));
            false
        }
    };

    BundleVerification {
        integrity_valid,
        chain_valid,
        signature_valid,
        details,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid bundle in-memory without a database.
    fn make_test_bundle() -> EvidenceBundle {
        let kp = SigningKeyPair::generate();

        let event_json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "event_type": "auth.login.failure",
            "severity": "High",
            "occurred_at": "2026-01-01T00:00:00Z"
        });
        let event_bytes = serde_json::to_vec(&event_json).unwrap();
        let event_hash = hash_blake3(&event_bytes);

        let raw_content = b"raw log line: failed login from 10.0.0.1";
        let raw_hash = hash_blake3(raw_content);
        let raw_b64 = base64::engine::general_purpose::STANDARD.encode(raw_content);

        let manifest = BundleManifest {
            bundle_version: "1.0".to_string(),
            case_id: "00000000-0000-0000-0000-000000000099".to_string(),
            case_name: "Test Case".to_string(),
            event_count: 1,
            time_range: Some(TimeRange {
                start: "2026-01-01T00:00:00Z".to_string(),
                end: "2026-01-01T00:00:00Z".to_string(),
            }),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            generator: format!("StreamTrace v{}", env!("CARGO_PKG_VERSION")),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hash = hash_blake3(&manifest_bytes);

        let integrity = vec![
            FileIntegrity {
                path: "events/00000000-0000-0000-0000-000000000001.json".to_string(),
                hash_algorithm: "BLAKE3".to_string(),
                hash_hex: event_hash.hex_digest.clone(),
                size_bytes: event_bytes.len(),
            },
            FileIntegrity {
                path: "raw/00000000-0000-0000-0000-000000000002.bin".to_string(),
                hash_algorithm: "BLAKE3".to_string(),
                hash_hex: raw_hash.hex_digest.clone(),
                size_bytes: raw_content.len(),
            },
            FileIntegrity {
                path: "manifest.json".to_string(),
                hash_algorithm: "BLAKE3".to_string(),
                hash_hex: manifest_hash.hex_digest.clone(),
                size_bytes: manifest_bytes.len(),
            },
        ];

        let file_hashes: Vec<String> = integrity.iter().map(|fi| fi.hash_hex.clone()).collect();
        let concatenated = file_hashes.join("");
        let root = hash_blake3(concatenated.as_bytes());

        let chain = IntegrityChain {
            algorithm: "BLAKE3".to_string(),
            file_hashes,
            root_hash: root.hex_digest,
        };

        let chain_json = serde_json::to_vec(&chain).unwrap();
        let signature = kp.sign(&chain_json);
        let public_key = kp.public_key_info();

        EvidenceBundle {
            manifest,
            events: vec![event_json],
            raw_events: vec![RawBundleEntry {
                raw_event_id: "00000000-0000-0000-0000-000000000002".to_string(),
                content_hash: raw_hash.hex_digest,
                content_type: "text/plain".to_string(),
                content_base64: raw_b64,
            }],
            integrity,
            chain,
            signature,
            public_key,
        }
    }

    #[test]
    fn valid_bundle_passes_verification() {
        let bundle = make_test_bundle();
        let result = verify_bundle(&bundle);

        assert!(result.integrity_valid, "integrity: {:?}", result.details);
        assert!(result.chain_valid, "chain: {:?}", result.details);
        assert!(result.signature_valid, "signature: {:?}", result.details);
    }

    #[test]
    fn tampered_event_fails_integrity() {
        let mut bundle = make_test_bundle();

        // Tamper with the event content
        bundle.events[0] = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "event_type": "auth.login.success",
            "severity": "Low",
            "occurred_at": "2026-01-01T00:00:00Z"
        });

        let result = verify_bundle(&bundle);
        assert!(
            !result.integrity_valid,
            "tampered event should fail integrity"
        );
    }

    #[test]
    fn tampered_chain_root_fails_chain_check() {
        let mut bundle = make_test_bundle();

        // Tamper with the root hash
        bundle.chain.root_hash = "0".repeat(64);

        let result = verify_bundle(&bundle);
        assert!(!result.chain_valid, "tampered root should fail chain check");
    }

    #[test]
    fn tampered_chain_fails_signature() {
        let mut bundle = make_test_bundle();

        // Tamper with a file hash in the chain (which changes the chain JSON
        // that was signed, so the signature should fail)
        if let Some(h) = bundle.chain.file_hashes.first_mut() {
            let mut bytes = hex::decode(&*h).unwrap();
            bytes[0] ^= 0xFF;
            *h = hex::encode(&bytes);
        }

        // Recompute root to keep chain internally consistent but
        // the signature was over the original chain
        let concatenated = bundle.chain.file_hashes.join("");
        let root = hash_blake3(concatenated.as_bytes());
        bundle.chain.root_hash = root.hex_digest;

        let result = verify_bundle(&bundle);
        assert!(
            !result.signature_valid,
            "tampered chain should invalidate signature"
        );
    }

    #[test]
    fn tampered_raw_event_fails_integrity() {
        let mut bundle = make_test_bundle();

        // Tamper with raw event base64 content
        bundle.raw_events[0].content_base64 =
            base64::engine::general_purpose::STANDARD.encode(b"tampered content");

        let result = verify_bundle(&bundle);
        assert!(
            !result.integrity_valid,
            "tampered raw event should fail integrity"
        );
    }

    #[test]
    fn bundle_serialization_round_trip() {
        let bundle = make_test_bundle();
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let deserialized: EvidenceBundle = serde_json::from_str(&json).unwrap();

        // Re-verify the deserialized bundle
        let result = verify_bundle(&deserialized);
        assert!(result.integrity_valid);
        assert!(result.chain_valid);
        assert!(result.signature_valid);
    }

    #[test]
    fn empty_bundle_verifies() {
        let kp = SigningKeyPair::generate();

        let manifest = BundleManifest {
            bundle_version: "1.0".to_string(),
            case_id: "00000000-0000-0000-0000-000000000099".to_string(),
            case_name: "Empty Case".to_string(),
            event_count: 0,
            time_range: None,
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            generator: format!("StreamTrace v{}", env!("CARGO_PKG_VERSION")),
        };

        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hash = hash_blake3(&manifest_bytes);

        let integrity = vec![FileIntegrity {
            path: "manifest.json".to_string(),
            hash_algorithm: "BLAKE3".to_string(),
            hash_hex: manifest_hash.hex_digest.clone(),
            size_bytes: manifest_bytes.len(),
        }];

        let file_hashes = vec![manifest_hash.hex_digest.clone()];
        let root = hash_blake3(file_hashes.join("").as_bytes());

        let chain = IntegrityChain {
            algorithm: "BLAKE3".to_string(),
            file_hashes,
            root_hash: root.hex_digest,
        };

        let chain_json = serde_json::to_vec(&chain).unwrap();
        let signature = kp.sign(&chain_json);
        let public_key = kp.public_key_info();

        let bundle = EvidenceBundle {
            manifest,
            events: vec![],
            raw_events: vec![],
            integrity,
            chain,
            signature,
            public_key,
        };

        let result = verify_bundle(&bundle);
        assert!(result.integrity_valid);
        assert!(result.chain_valid);
        assert!(result.signature_valid);
    }

    #[test]
    fn manifest_fields_populated() {
        let bundle = make_test_bundle();
        assert_eq!(bundle.manifest.bundle_version, "1.0");
        assert_eq!(bundle.manifest.event_count, 1);
        assert!(bundle.manifest.time_range.is_some());
        assert!(
            bundle.manifest.generator.starts_with("StreamTrace v"),
            "generator should include version: {}",
            bundle.manifest.generator
        );
    }

    #[test]
    fn integrity_chain_hash_count_matches() {
        let bundle = make_test_bundle();
        assert_eq!(bundle.integrity.len(), bundle.chain.file_hashes.len());
    }
}
