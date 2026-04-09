//! Core type aliases and enums shared across all StreamTrace crates.

use serde::{Deserialize, Serialize};

/// Unique identifier for a normalized forensic event (UUIDv7).
pub type EventId = uuid::Uuid;

/// Unique identifier for a raw ingested event (UUIDv7).
pub type RawEventId = uuid::Uuid;

/// Unique identifier for an investigation case (UUIDv7).
pub type CaseId = uuid::Uuid;

/// Unique identifier for an entity in the entity graph (UUIDv7).
pub type EntityId = uuid::Uuid;

/// BLAKE3 hex-encoded content hash for integrity verification.
pub type ContentHash = String;

/// Maximum recursion depth for entity graph traversal.
///
/// Bounds the cost of recursive CTE queries. Shared between the
/// store layer (which enforces it in SQL) and the API layer (which
/// clamps user input).
pub const MAX_GRAPH_DEPTH: u32 = 3;

/// Severity level for forensic events, ordered from informational to critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(i16)]
pub enum Severity {
    /// Informational event, no action required.
    Info = 0,
    /// Low severity, minor concern.
    Low = 1,
    /// Medium severity, warrants investigation.
    Medium = 2,
    /// High severity, requires prompt response.
    High = 3,
    /// Critical severity, immediate action required.
    Critical = 4,
}

/// Sort direction for query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    /// Ascending order (oldest first, lowest first).
    Asc,
    /// Descending order (newest first, highest first).
    Desc,
}

/// Status of an investigation case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Case is actively under investigation.
    Open,
    /// Case has been closed.
    Closed,
    /// Case data has been exported.
    Exported,
    /// Case has been archived for long-term storage.
    Archived,
}

/// Access permission levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// Read-only access.
    Read,
    /// Read and write access.
    Write,
    /// Full administrative access.
    Admin,
}
