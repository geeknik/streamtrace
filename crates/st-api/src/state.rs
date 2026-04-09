//! Shared application state threaded through all request handlers.

use std::sync::Arc;

use st_cases::CaseManager;
use st_crypto::SigningKeyPair;
use st_index::EventIndex;
use st_ingest::IngestPipeline;
use st_store::Database;

/// Application state shared across all axum handlers via `State` extractor.
///
/// Cloning is cheap -- all inner fields are behind `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Database handle (connection pool).
    pub db: Arc<Database>,
    /// Ingestion pipeline for processing incoming events.
    pub ingest: Arc<IngestPipeline>,
    /// Query and search index over forensic events.
    pub index: Arc<EventIndex>,
    /// Case management facade.
    pub cases: Arc<CaseManager>,
    /// Ed25519 signing key pair for evidence bundles.
    pub signing_key: Arc<SigningKeyPair>,
}
