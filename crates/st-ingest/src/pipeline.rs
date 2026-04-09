//! Core ingestion pipeline for StreamTrace.
//!
//! Orchestrates the full ingest flow: validate -> hash -> store raw ->
//! parse -> normalize -> extract keys -> store normalized -> resolve entities.
//!
//! All database mutations within a single `ingest_raw` call execute inside
//! one transaction. On any failure the transaction rolls back automatically,
//! preventing orphaned raw events, events without correlation keys, or
//! inconsistent entity state.

use std::sync::Arc;

use st_common::config::IngestConfig;
use st_common::error::StError;
use st_parser::ParserRegistry;
use st_store::Database;

use crate::handler;
use crate::types::IngestResult;
use crate::validation::{validate_batch_size, validate_body_size};

/// The ingestion pipeline. Thread-safe and shareable via `Arc`.
///
/// Holds references to the database, parser registry, and ingest
/// configuration. Instantiated once at startup and shared across
/// request handlers.
pub struct IngestPipeline {
    db: Arc<Database>,
    parsers: Arc<ParserRegistry>,
    config: IngestConfig,
}

impl IngestPipeline {
    /// Creates a new ingestion pipeline.
    pub fn new(db: Arc<Database>, parsers: Arc<ParserRegistry>, config: IngestConfig) -> Self {
        Self {
            db,
            parsers,
            config,
        }
    }

    /// Ingest raw bytes with a specified or auto-detected parser.
    ///
    /// This is the main entry point for `POST /v1/ingest/raw`. The body
    /// is stored as a raw event, then parsed and normalized into one or
    /// more forensic events.
    ///
    /// All database writes (raw event, normalized events, correlation keys,
    /// entity resolution) execute within a single transaction. If any step
    /// fails, the entire ingest is rolled back atomically.
    ///
    /// # Errors
    ///
    /// Returns `StError::PayloadTooLarge` if the body exceeds the configured limit.
    /// Returns `StError::ParseError` if no parser can handle the content.
    /// Returns `StError::Validation` if the parsed batch exceeds the batch limit.
    /// Returns `StError::Database` on storage failures.
    pub async fn ingest_raw(
        &self,
        body: &[u8],
        content_type: &str,
        source_id: &str,
        source_type: &str,
        source_name: Option<&str>,
        parser_id: Option<&str>,
    ) -> Result<IngestResult, StError> {
        // Step 1: Validate body size (no DB).
        validate_body_size(body, self.config.max_event_size_bytes)?;

        // Step 2: Hash the raw content (no DB).
        let content_hash = handler::hash_content(body);

        // Step 3: Parse into intermediate events (no DB).
        // Moved before DB writes so we fail fast on parse errors without
        // starting a transaction.
        let parsed_events = self.parsers.parse(body, content_type, parser_id)?;

        // Step 4: Validate batch size (no DB).
        validate_batch_size(parsed_events.len(), self.config.max_batch_size)?;

        // --- Begin transaction ---
        // All database mutations below happen within this transaction.
        // On error, the transaction is dropped and automatically rolled back.
        let mut tx = self.db.begin().await?;

        // Step 5: Store the raw event (in tx).
        let raw_event_id = handler::store_raw_tx(
            &mut tx,
            body,
            &content_hash,
            content_type,
            source_id,
            source_type,
            source_name,
            parser_id,
        )
        .await?;

        tracing::info!(
            raw_event_id = %raw_event_id,
            content_hash = %content_hash,
            byte_size = body.len(),
            "raw event stored (in tx)"
        );

        // Steps 6-8: Normalize, extract keys, store, and resolve entities.
        let mut event_ids = Vec::with_capacity(parsed_events.len());

        for parsed in &parsed_events {
            let event =
                handler::normalize(parsed, raw_event_id, source_id, source_type, source_name)?;

            let keys = handler::extract_keys(&event, &parsed.correlation_hints);

            let event_id = handler::store_normalized_tx(&mut tx, &event, &keys).await?;

            // Step 7: Resolve entities (best-effort within the transaction --
            // log errors but do not fail the ingest since entity resolution
            // is supplementary to the core event storage).
            if let Err(e) = handler::resolve_entities_tx(&mut tx, &event, event_id).await {
                tracing::warn!(
                    event_id = %event_id,
                    error = %e,
                    "entity resolution failed for event (in tx)"
                );
            }

            tracing::debug!(
                event_id = %event_id,
                event_type = %event.event_type,
                correlation_keys = keys.len(),
                "normalized event stored (in tx)"
            );

            event_ids.push(event_id);
        }

        // --- Commit transaction ---
        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "failed to commit ingest transaction");
            StError::Database(format!("commit failed: {e}"))
        })?;

        tracing::info!(
            raw_event_id = %raw_event_id,
            accepted = event_ids.len(),
            "ingest_raw completed"
        );

        Ok(IngestResult {
            accepted: event_ids.len(),
            event_ids,
            raw_event_id,
        })
    }

    /// Ingest one or more events in the native JSON format.
    ///
    /// This is the main entry point for `POST /v1/ingest/events`. The body
    /// is expected to be a JSON object (single event) or JSON array (batch).
    /// Events are parsed using the built-in `application/json` content type.
    ///
    /// # Errors
    ///
    /// Returns `StError::PayloadTooLarge` if the body exceeds the configured limit.
    /// Returns `StError::ParseError` if the JSON is malformed.
    /// Returns `StError::Validation` if the batch exceeds the batch limit.
    /// Returns `StError::Database` on storage failures.
    pub async fn ingest_events(
        &self,
        body: &[u8],
        source_id: &str,
        source_type: &str,
        source_name: Option<&str>,
    ) -> Result<IngestResult, StError> {
        self.ingest_raw(
            body,
            "application/json",
            source_id,
            source_type,
            source_name,
            None,
        )
        .await
    }

    /// Returns a reference to the underlying database.
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Returns a reference to the ingest configuration.
    pub fn config(&self) -> &IngestConfig {
        &self.config
    }
}

impl std::fmt::Debug for IngestPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestPipeline")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
