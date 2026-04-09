//! `st-ingest` -- event ingestion pipeline for StreamTrace.
//!
//! Orchestrates the full lifecycle of incoming event data:
//! validate -> hash -> store raw -> parse -> normalize ->
//! extract correlation keys -> store normalized events.
//!
//! The [`IngestPipeline`] is the main entry point, providing
//! `ingest_events` (JSON) and `ingest_raw` (arbitrary format) methods.

pub mod handler;
pub mod pipeline;
pub mod types;
pub mod validation;

pub use pipeline::IngestPipeline;
pub use types::IngestResult;
