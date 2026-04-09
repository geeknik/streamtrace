//! `st-correlate` -- correlation key extraction, entity resolution, and
//! sequence detection for StreamTrace.
//!
//! Extracts correlation keys (identity, IP, session, device, etc.) from
//! normalized forensic events, resolves entities from event fields, and
//! detects ordered behavioural sequences.

pub mod entities;
pub mod keys;
pub mod linker;
pub mod sequences;

pub use entities::extract_entities;
pub use keys::extract_correlation_keys;
pub use linker::describe_correlation;
pub use sequences::{
    builtin_patterns, matches_event_type, DetectedSequence, SequenceDetector, SequencePattern,
    SequenceStep,
};
