//! Request and response types for the ingestion pipeline.

use serde::Serialize;
use st_common::types::{EventId, RawEventId};

/// Result of an ingestion operation.
///
/// Returned to the caller after events have been validated, parsed,
/// normalized, and stored.
#[derive(Debug, Clone, Serialize)]
pub struct IngestResult {
    /// Number of events accepted and stored.
    pub accepted: usize,
    /// UUIDs of the created normalized events.
    pub event_ids: Vec<EventId>,
    /// UUID of the raw event storage record.
    pub raw_event_id: RawEventId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_result_serializes_to_json() {
        let result = IngestResult {
            accepted: 2,
            event_ids: vec![uuid::Uuid::nil(), uuid::Uuid::nil()],
            raw_event_id: uuid::Uuid::nil(),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed["accepted"], 2);
        assert_eq!(parsed["event_ids"].as_array().unwrap().len(), 2);
        assert!(parsed["raw_event_id"].is_string());
    }

    #[test]
    fn ingest_result_empty_event_ids() {
        let result = IngestResult {
            accepted: 0,
            event_ids: Vec::new(),
            raw_event_id: uuid::Uuid::nil(),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed["accepted"], 0);
        assert!(parsed["event_ids"].as_array().unwrap().is_empty());
    }
}
