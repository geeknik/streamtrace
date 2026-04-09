//! Core parser trait and intermediate event representation.
//!
//! All parsers implement [`EventParser`] and produce [`ParsedEvent`] instances
//! that are later promoted to full [`ForensicEvent`]s by the ingest pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use st_common::error::StError;
use st_common::event::{
    Actor, CorrelationKey, DeviceContext, EventObject, NetworkContext, Subject,
};
use st_common::types::Severity;

/// Intermediate representation produced by parsing raw bytes.
///
/// Contains all the normalized fields that will eventually populate a
/// [`ForensicEvent`]. The ingest layer is responsible for assigning IDs,
/// source attribution, and persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEvent {
    /// Canonical event type (e.g. "auth.login", "syslog.sshd").
    pub event_type: String,
    /// Severity classification.
    pub severity: Severity,
    /// When the event originally occurred.
    pub occurred_at: DateTime<Utc>,
    /// When the event was first observed (may differ from `occurred_at`).
    pub observed_at: Option<DateTime<Utc>>,
    /// The actor (initiator) involved in the event.
    pub actor: Option<Actor>,
    /// The subject (target) involved in the event.
    pub subject: Option<Subject>,
    /// The object (resource) involved in the event.
    pub object: Option<EventObject>,
    /// Network-level context.
    pub network: Option<NetworkContext>,
    /// Device-level context.
    pub device: Option<DeviceContext>,
    /// Free-form tags for categorization.
    pub tags: Vec<String>,
    /// Arbitrary extra data that does not fit the canonical schema.
    pub custom_fields: serde_json::Value,
    /// Pre-extracted correlation hints for the correlation engine.
    pub correlation_hints: Vec<CorrelationKey>,
}

/// Trait that all event parsers must implement.
///
/// Parsers are stateless, thread-safe transformers that convert raw bytes
/// into zero or more [`ParsedEvent`] instances.
pub trait EventParser: Send + Sync {
    /// Unique, stable identifier for this parser (e.g. "json_generic", "syslog").
    fn id(&self) -> &str;

    /// MIME content types this parser can handle (e.g. "application/json").
    fn supported_content_types(&self) -> &[&str];

    /// Quick heuristic check: can this parser likely handle the given content?
    ///
    /// Implementations should be cheap -- avoid full parsing. Used by the
    /// registry for auto-detection when no explicit parser ID is provided.
    fn can_parse(&self, content: &[u8], content_type: &str) -> bool;

    /// Parse raw bytes into zero or more normalized events.
    ///
    /// Returns an empty `Vec` if the content is valid but contains no events.
    /// Returns `Err(StError::ParseError(..))` on malformed input.
    fn parse(&self, content: &[u8], content_type: &str) -> Result<Vec<ParsedEvent>, StError>;
}
