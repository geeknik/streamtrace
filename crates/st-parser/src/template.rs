//! Parser template for StreamTrace contributors.
//!
//! # How to use this template
//!
//! 1. Copy this file to a new name (e.g., `cloudtrail.rs`).
//! 2. Find/replace `TemplateParser` with your parser name (e.g., `CloudTrailParser`).
//! 3. Find/replace `"template"` with your parser ID (e.g., `"cloudtrail"`).
//! 4. Find/replace `"template."` with your event type prefix (e.g., `"cloudtrail."`).
//! 5. Fill in every `// TODO:` section with your format-specific logic.
//! 6. Register your parser in `registry.rs` (see instructions at the bottom).
//! 7. Add `pub mod your_module;` and `pub use your_module::YourParser;` to `lib.rs`.
//! 8. Run `cargo test -p st-parser` to verify.
//!
//! # Example format this template handles
//!
//! This template parses a "generic webhook" JSON format as a working example:
//!
//! ```json
//! {
//!   "timestamp": "2026-04-09T12:00:00Z",
//!   "type": "user.login",
//!   "user": { "id": "u-123", "email": "alice@example.com" },
//!   "ip": "203.0.113.10",
//!   "details": { "mfa": true, "provider": "okta" }
//! }
//! ```
//!
//! The template also handles batch payloads (JSON arrays of the above).
//!
//! Replace the JSON shape and field extraction with your target format.

use chrono::{DateTime, Utc};

use st_common::error::StError;
use st_common::event::{
    Actor, CorrelationKey, CorrelationKeyType, DeviceContext, EventObject, NetworkContext, Subject,
};
use st_common::types::Severity;

use crate::traits::{EventParser, ParsedEvent};

// ---------------------------------------------------------------------------
// Parser struct
// ---------------------------------------------------------------------------

/// Parser for the generic webhook format.
///
/// TODO: Replace this doc comment with a description of your log format.
/// Include a link to the format specification if one exists.
pub struct TemplateParser;

impl TemplateParser {
    /// Creates a new parser instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TemplateParser {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

/// Parse a timestamp string from common formats into a UTC DateTime.
///
/// Tries these formats in order:
/// 1. RFC 3339 / ISO 8601 with timezone (e.g., "2026-04-09T12:00:00Z")
/// 2. ISO 8601 without timezone, assumed UTC (e.g., "2026-04-09T12:00:00")
/// 3. Unix epoch as seconds (e.g., "1775908800")
/// 4. Unix epoch as milliseconds (e.g., "1775908800000")
///
/// Returns `None` if none of the formats match.
///
/// TODO: If your format uses a different timestamp representation, add it here
/// or replace these with your format-specific parsing.
fn parse_timestamp(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    match value {
        serde_json::Value::String(s) => parse_timestamp_str(s),
        serde_json::Value::Number(n) => {
            // Try seconds first, then milliseconds.
            if let Some(secs) = n.as_i64() {
                // Heuristic: values above 1e12 are likely milliseconds.
                if secs > 1_000_000_000_000 {
                    DateTime::from_timestamp_millis(secs)
                } else {
                    DateTime::from_timestamp(secs, 0)
                }
            } else if let Some(f) = n.as_f64() {
                let secs = f as i64;
                let nanos = ((f - secs as f64) * 1_000_000_000.0) as u32;
                DateTime::from_timestamp(secs, nanos)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse a timestamp from a string value.
fn parse_timestamp_str(s: &str) -> Option<DateTime<Utc>> {
    // RFC 3339 / ISO 8601 with timezone offset.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // ISO 8601 without timezone, assume UTC.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }
    // With fractional seconds but no timezone.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(naive.and_utc());
    }
    // Unix epoch as a string of digits.
    if let Ok(secs) = s.parse::<i64>() {
        if secs > 1_000_000_000_000 {
            return DateTime::from_timestamp_millis(secs);
        }
        return DateTime::from_timestamp(secs, 0);
    }
    None
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

/// Map a source-specific severity/level string to a StreamTrace Severity.
///
/// TODO: Replace with mappings appropriate to your log format.
/// For example, AWS CloudTrail does not have severity levels -- you would
/// derive severity from the event name (e.g., "ConsoleLogin" with MFA
/// failure -> High).
fn map_severity(event_type: &str) -> Severity {
    // Example: derive severity from the event type prefix.
    if event_type.contains("error") || event_type.contains("fail") {
        Severity::High
    } else if event_type.contains("warn")
        || event_type.contains("delete")
        || event_type.contains("remove")
    {
        Severity::Medium
    } else if event_type.contains("login") || event_type.contains("auth") {
        Severity::Low
    } else {
        Severity::Info
    }
}

// ---------------------------------------------------------------------------
// Single-event parsing
// ---------------------------------------------------------------------------

/// Parse a single JSON object into a ParsedEvent.
///
/// TODO: This is the core function you need to customize. Replace the field
/// extraction logic to match your log format's JSON structure.
fn parse_single_event(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<ParsedEvent, StError> {
    // -- Timestamp ----------------------------------------------------------
    // TODO: Change "timestamp" to the field name your format uses.
    let occurred_at = obj
        .get("timestamp")
        .and_then(parse_timestamp)
        .ok_or_else(|| StError::ParseError("missing or invalid 'timestamp' field".to_string()))?;

    // -- Event type ---------------------------------------------------------
    // TODO: Change "type" to the field name your format uses, and adjust the
    // prefix to match your parser ID (e.g., "cloudtrail.ConsoleLogin").
    let raw_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let event_type = format!("template.{}", raw_type);

    // -- Severity -----------------------------------------------------------
    let severity = map_severity(raw_type);

    // -- Actor (who initiated the action) -----------------------------------
    // TODO: Extract the actor from your format. This example reads a nested
    // "user" object; your format might use "userIdentity", "principal", etc.
    let actor = obj.get("user").and_then(|u| {
        let user_obj = u.as_object()?;
        Some(Actor {
            id: user_obj
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from),
            name: user_obj
                .get("email")
                .and_then(|v| v.as_str())
                .map(String::from),
            actor_type: Some("user".to_string()),
        })
    });

    // -- Subject (what was acted upon) --------------------------------------
    // TODO: Extract the subject if your format has one. For example, in
    // Kubernetes audit logs, the subject would be the resource being accessed.
    // Remove or set to None if not applicable.
    let subject: Option<Subject> = None;

    // -- Object (the resource involved) -------------------------------------
    // TODO: Extract the object if your format has one. For example, in AWS
    // CloudTrail, the object might be the S3 bucket or EC2 instance.
    let object: Option<EventObject> = None;

    // -- Network context ----------------------------------------------------
    // TODO: Extract network information. This example reads a top-level "ip"
    // field; your format might have nested structures like
    // "sourceIPAddress", "client.ip", etc.
    let network = obj
        .get("ip")
        .and_then(|v| v.as_str())
        .map(|ip| NetworkContext {
            src_ip: Some(ip.to_string()),
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
        });

    // -- Device context -----------------------------------------------------
    // TODO: Extract device/host information if present. Many cloud log formats
    // include a user-agent or hostname. Set to None if not applicable.
    let device: Option<DeviceContext> =
        obj.get("device")
            .and_then(|d| d.as_object())
            .map(|d| DeviceContext {
                device_id: d.get("id").and_then(|v| v.as_str()).map(String::from),
                device_name: d.get("name").and_then(|v| v.as_str()).map(String::from),
                device_type: d.get("type").and_then(|v| v.as_str()).map(String::from),
                hostname: d.get("hostname").and_then(|v| v.as_str()).map(String::from),
            });

    // -- Tags ---------------------------------------------------------------
    // TODO: Add tags that help categorize this event. Tags are free-form
    // strings used for filtering in the UI.
    let tags: Vec<String> = vec!["template".to_string()];

    // -- Custom fields (everything that doesn't fit the canonical schema) ----
    // TODO: Preserve source-specific fields that don't map to the canonical
    // model. This example stores the "details" sub-object.
    let mut custom = serde_json::Map::new();
    if let Some(details) = obj.get("details") {
        custom.insert("details".to_string(), details.clone());
    }
    // Preserve the original event type string.
    custom.insert(
        "raw_type".to_string(),
        serde_json::Value::String(raw_type.to_string()),
    );

    // -- Correlation hints --------------------------------------------------
    // These keys allow the correlation engine to link this event with related
    // events across sources. Add every identifier that might appear in other
    // log sources.
    //
    // TODO: Add correlation hints specific to your format. Common choices:
    // - User ID / email (CorrelationKeyType::Identity)
    // - Session ID (CorrelationKeyType::Session)
    // - Source IP (CorrelationKeyType::Ip)
    // - Hostname (CorrelationKeyType::Host)
    // - Request ID or trace ID (CorrelationKeyType::Custom("request_id"))
    let mut correlation_hints = Vec::new();

    if let Some(ref a) = actor {
        if let Some(ref id) = a.id {
            correlation_hints.push(CorrelationKey {
                key_type: CorrelationKeyType::Identity,
                key_value: id.clone(),
            });
        }
    }

    if let Some(ref n) = network {
        if let Some(ref ip) = n.src_ip {
            correlation_hints.push(CorrelationKey {
                key_type: CorrelationKeyType::Ip,
                key_value: ip.clone(),
            });
        }
    }

    Ok(ParsedEvent {
        event_type,
        severity,
        occurred_at,
        observed_at: None,
        actor,
        subject,
        object,
        network,
        device,
        tags,
        custom_fields: serde_json::Value::Object(custom),
        correlation_hints,
    })
}

// ---------------------------------------------------------------------------
// EventParser implementation
// ---------------------------------------------------------------------------

impl EventParser for TemplateParser {
    fn id(&self) -> &str {
        // TODO: Change to your parser's unique identifier (e.g., "cloudtrail").
        // This ID is used in the registry and can be specified by callers to
        // force a specific parser.
        "template"
    }

    fn supported_content_types(&self) -> &[&str] {
        // TODO: List the MIME types your parser handles. For JSON-based formats,
        // "application/json" is standard. Some formats may use vendor-specific
        // types (e.g., "application/vnd.amazonaws.cloudtrail+json").
        &["application/json"]
    }

    fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
        // TODO: Implement a CHEAP heuristic to detect your format.
        //
        // This is called by the registry during auto-detection. It must be fast
        // (no full parsing). Check for:
        // - A specific content type
        // - A distinctive top-level field in JSON
        // - A magic byte sequence or header line
        //
        // Return `true` only if you are reasonably confident this content
        // belongs to your format. False positives cause the wrong parser to
        // be selected.
        //
        // IMPORTANT: If your format shares "application/json" with other
        // parsers, you MUST inspect the content to disambiguate. Otherwise
        // the first registered JSON parser wins.

        // Example: check for our distinctive "type" field pattern.
        if content_type == "application/vnd.template+json" {
            return true;
        }

        // For shared content types, peek at the content.
        if content_type == "application/json" || content_type == "application/octet-stream" {
            // Quick scan: look for a distinctive field name in the first 512 bytes.
            let peek = &content[..content.len().min(512)];
            if let Ok(s) = std::str::from_utf8(peek) {
                // TODO: Replace with a field unique to your format.
                return s.contains("\"type\"") && s.contains("\"timestamp\"");
            }
        }

        false
    }

    fn parse(&self, content: &[u8], _content_type: &str) -> Result<Vec<ParsedEvent>, StError> {
        if content.is_empty() {
            return Err(StError::ParseError("empty input".to_string()));
        }

        let text = std::str::from_utf8(content)
            .map_err(|e| StError::ParseError(format!("invalid UTF-8: {}", e)))?;

        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(StError::ParseError(
                "empty input after trimming".to_string(),
            ));
        }

        // Handle both single objects and arrays of objects.
        // TODO: If your format is not JSON-based (e.g., line-delimited text),
        // replace this with line-by-line parsing similar to the syslog parser.
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| StError::ParseError(format!("invalid JSON: {}", e)))?;

        let events = match value {
            serde_json::Value::Array(arr) => {
                // Batch payload: array of event objects.
                let mut results = Vec::with_capacity(arr.len());
                for (i, item) in arr.iter().enumerate() {
                    let obj = item.as_object().ok_or_else(|| {
                        StError::ParseError(format!("array element {} is not an object", i))
                    })?;
                    results.push(parse_single_event(obj)?);
                }
                if results.is_empty() {
                    return Err(StError::ParseError("empty array".to_string()));
                }
                results
            }
            serde_json::Value::Object(ref obj) => {
                // Single event.
                vec![parse_single_event(obj)?]
            }
            _ => {
                return Err(StError::ParseError(
                    "expected JSON object or array".to_string(),
                ));
            }
        };

        Ok(events)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// TODO: Replace these test inputs with examples from your actual log format.
// Keep the test structure: positive cases, batch payloads, missing fields,
// malformed input, and the can_parse heuristic.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::EventParser;

    fn parser() -> TemplateParser {
        TemplateParser::new()
    }

    /// Minimal valid single event.
    const SINGLE_EVENT: &str = r#"{
        "timestamp": "2026-04-09T12:00:00Z",
        "type": "user.login",
        "user": { "id": "u-123", "email": "alice@example.com" },
        "ip": "203.0.113.10",
        "details": { "mfa": true, "provider": "okta" }
    }"#;

    // -- Positive cases -----------------------------------------------------

    #[test]
    fn parse_single_event_extracts_all_fields() {
        let events = parser()
            .parse(SINGLE_EVENT.as_bytes(), "application/json")
            .unwrap();
        assert_eq!(events.len(), 1);

        let e = &events[0];
        assert_eq!(e.event_type, "template.user.login");
        assert_eq!(e.severity, Severity::Low); // contains "login"
        assert_eq!(
            e.occurred_at,
            "2026-04-09T12:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // Actor
        let actor = e.actor.as_ref().expect("actor should be present");
        assert_eq!(actor.id.as_deref(), Some("u-123"));
        assert_eq!(actor.name.as_deref(), Some("alice@example.com"));
        assert_eq!(actor.actor_type.as_deref(), Some("user"));

        // Network
        let net = e.network.as_ref().expect("network should be present");
        assert_eq!(net.src_ip.as_deref(), Some("203.0.113.10"));

        // Custom fields
        assert!(e.custom_fields.get("details").is_some());
        assert_eq!(
            e.custom_fields.get("raw_type").and_then(|v| v.as_str()),
            Some("user.login")
        );

        // Correlation hints
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Identity && h.key_value == "u-123"));
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Ip && h.key_value == "203.0.113.10"));

        // Tags
        assert!(e.tags.contains(&"template".to_string()));
    }

    #[test]
    fn parse_batch_payload() {
        let input = r#"[
            {
                "timestamp": "2026-04-09T12:00:00Z",
                "type": "user.login",
                "user": { "id": "u-1" },
                "ip": "10.0.0.1"
            },
            {
                "timestamp": "2026-04-09T12:01:00Z",
                "type": "user.logout",
                "user": { "id": "u-2" },
                "ip": "10.0.0.2"
            }
        ]"#;

        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "template.user.login");
        assert_eq!(events[1].event_type, "template.user.logout");
    }

    #[test]
    fn parse_event_without_optional_fields() {
        let input = r#"{
            "timestamp": "2026-04-09T12:00:00Z",
            "type": "system.heartbeat"
        }"#;

        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        assert_eq!(events.len(), 1);

        let e = &events[0];
        assert_eq!(e.event_type, "template.system.heartbeat");
        assert!(e.actor.is_none());
        assert!(e.network.is_none());
        assert!(e.device.is_none());
        assert!(e.correlation_hints.is_empty());
    }

    #[test]
    fn parse_event_with_device_context() {
        let input = r#"{
            "timestamp": "2026-04-09T12:00:00Z",
            "type": "agent.checkin",
            "device": {
                "id": "d-42",
                "name": "workstation-7",
                "type": "workstation",
                "hostname": "ws7.corp.example.com"
            }
        }"#;

        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        let dev = events[0].device.as_ref().expect("device should be present");
        assert_eq!(dev.device_id.as_deref(), Some("d-42"));
        assert_eq!(dev.hostname.as_deref(), Some("ws7.corp.example.com"));
    }

    // -- Severity mapping ---------------------------------------------------

    #[test]
    fn severity_mapping() {
        assert_eq!(map_severity("auth.login"), Severity::Low);
        assert_eq!(map_severity("auth.login.failure"), Severity::High);
        assert_eq!(map_severity("resource.warning"), Severity::Medium);
        assert_eq!(map_severity("resource.delete"), Severity::Medium);
        assert_eq!(map_severity("system.heartbeat"), Severity::Info);
    }

    // -- Timestamp parsing --------------------------------------------------

    #[test]
    fn parse_rfc3339_timestamp() {
        let val = serde_json::json!("2026-04-09T12:00:00Z");
        let dt = parse_timestamp(&val).unwrap();
        assert_eq!(dt, "2026-04-09T12:00:00Z".parse::<DateTime<Utc>>().unwrap());
    }

    #[test]
    fn parse_rfc3339_with_offset() {
        let val = serde_json::json!("2026-04-09T12:00:00+05:00");
        let dt = parse_timestamp(&val).unwrap();
        assert_eq!(dt, "2026-04-09T07:00:00Z".parse::<DateTime<Utc>>().unwrap());
    }

    #[test]
    fn parse_naive_iso8601_timestamp() {
        let val = serde_json::json!("2026-04-09T12:00:00");
        let dt = parse_timestamp(&val).unwrap();
        assert_eq!(dt, "2026-04-09T12:00:00Z".parse::<DateTime<Utc>>().unwrap());
    }

    #[test]
    fn parse_unix_epoch_seconds() {
        let val = serde_json::json!(1775908800);
        let dt = parse_timestamp(&val).unwrap();
        assert_eq!(dt, DateTime::from_timestamp(1775908800, 0).unwrap());
    }

    #[test]
    fn parse_unix_epoch_millis() {
        let val = serde_json::json!(1775908800000_i64);
        let dt = parse_timestamp(&val).unwrap();
        assert_eq!(dt, DateTime::from_timestamp(1775908800, 0).unwrap());
    }

    #[test]
    fn parse_unix_epoch_string() {
        let val = serde_json::json!("1775908800");
        let dt = parse_timestamp(&val).unwrap();
        assert_eq!(dt, DateTime::from_timestamp(1775908800, 0).unwrap());
    }

    #[test]
    fn parse_invalid_timestamp_returns_none() {
        assert!(parse_timestamp(&serde_json::json!("not-a-date")).is_none());
        assert!(parse_timestamp(&serde_json::json!(true)).is_none());
        assert!(parse_timestamp(&serde_json::json!(null)).is_none());
    }

    // -- Error cases --------------------------------------------------------

    #[test]
    fn empty_input_returns_error() {
        let result = parser().parse(b"", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn whitespace_only_returns_error() {
        let result = parser().parse(b"   \n  ", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_json_returns_error() {
        let result = parser().parse(b"not json at all", "application/json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("invalid JSON"));
    }

    #[test]
    fn missing_timestamp_returns_error() {
        let input = r#"{"type": "test"}"#;
        let result = parser().parse(input.as_bytes(), "application/json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("timestamp"));
    }

    #[test]
    fn non_object_json_returns_error() {
        let result = parser().parse(b"42", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn empty_array_returns_error() {
        let result = parser().parse(b"[]", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn array_with_non_object_returns_error() {
        let result = parser().parse(b"[1, 2, 3]", "application/json");
        assert!(result.is_err());
    }

    // -- can_parse heuristic ------------------------------------------------

    #[test]
    fn can_parse_vendor_content_type() {
        let p = parser();
        assert!(p.can_parse(b"{}", "application/vnd.template+json"));
    }

    #[test]
    fn can_parse_json_with_matching_fields() {
        let p = parser();
        assert!(p.can_parse(SINGLE_EVENT.as_bytes(), "application/json"));
    }

    #[test]
    fn can_parse_rejects_unrelated_json() {
        let p = parser();
        assert!(!p.can_parse(b"{\"foo\": 1}", "application/json"));
    }

    #[test]
    fn can_parse_rejects_non_json_content_type() {
        let p = parser();
        assert!(!p.can_parse(b"not json", "text/plain"));
    }

    // -- Parser metadata ----------------------------------------------------

    #[test]
    fn parser_id() {
        assert_eq!(parser().id(), "template");
    }

    #[test]
    fn parser_supported_content_types() {
        let p = parser();
        let types = p.supported_content_types();
        assert!(types.contains(&"application/json"));
    }
}
