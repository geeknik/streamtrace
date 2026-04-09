//! Generic JSON parser for the native StreamTrace event format.
//!
//! Accepts single JSON objects or arrays of objects. Each object is mapped
//! to a [`ParsedEvent`] with automatic correlation hint extraction.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::BTreeMap;

use st_common::error::StError;
use st_common::event::{
    Actor, CorrelationKey, CorrelationKeyType, DeviceContext, EventObject, NetworkContext, Subject,
};
use st_common::types::Severity;

use crate::traits::{EventParser, ParsedEvent};

/// Input shape for the actor field in JSON events.
#[derive(Debug, Deserialize)]
struct ActorInput {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    actor_type: Option<String>,
}

/// Input shape for the subject field in JSON events.
#[derive(Debug, Deserialize)]
struct SubjectInput {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    subject_type: Option<String>,
}

/// Input shape for the object field in JSON events.
#[derive(Debug, Deserialize)]
struct ObjectInput {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    object_type: Option<String>,
}

/// Input shape for the network context field in JSON events.
#[derive(Debug, Deserialize)]
struct NetworkInput {
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    dst_ip: Option<String>,
    #[serde(default)]
    src_port: Option<i32>,
    #[serde(default)]
    dst_port: Option<i32>,
    #[serde(default)]
    protocol: Option<String>,
}

/// Input shape for the device context field in JSON events.
#[derive(Debug, Deserialize)]
struct DeviceInput {
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    device_type: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
}

/// Top-level JSON event input structure.
///
/// Unknown fields are captured into `extra` via `serde(flatten)`.
#[derive(Debug, Deserialize)]
struct JsonInputEvent {
    event_type: String,
    #[serde(default)]
    severity: Option<String>,
    occurred_at: String,
    #[serde(default)]
    observed_at: Option<String>,
    #[serde(default)]
    actor: Option<ActorInput>,
    #[serde(default)]
    subject: Option<SubjectInput>,
    #[serde(default)]
    object: Option<ObjectInput>,
    #[serde(default)]
    network: Option<NetworkInput>,
    #[serde(default)]
    device: Option<DeviceInput>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    /// Catch-all for fields not in the canonical schema.
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Parser for the native StreamTrace JSON event format.
///
/// Handles both single JSON objects and JSON arrays for batch ingest.
pub struct JsonGenericParser;

impl JsonGenericParser {
    /// Creates a new JSON parser instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonGenericParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an ISO 8601 timestamp string, returning a descriptive error on failure.
fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, StError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| StError::ParseError(format!("invalid timestamp '{}': {}", s, e)))
}

/// Map a severity string to the Severity enum. Defaults to Info for unknown values.
fn parse_severity(s: Option<&str>) -> Severity {
    match s.map(|v| v.to_ascii_lowercase()).as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") | None => Severity::Info,
        Some(_) => Severity::Info,
    }
}

/// Extract correlation hints from the parsed fields.
fn extract_correlation_hints(
    actor: &Option<Actor>,
    network: &Option<NetworkContext>,
    device: &Option<DeviceContext>,
) -> Vec<CorrelationKey> {
    let mut hints = Vec::new();

    if let Some(ref a) = actor {
        if let Some(ref id) = a.id {
            if !id.is_empty() {
                hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Identity,
                    key_value: id.clone(),
                });
            }
        }
    }

    if let Some(ref n) = network {
        if let Some(ref ip) = n.src_ip {
            if !ip.is_empty() {
                hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Ip,
                    key_value: ip.clone(),
                });
            }
        }
    }

    if let Some(ref d) = device {
        if let Some(ref did) = d.device_id {
            if !did.is_empty() {
                hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Device,
                    key_value: did.clone(),
                });
            }
        }
        if let Some(ref host) = d.hostname {
            if !host.is_empty() {
                hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Host,
                    key_value: host.clone(),
                });
            }
        }
    }

    hints
}

/// Convert a single deserialized input event to a ParsedEvent.
fn convert_input(input: JsonInputEvent) -> Result<ParsedEvent, StError> {
    let occurred_at = parse_timestamp(&input.occurred_at)?;
    let observed_at = input
        .observed_at
        .as_deref()
        .map(parse_timestamp)
        .transpose()?;
    let severity = parse_severity(input.severity.as_deref());

    let actor = input.actor.map(|a| Actor {
        id: a.id,
        name: a.name,
        actor_type: a.actor_type,
    });

    let subject = input.subject.map(|s| Subject {
        id: s.id,
        name: s.name,
        subject_type: s.subject_type,
    });

    let object = input.object.map(|o| EventObject {
        id: o.id,
        name: o.name,
        object_type: o.object_type,
    });

    let network = input.network.map(|n| NetworkContext {
        src_ip: n.src_ip,
        dst_ip: n.dst_ip,
        src_port: n.src_port,
        dst_port: n.dst_port,
        protocol: n.protocol,
    });

    let device = input.device.map(|d| DeviceContext {
        device_id: d.device_id,
        device_name: d.device_name,
        device_type: d.device_type,
        hostname: d.hostname,
    });

    let correlation_hints = extract_correlation_hints(&actor, &network, &device);

    let custom_fields = if input.extra.is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        serde_json::to_value(&input.extra)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()))
    };

    Ok(ParsedEvent {
        event_type: input.event_type,
        severity,
        occurred_at,
        observed_at,
        actor,
        subject,
        object,
        network,
        device,
        tags: input.tags.unwrap_or_default(),
        custom_fields,
        correlation_hints,
    })
}

impl EventParser for JsonGenericParser {
    fn id(&self) -> &str {
        "json_generic"
    }

    fn supported_content_types(&self) -> &[&str] {
        &["application/json", "text/json"]
    }

    fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
        if content_type == "application/json" || content_type == "text/json" {
            return true;
        }
        // Heuristic: check if content starts with '{' or '[' after optional whitespace.
        let trimmed = content.iter().copied().find(|b| !b.is_ascii_whitespace());
        matches!(trimmed, Some(b'{') | Some(b'['))
    }

    fn parse(&self, content: &[u8], _content_type: &str) -> Result<Vec<ParsedEvent>, StError> {
        if content.is_empty() {
            return Err(StError::ParseError("empty input".to_string()));
        }

        let text = std::str::from_utf8(content)
            .map_err(|e| StError::ParseError(format!("invalid UTF-8: {}", e)))?;

        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(StError::ParseError("empty input".to_string()));
        }

        // Determine if this is an array or a single object.
        if trimmed.starts_with('[') {
            let items: Vec<JsonInputEvent> = serde_json::from_str(trimmed)
                .map_err(|e| StError::ParseError(format!("invalid JSON array: {}", e)))?;
            items.into_iter().map(convert_input).collect()
        } else {
            let item: JsonInputEvent = serde_json::from_str(trimmed)
                .map_err(|e| StError::ParseError(format!("invalid JSON object: {}", e)))?;
            Ok(vec![convert_input(item)?])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::EventParser;

    fn parser() -> JsonGenericParser {
        JsonGenericParser::new()
    }

    #[test]
    fn parse_minimal_event() {
        let input = r#"{"event_type":"auth.login","occurred_at":"2026-04-09T12:00:00Z"}"#;
        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "auth.login");
        assert_eq!(events[0].severity, Severity::Info);
        assert!(events[0].actor.is_none());
        assert!(events[0].network.is_none());
    }

    #[test]
    fn parse_complex_event_all_fields() {
        let input = r#"{
            "event_type": "file.access",
            "severity": "high",
            "occurred_at": "2026-04-09T12:00:00Z",
            "observed_at": "2026-04-09T12:00:01Z",
            "actor": {"id": "alice", "name": "Alice Smith", "type": "user"},
            "subject": {"id": "server-1", "name": "Web Server", "type": "host"},
            "object": {"id": "file-42", "name": "/etc/passwd", "type": "file"},
            "network": {"src_ip": "203.0.113.10", "dst_ip": "10.0.0.1", "src_port": 54321, "dst_port": 443, "protocol": "tcp"},
            "device": {"device_id": "dev-001", "device_name": "Laptop", "device_type": "workstation", "hostname": "alice-laptop"},
            "tags": ["vpn", "suspicious"],
            "custom_field_1": "extra_value"
        }"#;
        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "file.access");
        assert_eq!(e.severity, Severity::High);
        assert!(e.observed_at.is_some());

        let actor = e.actor.as_ref().unwrap();
        assert_eq!(actor.id.as_deref(), Some("alice"));
        assert_eq!(actor.name.as_deref(), Some("Alice Smith"));
        assert_eq!(actor.actor_type.as_deref(), Some("user"));

        let subject = e.subject.as_ref().unwrap();
        assert_eq!(subject.id.as_deref(), Some("server-1"));

        let object = e.object.as_ref().unwrap();
        assert_eq!(object.name.as_deref(), Some("/etc/passwd"));

        let net = e.network.as_ref().unwrap();
        assert_eq!(net.src_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(net.dst_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(net.src_port, Some(54321));
        assert_eq!(net.dst_port, Some(443));
        assert_eq!(net.protocol.as_deref(), Some("tcp"));

        let dev = e.device.as_ref().unwrap();
        assert_eq!(dev.device_id.as_deref(), Some("dev-001"));
        assert_eq!(dev.hostname.as_deref(), Some("alice-laptop"));

        assert_eq!(e.tags, vec!["vpn", "suspicious"]);

        // Extra fields captured
        assert_eq!(
            e.custom_fields
                .get("custom_field_1")
                .and_then(|v| v.as_str()),
            Some("extra_value")
        );

        // Correlation hints: identity, ip, device, host
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Identity && h.key_value == "alice"));
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Ip && h.key_value == "203.0.113.10"));
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Device && h.key_value == "dev-001"));
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Host && h.key_value == "alice-laptop"));
    }

    #[test]
    fn parse_batch_array() {
        let input = r#"[
            {"event_type":"a","occurred_at":"2026-04-09T12:00:00Z"},
            {"event_type":"b","occurred_at":"2026-04-09T12:01:00Z"}
        ]"#;
        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "a");
        assert_eq!(events[1].event_type, "b");
    }

    #[test]
    fn parse_missing_optional_fields_defaults() {
        let input = r#"{"event_type":"test","occurred_at":"2026-04-09T12:00:00Z"}"#;
        let events = parser()
            .parse(input.as_bytes(), "application/json")
            .unwrap();
        let e = &events[0];
        assert_eq!(e.severity, Severity::Info);
        assert!(e.observed_at.is_none());
        assert!(e.actor.is_none());
        assert!(e.subject.is_none());
        assert!(e.object.is_none());
        assert!(e.network.is_none());
        assert!(e.device.is_none());
        assert!(e.tags.is_empty());
        assert!(e.correlation_hints.is_empty());
    }

    #[test]
    fn parse_invalid_timestamp_returns_error() {
        let input = r#"{"event_type":"test","occurred_at":"not-a-date"}"#;
        let result = parser().parse(input.as_bytes(), "application/json");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("invalid timestamp"));
    }

    #[test]
    fn parse_empty_input_returns_error() {
        let result = parser().parse(b"", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_malformed_json_returns_error() {
        let result = parser().parse(b"{not json}", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_required_field_returns_error() {
        // Missing event_type
        let input = r#"{"occurred_at":"2026-04-09T12:00:00Z"}"#;
        let result = parser().parse(input.as_bytes(), "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn can_parse_by_content_type() {
        let p = parser();
        assert!(p.can_parse(b"{}", "application/json"));
        assert!(p.can_parse(b"{}", "text/json"));
        assert!(!p.can_parse(b"not json", "text/plain"));
    }

    #[test]
    fn can_parse_by_heuristic() {
        let p = parser();
        assert!(p.can_parse(b"  {\"key\":1}", "text/plain"));
        assert!(p.can_parse(b"\n[1,2]", "text/plain"));
        assert!(!p.can_parse(b"hello", "text/plain"));
    }

    #[test]
    fn severity_parsing() {
        assert_eq!(parse_severity(Some("critical")), Severity::Critical);
        assert_eq!(parse_severity(Some("CRITICAL")), Severity::Critical);
        assert_eq!(parse_severity(Some("High")), Severity::High);
        assert_eq!(parse_severity(Some("medium")), Severity::Medium);
        assert_eq!(parse_severity(Some("low")), Severity::Low);
        assert_eq!(parse_severity(Some("info")), Severity::Info);
        assert_eq!(parse_severity(Some("unknown")), Severity::Info);
        assert_eq!(parse_severity(None), Severity::Info);
    }

    #[test]
    fn empty_array_returns_empty_vec() {
        let events = parser().parse(b"[]", "application/json").unwrap();
        assert!(events.is_empty());
    }
}
