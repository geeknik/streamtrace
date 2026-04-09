//! Generic CSV parser with automatic header-based column mapping.
//!
//! The first row is treated as headers. Known header names are mapped to
//! canonical event fields; all other columns become `custom_fields`.

use chrono::{DateTime, Utc};
use std::io::Cursor;

use st_common::error::StError;
use st_common::event::{Actor, CorrelationKey, CorrelationKeyType, DeviceContext, NetworkContext};
use st_common::types::Severity;

use crate::traits::{EventParser, ParsedEvent};

/// Parser for CSV-formatted event data.
///
/// Maps well-known header names to canonical event fields.
/// Unrecognized headers are captured as custom fields.
pub struct CsvGenericParser;

impl CsvGenericParser {
    /// Creates a new CSV parser instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CsvGenericParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify a header name to a canonical field, or None for custom fields.
#[derive(Debug, Clone, Copy, PartialEq)]
enum FieldMapping {
    EventType,
    OccurredAt,
    ActorId,
    ActorName,
    SrcIp,
    DstIp,
    Hostname,
    Severity,
    Custom,
}

fn classify_header(header: &str) -> FieldMapping {
    match header.to_ascii_lowercase().trim() {
        "event_type" | "type" => FieldMapping::EventType,
        "occurred_at" | "timestamp" | "time" | "date" => FieldMapping::OccurredAt,
        "actor_id" | "user" | "user_id" => FieldMapping::ActorId,
        "actor_name" | "username" => FieldMapping::ActorName,
        "src_ip" | "source_ip" | "ip" => FieldMapping::SrcIp,
        "dst_ip" | "dest_ip" | "destination_ip" => FieldMapping::DstIp,
        "hostname" | "host" => FieldMapping::Hostname,
        "severity" | "level" => FieldMapping::Severity,
        _ => FieldMapping::Custom,
    }
}

/// Parse a severity string. Returns `Severity::Info` for unrecognized values.
fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().trim() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "" => Severity::Info,
        _ => Severity::Info,
    }
}

/// Attempt to parse a timestamp. Returns `None` for empty/malformed strings.
fn try_parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

impl EventParser for CsvGenericParser {
    fn id(&self) -> &str {
        "csv_generic"
    }

    fn supported_content_types(&self) -> &[&str] {
        &["text/csv", "application/csv"]
    }

    fn can_parse(&self, _content: &[u8], content_type: &str) -> bool {
        content_type == "text/csv" || content_type == "application/csv"
    }

    fn parse(&self, content: &[u8], _content_type: &str) -> Result<Vec<ParsedEvent>, StError> {
        if content.is_empty() {
            return Err(StError::ParseError("empty CSV input".to_string()));
        }

        let cursor = Cursor::new(content);
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(cursor);

        // Read and classify headers.
        let headers = reader
            .headers()
            .map_err(|e| StError::ParseError(format!("failed to read CSV headers: {}", e)))?
            .clone();

        if headers.is_empty() {
            return Err(StError::ParseError("CSV has no headers".to_string()));
        }

        let mappings: Vec<(FieldMapping, String)> = headers
            .iter()
            .map(|h| (classify_header(h), h.to_string()))
            .collect();

        let mut events = Vec::new();

        for result in reader.records() {
            let record =
                result.map_err(|e| StError::ParseError(format!("malformed CSV row: {}", e)))?;

            let mut event_type: Option<String> = None;
            let mut occurred_at_str: Option<String> = None;
            let mut actor_id: Option<String> = None;
            let mut actor_name: Option<String> = None;
            let mut src_ip: Option<String> = None;
            let mut dst_ip: Option<String> = None;
            let mut hostname: Option<String> = None;
            let mut severity_str: Option<String> = None;
            let mut custom = serde_json::Map::new();

            for (i, field) in record.iter().enumerate() {
                let field = field.trim();
                if field.is_empty() {
                    continue;
                }
                if i >= mappings.len() {
                    // Extra columns beyond headers are ignored.
                    continue;
                }
                let (mapping, ref header_name) = mappings[i];
                match mapping {
                    FieldMapping::EventType => event_type = Some(field.to_string()),
                    FieldMapping::OccurredAt => occurred_at_str = Some(field.to_string()),
                    FieldMapping::ActorId => actor_id = Some(field.to_string()),
                    FieldMapping::ActorName => actor_name = Some(field.to_string()),
                    FieldMapping::SrcIp => src_ip = Some(field.to_string()),
                    FieldMapping::DstIp => dst_ip = Some(field.to_string()),
                    FieldMapping::Hostname => hostname = Some(field.to_string()),
                    FieldMapping::Severity => severity_str = Some(field.to_string()),
                    FieldMapping::Custom => {
                        custom.insert(
                            header_name.clone(),
                            serde_json::Value::String(field.to_string()),
                        );
                    }
                }
            }

            // Determine occurred_at: parse provided value or default to now.
            let occurred_at = occurred_at_str
                .as_deref()
                .and_then(try_parse_timestamp)
                .unwrap_or_else(Utc::now);

            let severity = severity_str
                .as_deref()
                .map(parse_severity)
                .unwrap_or(Severity::Info);

            let actor = if actor_id.is_some() || actor_name.is_some() {
                Some(Actor {
                    id: actor_id.clone(),
                    name: actor_name,
                    actor_type: None,
                })
            } else {
                None
            };

            let network = if src_ip.is_some() || dst_ip.is_some() {
                Some(NetworkContext {
                    src_ip: src_ip.clone(),
                    dst_ip,
                    src_port: None,
                    dst_port: None,
                    protocol: None,
                })
            } else {
                None
            };

            let device = hostname.clone().map(|h| DeviceContext {
                device_id: None,
                device_name: None,
                device_type: None,
                hostname: Some(h),
            });

            // Extract correlation hints.
            let mut correlation_hints = Vec::new();
            if let Some(ref id) = actor_id {
                correlation_hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Identity,
                    key_value: id.clone(),
                });
            }
            if let Some(ref ip) = src_ip {
                correlation_hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Ip,
                    key_value: ip.clone(),
                });
            }
            if let Some(ref host) = hostname {
                correlation_hints.push(CorrelationKey {
                    key_type: CorrelationKeyType::Host,
                    key_value: host.clone(),
                });
            }

            events.push(ParsedEvent {
                event_type: event_type.unwrap_or_else(|| "csv.event".to_string()),
                severity,
                occurred_at,
                observed_at: None,
                actor,
                subject: None,
                object: None,
                network,
                device,
                tags: Vec::new(),
                custom_fields: serde_json::Value::Object(custom),
                correlation_hints,
            });
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::EventParser;

    fn parser() -> CsvGenericParser {
        CsvGenericParser::new()
    }

    #[test]
    fn parse_minimal_csv() {
        let input = "event_type,occurred_at\nauth.login,2026-04-09T12:00:00Z\n";
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "auth.login");
        assert_eq!(events[0].severity, Severity::Info);
    }

    #[test]
    fn parse_complex_csv_all_mapped_fields() {
        let input = "event_type,timestamp,user_id,username,src_ip,dst_ip,hostname,severity,extra_col\n\
                      file.read,2026-04-09T12:00:00Z,alice,Alice Smith,10.0.0.1,10.0.0.2,web-01,high,bonus\n";
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "file.read");
        assert_eq!(e.severity, Severity::High);

        let actor = e.actor.as_ref().unwrap();
        assert_eq!(actor.id.as_deref(), Some("alice"));
        assert_eq!(actor.name.as_deref(), Some("Alice Smith"));

        let net = e.network.as_ref().unwrap();
        assert_eq!(net.src_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(net.dst_ip.as_deref(), Some("10.0.0.2"));

        let dev = e.device.as_ref().unwrap();
        assert_eq!(dev.hostname.as_deref(), Some("web-01"));

        assert_eq!(
            e.custom_fields.get("extra_col").and_then(|v| v.as_str()),
            Some("bonus")
        );

        // Correlation hints
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Identity && h.key_value == "alice"));
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Ip && h.key_value == "10.0.0.1"));
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Host && h.key_value == "web-01"));
    }

    #[test]
    fn parse_multiple_rows() {
        let input = "type,timestamp\na,2026-04-09T12:00:00Z\nb,2026-04-09T12:01:00Z\nc,2026-04-09T12:02:00Z\n";
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "a");
        assert_eq!(events[1].event_type, "b");
        assert_eq!(events[2].event_type, "c");
    }

    #[test]
    fn missing_optional_fields_use_defaults() {
        let input = "extra\nvalue\n";
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert_eq!(events.len(), 1);
        // event_type defaults to "csv.event"
        assert_eq!(events[0].event_type, "csv.event");
        // severity defaults to Info
        assert_eq!(events[0].severity, Severity::Info);
        // actor is None since no actor columns
        assert!(events[0].actor.is_none());
    }

    #[test]
    fn malformed_date_uses_fallback() {
        let input = "event_type,timestamp\ntest,not-a-date\n";
        // Malformed dates fall back to now rather than erroring, for CSV robustness.
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert_eq!(events.len(), 1);
        // The occurred_at should be approximately now.
        let diff = (Utc::now() - events[0].occurred_at).num_seconds().abs();
        assert!(diff < 5);
    }

    #[test]
    fn empty_input_returns_error() {
        let result = parser().parse(b"", "text/csv");
        assert!(result.is_err());
    }

    #[test]
    fn headers_only_returns_empty_vec() {
        let input = "event_type,timestamp\n";
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn can_parse_check() {
        let p = parser();
        assert!(p.can_parse(b"", "text/csv"));
        assert!(p.can_parse(b"", "application/csv"));
        assert!(!p.can_parse(b"", "application/json"));
    }

    #[test]
    fn alternative_header_names() {
        let input = "type,time,user,source_ip,dest_ip,host,level\n\
                      login,2026-04-09T12:00:00Z,bob,1.2.3.4,5.6.7.8,srv-1,medium\n";
        let events = parser().parse(input.as_bytes(), "text/csv").unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "login");
        assert_eq!(e.severity, Severity::Medium);
        assert_eq!(e.actor.as_ref().unwrap().id.as_deref(), Some("bob"));
        assert_eq!(
            e.network.as_ref().unwrap().src_ip.as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            e.network.as_ref().unwrap().dst_ip.as_deref(),
            Some("5.6.7.8")
        );
        assert_eq!(
            e.device.as_ref().unwrap().hostname.as_deref(),
            Some("srv-1")
        );
    }
}
