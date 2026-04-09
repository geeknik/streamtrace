//! Syslog parser supporting both RFC 5424 and BSD/RFC 3164 formats.
//!
//! Uses simple string parsing (no regex) to extract priority, timestamp,
//! hostname, application name, and message body from syslog lines.

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};

use st_common::error::StError;
use st_common::event::{CorrelationKey, CorrelationKeyType, DeviceContext};
use st_common::types::Severity;

use crate::traits::{EventParser, ParsedEvent};

/// Parser for syslog messages in RFC 5424 and RFC 3164 (BSD) formats.
///
/// Extracts structured fields from syslog lines and maps them to
/// [`ParsedEvent`] instances. One line produces one event.
pub struct SyslogParser;

impl SyslogParser {
    /// Creates a new syslog parser instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyslogParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Syslog priority facility/severity encoding.
/// Priority = Facility * 8 + Severity
/// We only care about the severity portion (lower 3 bits).
fn priority_to_severity(pri: u32) -> Severity {
    let syslog_severity = pri & 0x07;
    match syslog_severity {
        0..=2 => Severity::Critical, // Emergency, Alert, Critical
        3 => Severity::High,         // Error
        4 => Severity::Medium,       // Warning
        5 | 6 => Severity::Low,      // Notice, Informational
        7 => Severity::Info,         // Debug
        _ => Severity::Info,
    }
}

/// Extract the priority number from `<PRI>` prefix.
/// Returns (priority, rest_of_string) or None if not valid.
fn extract_priority(line: &str) -> Option<(u32, &str)> {
    if !line.starts_with('<') {
        return None;
    }
    let end = line.find('>')?;
    if !(2..=4).contains(&end) {
        // PRI is 1-3 digits
        return None;
    }
    let pri_str = &line[1..end];
    let pri: u32 = pri_str.parse().ok()?;
    if pri > 191 {
        // Max valid: facility 23 * 8 + severity 7 = 191
        return None;
    }
    Some((pri, &line[end + 1..]))
}

/// Parsed fields from a syslog line.
struct SyslogFields {
    priority: u32,
    timestamp: Option<DateTime<Utc>>,
    hostname: Option<String>,
    app_name: Option<String>,
    message: String,
}

/// Try to parse as RFC 5424: `VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG`
fn try_parse_rfc5424(rest: &str) -> Option<SyslogFields> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }

    let first_char = rest.as_bytes().first()?;
    if !first_char.is_ascii_digit() {
        return None;
    }

    let mut parts = rest.splitn(7, ' ');

    let version = parts.next()?;
    if version != "1" {
        return None;
    }

    let timestamp_str = parts.next().unwrap_or("-");
    let hostname = parts.next().unwrap_or("-");
    let app_name = parts.next().unwrap_or("-");
    let _procid = parts.next().unwrap_or("-");
    let _msgid = parts.next().unwrap_or("-");
    let message = parts.next().unwrap_or("");

    let timestamp = parse_rfc5424_timestamp(timestamp_str);

    Some(SyslogFields {
        priority: 0, // Will be set by caller
        timestamp,
        hostname: if hostname == "-" {
            None
        } else {
            Some(hostname.to_string())
        },
        app_name: if app_name == "-" {
            None
        } else {
            Some(app_name.to_string())
        },
        message: message.to_string(),
    })
}

/// Parse RFC 5424 timestamp (ISO 8601 / RFC 3339 subset).
fn parse_rfc5424_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if s == "-" {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

/// BSD syslog month abbreviations.
const BSD_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parse BSD/RFC 3164 timestamp: `Mon DD HH:MM:SS`
fn parse_bsd_timestamp(month_str: &str, day_str: &str, time_str: &str) -> Option<DateTime<Utc>> {
    let month = BSD_MONTHS
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(month_str))?
        + 1;
    let day: u32 = day_str.trim().parse().ok()?;

    // BSD syslog doesn't include year; use current year.
    let year = Utc::now().year();

    let datetime_str = format!("{}-{:02}-{:02}T{}", year, month, day, time_str);
    NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

/// Try to parse as BSD/RFC 3164: `Mon DD HH:MM:SS HOSTNAME MSG`
fn try_parse_bsd(rest: &str) -> Option<SyslogFields> {
    let rest = rest.trim_start();
    if rest.len() < 15 {
        return None;
    }

    let month_candidate = if rest.len() >= 3 { &rest[..3] } else { "" };
    if !BSD_MONTHS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(month_candidate))
    {
        return None;
    }

    let after_month = &rest[3..];
    let after_month = after_month.trim_start();

    let space_idx = after_month.find(' ')?;
    let day_str = &after_month[..space_idx];
    let after_day = &after_month[space_idx + 1..];

    let space_idx = after_day.find(' ');
    let (time_str, after_time) = match space_idx {
        Some(idx) => (&after_day[..idx], &after_day[idx + 1..]),
        None => (after_day, ""),
    };

    if time_str.len() < 8
        || time_str.as_bytes().get(2) != Some(&b':')
        || time_str.as_bytes().get(5) != Some(&b':')
    {
        return None;
    }

    let timestamp = parse_bsd_timestamp(month_candidate, day_str, &time_str[..8]);

    let after_time = after_time.trim_start();
    let (hostname, message) = if after_time.is_empty() {
        (None, String::new())
    } else {
        match after_time.find(' ') {
            Some(idx) => (
                Some(after_time[..idx].to_string()),
                after_time[idx + 1..].to_string(),
            ),
            None => (Some(after_time.to_string()), String::new()),
        }
    };

    let (app_name, final_message) = extract_app_from_message(&message);

    Some(SyslogFields {
        priority: 0, // Will be set by caller
        timestamp,
        hostname,
        app_name,
        message: final_message,
    })
}

/// Extract app name from a syslog message body.
/// Handles patterns like "sshd[12345]: message" or "sshd: message".
fn extract_app_from_message(msg: &str) -> (Option<String>, String) {
    if let Some(colon_idx) = msg.find(": ") {
        let prefix = &msg[..colon_idx];
        let app = if let Some(bracket_idx) = prefix.find('[') {
            &prefix[..bracket_idx]
        } else {
            prefix
        };
        if !app.is_empty()
            && app
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return (Some(app.to_string()), msg[colon_idx + 2..].to_string());
        }
    }
    (None, msg.to_string())
}

/// Parse a single syslog line into SyslogFields.
fn parse_syslog_line(line: &str) -> Result<SyslogFields, StError> {
    let (priority, rest) = extract_priority(line)
        .ok_or_else(|| StError::ParseError("missing syslog priority".to_string()))?;

    let mut fields = if let Some(f) = try_parse_rfc5424(rest) {
        f
    } else if let Some(f) = try_parse_bsd(rest) {
        f
    } else {
        SyslogFields {
            priority,
            timestamp: None,
            hostname: None,
            app_name: None,
            message: rest.to_string(),
        }
    };

    fields.priority = priority;
    Ok(fields)
}

/// Convert parsed syslog fields into a ParsedEvent.
fn fields_to_event(fields: SyslogFields) -> ParsedEvent {
    let severity = priority_to_severity(fields.priority);
    let occurred_at = fields.timestamp.unwrap_or_else(Utc::now);

    let app_label = fields.app_name.as_deref().unwrap_or("unknown");
    let event_type = format!("syslog.{}", app_label);

    let device = fields.hostname.as_ref().map(|h| DeviceContext {
        device_id: None,
        device_name: None,
        device_type: None,
        hostname: Some(h.clone()),
    });

    let mut correlation_hints = Vec::new();
    if let Some(ref h) = fields.hostname {
        correlation_hints.push(CorrelationKey {
            key_type: CorrelationKeyType::Host,
            key_value: h.clone(),
        });
    }

    let mut custom = serde_json::Map::new();
    if !fields.message.is_empty() {
        custom.insert(
            "message".to_string(),
            serde_json::Value::String(fields.message),
        );
    }
    if let Some(ref app) = fields.app_name {
        custom.insert(
            "app_name".to_string(),
            serde_json::Value::String(app.clone()),
        );
    }
    custom.insert(
        "priority".to_string(),
        serde_json::Value::Number(serde_json::Number::from(fields.priority)),
    );

    ParsedEvent {
        event_type,
        severity,
        occurred_at,
        observed_at: None,
        actor: None,
        subject: None,
        object: None,
        network: None,
        device,
        tags: Vec::new(),
        custom_fields: serde_json::Value::Object(custom),
        correlation_hints,
    }
}

impl EventParser for SyslogParser {
    fn id(&self) -> &str {
        "syslog"
    }

    fn supported_content_types(&self) -> &[&str] {
        &["text/syslog", "text/plain"]
    }

    fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
        if content_type == "text/syslog" {
            return true;
        }
        // Heuristic: content starts with `<` followed by digits and `>`.
        let trimmed: Vec<u8> = content
            .iter()
            .copied()
            .skip_while(|b| b.is_ascii_whitespace())
            .take(6)
            .collect();
        if trimmed.len() >= 3 && trimmed[0] == b'<' {
            let mut i = 1;
            while i < trimmed.len() && trimmed[i].is_ascii_digit() {
                i += 1;
            }
            return i > 1 && i < trimmed.len() && trimmed[i] == b'>';
        }
        false
    }

    fn parse(&self, content: &[u8], _content_type: &str) -> Result<Vec<ParsedEvent>, StError> {
        if content.is_empty() {
            return Err(StError::ParseError("empty syslog input".to_string()));
        }

        let text = std::str::from_utf8(content)
            .map_err(|e| StError::ParseError(format!("invalid UTF-8: {}", e)))?;

        let mut events = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let fields = parse_syslog_line(line)?;
            events.push(fields_to_event(fields));
        }

        if events.is_empty() {
            return Err(StError::ParseError(
                "no valid syslog messages found".to_string(),
            ));
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::EventParser;

    fn parser() -> SyslogParser {
        SyslogParser::new()
    }

    #[test]
    fn parse_rfc5424_minimal() {
        let input = "<134>1 2026-04-09T12:00:00Z myhost myapp 1234 ID47 Test message";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "syslog.myapp");
        assert_eq!(e.severity, Severity::Low); // 134 & 7 = 6 (Informational) -> Low
        assert_eq!(
            e.device.as_ref().unwrap().hostname.as_deref(),
            Some("myhost")
        );
        assert_eq!(
            e.custom_fields.get("message").and_then(|v| v.as_str()),
            Some("Test message")
        );
        assert_eq!(
            e.custom_fields.get("app_name").and_then(|v| v.as_str()),
            Some("myapp")
        );
    }

    #[test]
    fn parse_rfc5424_all_fields() {
        let input = "<165>1 2026-04-09T14:30:00Z router1 sshd 5678 MSG01 Failed password for root from 10.0.0.1 port 22 ssh2";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.severity, Severity::Low); // 165 & 7 = 5 (Notice) -> Low
        assert_eq!(e.event_type, "syslog.sshd");
        assert!(e
            .correlation_hints
            .iter()
            .any(|h| h.key_type == CorrelationKeyType::Host && h.key_value == "router1"));
    }

    #[test]
    fn parse_bsd_format() {
        let input = "<34>Jan  5 14:30:00 myhost sshd[12345]: Failed password for user root";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.severity, Severity::Critical); // 34 & 7 = 2 -> Critical
        assert_eq!(e.event_type, "syslog.sshd");
        assert_eq!(
            e.device.as_ref().unwrap().hostname.as_deref(),
            Some("myhost")
        );
        assert_eq!(
            e.custom_fields.get("message").and_then(|v| v.as_str()),
            Some("Failed password for user root")
        );
    }

    #[test]
    fn parse_multiple_lines() {
        let input = "<134>1 2026-04-09T12:00:00Z host1 app1 - - msg1\n\
                      <134>1 2026-04-09T12:01:00Z host2 app2 - - msg2\n";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "syslog.app1");
        assert_eq!(events[1].event_type, "syslog.app2");
    }

    #[test]
    fn missing_hostname_in_rfc5424() {
        let input = "<134>1 2026-04-09T12:00:00Z - myapp - - test";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].device.is_none());
        assert!(events[0].correlation_hints.is_empty());
    }

    #[test]
    fn empty_input_returns_error() {
        let result = parser().parse(b"", "text/syslog");
        assert!(result.is_err());
    }

    #[test]
    fn whitespace_only_returns_error() {
        let result = parser().parse(b"  \n  \n  ", "text/syslog");
        assert!(result.is_err());
    }

    #[test]
    fn malformed_priority_returns_error() {
        let result = parser().parse(b"no priority here", "text/syslog");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("priority"));
    }

    #[test]
    fn priority_to_severity_mapping() {
        assert_eq!(priority_to_severity(0), Severity::Critical);
        assert_eq!(priority_to_severity(1), Severity::Critical);
        assert_eq!(priority_to_severity(2), Severity::Critical);
        assert_eq!(priority_to_severity(3), Severity::High);
        assert_eq!(priority_to_severity(4), Severity::Medium);
        assert_eq!(priority_to_severity(5), Severity::Low);
        assert_eq!(priority_to_severity(6), Severity::Low);
        assert_eq!(priority_to_severity(7), Severity::Info);
    }

    #[test]
    fn can_parse_heuristic() {
        let p = parser();
        assert!(p.can_parse(b"<134>1 ...", "text/plain"));
        assert!(p.can_parse(b"<34>Jan ...", "text/plain"));
        assert!(p.can_parse(b"", "text/syslog"));
        assert!(!p.can_parse(b"hello", "text/plain"));
        assert!(!p.can_parse(b"<>foo", "text/plain"));
    }

    #[test]
    fn high_priority_error() {
        let input = "<11>1 2026-04-09T12:00:00Z myhost myapp - - error occurred";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events[0].severity, Severity::High); // 11 & 7 = 3 (Error) -> High
    }

    #[test]
    fn warning_severity() {
        let input = "<12>1 2026-04-09T12:00:00Z myhost myapp - - warning message";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events[0].severity, Severity::Medium); // 12 & 7 = 4 (Warning) -> Medium
    }

    #[test]
    fn fallback_for_non_standard_format() {
        let input = "<134>some random text here";
        let events = parser().parse(input.as_bytes(), "text/syslog").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "syslog.unknown");
        assert!(events[0].device.is_none());
    }
}
