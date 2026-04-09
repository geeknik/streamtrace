//! Parser registry for managing and dispatching to event parsers.
//!
//! The [`ParserRegistry`] holds registered [`EventParser`] implementations and
//! provides auto-detection of the correct parser for a given content type.

use std::sync::Arc;

use st_common::error::StError;

use crate::csv_generic::CsvGenericParser;
use crate::json_generic::JsonGenericParser;
use crate::syslog::SyslogParser;
use crate::traits::{EventParser, ParsedEvent};

/// Central registry that owns parser instances and dispatches parsing requests.
///
/// Parsers are checked in registration order for auto-detection. Register
/// more specific parsers first for correct priority.
pub struct ParserRegistry {
    parsers: Vec<Arc<dyn EventParser>>,
}

impl ParserRegistry {
    /// Creates an empty registry with no parsers registered.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// Creates a registry pre-loaded with all built-in parsers.
    ///
    /// Registers: `json_generic`, `csv_generic`, `syslog`.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(JsonGenericParser::new()));
        registry.register(Arc::new(CsvGenericParser::new()));
        registry.register(Arc::new(SyslogParser::new()));
        registry
    }

    /// Registers a parser. Later registrations are checked after earlier ones
    /// during auto-detection.
    pub fn register(&mut self, parser: Arc<dyn EventParser>) {
        self.parsers.push(parser);
    }

    /// Looks up a parser by its unique identifier.
    pub fn get_by_id(&self, id: &str) -> Option<&Arc<dyn EventParser>> {
        self.parsers.iter().find(|p| p.id() == id)
    }

    /// Auto-detects the first parser that can handle the given content.
    ///
    /// Iterates through registered parsers in order and returns the first
    /// one whose [`EventParser::can_parse`] returns `true`.
    pub fn detect_parser(
        &self,
        content: &[u8],
        content_type: &str,
    ) -> Option<&Arc<dyn EventParser>> {
        self.parsers
            .iter()
            .find(|p| p.can_parse(content, content_type))
    }

    /// Parses content using the specified parser or auto-detection.
    ///
    /// If `parser_id` is `Some`, that specific parser is used. Otherwise the
    /// registry auto-detects based on content and content type.
    ///
    /// Returns `Err(StError::ParseError(..))` if no suitable parser is found
    /// or if parsing fails.
    pub fn parse(
        &self,
        content: &[u8],
        content_type: &str,
        parser_id: Option<&str>,
    ) -> Result<Vec<ParsedEvent>, StError> {
        let parser = match parser_id {
            Some(id) => self.get_by_id(id).ok_or_else(|| {
                StError::ParseError(format!("unknown parser: {}", id))
            })?,
            None => self.detect_parser(content, content_type).ok_or_else(|| {
                StError::ParseError(format!(
                    "no parser found for content type '{}'",
                    content_type
                ))
            })?,
        };
        parser.parse(content, content_type)
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_defaults_includes_all_parsers() {
        let reg = ParserRegistry::with_defaults();
        assert!(reg.get_by_id("json_generic").is_some());
        assert!(reg.get_by_id("csv_generic").is_some());
        assert!(reg.get_by_id("syslog").is_some());
    }

    #[test]
    fn get_by_id_unknown_returns_none() {
        let reg = ParserRegistry::with_defaults();
        assert!(reg.get_by_id("nonexistent").is_none());
    }

    #[test]
    fn detect_json_by_content_type() {
        let reg = ParserRegistry::with_defaults();
        let p = reg
            .detect_parser(b"{}", "application/json")
            .unwrap();
        assert_eq!(p.id(), "json_generic");
    }

    #[test]
    fn detect_csv_by_content_type() {
        let reg = ParserRegistry::with_defaults();
        let p = reg.detect_parser(b"a,b\n1,2", "text/csv").unwrap();
        assert_eq!(p.id(), "csv_generic");
    }

    #[test]
    fn detect_syslog_by_content_type() {
        let reg = ParserRegistry::with_defaults();
        let p = reg
            .detect_parser(b"<134>1 ...", "text/syslog")
            .unwrap();
        assert_eq!(p.id(), "syslog");
    }

    #[test]
    fn detect_json_by_heuristic() {
        let reg = ParserRegistry::with_defaults();
        let p = reg
            .detect_parser(b"  {\"key\":1}", "application/octet-stream")
            .unwrap();
        assert_eq!(p.id(), "json_generic");
    }

    #[test]
    fn detect_syslog_by_heuristic() {
        let reg = ParserRegistry::with_defaults();
        let p = reg
            .detect_parser(b"<134>1 2026-04-09T12:00:00Z host app - - msg", "text/plain")
            .unwrap();
        // JSON parser checks heuristic first but <134> doesn't start with { or [
        // Syslog parser checks heuristic and matches
        assert_eq!(p.id(), "syslog");
    }

    #[test]
    fn parse_with_explicit_parser_id() {
        let reg = ParserRegistry::with_defaults();
        let input = r#"{"event_type":"test","occurred_at":"2026-04-09T12:00:00Z"}"#;
        let events = reg
            .parse(input.as_bytes(), "text/plain", Some("json_generic"))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "test");
    }

    #[test]
    fn parse_with_auto_detect() {
        let reg = ParserRegistry::with_defaults();
        let input = r#"{"event_type":"auto","occurred_at":"2026-04-09T12:00:00Z"}"#;
        let events = reg
            .parse(input.as_bytes(), "application/json", None)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "auto");
    }

    #[test]
    fn parse_unknown_parser_id_returns_error() {
        let reg = ParserRegistry::with_defaults();
        let result = reg.parse(b"data", "text/plain", Some("bogus"));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unknown parser"));
    }

    #[test]
    fn parse_no_matching_parser_returns_error() {
        let reg = ParserRegistry::with_defaults();
        // Content that doesn't match any heuristic or content type
        let result = reg.parse(b"random bytes", "application/octet-stream", None);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("no parser found"));
    }

    #[test]
    fn explicit_parser_overrides_auto_detection() {
        let reg = ParserRegistry::with_defaults();
        // Even though content_type is text/csv, if we specify json_generic it should use that
        let input = r#"{"event_type":"override","occurred_at":"2026-04-09T12:00:00Z"}"#;
        let events = reg
            .parse(input.as_bytes(), "text/csv", Some("json_generic"))
            .unwrap();
        assert_eq!(events[0].event_type, "override");
    }

    #[test]
    fn empty_registry_returns_error() {
        let reg = ParserRegistry::new();
        let result = reg.parse(b"data", "text/plain", None);
        assert!(result.is_err());
    }
}
