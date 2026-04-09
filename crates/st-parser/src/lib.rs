//! Parser framework and built-in parsers for StreamTrace.
//!
//! This crate provides the [`EventParser`] trait and a [`ParserRegistry`] that
//! manages parser instances and dispatches parsing requests. Built-in parsers
//! handle JSON, CSV, and syslog formats.
//!
//! # Architecture
//!
//! Raw bytes flow through a parser to produce [`ParsedEvent`] instances, which
//! are intermediate representations that the ingest pipeline promotes to full
//! [`ForensicEvent`]s with IDs, source attribution, and persistence.
//!
//! # Built-in parsers
//!
//! - [`JsonGenericParser`] -- Native StreamTrace JSON format (single or batch)
//! - [`CsvGenericParser`] -- CSV with automatic header-based column mapping
//! - [`SyslogParser`] -- RFC 5424 and BSD/RFC 3164 syslog messages
//!
//! # Parser template
//!
//! - [`TemplateParser`] -- A working example parser for contributors to copy
//!   and customize. See [`template`] module docs and `crates/st-parser/PARSERS.md`.

pub mod csv_generic;
pub mod json_generic;
pub mod registry;
pub mod syslog;
pub mod template;
pub mod traits;

pub use csv_generic::CsvGenericParser;
pub use json_generic::JsonGenericParser;
pub use registry::ParserRegistry;
pub use syslog::SyslogParser;
pub use template::TemplateParser;
pub use traits::{EventParser, ParsedEvent};
