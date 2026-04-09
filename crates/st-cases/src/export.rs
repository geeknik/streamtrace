//! Case export in JSON, CSV, and Markdown formats.
//!
//! All rendering is done in-memory and returns a `String`. No
//! temporary files are created.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use st_common::error::{StError, StResult};
use st_common::event::ForensicEvent;
use st_common::types::CaseStatus;
use st_store::cases::{Case, CaseEvent};

/// Supported export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// Pretty-printed JSON.
    Json,
    /// Comma-separated values.
    Csv,
    /// Human-readable Markdown report.
    Markdown,
}

impl ExportFormat {
    /// Parses a format string, returning `StError::Validation` on unknown values.
    ///
    /// Accepts "json", "csv", "markdown", and "md" (case-insensitive).
    pub fn from_str_checked(s: &str) -> StResult<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "markdown" | "md" => Ok(Self::Markdown),
            _ => Err(StError::Validation(format!(
                "unsupported export format: {s}"
            ))),
        }
    }
}

/// A case with all attached events and their full details, ready for export.
#[derive(Debug, Clone, Serialize)]
pub struct ExportedCase {
    /// The investigation case.
    pub case: Case,
    /// Events attached to the case, with full event details.
    pub events: Vec<CaseEventWithDetail>,
    /// Timestamp when the export was generated.
    pub exported_at: DateTime<Utc>,
}

/// A case-event junction record paired with the full forensic event.
#[derive(Debug, Clone, Serialize)]
pub struct CaseEventWithDetail {
    /// The case-event attachment metadata.
    pub case_event: CaseEvent,
    /// The full forensic event.
    pub event: ForensicEvent,
}

/// Renders an exported case in the specified format.
pub(crate) fn render(exported: &ExportedCase, format: ExportFormat) -> StResult<String> {
    match format {
        ExportFormat::Json => render_json(exported),
        ExportFormat::Csv => Ok(render_csv(exported)),
        ExportFormat::Markdown => Ok(render_markdown(exported)),
    }
}

/// Renders the exported case as pretty-printed JSON.
fn render_json(exported: &ExportedCase) -> StResult<String> {
    serde_json::to_string_pretty(exported).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize case export to JSON");
        StError::Internal("failed to serialize export".to_string())
    })
}

/// Renders the exported case as CSV.
///
/// Columns: event_type, occurred_at, actor_id, source_id, severity, annotation
fn render_csv(exported: &ExportedCase) -> String {
    let mut out = String::with_capacity(1024);

    // Header row.
    out.push_str("event_type,occurred_at,actor_id,source_id,severity,annotation\n");

    for entry in &exported.events {
        let event = &entry.event;
        let annotation = &entry.case_event.annotation;

        let actor_id = event
            .actor
            .as_ref()
            .and_then(|a| a.id.as_deref())
            .unwrap_or("");

        let severity = format!("{:?}", event.severity);

        // Escape CSV fields that may contain commas, quotes, or newlines.
        out.push_str(&csv_escape(&event.event_type));
        out.push(',');
        out.push_str(&event.occurred_at.to_rfc3339());
        out.push(',');
        out.push_str(&csv_escape(actor_id));
        out.push(',');
        out.push_str(&csv_escape(&event.source.source_id));
        out.push(',');
        out.push_str(&severity);
        out.push(',');
        out.push_str(&csv_escape(annotation));
        out.push('\n');
    }

    out
}

/// Escapes a CSV field value.
///
/// If the value contains a comma, double-quote, or newline, the entire
/// field is wrapped in double-quotes and internal double-quotes are doubled.
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// Renders the exported case as a Markdown investigation report.
fn render_markdown(exported: &ExportedCase) -> String {
    let case = &exported.case;
    let mut out = String::with_capacity(2048);

    // Title and metadata.
    out.push_str(&format!("# Investigation Report: {}\n\n", case.name));

    out.push_str(&format!(
        "**Status:** {}  \n",
        status_display(case.status)
    ));
    out.push_str(&format!("**Created by:** {}  \n", case.created_by));
    out.push_str(&format!(
        "**Created at:** {}  \n",
        case.created_at.to_rfc3339()
    ));
    out.push_str(&format!(
        "**Exported at:** {}  \n\n",
        exported.exported_at.to_rfc3339()
    ));

    // Description.
    out.push_str("## Description\n\n");
    if case.description.is_empty() {
        out.push_str("_No description provided._\n\n");
    } else {
        out.push_str(&case.description);
        out.push_str("\n\n");
    }

    // Event timeline table.
    out.push_str("## Event Timeline\n\n");

    if exported.events.is_empty() {
        out.push_str("_No events attached to this case._\n\n");
    } else {
        out.push_str(
            "| # | Event Type | Occurred At | Actor | Source | Severity | Pinned | Annotation |\n",
        );
        out.push_str(
            "|---|------------|-------------|-------|--------|----------|--------|------------|\n",
        );

        for (i, entry) in exported.events.iter().enumerate() {
            let event = &entry.event;
            let ce = &entry.case_event;

            let actor_id = event
                .actor
                .as_ref()
                .and_then(|a| a.id.as_deref())
                .unwrap_or("-");

            let severity = format!("{:?}", event.severity);
            let pinned = if ce.pinned { "Yes" } else { "No" };
            let annotation = if ce.annotation.is_empty() {
                "-"
            } else {
                &ce.annotation
            };

            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                i + 1,
                md_escape(&event.event_type),
                event.occurred_at.to_rfc3339(),
                md_escape(actor_id),
                md_escape(&event.source.source_id),
                severity,
                pinned,
                md_escape(annotation),
            ));
        }
        out.push('\n');
    }

    // Annotations section for pinned events.
    let pinned: Vec<_> = exported
        .events
        .iter()
        .filter(|e| e.case_event.pinned)
        .collect();

    if !pinned.is_empty() {
        out.push_str("## Pinned Events\n\n");
        for entry in &pinned {
            let ce = &entry.case_event;
            let event = &entry.event;
            out.push_str(&format!(
                "- **{}** ({}): {}\n",
                event.event_type,
                event.occurred_at.to_rfc3339(),
                if ce.annotation.is_empty() {
                    "_No annotation_"
                } else {
                    &ce.annotation
                },
            ));
        }
        out.push('\n');
    }

    out
}

/// Escapes pipe characters in Markdown table cells.
fn md_escape(value: &str) -> String {
    value.replace('|', "\\|")
}

/// Human-readable display for case status.
fn status_display(status: CaseStatus) -> &'static str {
    match status {
        CaseStatus::Open => "Open",
        CaseStatus::Closed => "Closed",
        CaseStatus::Exported => "Exported",
        CaseStatus::Archived => "Archived",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use st_common::event::SourceAttribution;
    use st_common::types::{CaseId, Severity};
    use uuid::Uuid;

    fn make_case() -> Case {
        Case {
            id: Uuid::now_v7(),
            name: "Test Investigation".to_string(),
            description: "Investigating suspicious login activity.".to_string(),
            status: CaseStatus::Open,
            created_by: "analyst-1".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_forensic_event() -> ForensicEvent {
        let now = Utc::now();
        let mut event = ForensicEvent::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "auth.login.failure".to_string(),
            Severity::High,
            now,
            now,
            SourceAttribution {
                source_id: "src-001".to_string(),
                source_type: "auth-service".to_string(),
                source_name: Some("Auth Gateway".to_string()),
            },
        );
        event.actor = Some(st_common::event::Actor {
            id: Some("user-42".to_string()),
            name: Some("Alice".to_string()),
            actor_type: Some("user".to_string()),
        });
        event
    }

    fn make_case_event(case_id: CaseId, event_id: uuid::Uuid) -> CaseEvent {
        CaseEvent {
            id: Uuid::now_v7(),
            case_id,
            event_id,
            pinned: false,
            annotation: String::new(),
            added_at: Utc::now(),
            added_by: "analyst-1".to_string(),
        }
    }

    fn make_exported_case() -> ExportedCase {
        let case = make_case();
        let event = make_forensic_event();
        let case_event = make_case_event(case.id, event.id);

        ExportedCase {
            case,
            events: vec![CaseEventWithDetail {
                case_event,
                event,
            }],
            exported_at: Utc::now(),
        }
    }

    // ---- ExportFormat serde round-trip ----

    #[test]
    fn export_format_serde_json() {
        let json_str = serde_json::to_string(&ExportFormat::Json).unwrap();
        assert_eq!(json_str, "\"json\"");
        let parsed: ExportFormat = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed, ExportFormat::Json);
    }

    #[test]
    fn export_format_serde_csv() {
        let csv_str = serde_json::to_string(&ExportFormat::Csv).unwrap();
        assert_eq!(csv_str, "\"csv\"");
        let parsed: ExportFormat = serde_json::from_str(&csv_str).unwrap();
        assert_eq!(parsed, ExportFormat::Csv);
    }

    #[test]
    fn export_format_serde_markdown() {
        let md_str = serde_json::to_string(&ExportFormat::Markdown).unwrap();
        assert_eq!(md_str, "\"markdown\"");
        let parsed: ExportFormat = serde_json::from_str(&md_str).unwrap();
        assert_eq!(parsed, ExportFormat::Markdown);
    }

    #[test]
    fn export_format_from_str_checked() {
        assert_eq!(
            ExportFormat::from_str_checked("json").unwrap(),
            ExportFormat::Json
        );
        assert_eq!(
            ExportFormat::from_str_checked("csv").unwrap(),
            ExportFormat::Csv
        );
        assert_eq!(
            ExportFormat::from_str_checked("markdown").unwrap(),
            ExportFormat::Markdown
        );
        assert_eq!(
            ExportFormat::from_str_checked("md").unwrap(),
            ExportFormat::Markdown
        );
        assert!(ExportFormat::from_str_checked("xml").is_err());
    }

    // ---- JSON export ----

    #[test]
    fn json_export_is_valid_json() {
        let exported = make_exported_case();
        let result = render_json(&exported).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("case").is_some());
        assert!(parsed.get("events").is_some());
        assert!(parsed.get("exported_at").is_some());
    }

    #[test]
    fn json_export_round_trip() {
        let exported = make_exported_case();
        let json = render_json(&exported).unwrap();
        // Should be valid JSON that can be parsed back.
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    // ---- CSV export ----

    #[test]
    fn csv_export_has_header_row() {
        let exported = make_exported_case();
        let result = render_csv(&exported);
        let lines: Vec<&str> = result.lines().collect();
        assert!(lines.len() >= 2, "CSV should have header + data rows");
        assert_eq!(
            lines[0],
            "event_type,occurred_at,actor_id,source_id,severity,annotation"
        );
    }

    #[test]
    fn csv_export_correct_column_count() {
        let exported = make_exported_case();
        let result = render_csv(&exported);
        for line in result.lines() {
            let col_count = count_csv_columns(line);
            assert_eq!(
                col_count, 6,
                "expected 6 columns, got {col_count} in line: {line}"
            );
        }
    }

    #[test]
    fn csv_export_empty_events() {
        let mut exported = make_exported_case();
        exported.events.clear();
        let result = render_csv(&exported);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 1, "CSV with no events should have only header");
    }

    #[test]
    fn csv_escape_handles_commas() {
        let escaped = csv_escape("hello, world");
        assert_eq!(escaped, "\"hello, world\"");
    }

    #[test]
    fn csv_escape_handles_quotes() {
        let escaped = csv_escape("say \"hi\"");
        assert_eq!(escaped, "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_escape_no_special_chars() {
        let escaped = csv_escape("plain");
        assert_eq!(escaped, "plain");
    }

    // ---- Markdown export ----

    #[test]
    fn markdown_export_contains_case_name() {
        let exported = make_exported_case();
        let result = render_markdown(&exported);
        assert!(result.contains("# Investigation Report: Test Investigation"));
    }

    #[test]
    fn markdown_export_contains_status() {
        let exported = make_exported_case();
        let result = render_markdown(&exported);
        assert!(result.contains("**Status:** Open"));
    }

    #[test]
    fn markdown_export_contains_description() {
        let exported = make_exported_case();
        let result = render_markdown(&exported);
        assert!(result.contains("## Description"));
        assert!(result.contains("Investigating suspicious login activity."));
    }

    #[test]
    fn markdown_export_contains_event_timeline_table() {
        let exported = make_exported_case();
        let result = render_markdown(&exported);
        assert!(result.contains("## Event Timeline"));
        assert!(result.contains("| # | Event Type |"));
        assert!(result.contains("auth.login.failure"));
    }

    #[test]
    fn markdown_export_empty_description() {
        let mut exported = make_exported_case();
        exported.case.description = String::new();
        let result = render_markdown(&exported);
        assert!(result.contains("_No description provided._"));
    }

    #[test]
    fn markdown_export_empty_events() {
        let mut exported = make_exported_case();
        exported.events.clear();
        let result = render_markdown(&exported);
        assert!(result.contains("_No events attached to this case._"));
    }

    #[test]
    fn markdown_export_pinned_events_section() {
        let mut exported = make_exported_case();
        exported.events[0].case_event.pinned = true;
        exported.events[0].case_event.annotation = "Key evidence".to_string();
        let result = render_markdown(&exported);
        assert!(result.contains("## Pinned Events"));
        assert!(result.contains("Key evidence"));
    }

    #[test]
    fn md_escape_handles_pipes() {
        assert_eq!(md_escape("a|b"), "a\\|b");
    }

    #[test]
    fn md_escape_no_pipes() {
        assert_eq!(md_escape("plain text"), "plain text");
    }

    // ---- helpers ----

    /// Counts the number of CSV columns in a line by counting
    /// unquoted commas.
    fn count_csv_columns(line: &str) -> usize {
        let mut count = 1;
        let mut in_quotes = false;
        for ch in line.chars() {
            match ch {
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => count += 1,
                _ => {}
            }
        }
        count
    }
}
