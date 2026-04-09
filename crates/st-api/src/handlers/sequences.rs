//! Sequence detection endpoints.
//!
//! - `GET  /v1/sequences/patterns`  -- list all sequence patterns
//! - `GET  /v1/sequences/detected`  -- list detected sequences
//! - `POST /v1/sequences/scan`      -- trigger a scan over a time range

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use st_common::error::StError;
use st_common::types::{Permission, SortOrder};
use st_correlate::{builtin_patterns, SequenceDetector, SequencePattern};
use st_store::events::TimelineQuery;
use st_store::sequences::SequencePatternRecord;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_DETECTED_LIMIT: u32 = 50;
const MAX_DETECTED_LIMIT: u32 = 1000;

/// Maximum events to load for a single scan pass.
///
/// Capped at 50,000 to bound memory usage during sequence detection.
/// At ~2 KB per event, this consumes roughly 100 MB of heap, which is
/// acceptable for a scan operation that runs infrequently.
const MAX_SCAN_EVENTS: u32 = 50_000;

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

/// Query parameters for `GET /v1/sequences/detected`.
#[derive(Debug, Deserialize)]
pub struct DetectedParams {
    #[serde(default = "default_detected_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_detected_limit() -> u32 {
    DEFAULT_DETECTED_LIMIT
}

/// Query parameters for `POST /v1/sequences/scan`.
#[derive(Debug, Deserialize)]
pub struct ScanParams {
    /// Inclusive start of the time window (RFC 3339).
    pub start: DateTime<Utc>,
    /// Exclusive end of the time window (RFC 3339).
    pub end: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A pattern entry in the list response, combining built-in and stored
/// patterns into a uniform shape.
#[derive(Debug, Serialize)]
struct PatternEntry {
    /// Pattern ID (UUID for stored patterns, deterministic for built-in).
    id: Option<uuid::Uuid>,
    name: String,
    description: String,
    builtin: bool,
    enabled: bool,
    steps: Vec<StepEntry>,
    max_total_duration_secs: u64,
    same_actor: bool,
}

#[derive(Debug, Serialize)]
struct StepEntry {
    event_type_pattern: String,
    max_gap_secs: Option<u64>,
}

/// Response for `POST /v1/sequences/scan`.
#[derive(Debug, Serialize)]
struct ScanResponse {
    /// Number of events scanned.
    events_scanned: usize,
    /// Number of patterns checked.
    patterns_checked: usize,
    /// Number of new sequences detected and stored.
    sequences_detected: usize,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all sequence patterns (built-in + stored).
///
/// `GET /v1/sequences/patterns`
pub async fn list_patterns(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    // Fetch stored patterns from DB.
    let stored: Vec<SequencePatternRecord> = state
        .db
        .list_sequence_patterns()
        .await
        .map_err(ApiError::from)?;

    let mut entries: Vec<PatternEntry> = Vec::new();

    // Add built-in patterns.
    for bp in builtin_patterns() {
        entries.push(PatternEntry {
            id: None,
            name: bp.name,
            description: bp.description,
            builtin: true,
            enabled: true,
            steps: bp
                .steps
                .iter()
                .map(|s| StepEntry {
                    event_type_pattern: s.event_type_pattern.clone(),
                    max_gap_secs: s.max_gap_secs,
                })
                .collect(),
            max_total_duration_secs: bp.max_total_duration_secs,
            same_actor: bp.same_actor,
        });
    }

    // Add stored patterns.
    for sp in stored {
        // Try to deserialize the definition to extract steps.
        let parsed: Option<SequencePattern> =
            serde_json::from_value(sp.definition.clone()).ok();

        entries.push(PatternEntry {
            id: Some(sp.id),
            name: sp.name,
            description: sp.description,
            builtin: false,
            enabled: sp.enabled,
            steps: parsed
                .as_ref()
                .map(|p| {
                    p.steps
                        .iter()
                        .map(|s| StepEntry {
                            event_type_pattern: s.event_type_pattern.clone(),
                            max_gap_secs: s.max_gap_secs,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            max_total_duration_secs: parsed
                .as_ref()
                .map(|p| p.max_total_duration_secs)
                .unwrap_or(0),
            same_actor: parsed.as_ref().map(|p| p.same_actor).unwrap_or(false),
        });
    }

    Ok(Json(entries))
}

/// List detected sequences with pagination.
///
/// `GET /v1/sequences/detected?limit=50&offset=0`
pub async fn list_detected(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<DetectedParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let limit = params.limit.clamp(1, MAX_DETECTED_LIMIT);
    let offset = params.offset;

    let detected = state
        .db
        .list_detected_sequences(limit, offset)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(detected))
}

/// Trigger a scan for sequence patterns in a time range.
///
/// `POST /v1/sequences/scan?start=...&end=...`
///
/// Fetches events in the time range, runs the SequenceDetector against all
/// enabled patterns (built-in + stored), stores detected sequences, and
/// returns the count.
pub async fn scan(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<ScanParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    if params.start >= params.end {
        return Err(ApiError(StError::Validation(
            "start must be before end".to_string(),
        )));
    }

    // Fetch events in ascending order for sequence detection.
    let query = TimelineQuery {
        start: params.start,
        end: params.end,
        event_types: None,
        actor_id: None,
        source_id: None,
        severity_min: None,
        src_ip: None,
        search: None,
        tags: None,
        limit: MAX_SCAN_EVENTS,
        cursor: None,
        order: SortOrder::Asc,
    };

    let result = state
        .db
        .query_timeline(&query)
        .await
        .map_err(ApiError::from)?;
    let events = result.events;
    let events_scanned = events.len();

    // Collect all enabled patterns: built-in + stored (enabled only).
    let mut patterns: Vec<(Option<uuid::Uuid>, SequencePattern)> = Vec::new();

    for bp in builtin_patterns() {
        patterns.push((None, bp));
    }

    let stored = state
        .db
        .list_sequence_patterns()
        .await
        .map_err(ApiError::from)?;

    for sp in stored {
        if !sp.enabled {
            continue;
        }
        if let Ok(parsed) = serde_json::from_value::<SequencePattern>(sp.definition.clone()) {
            patterns.push((Some(sp.id), parsed));
        }
    }

    let patterns_checked = patterns.len();
    let detector = SequenceDetector::new();
    let mut sequences_detected: usize = 0;

    for (pattern_id, pattern) in &patterns {
        let matches = detector.detect(pattern, &events);

        for m in &matches {
            // For built-in patterns without a DB record, use a nil UUID.
            let db_pattern_id = pattern_id.unwrap_or(uuid::Uuid::nil());

            let _stored_id = state
                .db
                .store_detected_sequence(
                    db_pattern_id,
                    &m.pattern_name,
                    &m.event_ids,
                    m.actor_id.as_deref(),
                    m.started_at,
                    m.ended_at,
                    m.confidence,
                )
                .await
                .map_err(ApiError::from)?;

            sequences_detected += 1;
        }
    }

    tracing::info!(
        events_scanned,
        patterns_checked,
        sequences_detected,
        start = %params.start,
        end = %params.end,
        "sequence scan completed"
    );

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "sequence.scan",
                    &actor,
                    Some("sequences"),
                    None,
                    serde_json::json!({
                        "events_scanned": events_scanned,
                        "sequences_detected": sequences_detected,
                    }),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok(Json(ScanResponse {
        events_scanned,
        patterns_checked,
        sequences_detected,
    }))
}
