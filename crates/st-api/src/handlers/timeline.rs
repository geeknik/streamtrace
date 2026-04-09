//! Timeline query endpoint.
//!
//! `GET /v1/timeline` -- paginated, filtered timeline of forensic events.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use st_common::types::{Permission, Severity, SortOrder};
use st_store::events::TimelineQuery;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

/// Query parameters for the timeline endpoint, deserialized from the URL.
///
/// Comma-separated fields (`event_types`, `tags`) are split after
/// deserialization. All fields have sensible defaults.
#[derive(Debug, Deserialize)]
pub struct TimelineQueryParams {
    /// Inclusive start of the time window (RFC 3339).
    pub start: DateTime<Utc>,
    /// Exclusive end of the time window (RFC 3339).
    pub end: DateTime<Utc>,
    /// Comma-separated event types to filter by.
    #[serde(default)]
    pub event_types: Option<String>,
    /// Filter by actor ID.
    #[serde(default)]
    pub actor_id: Option<String>,
    /// Filter by source ID.
    #[serde(default)]
    pub source_id: Option<String>,
    /// Minimum severity threshold.
    #[serde(default)]
    pub severity_min: Option<Severity>,
    /// Filter by source IP address.
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Full-text search query.
    #[serde(default)]
    pub search: Option<String>,
    /// Comma-separated tags to filter by (all must match).
    #[serde(default)]
    pub tags: Option<String>,
    /// Maximum results to return (default 100, max 1000).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Opaque cursor for keyset pagination.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Sort order: "Asc" or "Desc" (default: Desc).
    #[serde(default = "default_order")]
    pub order: SortOrder,
}

fn default_limit() -> u32 {
    100
}

fn default_order() -> SortOrder {
    SortOrder::Desc
}

/// Parses a comma-separated string into a `Vec<String>`, filtering empty segments.
fn parse_comma_separated(s: &str) -> Vec<String> {
    s.split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

/// Query the forensic event timeline with filters and cursor-based pagination.
///
/// `GET /v1/timeline?start=...&end=...`
pub async fn get_timeline(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<TimelineQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let event_types = params
        .event_types
        .as_deref()
        .map(parse_comma_separated)
        .filter(|v| !v.is_empty());

    let tags = params
        .tags
        .as_deref()
        .map(parse_comma_separated)
        .filter(|v| !v.is_empty());

    let query = TimelineQuery {
        start: params.start,
        end: params.end,
        event_types,
        actor_id: params.actor_id,
        source_id: params.source_id,
        severity_min: params.severity_min,
        src_ip: params.src_ip,
        search: params.search,
        tags,
        limit: params.limit,
        cursor: params.cursor,
        order: params.order,
    };

    let result = state
        .index
        .query_timeline(&query)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(result))
}
