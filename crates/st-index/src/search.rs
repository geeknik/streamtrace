//! Full-text search over forensic events.
//!
//! Uses PostgreSQL `plainto_tsquery` against the `search_text` tsvector
//! column. Query strings are sanitized before execution.

use serde::{Deserialize, Serialize};
use sqlx::Row;

use st_common::error::{StError, StResult};
use st_common::event::ForensicEvent;
use st_store::Database;

use crate::filters::sanitize_search_query;

/// Maximum allowed search result limit.
const MAX_SEARCH_LIMIT: u32 = 100;

/// Default search result limit.
const DEFAULT_SEARCH_LIMIT: u32 = 20;

/// Maximum allowed offset for search pagination.
/// Deep offsets are expensive on large tables; callers should use
/// cursor-based pagination for deep result sets.
const MAX_SEARCH_OFFSET: u32 = 10_000;

/// Full-text search query over forensic events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// The search text. Must not be empty after trimming.
    pub query: String,
    /// Maximum number of results to return. Default 20, max 100.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Offset for pagination. Default 0.
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    DEFAULT_SEARCH_LIMIT
}

/// Paginated search result with total count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Matching events for this page.
    pub events: Vec<ForensicEvent>,
    /// Total number of matching events (for pagination).
    pub total: u64,
    /// The limit that was applied.
    pub limit: u32,
    /// The offset that was applied.
    pub offset: u32,
}

/// Validates a search query and executes it against the database.
///
/// This function is internal to the crate; the public API is
/// [`EventIndex::search`](crate::EventIndex::search).
pub(crate) async fn execute_search(db: &Database, query: &SearchQuery) -> StResult<SearchResult> {
    let sanitized = sanitize_search_query(&query.query);
    if sanitized.is_empty() {
        return Err(StError::Validation(
            "search query must not be empty".to_string(),
        ));
    }

    if query.offset > MAX_SEARCH_OFFSET {
        return Err(StError::Validation(
            "offset too large, use cursor-based pagination for deep results".to_string(),
        ));
    }

    let limit = if query.limit == 0 {
        DEFAULT_SEARCH_LIMIT
    } else {
        query.limit.min(MAX_SEARCH_LIMIT)
    };

    let offset = query.offset;

    tracing::debug!(
        query = %sanitized,
        limit,
        offset,
        "executing full-text search"
    );

    // Count total matches.
    let count_row = sqlx::query(
        r#"
        SELECT COUNT(*) AS total
        FROM events
        WHERE search_text @@ plainto_tsquery('simple', $1)
        "#,
    )
    .bind(&sanitized)
    .fetch_one(db.pool())
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "search count query failed");
        StError::Database(e.to_string())
    })?;

    let total: i64 = count_row.get("total");

    // Fetch the page of results.
    let rows = sqlx::query(
        r#"
        SELECT id, raw_event_id, event_type, severity,
               occurred_at, observed_at, received_at,
               actor_id, actor_name, actor_type,
               subject_id, subject_name, subject_type,
               object_id, object_name, object_type,
               host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
               src_port, dst_port, protocol,
               device_id, device_name, device_type, hostname,
               source_id, source_type, source_name,
               tags, custom_fields
        FROM events
        WHERE search_text @@ plainto_tsquery('simple', $1)
        ORDER BY occurred_at DESC, id DESC
        LIMIT $2
        OFFSET $3
        "#,
    )
    .bind(&sanitized)
    .bind(i64::from(limit))
    .bind(i64::from(offset))
    .fetch_all(db.pool())
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "search query failed");
        StError::Database(e.to_string())
    })?;

    let events: Vec<ForensicEvent> = rows
        .iter()
        .map(st_store::events::forensic_event_from_row)
        .collect();

    Ok(SearchResult {
        events,
        total: total as u64,
        limit,
        offset,
    })
}
