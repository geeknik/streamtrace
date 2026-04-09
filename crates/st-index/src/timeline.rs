//! Timeline query facade.
//!
//! Provides a validated, higher-level interface over `st-store` timeline
//! queries. All parameters are checked before forwarding to the database.

use std::sync::Arc;

use st_common::error::{StError, StResult};
use st_store::events::{TimelineQuery, TimelineResult};
use st_store::Database;

use crate::filters::validate_time_range;
use crate::search::{SearchQuery, SearchResult};

/// High-level index over forensic events.
///
/// Validates query parameters before delegating to the underlying
/// [`Database`] methods. Designed to be shared across async tasks
/// via `Arc`.
pub struct EventIndex {
    db: Arc<Database>,
}

impl EventIndex {
    /// Creates a new `EventIndex` backed by the given database handle.
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Executes a timeline query after validating parameters.
    ///
    /// Enforces:
    /// - `start` must be strictly before `end`
    /// - `limit` must be in `[1, 1000]`
    pub async fn query_timeline(&self, query: &TimelineQuery) -> StResult<TimelineResult> {
        validate_time_range(&query.start, &query.end)?;

        if query.limit == 0 {
            return Err(StError::Validation(
                "limit must be greater than 0".to_string(),
            ));
        }
        if query.limit > 1000 {
            return Err(StError::Validation(
                "limit must not exceed 1000".to_string(),
            ));
        }

        tracing::debug!(
            start = %query.start,
            end = %query.end,
            limit = query.limit,
            "executing timeline query"
        );

        self.db.query_timeline(query).await
    }

    /// Executes a full-text search against the event index.
    ///
    /// Validates query parameters and delegates to the search module.
    pub async fn search(&self, query: &SearchQuery) -> StResult<SearchResult> {
        crate::search::execute_search(&self.db, query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use st_common::types::SortOrder;

    fn make_query(start_offset_hours: i64, end_offset_hours: i64, limit: u32) -> TimelineQuery {
        let now = Utc::now();
        TimelineQuery {
            start: now - Duration::hours(start_offset_hours),
            end: now - Duration::hours(end_offset_hours),
            event_types: None,
            actor_id: None,
            source_id: None,
            severity_min: None,
            src_ip: None,
            search: None,
            tags: None,
            limit,
            cursor: None,
            order: SortOrder::Desc,
        }
    }

    // Validation tests do not need a database -- they fail before any I/O.

    #[test]
    fn rejects_inverted_time_range() {
        // start after end: start = now+2h, end = now
        let q = make_query(-2, 0, 100);
        let result = validate_time_range(&q.start, &q.end);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_equal_time_range() {
        let now = Utc::now();
        let result = validate_time_range(&now, &now);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_valid_time_range() {
        let now = Utc::now();
        let earlier = now - Duration::hours(1);
        let result = validate_time_range(&earlier, &now);
        assert!(result.is_ok());
    }
}
