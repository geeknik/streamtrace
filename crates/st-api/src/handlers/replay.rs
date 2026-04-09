//! Event replay endpoint via Server-Sent Events (SSE).
//!
//! `GET /v1/replay?start=...&end=...&speed=1.0`
//!
//! Streams forensic events in chronological order as SSE. The `speed`
//! parameter controls real-time playback: 1.0 = real-time gaps between
//! events, 10.0 = 10x faster, 0 = instant dump with no delays.

use std::convert::Infallible;

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use st_common::types::{Permission, SortOrder};
use st_store::events::TimelineQuery;
use tokio_stream::Stream;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

/// Maximum number of events that can be replayed in a single request.
///
/// Capped at 10,000 to bound memory usage. At ~2 KB per serialized event,
/// 10,000 events consumes roughly 20 MB of heap, which is acceptable for
/// a single SSE stream.
const MAX_REPLAY_LIMIT: u32 = 10_000;
/// Default number of events returned.
const DEFAULT_REPLAY_LIMIT: u32 = 1_000;
/// Maximum inter-event delay in milliseconds (caps very long real-time gaps).
const MAX_DELAY_MS: u64 = 5_000;

/// Query parameters for the replay endpoint.
#[derive(Debug, Deserialize)]
pub struct ReplayParams {
    /// Inclusive start of the time window (RFC 3339).
    pub start: DateTime<Utc>,
    /// Exclusive end of the time window (RFC 3339).
    pub end: DateTime<Utc>,
    /// Playback speed multiplier. 0 = instant, 1.0 = real-time.
    #[serde(default = "default_speed")]
    pub speed: f64,
    /// Filter to events linked to this entity ID.
    #[serde(default)]
    pub entity_id: Option<String>,
    /// Filter to events from this source ID.
    #[serde(default)]
    pub source_id: Option<String>,
    /// Maximum number of events to replay (default 1000, max 10000).
    #[serde(default = "default_replay_limit")]
    pub limit: u32,
}

fn default_speed() -> f64 {
    1.0
}

fn default_replay_limit() -> u32 {
    DEFAULT_REPLAY_LIMIT
}

/// Stream forensic events as SSE in chronological order.
///
/// Events are fetched from the database and emitted with timing
/// proportional to their real-world occurrence gaps divided by the
/// speed multiplier.
pub async fn replay(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<ReplayParams>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    auth.require_permission(Permission::Read)?;

    // Validate parameters.
    if params.start >= params.end {
        return Err(ApiError(st_common::error::StError::Validation(
            "start must be before end".to_string(),
        )));
    }
    if params.speed < 0.0 {
        return Err(ApiError(st_common::error::StError::Validation(
            "speed must be >= 0".to_string(),
        )));
    }

    let limit = params.limit.clamp(1, MAX_REPLAY_LIMIT);
    let speed = params.speed;

    // Build a timeline query in ascending chronological order.
    let query = TimelineQuery {
        start: params.start,
        end: params.end,
        event_types: None,
        actor_id: None,
        source_id: params.source_id,
        severity_min: None,
        src_ip: None,
        search: None,
        tags: None,
        limit,
        cursor: None,
        order: SortOrder::Asc,
    };

    // Fetch events upfront. The limit cap at 10k keeps memory bounded.
    let result = state
        .db
        .query_timeline(&query)
        .await
        .map_err(ApiError::from)?;
    let events = result.events;

    tracing::info!(
        event_count = events.len(),
        speed = speed,
        start = %params.start,
        end = %params.end,
        "starting event replay"
    );

    // Build an async stream that yields SSE events with timing.
    let stream = async_stream::stream! {
        let mut prev_time: Option<DateTime<Utc>> = None;

        for event in &events {
            // Compute inter-event delay if speed > 0.
            if speed > 0.0 {
                if let Some(prev) = prev_time {
                    let gap = event.occurred_at - prev;
                    let gap_ms = gap.num_milliseconds().max(0) as u64;
                    if gap_ms > 0 {
                        let delay_ms = ((gap_ms as f64) / speed) as u64;
                        let capped_ms = delay_ms.min(MAX_DELAY_MS);
                        if capped_ms > 0 {
                            tokio::time::sleep(
                                tokio::time::Duration::from_millis(capped_ms),
                            )
                            .await;
                        }
                    }
                }
            }
            prev_time = Some(event.occurred_at);

            // Serialize the event as JSON for the SSE data field.
            match serde_json::to_string(&event) {
                Ok(json) => {
                    let sse_event = Event::default()
                        .event("event")
                        .data(json)
                        .id(event.id.to_string());
                    yield Ok::<_, Infallible>(sse_event);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize event for replay");
                    // Skip events that fail to serialize rather than
                    // breaking the stream.
                }
            }
        }

        // Send a final "done" event so clients know the stream is complete.
        let done_event = Event::default()
            .event("done")
            .data(format!("{{\"total\":{}}}", events.len()));
        yield Ok::<_, Infallible>(done_event);
    };

    Ok(
        Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(tokio::time::Duration::from_secs(15))),
    )
}
