//! Correlation chain and entity search endpoints.
//!
//! - `GET  /v1/correlate/chain`   -- build correlation chain from a seed event
//! - `POST /v1/correlate/search`  -- search entities by type/identifier

use std::collections::{HashSet, VecDeque};

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use st_common::error::StError;
use st_common::event::{Entity, ForensicEvent};
use st_common::types::Permission;
use st_correlate::extract_entities;
use uuid::Uuid;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_CHAIN_DEPTH: u32 = 3;
const DEFAULT_CHAIN_DEPTH: u32 = 1;
const DEFAULT_TIME_WINDOW_SECS: u64 = 3600;
const MAX_TIME_WINDOW_SECS: u64 = 86400;
const MAX_CHAIN_EVENTS: usize = 500;

const DEFAULT_SEARCH_LIMIT: u32 = 50;
const MAX_SEARCH_LIMIT: u32 = 500;

// ---------------------------------------------------------------------------
// Query / body params
// ---------------------------------------------------------------------------

/// Query parameters for `GET /v1/correlate/chain`.
#[derive(Debug, Deserialize)]
pub struct ChainParams {
    /// UUID of the seed event.
    pub seed_event_id: Uuid,
    /// Time window in seconds around the seed event for finding related events.
    #[serde(default = "default_time_window")]
    pub time_window_secs: u64,
    /// Maximum BFS depth (1-3).
    #[serde(default = "default_chain_depth")]
    pub max_depth: u32,
}

fn default_time_window() -> u64 {
    DEFAULT_TIME_WINDOW_SECS
}

fn default_chain_depth() -> u32 {
    DEFAULT_CHAIN_DEPTH
}

/// Request body for `POST /v1/correlate/search`.
#[derive(Debug, Deserialize)]
pub struct EntitySearchBody {
    /// Optional entity type filter.
    #[serde(default)]
    pub entity_type: Option<String>,
    /// Optional substring to match against entity identifiers.
    #[serde(default)]
    pub identifier_contains: Option<String>,
    /// Maximum results.
    #[serde(default = "default_search_limit")]
    pub limit: Option<u32>,
}

fn default_search_limit() -> Option<u32> {
    Some(DEFAULT_SEARCH_LIMIT)
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response for `GET /v1/correlate/chain`.
#[derive(Debug, Serialize)]
struct ChainResponse {
    seed_event: ForensicEvent,
    chain: Vec<ForensicEvent>,
    entities: Vec<Entity>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Build a correlation chain from a seed event.
///
/// `GET /v1/correlate/chain?seed_event_id=...&time_window_secs=3600&max_depth=1`
///
/// 1. Fetch the seed event.
/// 2. Extract its entities.
/// 3. For each entity, get related events within the time window.
/// 4. If max_depth > 1, recurse (BFS) on newly found events.
/// 5. Return the seed, chain of related events, and involved entities.
pub async fn correlation_chain(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<ChainParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let max_depth = params.max_depth.clamp(1, MAX_CHAIN_DEPTH);
    let time_window = params
        .time_window_secs
        .clamp(1, MAX_TIME_WINDOW_SECS);
    let half_window = Duration::seconds(time_window as i64 / 2);

    // 1. Get the seed event.
    let seed_event = state
        .db
        .get_event(params.seed_event_id)
        .await
        .map_err(ApiError::from)?;

    // Track seen event IDs and entity IDs to avoid duplicates.
    let mut seen_event_ids: HashSet<Uuid> = HashSet::new();
    seen_event_ids.insert(seed_event.id);

    let mut seen_entity_ids: HashSet<Uuid> = HashSet::new();
    let mut all_entities: Vec<Entity> = Vec::new();
    let mut chain: Vec<ForensicEvent> = Vec::new();

    // BFS queue: events to process at each depth level.
    let mut queue: VecDeque<(ForensicEvent, u32)> = VecDeque::new();
    queue.push_back((seed_event.clone(), 0));

    while let Some((event, depth)) = queue.pop_front() {
        if chain.len() >= MAX_CHAIN_EVENTS {
            break;
        }

        // Extract entities from this event.
        let (observed, _relationships) = extract_entities(&event);

        let window_start = event.occurred_at - half_window;
        let window_end = event.occurred_at + half_window;

        for obs in &observed {
            if chain.len() >= MAX_CHAIN_EVENTS {
                break;
            }

            // Look up the entity in the database by type + identifier.
            let db_entity = match state
                .db
                .get_entity_by_identifier(&obs.entity_type, &obs.identifier)
                .await
            {
                Ok(Some(e)) => e,
                Ok(None) => continue,
                Err(_) => continue,
            };

            // Track entity.
            if seen_entity_ids.insert(db_entity.id) {
                all_entities.push(db_entity.clone());
            }

            // Get related events for this entity within the time window.
            let remaining = (MAX_CHAIN_EVENTS - chain.len()).min(100) as u32;
            let related = match state
                .db
                .get_entity_events(db_entity.id, window_start, window_end, remaining)
                .await
            {
                Ok(events) => events,
                Err(_) => continue,
            };

            for rel_event in related {
                if chain.len() >= MAX_CHAIN_EVENTS {
                    break;
                }
                if seen_event_ids.insert(rel_event.id) {
                    // Queue for further BFS if within depth.
                    if depth + 1 < max_depth {
                        queue.push_back((rel_event.clone(), depth + 1));
                    }
                    chain.push(rel_event);
                }
            }
        }
    }

    // Sort chain chronologically.
    chain.sort_by_key(|e| e.occurred_at);

    Ok(Json(ChainResponse {
        seed_event,
        chain,
        entities: all_entities,
    }))
}

/// Search for entities matching criteria.
///
/// `POST /v1/correlate/search`
///
/// Body: `{ "entity_type": "user", "identifier_contains": "alice", "limit": 50 }`
pub async fn entity_search(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Json(body): Json<EntitySearchBody>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    // Validate that at least one search criterion is provided.
    if body.entity_type.is_none() && body.identifier_contains.is_none() {
        return Err(ApiError(StError::Validation(
            "at least one of entity_type or identifier_contains must be provided".to_string(),
        )));
    }

    // Reject empty identifier_contains.
    if let Some(ref ic) = body.identifier_contains {
        let trimmed = ic.trim();
        if trimmed.is_empty() {
            return Err(ApiError(StError::Validation(
                "identifier_contains must not be empty".to_string(),
            )));
        }
        // Cap length to prevent abuse.
        if trimmed.len() > 256 {
            return Err(ApiError(StError::Validation(
                "identifier_contains must be at most 256 characters".to_string(),
            )));
        }
    }

    let limit = body
        .limit
        .unwrap_or(DEFAULT_SEARCH_LIMIT)
        .clamp(1, MAX_SEARCH_LIMIT);

    let entities = state
        .db
        .search_entities(
            body.entity_type.as_deref(),
            body.identifier_contains.as_deref(),
            limit,
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Json(entities))
}
