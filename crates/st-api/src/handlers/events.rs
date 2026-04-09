//! Individual event endpoints.
//!
//! - `GET /v1/events/:id`            -- fetch a normalized event
//! - `GET /v1/events/:id/raw`        -- fetch the raw event with integrity info
//! - `GET /v1/events/:id/correlated` -- fetch correlated events

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use st_common::event::ForensicEvent;
use st_common::types::Permission;
use st_correlate::extract_correlation_keys;
use st_crypto::hash::hash_blake3;
use uuid::Uuid;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

/// Fetch a single normalized forensic event by ID.
///
/// `GET /v1/events/:id`
///
/// Returns 200 with the event JSON, or 404 if not found.
pub async fn get_event(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let event = state
        .db
        .get_event(id)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(event))
}

/// Response for the raw event endpoint, including integrity verification.
#[derive(Debug, Serialize)]
struct RawEventResponse {
    /// Unique ID of the raw event.
    id: Uuid,
    /// BLAKE3 content hash stored at ingestion time.
    content_hash: String,
    /// MIME type / content type of the raw data.
    content_type: String,
    /// Size in bytes.
    byte_size: i32,
    /// Source ID that produced this event.
    source_id: String,
    /// Source type.
    source_type: String,
    /// Optional source name.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_name: Option<String>,
    /// When the raw event was received.
    received_at: chrono::DateTime<chrono::Utc>,
    /// Parser that was used (if specified).
    #[serde(skip_serializing_if = "Option::is_none")]
    parser_id: Option<String>,
    /// Whether the stored content matches the recorded hash.
    hash_verified: bool,
}

/// Fetch the raw event associated with a normalized event.
///
/// `GET /v1/events/:id/raw`
///
/// Looks up the normalized event to find its `raw_event_id`, then fetches
/// the raw event. Recomputes the BLAKE3 hash and compares against the
/// stored hash for integrity verification.
pub async fn get_event_raw(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    // Get the normalized event to find the raw_event_id.
    let event = state
        .db
        .get_event(id)
        .await
        .map_err(ApiError::from)?;

    let raw = state
        .db
        .get_raw_event(event.raw_event_id)
        .await
        .map_err(ApiError::from)?;

    // Verify content integrity by recomputing the hash.
    let computed = hash_blake3(&raw.content);
    let hash_verified = computed.hex_digest == raw.content_hash;

    if !hash_verified {
        tracing::warn!(
            raw_event_id = %raw.id,
            stored_hash = %raw.content_hash,
            computed_hash = %computed.hex_digest,
            "raw event integrity check failed"
        );
    }

    let response = RawEventResponse {
        id: raw.id,
        content_hash: raw.content_hash,
        content_type: raw.content_type,
        byte_size: raw.byte_size,
        source_id: raw.source_id,
        source_type: raw.source_type,
        source_name: raw.source_name,
        received_at: raw.received_at,
        parser_id: raw.parser_id,
        hash_verified,
    };

    Ok(axum::Json(response))
}

/// Query parameters for the correlated events endpoint.
#[derive(Debug, Deserialize)]
pub struct CorrelatedParams {
    /// Maximum number of correlated events to return (default 50, max 1000).
    #[serde(default = "default_correlated_limit")]
    pub limit: u32,
}

fn default_correlated_limit() -> u32 {
    50
}

/// Response for the correlated events endpoint.
#[derive(Debug, Serialize)]
struct CorrelatedResponse {
    /// The source event.
    source_event_id: Uuid,
    /// Correlation description.
    correlation_description: String,
    /// Correlated events found.
    events: Vec<ForensicEvent>,
    /// Total correlated events returned.
    count: usize,
}

/// Fetch events correlated to the given event via shared correlation keys.
///
/// `GET /v1/events/:id/correlated?limit=50`
///
/// Extracts correlation keys from the event and queries each key type/value
/// pair for matching events. Deduplicates and excludes the source event itself.
pub async fn get_correlated_events(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<CorrelatedParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let limit = params.limit.clamp(1, 1000);

    // Get the source event.
    let event = state
        .db
        .get_event(id)
        .await
        .map_err(ApiError::from)?;

    // Extract correlation keys from the event.
    let keys = extract_correlation_keys(&event);
    let description = st_correlate::describe_correlation(&keys);

    // Query for correlated events across all keys.
    let mut seen = std::collections::HashSet::new();
    seen.insert(id); // Exclude the source event.
    let mut correlated: Vec<ForensicEvent> = Vec::new();

    for key in &keys {
        if correlated.len() >= limit as usize {
            break;
        }

        let key_type_str = correlation_key_type_to_str(&key.key_type);
        let remaining = limit.saturating_sub(correlated.len() as u32);

        let events = state
            .db
            .get_correlated_events(&key_type_str, &key.key_value, remaining)
            .await
            .map_err(ApiError::from)?;

        for evt in events {
            if correlated.len() >= limit as usize {
                break;
            }
            if seen.insert(evt.id) {
                correlated.push(evt);
            }
        }
    }

    let count = correlated.len();
    let response = CorrelatedResponse {
        source_event_id: id,
        correlation_description: description,
        events: correlated,
        count,
    };

    Ok(axum::Json(response))
}

/// Convert a correlation key type to its database string representation.
fn correlation_key_type_to_str(kt: &st_common::event::CorrelationKeyType) -> String {
    use st_common::event::CorrelationKeyType;
    match kt {
        CorrelationKeyType::Identity => "identity".to_string(),
        CorrelationKeyType::Session => "session".to_string(),
        CorrelationKeyType::Token => "token".to_string(),
        CorrelationKeyType::Ip => "ip".to_string(),
        CorrelationKeyType::Device => "device".to_string(),
        CorrelationKeyType::Host => "host".to_string(),
        CorrelationKeyType::Custom(s) => s.clone(),
    }
}
