//! Entity graph endpoints.
//!
//! - `GET  /v1/entities`               -- list entities
//! - `GET  /v1/entities/{id}`          -- entity detail + relationships
//! - `GET  /v1/entities/{id}/timeline` -- events involving this entity
//! - `GET  /v1/entities/{id}/graph`    -- entity neighborhood graph

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use st_common::event::{Entity, EntityRelationship};
use st_common::types::Permission;
use st_common::MAX_GRAPH_DEPTH;
use st_store::entities::EntityGraph;
use uuid::Uuid;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_ENTITY_LIST_LIMIT: u32 = 50;
const MAX_ENTITY_LIST_LIMIT: u32 = 500;

const DEFAULT_TIMELINE_LIMIT: u32 = 100;
const MAX_TIMELINE_LIMIT: u32 = 1000;

const DEFAULT_GRAPH_DEPTH: u32 = 1;

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

/// Query parameters for `GET /v1/entities`.
#[derive(Debug, Deserialize)]
pub struct ListEntitiesParams {
    /// Optional entity type filter (e.g. "user", "ip", "device").
    #[serde(default)]
    pub entity_type: Option<String>,
    /// Maximum number of entities to return.
    #[serde(default = "default_entity_list_limit")]
    pub limit: u32,
}

fn default_entity_list_limit() -> u32 {
    DEFAULT_ENTITY_LIST_LIMIT
}

/// Query parameters for `GET /v1/entities/{id}/timeline`.
#[derive(Debug, Deserialize)]
pub struct EntityTimelineParams {
    /// Inclusive start of the time window (RFC 3339).
    pub start: DateTime<Utc>,
    /// Exclusive end of the time window (RFC 3339).
    pub end: DateTime<Utc>,
    /// Maximum events to return.
    #[serde(default = "default_timeline_limit")]
    pub limit: u32,
}

fn default_timeline_limit() -> u32 {
    DEFAULT_TIMELINE_LIMIT
}

/// Query parameters for `GET /v1/entities/{id}/graph`.
#[derive(Debug, Deserialize)]
pub struct EntityGraphParams {
    /// Maximum hop depth for graph traversal (1-3).
    #[serde(default = "default_graph_depth")]
    pub max_depth: u32,
}

fn default_graph_depth() -> u32 {
    DEFAULT_GRAPH_DEPTH
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response for `GET /v1/entities/{id}`.
#[derive(Debug, Serialize)]
struct EntityDetailResponse {
    entity: Entity,
    relationships: Vec<EntityRelationship>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List entities with optional type filter.
///
/// `GET /v1/entities?entity_type=user&limit=50`
pub async fn list_entities(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<ListEntitiesParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let limit = params.limit.clamp(1, MAX_ENTITY_LIST_LIMIT);

    let entities = state
        .db
        .list_entities(params.entity_type.as_deref(), limit)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(entities))
}

/// Get entity details with relationships.
///
/// `GET /v1/entities/{id}`
pub async fn get_entity(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let entity = state.db.get_entity(id).await.map_err(ApiError::from)?;

    let relationships = state
        .db
        .get_entity_relationships(id)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(EntityDetailResponse {
        entity,
        relationships,
    }))
}

/// Get events involving an entity within a time range.
///
/// `GET /v1/entities/{id}/timeline?start=...&end=...&limit=100`
pub async fn get_entity_timeline(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<EntityTimelineParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    if params.start >= params.end {
        return Err(ApiError(st_common::error::StError::Validation(
            "start must be before end".to_string(),
        )));
    }

    let limit = params.limit.clamp(1, MAX_TIMELINE_LIMIT);

    // Verify entity exists (returns 404 if not).
    let _entity = state.db.get_entity(id).await.map_err(ApiError::from)?;

    let events = state
        .db
        .get_entity_events(id, params.start, params.end, limit)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(events))
}

/// Get the entity neighborhood graph.
///
/// `GET /v1/entities/{id}/graph?max_depth=2`
pub async fn get_entity_graph(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<EntityGraphParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let max_depth = params.max_depth.clamp(1, MAX_GRAPH_DEPTH);

    let graph: EntityGraph = state
        .db
        .get_entity_graph(id, max_depth)
        .await
        .map_err(ApiError::from)?;

    Ok(axum::Json(graph))
}
