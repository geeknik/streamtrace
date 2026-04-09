//! Legal hold management endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use st_common::error::StError;
use st_common::types::Permission;
use st_store::events::forensic_event_from_row;
use uuid::Uuid;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / query types
// ---------------------------------------------------------------------------

/// Allowed hold types.
const VALID_HOLD_TYPES: &[&str] = &["time_range", "entity", "case", "query"];

/// Maximum serialized size for hold criteria JSON (10 KB).
const MAX_CRITERIA_SIZE_BYTES: usize = 10_240;

/// Request body for creating a legal hold.
#[derive(Debug, Deserialize)]
pub struct CreateHoldBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub hold_type: String,
    pub criteria: serde_json::Value,
    pub created_by: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Query parameters for listing holds.
#[derive(Debug, Deserialize)]
pub struct ListHoldsParams {
    #[serde(default)]
    pub status: Option<String>,
    /// Maximum number of holds to return (default 100, max 1000).
    #[serde(default)]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Create a new legal hold.
///
/// `POST /v1/holds`
///
/// Returns 201 Created with the new `LegalHold`.
pub async fn create_hold(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Json(body): Json<CreateHoldBody>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    // Validate hold_type against allowed values before delegating.
    if !VALID_HOLD_TYPES.contains(&body.hold_type.as_str()) {
        return Err(ApiError::from(StError::Validation(
            "hold_type must be one of: time_range, entity, case, query".to_string(),
        )));
    }

    // Validate criteria JSON size to prevent oversized payloads.
    let criteria_size = serde_json::to_string(&body.criteria)
        .map(|s| s.len())
        .unwrap_or(0);
    if criteria_size > MAX_CRITERIA_SIZE_BYTES {
        return Err(ApiError(StError::Validation(
            "criteria too large (max 10KB)".into(),
        )));
    }

    let hold = state
        .cases
        .create_hold(
            &body.name,
            &body.description,
            &body.hold_type,
            body.criteria,
            &body.created_by,
            body.expires_at,
        )
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let hold_id_str = hold.id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "hold.create",
                    &actor,
                    Some("hold"),
                    Some(&hold_id_str),
                    serde_json::json!({}),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok((StatusCode::CREATED, Json(hold)))
}

/// List legal holds with optional status filter.
///
/// `GET /v1/holds?status=active&limit=100`
pub async fn list_holds(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<ListHoldsParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    // Validate the status filter if provided.
    if let Some(ref s) = params.status {
        match s.as_str() {
            "active" | "released" | "expired" => {}
            _ => {
                return Err(ApiError::from(StError::Validation(
                    "status must be one of: active, released, expired".to_string(),
                )));
            }
        }
    }

    let holds = state
        .cases
        .list_holds(params.status.as_deref(), params.limit)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(holds))
}

/// Get hold details with event count.
///
/// `GET /v1/holds/{id}`
///
/// Returns `{ hold, event_count }`.
pub async fn get_hold(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let hold = state
        .cases
        .get_hold(id)
        .await
        .map_err(ApiError::from)?;

    let event_count = state
        .cases
        .get_hold_event_count(id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({
        "hold": hold,
        "event_count": event_count,
    })))
}

/// Release a legal hold.
///
/// `POST /v1/holds/{id}/release`
pub async fn release_hold(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    let hold = state
        .cases
        .release_hold(id)
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let hold_id_str = id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "hold.release",
                    &actor,
                    Some("hold"),
                    Some(&hold_id_str),
                    serde_json::json!({}),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok(Json(hold))
}

/// Map a sqlx error to `StError::Database` (local helper).
fn map_sqlx_err(e: sqlx::Error) -> StError {
    tracing::error!(error = %e, "database query failed (holds)");
    StError::Database(e.to_string())
}

/// Materialize hold events based on hold criteria.
///
/// `POST /v1/holds/{id}/materialize`
///
/// For `time_range` holds: queries events in the time range and links them.
/// For `case` holds: takes all events from the referenced case.
/// For `entity` and `query` holds: returns 400 (not yet implemented).
/// Returns `{ events_added }`.
///
/// All reads and writes for materialization execute within a single
/// transaction to prevent inconsistent state if the operation is
/// interrupted mid-way.
pub async fn materialize_hold(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    let hold = state
        .cases
        .get_hold(id)
        .await
        .map_err(ApiError::from)?;

    if hold.status != "active" {
        return Err(ApiError::from(StError::Validation(
            "can only materialize events for active holds".to_string(),
        )));
    }

    let events_added: usize = match hold.hold_type.as_str() {
        "time_range" => {
            // Expect criteria: { "start": "...", "end": "..." }
            let start = hold
                .criteria
                .get("start")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .ok_or_else(|| {
                    StError::Validation("criteria.start is required for time_range holds".into())
                })?;

            let end = hold
                .criteria
                .get("end")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .ok_or_else(|| {
                    StError::Validation("criteria.end is required for time_range holds".into())
                })?;

            // Execute the query and insert within a single transaction.
            let mut tx = state.db.begin().await.map_err(ApiError::from)?;

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
                WHERE occurred_at >= $1 AND occurred_at <= $2
                ORDER BY occurred_at ASC
                LIMIT 10000
                "#,
            )
            .bind(start)
            .bind(end)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx_err)
            .map_err(ApiError::from)?;

            let events: Vec<_> = rows.iter().map(forensic_event_from_row).collect();

            if !events.is_empty() {
                let mut event_ids: Vec<Uuid> = Vec::with_capacity(events.len());
                let mut raw_event_ids: Vec<Uuid> = Vec::with_capacity(events.len());
                for e in &events {
                    event_ids.push(e.id);
                    raw_event_ids.push(e.raw_event_id);
                }

                let result = sqlx::query(
                    r#"
                    INSERT INTO hold_events (hold_id, event_id, raw_event_id)
                    SELECT $1, unnest($2::uuid[]), unnest($3::uuid[])
                    ON CONFLICT (hold_id, event_id) DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(&event_ids)
                .bind(&raw_event_ids)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)
                .map_err(ApiError::from)?;

                tx.commit().await.map_err(|e| {
                    tracing::error!(error = %e, "failed to commit hold materialization");
                    ApiError::from(StError::Database(format!("commit failed: {e}")))
                })?;

                result.rows_affected() as usize
            } else {
                tx.commit().await.map_err(|e| {
                    ApiError::from(StError::Database(format!("commit failed: {e}")))
                })?;
                0
            }
        }
        "case" => {
            // Expect criteria: { "case_id": "..." }
            let case_id_str = hold
                .criteria
                .get("case_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    StError::Validation("criteria.case_id is required for case holds".into())
                })?;

            let case_id: Uuid = case_id_str.parse().map_err(|_| {
                StError::Validation("criteria.case_id must be a valid UUID".into())
            })?;

            // Execute the case event lookup and hold insertion in a transaction.
            let mut tx = state.db.begin().await.map_err(ApiError::from)?;

            // Fetch case events within the transaction.
            let case_event_rows = sqlx::query(
                r#"
                SELECT id, case_id, event_id, pinned, annotation, added_at, added_by
                FROM case_events
                WHERE case_id = $1
                ORDER BY added_at ASC
                "#,
            )
            .bind(case_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx_err)
            .map_err(ApiError::from)?;

            // Fetch raw_event_id for each event within the same transaction.
            let mut event_ids: Vec<Uuid> = Vec::with_capacity(case_event_rows.len());
            let mut raw_event_ids: Vec<Uuid> = Vec::with_capacity(case_event_rows.len());

            for ce_row in &case_event_rows {
                let event_id: Uuid = ce_row.get("event_id");
                let event_row = sqlx::query(
                    r#"
                    SELECT id, raw_event_id
                    FROM events
                    WHERE id = $1
                    "#,
                )
                .bind(event_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_err)
                .map_err(ApiError::from)?;

                if let Some(row) = event_row {
                    event_ids.push(row.get("id"));
                    raw_event_ids.push(row.get("raw_event_id"));
                }
            }

            if !event_ids.is_empty() {
                let result = sqlx::query(
                    r#"
                    INSERT INTO hold_events (hold_id, event_id, raw_event_id)
                    SELECT $1, unnest($2::uuid[]), unnest($3::uuid[])
                    ON CONFLICT (hold_id, event_id) DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(&event_ids)
                .bind(&raw_event_ids)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)
                .map_err(ApiError::from)?;

                tx.commit().await.map_err(|e| {
                    tracing::error!(error = %e, "failed to commit hold materialization");
                    ApiError::from(StError::Database(format!("commit failed: {e}")))
                })?;

                result.rows_affected() as usize
            } else {
                tx.commit().await.map_err(|e| {
                    ApiError::from(StError::Database(format!("commit failed: {e}")))
                })?;
                0
            }
        }
        other @ ("entity" | "query") => {
            // Entity and query hold types require complex matching logic
            // that is not yet implemented. Return a clear error rather than
            // silently returning 0 matched events.
            return Err(ApiError::from(StError::Validation(format!(
                "materialization for '{other}' hold type is not yet implemented"
            ))));
        }
        _ => {
            return Err(ApiError::from(StError::Validation(format!(
                "unknown hold type: '{}'",
                hold.hold_type
            ))));
        }
    };

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let hold_id_str = id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "hold.materialize",
                    &actor,
                    Some("hold"),
                    Some(&hold_id_str),
                    serde_json::json!({ "events_added": events_added }),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok(Json(serde_json::json!({ "events_added": events_added })))
}
