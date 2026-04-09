//! Case management endpoints.
//!
//! CRUD operations for investigation cases and their associated events,
//! plus export in multiple formats.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use st_cases::ExportFormat;
use st_common::error::StError;
use st_common::types::{CaseStatus, EventId, Permission};
use uuid::Uuid;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / query types
// ---------------------------------------------------------------------------

/// Request body for creating a case.
#[derive(Debug, Deserialize)]
pub struct CreateCaseRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub created_by: String,
}

/// Request body for updating a case (all fields optional).
#[derive(Debug, Deserialize)]
pub struct UpdateCaseRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<CaseStatus>,
}

/// Query parameters for listing cases.
#[derive(Debug, Deserialize)]
pub struct ListCasesParams {
    #[serde(default)]
    pub status: Option<CaseStatus>,
    /// Maximum number of cases to return (default 100, max 1000).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Request body for adding an event to a case.
#[derive(Debug, Deserialize)]
pub struct AddCaseEventRequest {
    pub event_id: EventId,
    pub added_by: String,
}

/// Request body for updating a case-event attachment.
#[derive(Debug, Deserialize)]
pub struct UpdateCaseEventRequest {
    #[serde(default)]
    pub pinned: Option<bool>,
    #[serde(default)]
    pub annotation: Option<String>,
}

/// Query parameters for case export.
#[derive(Debug, Deserialize)]
pub struct ExportParams {
    /// Export format: "json", "csv", or "markdown".
    #[serde(default = "default_export_format")]
    pub format: String,
}

fn default_export_format() -> String {
    "json".to_string()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Create a new investigation case.
///
/// `POST /v1/cases`
///
/// Returns 201 Created with the new case.
pub async fn create_case(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Json(req): Json<CreateCaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    let case = state
        .cases
        .create_case(&req.name, &req.description, &req.created_by)
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let case_id_str = case.id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "case.create",
                    &actor,
                    Some("case"),
                    Some(&case_id_str),
                    serde_json::json!({}),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok((StatusCode::CREATED, Json(case)))
}

/// List all cases, optionally filtered by status.
///
/// `GET /v1/cases?status=open&limit=100`
pub async fn list_cases(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<ListCasesParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let cases = state
        .cases
        .list_cases(params.status, params.limit)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(cases))
}

/// Fetch a single case by ID.
///
/// `GET /v1/cases/:id`
pub async fn get_case(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let case = state
        .cases
        .get_case(id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(case))
}

/// Update a case (partial update).
///
/// `PATCH /v1/cases/:id`
pub async fn update_case(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    if req.name.is_none() && req.description.is_none() && req.status.is_none() {
        return Err(ApiError::from(StError::Validation(
            "at least one field must be provided for update".to_string(),
        )));
    }

    let case = state
        .cases
        .update_case(
            id,
            req.name.as_deref(),
            req.description.as_deref(),
            req.status,
        )
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let case_id_str = id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "case.update",
                    &actor,
                    Some("case"),
                    Some(&case_id_str),
                    serde_json::json!({}),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok(Json(case))
}

/// Add an event to a case.
///
/// `POST /v1/cases/:id/events`
///
/// Returns 201 Created with the case-event junction record.
pub async fn add_case_event(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Json(req): Json<AddCaseEventRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    let case_event = state
        .cases
        .add_event(case_id, req.event_id, &req.added_by)
        .await
        .map_err(ApiError::from)?;

    Ok((StatusCode::CREATED, Json(case_event)))
}

/// Remove an event from a case.
///
/// `DELETE /v1/cases/:id/events/:event_id`
///
/// Returns 204 No Content on success.
pub async fn remove_case_event(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path((case_id, event_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    state
        .cases
        .remove_event(case_id, event_id)
        .await
        .map_err(ApiError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Update a case-event attachment (pin/annotation).
///
/// `PATCH /v1/cases/:id/events/:event_id`
pub async fn update_case_event(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path((case_id, event_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateCaseEventRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    let case_event = state
        .cases
        .update_event(
            case_id,
            event_id,
            req.pinned,
            req.annotation.as_deref(),
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Json(case_event))
}

/// Export a case with all attached events in the specified format.
///
/// `GET /v1/cases/:id/export?format=json`
///
/// Supported formats: json, csv, markdown.
pub async fn export_case(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<ExportParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let format = ExportFormat::from_str_checked(&params.format)
        .map_err(ApiError::from)?;

    let content = state
        .cases
        .export(id, format)
        .await
        .map_err(ApiError::from)?;

    let content_type = match format {
        ExportFormat::Json => "application/json",
        ExportFormat::Csv => "text/csv",
        ExportFormat::Markdown => "text/markdown",
    };

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        content,
    ))
}
