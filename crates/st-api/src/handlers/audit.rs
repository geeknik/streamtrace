//! Audit log query endpoint.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use st_common::types::Permission;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// Query parameters for the audit log endpoint.
#[derive(Debug, Deserialize)]
pub struct AuditParams {
    /// Optional action filter (exact match).
    #[serde(default)]
    pub action: Option<String>,
    /// Maximum entries to return (default 50, max 1000).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Pagination offset (default 0).
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    50
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Query the audit log with optional filtering and pagination.
///
/// `GET /v1/audit?action=&limit=&offset=`
pub async fn query_audit(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Query(params): Query<AuditParams>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    // Clamp limit to [1, 1000].
    let limit = params.limit.clamp(1, 1000);

    let entries = state
        .db
        .query_audit_log(params.action.as_deref(), limit, params.offset)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(entries))
}
