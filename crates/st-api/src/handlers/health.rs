//! Health and readiness check endpoints.
//!
//! - `GET /healthz` -- always returns 200 if the process is alive.
//! - `GET /readyz`  -- returns 200 if the database is reachable, 503 otherwise.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// Liveness probe. Returns 200 if the process is running.
///
/// No external dependencies are checked -- this endpoint is for
/// load balancers and orchestrators to confirm the process is alive.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(json!({ "status": "ok" })))
}

/// Readiness probe. Returns 200 if the database is reachable.
///
/// Orchestrators should route traffic away from instances that fail
/// this check.
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.health_check().await {
        Ok(()) => (StatusCode::OK, axum::Json(json!({ "status": "ok" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": "unavailable" })),
        ),
    }
}
