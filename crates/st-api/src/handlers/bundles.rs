//! Evidence bundle generation and verification endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use st_cases::bundle::{verify_bundle, EvidenceBundle};
use st_common::error::StError;
use st_common::types::Permission;
use uuid::Uuid;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

/// Generate a signed evidence bundle for a case.
///
/// `POST /v1/cases/{id}/bundle`
///
/// Returns 201 Created with the full `EvidenceBundle` JSON.
pub async fn create_bundle(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    let bundle = state
        .cases
        .build_bundle(case_id, &state.signing_key)
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let case_id_str = case_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "bundle.generate",
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

    Ok((StatusCode::CREATED, Json(bundle)))
}

/// Verify an evidence bundle's integrity and signature.
///
/// `POST /v1/bundles/verify`
///
/// Accepts a full `EvidenceBundle` JSON and returns a verification result.
pub async fn verify_bundle_handler(
    auth: AuthenticatedKey,
    State(_state): State<AppState>,
    Json(raw): Json<serde_json::Value>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Read)?;

    let bundle: EvidenceBundle = serde_json::from_value(raw).map_err(|e| {
        ApiError::from(StError::Validation(format!("invalid evidence bundle: {e}")))
    })?;

    let result = verify_bundle(&bundle);

    Ok(Json(result))
}
