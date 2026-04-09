//! API key management endpoints (admin only).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use st_common::error::StError;
use st_common::types::Permission;
use uuid::Uuid;

use crate::auth::{hash_api_key_token, AuthenticatedKey};
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for creating a new API key.
#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    /// Human-readable name for the key.
    pub name: String,
    /// Permissions to grant: "read", "write", "admin".
    pub permissions: Vec<String>,
}

/// Response body returned when a key is created.
///
/// The `token` field is returned exactly once and is never retrievable again.
#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub key_id: Uuid,
    pub name: String,
    /// The full plaintext token. Returned only at creation time.
    pub token: String,
    /// First 8 characters of the token, used for lookup.
    pub prefix: String,
    pub permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Maximum length for key name.
const MAX_KEY_NAME_LEN: usize = 128;

/// Maximum number of permissions that can be granted.
const MAX_PERMISSIONS: usize = 3;

/// Allowed permission strings.
const VALID_PERMISSIONS: &[&str] = &["read", "write", "admin"];

/// Length of the key prefix stored for lookup.
const KEY_PREFIX_LENGTH: usize = 8;

fn parse_permission(s: &str) -> Result<Permission, ApiError> {
    match s {
        "read" => Ok(Permission::Read),
        "write" => Ok(Permission::Write),
        "admin" => Ok(Permission::Admin),
        _ => Err(ApiError::from(StError::Validation(format!(
            "invalid permission: {s}, allowed: {VALID_PERMISSIONS:?}"
        )))),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Create a new API key.
///
/// `POST /v1/admin/keys`
///
/// Requires `Admin` permission. Returns the plaintext token exactly once.
pub async fn create_key(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Json(body): Json<CreateKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Admin)?;

    // --- Input validation ---------------------------------------------------
    let name = body.name.trim();
    if name.is_empty() || name.len() > MAX_KEY_NAME_LEN {
        return Err(ApiError::from(StError::Validation(format!(
            "key name must be 1-{MAX_KEY_NAME_LEN} characters"
        ))));
    }
    if body.permissions.is_empty() || body.permissions.len() > MAX_PERMISSIONS {
        return Err(ApiError::from(StError::Validation(format!(
            "permissions must contain 1-{MAX_PERMISSIONS} entries"
        ))));
    }

    let mut permissions = Vec::with_capacity(body.permissions.len());
    for p in &body.permissions {
        permissions.push(parse_permission(p)?);
    }

    // --- Token generation ---------------------------------------------------
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let prefix = token[..KEY_PREFIX_LENGTH].to_string();

    let key_hash = hash_api_key_token(&token).map_err(|e| {
        tracing::error!(error = %e, "failed to hash API key token");
        ApiError::from(StError::Internal("key generation failed".to_string()))
    })?;

    // --- Persist ------------------------------------------------------------
    let api_key = state
        .db
        .create_api_key(name, &key_hash, &prefix, &permissions)
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let key_id_str = api_key.id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "api_key.create",
                    &actor,
                    Some("api_key"),
                    Some(&key_id_str),
                    serde_json::json!({}),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    let perm_strings: Vec<String> = permissions
        .iter()
        .map(|p| match p {
            Permission::Read => "read".to_string(),
            Permission::Write => "write".to_string(),
            Permission::Admin => "admin".to_string(),
        })
        .collect();

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            key_id: api_key.id,
            name: api_key.name,
            token,
            prefix,
            permissions: perm_strings,
        }),
    ))
}

/// Revoke an API key.
///
/// `DELETE /v1/admin/keys/{id}`
///
/// Requires `Admin` permission. Returns 204 No Content on success.
pub async fn revoke_key(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Admin)?;

    state.db.revoke_api_key(id).await.map_err(ApiError::from)?;

    // Fire-and-forget audit log.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let key_id_str = id.to_string();
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "api_key.revoke",
                    &actor,
                    Some("api_key"),
                    Some(&key_id_str),
                    serde_json::json!({}),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok(StatusCode::NO_CONTENT)
}
