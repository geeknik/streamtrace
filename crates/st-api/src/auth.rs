//! Bearer token authentication extractor.
//!
//! Implements `FromRequestParts` so handlers can declare
//! `AuthenticatedKey` as a parameter and receive a validated key record.
//!
//! Flow:
//! 1. Extract `Authorization: Bearer <token>` header.
//! 2. Split token into prefix (first 8 chars) and full token.
//! 3. Pass the full token to `db.validate_api_key(prefix, token)`.
//! 4. The database layer verifies the token against the stored Argon2id
//!    PHC hash (which contains its own random salt).
//! 5. Return 401 on any failure; inject `AuthenticatedKey` on success.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use st_common::error::StError;
use st_common::types::Permission;

use crate::error::ApiError;
use crate::state::AppState;

/// Minimum length for an API token (prefix + at least 24 chars of secret).
const MIN_TOKEN_LENGTH: usize = 32;

/// Length of the key prefix stored in cleartext for lookup.
const KEY_PREFIX_LENGTH: usize = 8;

/// Validated API key information available to handlers.
#[derive(Debug, Clone)]
pub struct AuthenticatedKey {
    /// Database row ID of the API key.
    pub key_id: uuid::Uuid,
    /// Human-readable key label.
    pub key_name: String,
    /// Permissions granted to this key.
    pub permissions: Vec<Permission>,
}

impl AuthenticatedKey {
    /// Returns `true` if this key has the given permission (or Admin).
    pub fn has_permission(&self, required: Permission) -> bool {
        self.permissions
            .iter()
            .any(|p| *p == required || *p == Permission::Admin)
    }

    /// Returns `Ok(())` if this key has the required permission, or an
    /// authorization error otherwise.
    pub fn require_permission(&self, perm: Permission) -> Result<(), ApiError> {
        if self.has_permission(perm) {
            Ok(())
        } else {
            Err(ApiError::from(StError::Authorization(
                "insufficient permissions".to_string(),
            )))
        }
    }
}

/// Error type returned when authentication fails.
///
/// Always produces a 401 with a generic message. Internal details are logged
/// but never sent to the client.
#[derive(Debug)]
pub struct AuthError;

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": {
                "code": "AUTHENTICATION_FAILED",
                "message": "authentication failed",
            }
        });
        (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
    }
}

impl FromRequestParts<AppState> for AuthenticatedKey {
    type Rejection = AuthError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let db = state.db.clone();
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        async move {
            let header_value = auth_header.ok_or_else(|| {
                tracing::debug!("missing Authorization header");
                AuthError
            })?;

            let token = header_value.strip_prefix("Bearer ").ok_or_else(|| {
                tracing::debug!("Authorization header is not Bearer scheme");
                AuthError
            })?;

            if token.len() < MIN_TOKEN_LENGTH {
                tracing::debug!("API token too short");
                return Err(AuthError);
            }

            let prefix = &token[..KEY_PREFIX_LENGTH];

            // Pass the full token to the database layer, which verifies it
            // against the stored Argon2id PHC hash (containing a random salt).
            let record = db
                .validate_api_key(prefix, token)
                .await
                .map_err(|_| {
                    tracing::debug!(prefix = prefix, "API key validation DB error");
                    AuthError
                })?
                .ok_or_else(|| {
                    tracing::debug!(prefix = prefix, "API key not found or hash mismatch");
                    AuthError
                })?;

            Ok(AuthenticatedKey {
                key_id: record.id,
                key_name: record.name,
                permissions: record.permissions,
            })
        }
    }
}

/// Hash an API key token using Argon2id with a random salt.
///
/// Returns the PHC-formatted hash string which embeds the algorithm
/// parameters, salt, and hash. This is the value stored in `key_hash`.
///
/// This function should be called when creating a new API key.
pub fn hash_api_key_token(
    token: &str,
) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(token.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_permission_admin_grants_all() {
        let key = AuthenticatedKey {
            key_id: uuid::Uuid::nil(),
            key_name: "test".into(),
            permissions: vec![Permission::Admin],
        };
        assert!(key.has_permission(Permission::Read));
        assert!(key.has_permission(Permission::Write));
        assert!(key.has_permission(Permission::Admin));
    }

    #[test]
    fn has_permission_read_only() {
        let key = AuthenticatedKey {
            key_id: uuid::Uuid::nil(),
            key_name: "test".into(),
            permissions: vec![Permission::Read],
        };
        assert!(key.has_permission(Permission::Read));
        assert!(!key.has_permission(Permission::Write));
        assert!(!key.has_permission(Permission::Admin));
    }

    #[test]
    fn require_permission_ok_for_admin() {
        let key = AuthenticatedKey {
            key_id: uuid::Uuid::nil(),
            key_name: "test".into(),
            permissions: vec![Permission::Admin],
        };
        assert!(key.require_permission(Permission::Read).is_ok());
        assert!(key.require_permission(Permission::Write).is_ok());
    }

    #[test]
    fn require_permission_denied_for_read_only() {
        let key = AuthenticatedKey {
            key_id: uuid::Uuid::nil(),
            key_name: "test".into(),
            permissions: vec![Permission::Read],
        };
        assert!(key.require_permission(Permission::Read).is_ok());
        assert!(key.require_permission(Permission::Write).is_err());
    }

    #[test]
    fn hash_api_key_token_produces_unique_salts() {
        let token = "abcdefgh_this_is_a_long_enough_token_for_testing";
        let h1 = hash_api_key_token(token).unwrap();
        let h2 = hash_api_key_token(token).unwrap();
        // Random salts means the same token produces different hashes.
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_api_key_token_verifiable_with_argon2() {
        use argon2::password_hash::PasswordHash;
        use argon2::{Argon2, PasswordVerifier};

        let token = "abcdefgh_this_is_a_long_enough_token_for_testing";
        let hash_str = hash_api_key_token(token).unwrap();
        let parsed = PasswordHash::new(&hash_str).unwrap();
        assert!(Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok());
    }
}
