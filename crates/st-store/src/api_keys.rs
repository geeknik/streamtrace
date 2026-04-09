//! API key storage and validation.
//!
//! Keys are stored as Argon2id hashes with a cleartext prefix for lookup.
//! The full key is never persisted. Validation uses the `argon2` crate's
//! built-in `verify_password` which performs constant-time comparison
//! internally.
//!
//! Each stored hash contains its own random salt (PHC string format),
//! eliminating the need for deterministic salts.

use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::{StError, StResult};
use st_common::types::Permission;

use crate::{map_sqlx_err, Database};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// An API key record. The actual secret is never stored; only the Argon2id
/// hash and first 8 characters (prefix) are persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: uuid::Uuid,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<Permission>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Permission <-> text helpers
// ---------------------------------------------------------------------------

fn permission_to_str(p: Permission) -> &'static str {
    match p {
        Permission::Read => "read",
        Permission::Write => "write",
        Permission::Admin => "admin",
    }
}

fn permission_from_str(s: &str) -> Option<Permission> {
    match s {
        "read" => Some(Permission::Read),
        "write" => Some(Permission::Write),
        "admin" => Some(Permission::Admin),
        other => {
            tracing::warn!(permission = other, "unknown permission in api_keys row");
            None
        }
    }
}

fn permissions_from_strings(strings: &[String]) -> Vec<Permission> {
    strings.iter().filter_map(|s| permission_from_str(s)).collect()
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

fn api_key_from_row(row: &sqlx::postgres::PgRow) -> ApiKey {
    let perm_strings: Vec<String> = row.get("permissions");
    ApiKey {
        id: row.get("id"),
        name: row.get("name"),
        key_prefix: row.get("key_prefix"),
        permissions: permissions_from_strings(&perm_strings),
        active: row.get("active"),
        created_at: row.get("created_at"),
        last_used_at: row.get("last_used_at"),
        expires_at: row.get("expires_at"),
    }
}

// ---------------------------------------------------------------------------
// Database methods
// ---------------------------------------------------------------------------

impl Database {
    /// Creates a new API key record.
    ///
    /// The caller is responsible for:
    /// - Generating the random key
    /// - Computing the Argon2id hash (`key_hash`) using `hash_api_key_token`
    /// - Extracting the prefix (first 8 characters)
    /// - Showing the plaintext key to the user exactly once
    ///
    /// The plaintext key is never stored.
    pub async fn create_api_key(
        &self,
        name: &str,
        key_hash: &str,
        key_prefix: &str,
        permissions: &[Permission],
    ) -> StResult<ApiKey> {
        let perm_strs: Vec<&str> = permissions.iter().map(|p| permission_to_str(*p)).collect();

        let row = sqlx::query(
            r#"
            INSERT INTO api_keys (name, key_hash, key_prefix, permissions)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, key_prefix, permissions, active,
                      created_at, last_used_at, expires_at
            "#,
        )
        .bind(name)
        .bind(key_hash)
        .bind(key_prefix)
        .bind(&perm_strs as &[&str])
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(api_key_from_row(&row))
    }

    /// Validates an API key by prefix and plaintext token.
    ///
    /// Looks up the key by its prefix (indexed partial index on active keys),
    /// verifies it is active and not expired, then uses Argon2id's
    /// `verify_password` to compare the token against the stored PHC hash
    /// (which contains its own random salt).
    ///
    /// On success, asynchronously updates `last_used_at` (fire-and-forget)
    /// and returns the `ApiKey` record.
    ///
    /// Returns `None` if the key is not found, inactive, expired, or the
    /// token does not match the stored hash.
    pub async fn validate_api_key(
        &self,
        key_prefix: &str,
        token: &str,
    ) -> StResult<Option<ApiKey>> {
        let row = sqlx::query(
            r#"
            SELECT id, name, key_hash, key_prefix, permissions, active,
                   created_at, last_used_at, expires_at
            FROM api_keys
            WHERE key_prefix = $1
              AND active = true
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(key_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let stored_hash: String = row.get("key_hash");

        // Parse the stored PHC hash string (contains algorithm params + salt + hash).
        let parsed_hash = match PasswordHash::new(&stored_hash) {
            Ok(h) => h,
            Err(_) => {
                tracing::error!(
                    key_prefix = key_prefix,
                    "stored key_hash is not a valid PHC string"
                );
                return Ok(None);
            }
        };

        // Verify the token against the stored hash using Argon2id's built-in
        // constant-time comparison.
        if Argon2::default()
            .verify_password(token.as_bytes(), &parsed_hash)
            .is_err()
        {
            tracing::warn!(
                key_prefix = key_prefix,
                "api key validation failed: hash mismatch"
            );
            return Ok(None);
        }

        // Update last_used_at asynchronously (best-effort, do not block the caller).
        let id: uuid::Uuid = row.get("id");
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        });

        Ok(Some(api_key_from_row(&row)))
    }

    /// Revokes an API key by setting `active = false`.
    ///
    /// Returns `StError::NotFound` if the key does not exist.
    pub async fn revoke_api_key(&self, id: uuid::Uuid) -> StResult<()> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET active = false
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        if result.rows_affected() == 0 {
            return Err(StError::NotFound(format!("api key {id} not found")));
        }
        Ok(())
    }

    /// Lightweight health probe -- executes `SELECT 1`.
    pub async fn health_check(&self) -> StResult<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
        Ok(())
    }
}
