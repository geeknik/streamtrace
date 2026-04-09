//! Legal hold storage -- CRUD for evidence preservation holds and
//! the hold-event junction table.
//!
//! Legal holds prevent deletion of events that may be relevant to
//! ongoing investigations or legal proceedings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::{StError, StResult};
use uuid::Uuid;

use crate::{map_sqlx_err, Database};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A legal hold on forensic events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHold {
    /// Unique identifier for this hold.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Description of why this hold exists.
    pub description: String,
    /// Type of hold: "time_range", "entity", "case", or "query".
    pub hold_type: String,
    /// JSON criteria defining which events are covered.
    pub criteria: serde_json::Value,
    /// Current status: "active", "released", or "expired".
    pub status: String,
    /// Identity of the person who created this hold.
    pub created_by: String,
    /// When the hold was created.
    pub created_at: DateTime<Utc>,
    /// When the hold was released (None if still active).
    pub released_at: Option<DateTime<Utc>>,
    /// When the hold automatically expires (None for indefinite).
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Pagination constants
// ---------------------------------------------------------------------------

/// Maximum number of holds returned by `list_holds`.
const MAX_LIST_HOLDS_LIMIT: u32 = 1000;

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

fn hold_from_row(row: &sqlx::postgres::PgRow) -> LegalHold {
    LegalHold {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        hold_type: row.get("hold_type"),
        criteria: row.get("criteria"),
        status: row.get("status"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        released_at: row.get("released_at"),
        expires_at: row.get("expires_at"),
    }
}

// ---------------------------------------------------------------------------
// Database methods -- legal holds
// ---------------------------------------------------------------------------

impl Database {
    /// Creates a new legal hold.
    pub async fn create_hold(
        &self,
        name: &str,
        description: &str,
        hold_type: &str,
        criteria: serde_json::Value,
        created_by: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> StResult<LegalHold> {
        let row = sqlx::query(
            r#"
            INSERT INTO legal_holds (name, description, hold_type, criteria, created_by, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, description, hold_type, criteria, status,
                      created_by, created_at, released_at, expires_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(hold_type)
        .bind(&criteria)
        .bind(created_by)
        .bind(expires_at)
        .fetch_one(self.pool())
        .await
        .map_err(map_sqlx_err)?;

        Ok(hold_from_row(&row))
    }

    /// Fetches a legal hold by its UUID.
    ///
    /// Returns `StError::NotFound` if no row exists.
    pub async fn get_hold(&self, id: Uuid) -> StResult<LegalHold> {
        let row = sqlx::query(
            r#"
            SELECT id, name, description, hold_type, criteria, status,
                   created_by, created_at, released_at, expires_at
            FROM legal_holds
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(hold_from_row(&row)),
            None => Err(StError::NotFound(format!("legal hold {id} not found"))),
        }
    }

    /// Lists legal holds, optionally filtered by status, with a result limit.
    ///
    /// Returns holds ordered by most recently created first. The `limit`
    /// parameter is clamped to [1, 1000] with a default of 100.
    pub async fn list_holds(&self, status: Option<&str>, limit: u32) -> StResult<Vec<LegalHold>> {
        let clamped = limit.clamp(1, MAX_LIST_HOLDS_LIMIT) as i64;

        let rows = if let Some(st) = status {
            sqlx::query(
                r#"
                SELECT id, name, description, hold_type, criteria, status,
                       created_by, created_at, released_at, expires_at
                FROM legal_holds
                WHERE status = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(st)
            .bind(clamped)
            .fetch_all(self.pool())
            .await
            .map_err(map_sqlx_err)?
        } else {
            sqlx::query(
                r#"
                SELECT id, name, description, hold_type, criteria, status,
                       created_by, created_at, released_at, expires_at
                FROM legal_holds
                ORDER BY created_at DESC
                LIMIT $1
                "#,
            )
            .bind(clamped)
            .fetch_all(self.pool())
            .await
            .map_err(map_sqlx_err)?
        };

        Ok(rows.iter().map(hold_from_row).collect())
    }

    /// Releases a legal hold, setting its status to "released" and
    /// recording the release timestamp.
    ///
    /// Returns `StError::NotFound` if no hold exists with the given ID.
    /// Returns `StError::Validation` if the hold is already released.
    pub async fn release_hold(&self, id: Uuid) -> StResult<LegalHold> {
        let row = sqlx::query(
            r#"
            UPDATE legal_holds
            SET status = 'released',
                released_at = NOW()
            WHERE id = $1 AND status = 'active'
            RETURNING id, name, description, hold_type, criteria, status,
                      created_by, created_at, released_at, expires_at
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(hold_from_row(&row)),
            None => {
                // Distinguish between not found and already released
                let exists = sqlx::query("SELECT status FROM legal_holds WHERE id = $1")
                    .bind(id)
                    .fetch_optional(self.pool())
                    .await
                    .map_err(map_sqlx_err)?;

                match exists {
                    Some(row) => {
                        let status: String = row.get("status");
                        Err(StError::Validation(format!(
                            "hold {id} cannot be released: current status is '{status}'"
                        )))
                    }
                    None => Err(StError::NotFound(format!("legal hold {id} not found"))),
                }
            }
        }
    }

    /// Batch-inserts event associations for a legal hold.
    ///
    /// Each tuple is `(event_id, raw_event_id)`. Returns the number of
    /// rows inserted. Duplicate entries are silently skipped.
    pub async fn add_hold_events(&self, hold_id: Uuid, events: &[(Uuid, Uuid)]) -> StResult<usize> {
        if events.is_empty() {
            return Ok(0);
        }

        // Build a batch insert using unnest for efficiency
        let mut event_ids: Vec<Uuid> = Vec::with_capacity(events.len());
        let mut raw_event_ids: Vec<Uuid> = Vec::with_capacity(events.len());

        for (event_id, raw_event_id) in events {
            event_ids.push(*event_id);
            raw_event_ids.push(*raw_event_id);
        }

        let result = sqlx::query(
            r#"
            INSERT INTO hold_events (hold_id, event_id, raw_event_id)
            SELECT $1, unnest($2::uuid[]), unnest($3::uuid[])
            ON CONFLICT (hold_id, event_id) DO NOTHING
            "#,
        )
        .bind(hold_id)
        .bind(&event_ids)
        .bind(&raw_event_ids)
        .execute(self.pool())
        .await
        .map_err(map_sqlx_err)?;

        Ok(result.rows_affected() as usize)
    }

    /// Returns the number of events associated with a legal hold.
    pub async fn get_hold_event_count(&self, hold_id: Uuid) -> StResult<i64> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM hold_events
            WHERE hold_id = $1
            "#,
        )
        .bind(hold_id)
        .fetch_one(self.pool())
        .await
        .map_err(map_sqlx_err)?;

        let count: i64 = row.get("count");
        Ok(count)
    }

    /// Checks whether an event is under any active legal hold.
    pub async fn is_event_held(&self, event_id: Uuid) -> StResult<bool> {
        let row = sqlx::query(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM hold_events he
                JOIN legal_holds lh ON lh.id = he.hold_id
                WHERE he.event_id = $1 AND lh.status = 'active'
            ) AS held
            "#,
        )
        .bind(event_id)
        .fetch_one(self.pool())
        .await
        .map_err(map_sqlx_err)?;

        let held: bool = row.get("held");
        Ok(held)
    }
}
