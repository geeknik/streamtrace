//! Case management storage -- CRUD for investigation cases and the
//! case-event junction table.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::{StError, StResult};
use st_common::types::{CaseId, CaseStatus, EventId};

use crate::{map_sqlx_err, Database};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// An investigation case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: CaseId,
    pub name: String,
    pub description: String,
    pub status: CaseStatus,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An event attached to a case, with optional annotation and pin flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvent {
    pub id: uuid::Uuid,
    pub case_id: CaseId,
    pub event_id: EventId,
    pub pinned: bool,
    pub annotation: String,
    pub added_at: DateTime<Utc>,
    pub added_by: String,
}

// ---------------------------------------------------------------------------
// Pagination constants
// ---------------------------------------------------------------------------


/// Maximum number of cases returned by `list_cases`.
const MAX_LIST_CASES_LIMIT: u32 = 1000;

// ---------------------------------------------------------------------------
// CaseStatus <-> text helpers
// ---------------------------------------------------------------------------

fn case_status_to_str(s: CaseStatus) -> &'static str {
    match s {
        CaseStatus::Open => "open",
        CaseStatus::Closed => "closed",
        CaseStatus::Exported => "exported",
        CaseStatus::Archived => "archived",
    }
}

/// Converts a database status string to a [`CaseStatus`] enum variant.
///
/// Defaults to `Open` for unrecognized values (fail-safe).
pub fn case_status_from_str(s: &str) -> CaseStatus {
    match s {
        "open" => CaseStatus::Open,
        "closed" => CaseStatus::Closed,
        "exported" => CaseStatus::Exported,
        "archived" => CaseStatus::Archived,
        other => {
            tracing::warn!(status = other, "unknown case status, defaulting to Open");
            CaseStatus::Open
        }
    }
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Maps a sqlx `PgRow` to a [`Case`].
pub fn case_from_row(row: &sqlx::postgres::PgRow) -> Case {
    let status_str: String = row.get("status");
    Case {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        status: case_status_from_str(&status_str),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// Maps a sqlx `PgRow` to a [`CaseEvent`].
pub fn case_event_from_row(row: &sqlx::postgres::PgRow) -> CaseEvent {
    CaseEvent {
        id: row.get("id"),
        case_id: row.get("case_id"),
        event_id: row.get("event_id"),
        pinned: row.get("pinned"),
        annotation: row.get("annotation"),
        added_at: row.get("added_at"),
        added_by: row.get("added_by"),
    }
}

// ---------------------------------------------------------------------------
// Database methods -- cases
// ---------------------------------------------------------------------------

impl Database {
    /// Creates a new investigation case and returns it.
    pub async fn create_case(
        &self,
        name: &str,
        description: &str,
        created_by: &str,
    ) -> StResult<Case> {
        let row = sqlx::query(
            r#"
            INSERT INTO cases (name, description, created_by)
            VALUES ($1, $2, $3)
            RETURNING id, name, description, status, created_by, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(case_from_row(&row))
    }

    /// Fetches a case by its UUID.
    ///
    /// Returns `StError::NotFound` if no row exists.
    pub async fn get_case(&self, id: CaseId) -> StResult<Case> {
        let row = sqlx::query(
            r#"
            SELECT id, name, description, status, created_by, created_at, updated_at
            FROM cases
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(case_from_row(&row)),
            None => Err(StError::NotFound(format!("case {id} not found"))),
        }
    }

    /// Lists cases, optionally filtered by status, with a result limit.
    ///
    /// Returns cases ordered by most recently updated first. The `limit`
    /// parameter is clamped to [1, 1000] with a default of 100.
    pub async fn list_cases(
        &self,
        status: Option<CaseStatus>,
        limit: u32,
    ) -> StResult<Vec<Case>> {
        let clamped = limit.clamp(1, MAX_LIST_CASES_LIMIT) as i64;

        let rows = if let Some(st) = status {
            sqlx::query(
                r#"
                SELECT id, name, description, status, created_by, created_at, updated_at
                FROM cases
                WHERE status = $1
                ORDER BY updated_at DESC
                LIMIT $2
                "#,
            )
            .bind(case_status_to_str(st))
            .bind(clamped)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?
        } else {
            sqlx::query(
                r#"
                SELECT id, name, description, status, created_by, created_at, updated_at
                FROM cases
                ORDER BY updated_at DESC
                LIMIT $1
                "#,
            )
            .bind(clamped)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?
        };

        Ok(rows.iter().map(case_from_row).collect())
    }

    /// Updates a case. Only provided fields are modified; `None` fields
    /// are left unchanged. Returns the updated case.
    ///
    /// Returns `StError::NotFound` if no row exists.
    pub async fn update_case(
        &self,
        id: CaseId,
        name: Option<&str>,
        description: Option<&str>,
        status: Option<CaseStatus>,
    ) -> StResult<Case> {
        let status_str = status.map(case_status_to_str);

        let row = sqlx::query(
            r#"
            UPDATE cases
            SET name        = COALESCE($2, name),
                description = COALESCE($3, description),
                status      = COALESCE($4, status),
                updated_at  = NOW()
            WHERE id = $1
            RETURNING id, name, description, status, created_by, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(status_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(case_from_row(&row)),
            None => Err(StError::NotFound(format!("case {id} not found"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Database methods -- case events
// ---------------------------------------------------------------------------

impl Database {
    /// Attaches an event to a case. Returns the junction record.
    ///
    /// The database enforces `UNIQUE(case_id, event_id)` -- duplicate
    /// attachments will return a `Database` error.
    pub async fn add_event_to_case(
        &self,
        case_id: CaseId,
        event_id: EventId,
        added_by: &str,
    ) -> StResult<CaseEvent> {
        let row = sqlx::query(
            r#"
            INSERT INTO case_events (case_id, event_id, added_by)
            VALUES ($1, $2, $3)
            RETURNING id, case_id, event_id, pinned, annotation, added_at, added_by
            "#,
        )
        .bind(case_id)
        .bind(event_id)
        .bind(added_by)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(case_event_from_row(&row))
    }

    /// Removes an event from a case.
    ///
    /// Returns `StError::NotFound` if the combination does not exist.
    pub async fn remove_event_from_case(
        &self,
        case_id: CaseId,
        event_id: EventId,
    ) -> StResult<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM case_events
            WHERE case_id = $1 AND event_id = $2
            "#,
        )
        .bind(case_id)
        .bind(event_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        if result.rows_affected() == 0 {
            return Err(StError::NotFound(format!(
                "event {event_id} not found in case {case_id}"
            )));
        }
        Ok(())
    }

    /// Updates the pin status and/or annotation of a case-event attachment.
    ///
    /// Only provided fields are modified. Returns the updated record.
    /// Returns `StError::NotFound` if the combination does not exist.
    pub async fn update_case_event(
        &self,
        case_id: CaseId,
        event_id: EventId,
        pinned: Option<bool>,
        annotation: Option<&str>,
    ) -> StResult<CaseEvent> {
        let row = sqlx::query(
            r#"
            UPDATE case_events
            SET pinned     = COALESCE($3, pinned),
                annotation = COALESCE($4, annotation)
            WHERE case_id = $1 AND event_id = $2
            RETURNING id, case_id, event_id, pinned, annotation, added_at, added_by
            "#,
        )
        .bind(case_id)
        .bind(event_id)
        .bind(pinned)
        .bind(annotation)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(case_event_from_row(&row)),
            None => Err(StError::NotFound(format!(
                "event {event_id} not found in case {case_id}"
            ))),
        }
    }

    /// Lists all events attached to a case, ordered by `added_at` ascending.
    pub async fn get_case_events(&self, case_id: CaseId) -> StResult<Vec<CaseEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT id, case_id, event_id, pinned, annotation, added_at, added_by
            FROM case_events
            WHERE case_id = $1
            ORDER BY added_at ASC
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(case_event_from_row).collect())
    }
}
