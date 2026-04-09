//! Sequence pattern and detection result storage.
//!
//! Manages the `sequence_patterns` and `detected_sequences` tables.
//! Patterns define ordered event-type steps; detected sequences record
//! instances found by the sequence detector.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::StResult;
use uuid::Uuid;

use crate::{map_sqlx_err, Database};

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

/// A sequence pattern as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencePatternRecord {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub definition: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A detected sequence instance as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSequenceRecord {
    pub id: Uuid,
    pub pattern_id: Uuid,
    pub pattern_name: String,
    pub event_ids: Vec<Uuid>,
    pub actor_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub confidence: f32,
    pub detected_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Hard limits
// ---------------------------------------------------------------------------

const MAX_LIST_LIMIT: i64 = 1000;

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

fn pattern_from_row(row: &sqlx::postgres::PgRow) -> SequencePatternRecord {
    SequencePatternRecord {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        definition: row.get("definition"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn detected_from_row(row: &sqlx::postgres::PgRow) -> DetectedSequenceRecord {
    DetectedSequenceRecord {
        id: row.get("id"),
        pattern_id: row.get("pattern_id"),
        pattern_name: row.get("pattern_name"),
        event_ids: row.get("event_ids"),
        actor_id: row.get("actor_id"),
        started_at: row.get("started_at"),
        ended_at: row.get("ended_at"),
        confidence: row.get("confidence"),
        detected_at: row.get("detected_at"),
    }
}

// ---------------------------------------------------------------------------
// Database methods
// ---------------------------------------------------------------------------

impl Database {
    /// List all sequence patterns, optionally filtered to enabled-only.
    pub async fn list_sequence_patterns(&self) -> StResult<Vec<SequencePatternRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, description, definition, enabled, created_at, updated_at
            FROM sequence_patterns
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(pattern_from_row).collect())
    }

    /// Fetch a single sequence pattern by ID.
    pub async fn get_sequence_pattern(&self, id: Uuid) -> StResult<SequencePatternRecord> {
        let row = sqlx::query(
            r#"
            SELECT id, name, description, definition, enabled, created_at, updated_at
            FROM sequence_patterns
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(pattern_from_row(&row)),
            None => Err(st_common::error::StError::NotFound(format!(
                "sequence pattern {id} not found"
            ))),
        }
    }

    /// Create a new sequence pattern. Returns the created record.
    ///
    /// The `definition` field is stored as JSONB and should contain the
    /// serialized `SequencePattern` from `st-correlate`.
    pub async fn create_sequence_pattern(
        &self,
        name: &str,
        description: &str,
        definition: &serde_json::Value,
    ) -> StResult<SequencePatternRecord> {
        let row = sqlx::query(
            r#"
            INSERT INTO sequence_patterns (name, description, definition)
            VALUES ($1, $2, $3)
            RETURNING id, name, description, definition, enabled, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(definition)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(pattern_from_row(&row))
    }

    /// Store a detected sequence instance. Returns the generated UUID.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_detected_sequence(
        &self,
        pattern_id: Uuid,
        pattern_name: &str,
        event_ids: &[Uuid],
        actor_id: Option<&str>,
        started_at: DateTime<Utc>,
        ended_at: DateTime<Utc>,
        confidence: f32,
    ) -> StResult<Uuid> {
        let row = sqlx::query(
            r#"
            INSERT INTO detected_sequences
                (pattern_id, pattern_name, event_ids, actor_id,
                 started_at, ended_at, confidence)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(pattern_id)
        .bind(pattern_name)
        .bind(event_ids)
        .bind(actor_id)
        .bind(started_at)
        .bind(ended_at)
        .bind(confidence)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(row.get("id"))
    }

    /// List detected sequences with pagination.
    pub async fn list_detected_sequences(
        &self,
        limit: u32,
        offset: u32,
    ) -> StResult<Vec<DetectedSequenceRecord>> {
        let clamped_limit = (limit as i64).clamp(1, MAX_LIST_LIMIT);
        let clamped_offset = offset as i64;

        let rows = sqlx::query(
            r#"
            SELECT id, pattern_id, pattern_name, event_ids, actor_id,
                   started_at, ended_at, confidence, detected_at
            FROM detected_sequences
            ORDER BY detected_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(clamped_limit)
        .bind(clamped_offset)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(detected_from_row).collect())
    }
}
