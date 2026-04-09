//! Append-only audit log for internal platform operations.
//!
//! Tracks security-relevant actions (key creation, case transitions,
//! authentication attempts, etc.) separately from the forensic event
//! stream. Rows must never be updated or deleted under normal operation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::StResult;

use crate::{map_sqlx_err, Database};

/// A single entry from the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Auto-incrementing row identifier.
    pub id: i64,
    /// Short verb string (e.g. "api_key.created", "case.status_changed").
    pub action: String,
    /// Identity of the user or service that performed the action.
    pub actor: String,
    /// Optional category of the affected resource (e.g. "case", "api_key").
    pub target_type: Option<String>,
    /// Optional identifier of the affected resource.
    pub target_id: Option<String>,
    /// Structured context as JSON. Must not contain secrets or PII.
    pub detail: serde_json::Value,
    /// When the audit event occurred.
    pub occurred_at: DateTime<Utc>,
}

impl Database {
    /// Appends an entry to the audit log.
    ///
    /// - `action`: a short verb string (e.g. "api_key.created", "case.status_changed").
    /// - `actor`: identity of the user or service performing the action.
    /// - `target_type`: optional category of the affected resource (e.g. "case", "api_key").
    /// - `target_id`: optional identifier of the affected resource.
    /// - `detail`: structured context as JSON. Must not contain secrets or PII.
    pub async fn log_audit(
        &self,
        action: &str,
        actor: &str,
        target_type: Option<&str>,
        target_id: Option<&str>,
        detail: serde_json::Value,
    ) -> StResult<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_log (action, actor, target_type, target_id, detail)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(action)
        .bind(actor)
        .bind(target_type)
        .bind(target_id)
        .bind(&detail)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        tracing::info!(
            action = action,
            actor = actor,
            target_type = target_type,
            target_id = target_id,
            "audit log entry recorded"
        );

        Ok(())
    }

    /// Queries the audit log with optional filtering and pagination.
    ///
    /// - `action`: optional filter by action string (exact match).
    /// - `limit`: maximum number of entries to return (capped at 1000).
    /// - `offset`: number of entries to skip for pagination.
    ///
    /// Returns entries ordered by most recent first.
    pub async fn query_audit_log(
        &self,
        action: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> StResult<Vec<AuditEntry>> {
        // Cap limit to prevent unbounded queries
        let capped_limit = limit.min(1000) as i64;
        let offset = offset as i64;

        let rows = if let Some(action_filter) = action {
            sqlx::query(
                r#"
                SELECT id, action, actor, target_type, target_id, detail, occurred_at
                FROM audit_log
                WHERE action = $1
                ORDER BY occurred_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(action_filter)
            .bind(capped_limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?
        } else {
            sqlx::query(
                r#"
                SELECT id, action, actor, target_type, target_id, detail, occurred_at
                FROM audit_log
                ORDER BY occurred_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(capped_limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?
        };

        Ok(rows
            .iter()
            .map(|row| AuditEntry {
                id: row.get("id"),
                action: row.get("action"),
                actor: row.get("actor"),
                target_type: row.get("target_type"),
                target_id: row.get("target_id"),
                detail: row.get("detail"),
                occurred_at: row.get("occurred_at"),
            })
            .collect())
    }
}
