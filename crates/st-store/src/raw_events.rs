//! Raw event storage -- INSERT ONLY, no update or delete.
//!
//! Raw events are the immutable evidence chain. Once inserted, they are
//! never modified; retention is managed by TimescaleDB `drop_chunks`.

use sqlx::Row;
use st_common::error::{StError, StResult};
use st_common::event::RawEvent;
use st_common::types::RawEventId;

use crate::{map_sqlx_err, Database, Transaction};

impl Database {
    /// Inserts a raw event and returns the generated UUID.
    ///
    /// The caller is responsible for computing `content_hash` (BLAKE3) and
    /// `byte_size` before calling this method. Deduplication by hash is the
    /// caller's responsibility (check `get_raw_event_by_hash` first if needed).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_raw_event(
        &self,
        content: &[u8],
        content_hash: &str,
        content_type: &str,
        source_id: &str,
        source_type: &str,
        source_name: Option<&str>,
        parser_id: Option<&str>,
    ) -> StResult<RawEventId> {
        let byte_size = i32::try_from(content.len()).map_err(|_| {
            StError::Validation(format!(
                "content length {} exceeds i32 max",
                content.len()
            ))
        })?;

        let row = sqlx::query(
            r#"
            INSERT INTO raw_events (content, content_hash, content_type, source_id, source_type, source_name, parser_id, byte_size)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
        )
        .bind(content)
        .bind(content_hash)
        .bind(content_type)
        .bind(source_id)
        .bind(source_type)
        .bind(source_name)
        .bind(parser_id)
        .bind(byte_size)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let id: RawEventId = row.get("id");
        Ok(id)
    }

    /// Fetches a raw event by its UUID.
    ///
    /// Returns `StError::NotFound` if no row exists.
    pub async fn get_raw_event(&self, id: RawEventId) -> StResult<RawEvent> {
        let row = sqlx::query(
            r#"
            SELECT id, content, content_hash, content_type, source_id, source_type,
                   source_name, received_at, parser_id, byte_size
            FROM raw_events
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(raw_event_from_row(&row)),
            None => Err(StError::NotFound(format!("raw event {id} not found"))),
        }
    }

    /// Fetches a raw event by its content hash (BLAKE3 hex digest).
    ///
    /// Returns `None` if no matching row exists. Used for deduplication.
    pub async fn get_raw_event_by_hash(
        &self,
        content_hash: &str,
    ) -> StResult<Option<RawEvent>> {
        let row = sqlx::query(
            r#"
            SELECT id, content, content_hash, content_type, source_id, source_type,
                   source_name, received_at, parser_id, byte_size
            FROM raw_events
            WHERE content_hash = $1
            LIMIT 1
            "#,
        )
        .bind(content_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(row.map(|r| raw_event_from_row(&r)))
    }
}

// ---------------------------------------------------------------------------
// Transaction-aware variant
// ---------------------------------------------------------------------------

/// Inserts a raw event within an existing transaction.
///
/// Identical SQL to [`Database::insert_raw_event`] but executes against
/// the provided transaction handle instead of the connection pool.
#[allow(clippy::too_many_arguments)]
pub async fn insert_raw_event_tx(
    tx: &mut Transaction<'_>,
    content: &[u8],
    content_hash: &str,
    content_type: &str,
    source_id: &str,
    source_type: &str,
    source_name: Option<&str>,
    parser_id: Option<&str>,
) -> StResult<RawEventId> {
    let byte_size = i32::try_from(content.len()).map_err(|_| {
        StError::Validation(format!(
            "content length {} exceeds i32 max",
            content.len()
        ))
    })?;

    let row = sqlx::query(
        r#"
        INSERT INTO raw_events (content, content_hash, content_type, source_id, source_type, source_name, parser_id, byte_size)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
    )
    .bind(content)
    .bind(content_hash)
    .bind(content_type)
    .bind(source_id)
    .bind(source_type)
    .bind(source_name)
    .bind(parser_id)
    .bind(byte_size)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    let id: RawEventId = row.get("id");
    Ok(id)
}

/// Maps a sqlx `PgRow` to a [`RawEvent`].
pub fn raw_event_from_row(row: &sqlx::postgres::PgRow) -> RawEvent {
    RawEvent {
        id: row.get("id"),
        content: row.get("content"),
        content_hash: row.get("content_hash"),
        content_type: row.get("content_type"),
        source_id: row.get("source_id"),
        source_type: row.get("source_type"),
        source_name: row.get("source_name"),
        received_at: row.get("received_at"),
        parser_id: row.get("parser_id"),
        byte_size: row.get("byte_size"),
    }
}
