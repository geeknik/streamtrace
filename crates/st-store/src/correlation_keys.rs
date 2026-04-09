//! Correlation key storage for linking related events.
//!
//! During normalization, each event may produce zero or more correlation
//! keys (e.g. session ID, IP address, user identity). These keys form a
//! many-to-many bridge between events, enabling cross-source correlation.

use chrono::{DateTime, Utc};
use st_common::error::StResult;
use st_common::event::{CorrelationKey, ForensicEvent};
use st_common::types::EventId;

use crate::events::forensic_event_from_row;
use crate::{map_sqlx_err, Database, Transaction};

impl Database {
    /// Batch-inserts correlation keys for a single event.
    ///
    /// All keys share the same `event_id` and `occurred_at`. This is
    /// typically called in the same transaction as `insert_event`.
    ///
    /// Does nothing if `keys` is empty.
    pub async fn insert_correlation_keys(
        &self,
        event_id: EventId,
        keys: &[CorrelationKey],
        occurred_at: DateTime<Utc>,
    ) -> StResult<()> {
        if keys.is_empty() {
            return Ok(());
        }

        // Build a single multi-row INSERT for efficiency.
        // Each key contributes a ($N, $N+1, $N+2, $N+3) values tuple.
        let mut sql = String::from(
            "INSERT INTO correlation_keys (event_id, key_type, key_value, occurred_at) VALUES ",
        );
        let mut param_idx: u32 = 1;

        for (i, _key) in keys.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            sql.push_str(&format!(
                "(${}, ${}, ${}, ${})",
                param_idx,
                param_idx + 1,
                param_idx + 2,
                param_idx + 3,
            ));
            param_idx += 4;
        }

        let mut query = sqlx::query(&sql);

        for key in keys {
            let key_type_str = correlation_key_type_to_str(&key.key_type);
            query = query
                .bind(event_id)
                .bind(key_type_str)
                .bind(&key.key_value)
                .bind(occurred_at);
        }

        query.execute(&self.pool).await.map_err(map_sqlx_err)?;

        Ok(())
    }

    /// Finds events that share a given correlation key.
    ///
    /// Joins `correlation_keys` to `events` on `event_id`, filtering by
    /// the specified key type and value. Results are ordered by `occurred_at`
    /// descending (newest first).
    ///
    /// The `limit` is clamped to [1, 1000].
    pub async fn get_correlated_events(
        &self,
        key_type: &str,
        key_value: &str,
        limit: u32,
    ) -> StResult<Vec<ForensicEvent>> {
        let clamped_limit = i64::from(limit.clamp(1, 1000));

        let rows = sqlx::query(
            r#"
            SELECT e.id, e.raw_event_id, e.event_type, e.severity,
                   e.occurred_at, e.observed_at, e.received_at,
                   e.actor_id, e.actor_name, e.actor_type,
                   e.subject_id, e.subject_name, e.subject_type,
                   e.object_id, e.object_name, e.object_type,
                   host(e.src_ip) AS src_ip, host(e.dst_ip) AS dst_ip,
                   e.src_port, e.dst_port, e.protocol,
                   e.device_id, e.device_name, e.device_type, e.hostname,
                   e.source_id, e.source_type, e.source_name,
                   e.tags, e.custom_fields
            FROM correlation_keys ck
            JOIN events e ON e.id = ck.event_id
                         AND e.occurred_at = ck.occurred_at
            WHERE ck.key_type = $1
              AND ck.key_value = $2
            ORDER BY ck.occurred_at DESC
            LIMIT $3
            "#,
        )
        .bind(key_type)
        .bind(key_value)
        .bind(clamped_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let events = rows.iter().map(forensic_event_from_row).collect();
        Ok(events)
    }
}

// ---------------------------------------------------------------------------
// Transaction-aware variant
// ---------------------------------------------------------------------------

/// Batch-inserts correlation keys within an existing transaction.
///
/// Identical SQL to [`Database::insert_correlation_keys`] but executes
/// against the provided transaction handle.
pub async fn insert_correlation_keys_tx(
    tx: &mut Transaction<'_>,
    event_id: EventId,
    keys: &[CorrelationKey],
    occurred_at: DateTime<Utc>,
) -> StResult<()> {
    if keys.is_empty() {
        return Ok(());
    }

    let mut sql = String::from(
        "INSERT INTO correlation_keys (event_id, key_type, key_value, occurred_at) VALUES ",
    );
    let mut param_idx: u32 = 1;

    for (i, _key) in keys.iter().enumerate() {
        if i > 0 {
            sql.push_str(", ");
        }
        sql.push_str(&format!(
            "(${}, ${}, ${}, ${})",
            param_idx,
            param_idx + 1,
            param_idx + 2,
            param_idx + 3,
        ));
        param_idx += 4;
    }

    let mut query = sqlx::query(&sql);

    for key in keys {
        let key_type_str = correlation_key_type_to_str(&key.key_type);
        query = query
            .bind(event_id)
            .bind(key_type_str)
            .bind(&key.key_value)
            .bind(occurred_at);
    }

    query.execute(&mut **tx).await.map_err(map_sqlx_err)?;

    Ok(())
}

/// Converts a [`CorrelationKeyType`] variant to its database string representation.
fn correlation_key_type_to_str(kt: &st_common::event::CorrelationKeyType) -> String {
    use st_common::event::CorrelationKeyType;
    match kt {
        CorrelationKeyType::Identity => "identity".to_string(),
        CorrelationKeyType::Session => "session".to_string(),
        CorrelationKeyType::Token => "token".to_string(),
        CorrelationKeyType::Ip => "ip".to_string(),
        CorrelationKeyType::Device => "device".to_string(),
        CorrelationKeyType::Host => "host".to_string(),
        CorrelationKeyType::Custom(s) => s.clone(),
    }
}
