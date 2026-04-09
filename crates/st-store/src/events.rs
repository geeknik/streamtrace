//! Normalized forensic event storage with timeline query support.
//!
//! Events are the primary analytical data in StreamTrace. This module
//! handles insert, fetch-by-id, and dynamic timeline queries with
//! cursor-based pagination.

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::{StError, StResult};
use st_common::event::{
    Actor, DeviceContext, EventObject, ForensicEvent, NetworkContext, SourceAttribution, Subject,
};
use st_common::types::{EventId, Severity, SortOrder};
use uuid::Uuid;

use crate::{map_sqlx_err, severity_from_i16, severity_to_i16, Database, Transaction};

/// URL-safe, no-pad base64 engine used for cursor encoding.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ---------------------------------------------------------------------------
// Query / result types
// ---------------------------------------------------------------------------

/// Parameters for a timeline query. Supports filtering, cursor-based
/// pagination, and configurable sort order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineQuery {
    /// Inclusive start of the time window.
    pub start: DateTime<Utc>,
    /// Exclusive end of the time window.
    pub end: DateTime<Utc>,
    /// Filter to specific event types (exact match).
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    /// Filter by actor ID (exact match).
    #[serde(default)]
    pub actor_id: Option<String>,
    /// Filter by source ID (exact match).
    #[serde(default)]
    pub source_id: Option<String>,
    /// Minimum severity threshold (inclusive).
    #[serde(default)]
    pub severity_min: Option<Severity>,
    /// Filter by source IP address (exact match).
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Full-text search query (uses PostgreSQL `plainto_tsquery`).
    #[serde(default)]
    pub search: Option<String>,
    /// Filter events containing all specified tags.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Maximum results to return (default 100, hard max 1000).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Opaque cursor for keyset pagination (base64-encoded `occurred_at,id`).
    #[serde(default)]
    pub cursor: Option<String>,
    /// Sort direction (default: descending / newest first).
    #[serde(default = "default_order")]
    pub order: SortOrder,
}

fn default_limit() -> u32 {
    100
}

fn default_order() -> SortOrder {
    SortOrder::Desc
}

/// Result of a timeline query, including cursor for the next page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineResult {
    /// Matching events for this page.
    pub events: Vec<ForensicEvent>,
    /// Opaque cursor for fetching the next page, if more results exist.
    pub next_cursor: Option<String>,
    /// Whether additional pages are available.
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Cursor encoding / decoding
// ---------------------------------------------------------------------------

/// Encodes a `(occurred_at, id)` pair into a base64 cursor string.
fn encode_cursor(occurred_at: &DateTime<Utc>, id: &Uuid) -> String {
    use std::io::Write;
    let mut buf = Vec::with_capacity(64);
    let _ = write!(buf, "{},{}", occurred_at.to_rfc3339(), id);
    base64_encode(&buf)
}

/// Decodes a base64 cursor string into `(occurred_at, id)`.
fn decode_cursor(cursor: &str) -> StResult<(DateTime<Utc>, Uuid)> {
    let bytes =
        base64_decode(cursor).map_err(|_| StError::Validation("invalid cursor encoding".into()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| StError::Validation("invalid cursor encoding".into()))?;
    let (ts_str, id_str) = text
        .split_once(',')
        .ok_or_else(|| StError::Validation("invalid cursor format".into()))?;
    let occurred_at = DateTime::parse_from_rfc3339(ts_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| StError::Validation("invalid cursor timestamp".into()))?;
    let id =
        Uuid::parse_str(id_str).map_err(|_| StError::Validation("invalid cursor id".into()))?;
    Ok((occurred_at, id))
}

// ---------------------------------------------------------------------------
// Base64 wrappers using the `base64` crate (URL-safe, no padding)
// ---------------------------------------------------------------------------

fn base64_encode(input: &[u8]) -> String {
    B64.encode(input)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(input)
}

// ---------------------------------------------------------------------------
// Database methods
// ---------------------------------------------------------------------------

impl Database {
    /// Inserts a normalized forensic event and returns its UUID.
    ///
    /// The database trigger `fn_events_update_search_text` automatically
    /// populates the `search_text` tsvector column; we do not set it here.
    ///
    /// `src_ip` and `dst_ip` are cast to `INET` in the SQL statement.
    pub async fn insert_event(&self, event: &ForensicEvent) -> StResult<EventId> {
        let severity_val = severity_to_i16(event.severity);
        let tags: Vec<&str> = event.tags.iter().map(|s| s.as_str()).collect();

        let (actor_id, actor_name, actor_type) = event
            .actor
            .as_ref()
            .map(|a| (a.id.as_deref(), a.name.as_deref(), a.actor_type.as_deref()))
            .unwrap_or((None, None, None));

        let (subject_id, subject_name, subject_type) = event
            .subject
            .as_ref()
            .map(|s| {
                (
                    s.id.as_deref(),
                    s.name.as_deref(),
                    s.subject_type.as_deref(),
                )
            })
            .unwrap_or((None, None, None));

        let (object_id, object_name, object_type) = event
            .object
            .as_ref()
            .map(|o| {
                (
                    o.id.as_deref(),
                    o.name.as_deref(),
                    o.object_type.as_deref(),
                )
            })
            .unwrap_or((None, None, None));

        let (src_ip, dst_ip, src_port, dst_port, protocol) = event
            .network
            .as_ref()
            .map(|n| {
                (
                    n.src_ip.as_deref(),
                    n.dst_ip.as_deref(),
                    n.src_port,
                    n.dst_port,
                    n.protocol.as_deref(),
                )
            })
            .unwrap_or((None, None, None, None, None));

        let (device_id, device_name, device_type, hostname) = event
            .device
            .as_ref()
            .map(|d| {
                (
                    d.device_id.as_deref(),
                    d.device_name.as_deref(),
                    d.device_type.as_deref(),
                    d.hostname.as_deref(),
                )
            })
            .unwrap_or((None, None, None, None));

        let row = sqlx::query(
            r#"
            INSERT INTO events (
                id, raw_event_id, event_type, severity,
                occurred_at, observed_at, received_at,
                actor_id, actor_name, actor_type,
                subject_id, subject_name, subject_type,
                object_id, object_name, object_type,
                src_ip, dst_ip, src_port, dst_port, protocol,
                device_id, device_name, device_type, hostname,
                source_id, source_type, source_name,
                tags, custom_fields
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7,
                $8, $9, $10,
                $11, $12, $13,
                $14, $15, $16,
                $17::INET, $18::INET, $19, $20, $21,
                $22, $23, $24, $25,
                $26, $27, $28,
                $29, $30
            )
            RETURNING id
            "#,
        )
        .bind(event.id)
        .bind(event.raw_event_id)
        .bind(&event.event_type)
        .bind(severity_val)
        .bind(event.occurred_at)
        .bind(event.observed_at)
        .bind(event.received_at)
        .bind(actor_id)
        .bind(actor_name)
        .bind(actor_type)
        .bind(subject_id)
        .bind(subject_name)
        .bind(subject_type)
        .bind(object_id)
        .bind(object_name)
        .bind(object_type)
        .bind(src_ip)
        .bind(dst_ip)
        .bind(src_port)
        .bind(dst_port)
        .bind(protocol)
        .bind(device_id)
        .bind(device_name)
        .bind(device_type)
        .bind(hostname)
        .bind(&event.source.source_id)
        .bind(&event.source.source_type)
        .bind(event.source.source_name.as_deref())
        .bind(&tags as &[&str])
        .bind(&event.custom_fields)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let id: EventId = row.get("id");
        Ok(id)
    }

    /// Fetches a normalized event by its UUID.
    ///
    /// Returns `StError::NotFound` if no row exists.
    pub async fn get_event(&self, id: EventId) -> StResult<ForensicEvent> {
        let row = sqlx::query(
            r#"
            SELECT id, raw_event_id, event_type, severity,
                   occurred_at, observed_at, received_at,
                   actor_id, actor_name, actor_type,
                   subject_id, subject_name, subject_type,
                   object_id, object_name, object_type,
                   host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
                   src_port, dst_port, protocol,
                   device_id, device_name, device_type, hostname,
                   source_id, source_type, source_name,
                   tags, custom_fields
            FROM events
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(forensic_event_from_row(&row)),
            None => Err(StError::NotFound(format!("event {id} not found"))),
        }
    }

    /// Queries the event timeline with dynamic filters and cursor-based pagination.
    ///
    /// Builds a parameterized SQL query at runtime. All filter values are
    /// bound as parameters -- never interpolated into the SQL string.
    pub async fn query_timeline(&self, params: &TimelineQuery) -> StResult<TimelineResult> {
        // Clamp limit to [1, 1000].
        let limit = params.limit.clamp(1, 1000);
        // Fetch one extra row to detect whether more pages exist.
        let fetch_limit = i64::from(limit) + 1;

        let order_dir = match params.order {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        };
        let cursor_op = match params.order {
            SortOrder::Asc => ">",
            SortOrder::Desc => "<",
        };

        // Build WHERE clause dynamically with positional parameters.
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx: u32 = 1;

        // Time window (always present).
        conditions.push(format!("occurred_at >= ${param_idx}"));
        param_idx += 1;
        conditions.push(format!("occurred_at < ${param_idx}"));
        param_idx += 1;

        // Cursor for keyset pagination.
        let decoded_cursor = if let Some(ref cursor_str) = params.cursor {
            let (ts, uid) = decode_cursor(cursor_str)?;
            conditions.push(format!(
                "(occurred_at, id) {cursor_op} (${p1}, ${p2})",
                p1 = param_idx,
                p2 = param_idx + 1,
            ));
            param_idx += 2;
            Some((ts, uid))
        } else {
            None
        };

        // Event types filter.
        let has_event_types = params
            .event_types
            .as_ref()
            .is_some_and(|v| !v.is_empty());
        if has_event_types {
            conditions.push(format!("event_type = ANY(${param_idx})"));
            param_idx += 1;
        }

        // Actor ID filter.
        let has_actor = params.actor_id.is_some();
        if has_actor {
            conditions.push(format!("actor_id = ${param_idx}"));
            param_idx += 1;
        }

        // Source ID filter.
        let has_source = params.source_id.is_some();
        if has_source {
            conditions.push(format!("source_id = ${param_idx}"));
            param_idx += 1;
        }

        // Severity minimum filter.
        let has_severity = params.severity_min.is_some();
        if has_severity {
            conditions.push(format!("severity >= ${param_idx}"));
            param_idx += 1;
        }

        // Source IP filter.
        let has_src_ip = params.src_ip.is_some();
        if has_src_ip {
            conditions.push(format!("src_ip = ${param_idx}::INET"));
            param_idx += 1;
        }

        // Full-text search filter.
        let has_search = params.search.as_ref().is_some_and(|s| !s.is_empty());
        if has_search {
            conditions.push(format!(
                "search_text @@ plainto_tsquery('simple', ${param_idx})"
            ));
            param_idx += 1;
        }

        // Tags containment filter.
        let has_tags = params.tags.as_ref().is_some_and(|v| !v.is_empty());
        if has_tags {
            conditions.push(format!("tags @> ${param_idx}"));
            param_idx += 1;
        }

        // Suppress unused-assignment warning for the final increment.
        let _ = param_idx;

        let where_clause = conditions.join(" AND ");

        let sql = format!(
            r#"
            SELECT id, raw_event_id, event_type, severity,
                   occurred_at, observed_at, received_at,
                   actor_id, actor_name, actor_type,
                   subject_id, subject_name, subject_type,
                   object_id, object_name, object_type,
                   host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
                   src_port, dst_port, protocol,
                   device_id, device_name, device_type, hostname,
                   source_id, source_type, source_name,
                   tags, custom_fields
            FROM events
            WHERE {where_clause}
            ORDER BY occurred_at {order_dir}, id {order_dir}
            LIMIT {fetch_limit}
            "#,
        );

        // Bind parameters in the exact positional order declared above.
        let mut query = sqlx::query(&sql);

        // Time window.
        query = query.bind(params.start).bind(params.end);

        // Cursor.
        if let Some((ref ts, ref uid)) = decoded_cursor {
            query = query.bind(*ts).bind(*uid);
        }

        if has_event_types {
            query = query.bind(params.event_types.as_ref().unwrap());
        }
        if has_actor {
            query = query.bind(params.actor_id.as_ref().unwrap());
        }
        if has_source {
            query = query.bind(params.source_id.as_ref().unwrap());
        }
        if has_severity {
            query = query.bind(severity_to_i16(params.severity_min.unwrap()));
        }
        if has_src_ip {
            query = query.bind(params.src_ip.as_ref().unwrap());
        }
        if has_search {
            query = query.bind(params.search.as_ref().unwrap());
        }
        if has_tags {
            let tags_ref: Vec<&str> = params
                .tags
                .as_ref()
                .unwrap()
                .iter()
                .map(|s| s.as_str())
                .collect();
            query = query.bind(tags_ref);
        }

        let rows = query.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;

        let has_more = rows.len() > limit as usize;
        let take = if has_more {
            limit as usize
        } else {
            rows.len()
        };

        let events: Vec<ForensicEvent> = rows[..take]
            .iter()
            .map(forensic_event_from_row)
            .collect();

        let next_cursor = if has_more {
            events.last().map(|e| encode_cursor(&e.occurred_at, &e.id))
        } else {
            None
        };

        Ok(TimelineResult {
            events,
            next_cursor,
            has_more,
        })
    }

    /// Queries events by time range (inclusive on both ends).
    ///
    /// Used by legal hold materialization to find all events
    /// within a given time window. Capped at 10,000 results.
    pub async fn query_events_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> StResult<Vec<ForensicEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT id, raw_event_id, event_type, severity,
                   occurred_at, observed_at, received_at,
                   actor_id, actor_name, actor_type,
                   subject_id, subject_name, subject_type,
                   object_id, object_name, object_type,
                   host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
                   src_port, dst_port, protocol,
                   device_id, device_name, device_type, hostname,
                   source_id, source_type, source_name,
                   tags, custom_fields
            FROM events
            WHERE occurred_at >= $1 AND occurred_at <= $2
            ORDER BY occurred_at ASC
            LIMIT 10000
            "#,
        )
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(forensic_event_from_row).collect())
    }
}

// ---------------------------------------------------------------------------
// Transaction-aware variant
// ---------------------------------------------------------------------------

/// Inserts a normalized forensic event within an existing transaction.
///
/// Identical SQL to [`Database::insert_event`] but executes against the
/// provided transaction handle instead of the connection pool.
pub async fn insert_event_tx(
    tx: &mut Transaction<'_>,
    event: &ForensicEvent,
) -> StResult<EventId> {
    let severity_val = severity_to_i16(event.severity);
    let tags: Vec<&str> = event.tags.iter().map(|s| s.as_str()).collect();

    let (actor_id, actor_name, actor_type) = event
        .actor
        .as_ref()
        .map(|a| (a.id.as_deref(), a.name.as_deref(), a.actor_type.as_deref()))
        .unwrap_or((None, None, None));

    let (subject_id, subject_name, subject_type) = event
        .subject
        .as_ref()
        .map(|s| {
            (
                s.id.as_deref(),
                s.name.as_deref(),
                s.subject_type.as_deref(),
            )
        })
        .unwrap_or((None, None, None));

    let (object_id, object_name, object_type) = event
        .object
        .as_ref()
        .map(|o| {
            (
                o.id.as_deref(),
                o.name.as_deref(),
                o.object_type.as_deref(),
            )
        })
        .unwrap_or((None, None, None));

    let (src_ip, dst_ip, src_port, dst_port, protocol) = event
        .network
        .as_ref()
        .map(|n| {
            (
                n.src_ip.as_deref(),
                n.dst_ip.as_deref(),
                n.src_port,
                n.dst_port,
                n.protocol.as_deref(),
            )
        })
        .unwrap_or((None, None, None, None, None));

    let (device_id, device_name, device_type, hostname) = event
        .device
        .as_ref()
        .map(|d| {
            (
                d.device_id.as_deref(),
                d.device_name.as_deref(),
                d.device_type.as_deref(),
                d.hostname.as_deref(),
            )
        })
        .unwrap_or((None, None, None, None));

    let row = sqlx::query(
        r#"
        INSERT INTO events (
            id, raw_event_id, event_type, severity,
            occurred_at, observed_at, received_at,
            actor_id, actor_name, actor_type,
            subject_id, subject_name, subject_type,
            object_id, object_name, object_type,
            src_ip, dst_ip, src_port, dst_port, protocol,
            device_id, device_name, device_type, hostname,
            source_id, source_type, source_name,
            tags, custom_fields
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7,
            $8, $9, $10,
            $11, $12, $13,
            $14, $15, $16,
            $17::INET, $18::INET, $19, $20, $21,
            $22, $23, $24, $25,
            $26, $27, $28,
            $29, $30
        )
        RETURNING id
        "#,
    )
    .bind(event.id)
    .bind(event.raw_event_id)
    .bind(&event.event_type)
    .bind(severity_val)
    .bind(event.occurred_at)
    .bind(event.observed_at)
    .bind(event.received_at)
    .bind(actor_id)
    .bind(actor_name)
    .bind(actor_type)
    .bind(subject_id)
    .bind(subject_name)
    .bind(subject_type)
    .bind(object_id)
    .bind(object_name)
    .bind(object_type)
    .bind(src_ip)
    .bind(dst_ip)
    .bind(src_port)
    .bind(dst_port)
    .bind(protocol)
    .bind(device_id)
    .bind(device_name)
    .bind(device_type)
    .bind(hostname)
    .bind(&event.source.source_id)
    .bind(&event.source.source_type)
    .bind(event.source.source_name.as_deref())
    .bind(&tags as &[&str])
    .bind(&event.custom_fields)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    let id: EventId = row.get("id");
    Ok(id)
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Maps a sqlx `PgRow` to a [`ForensicEvent`].
///
/// `src_ip` and `dst_ip` are returned as `TEXT` via `host()` in SELECT.
pub fn forensic_event_from_row(row: &sqlx::postgres::PgRow) -> ForensicEvent {
    let severity_val: i16 = row.get("severity");

    let actor = build_optional_struct(
        row.get::<Option<String>, _>("actor_id"),
        row.get::<Option<String>, _>("actor_name"),
        row.get::<Option<String>, _>("actor_type"),
        |id, name, typ| Actor {
            id,
            name,
            actor_type: typ,
        },
    );

    let subject = build_optional_struct(
        row.get::<Option<String>, _>("subject_id"),
        row.get::<Option<String>, _>("subject_name"),
        row.get::<Option<String>, _>("subject_type"),
        |id, name, typ| Subject {
            id,
            name,
            subject_type: typ,
        },
    );

    let object = build_optional_struct(
        row.get::<Option<String>, _>("object_id"),
        row.get::<Option<String>, _>("object_name"),
        row.get::<Option<String>, _>("object_type"),
        |id, name, typ| EventObject {
            id,
            name,
            object_type: typ,
        },
    );

    let src_ip: Option<String> = row.get("src_ip");
    let dst_ip: Option<String> = row.get("dst_ip");
    let src_port: Option<i32> = row.get("src_port");
    let dst_port: Option<i32> = row.get("dst_port");
    let protocol: Option<String> = row.get("protocol");
    let network = if src_ip.is_some()
        || dst_ip.is_some()
        || src_port.is_some()
        || dst_port.is_some()
        || protocol.is_some()
    {
        Some(NetworkContext {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    } else {
        None
    };

    let device_id: Option<String> = row.get("device_id");
    let device_name: Option<String> = row.get("device_name");
    let device_type: Option<String> = row.get("device_type");
    let hostname: Option<String> = row.get("hostname");
    let device = if device_id.is_some()
        || device_name.is_some()
        || device_type.is_some()
        || hostname.is_some()
    {
        Some(DeviceContext {
            device_id,
            device_name,
            device_type,
            hostname,
        })
    } else {
        None
    };

    let tags: Vec<String> = row.get("tags");
    let custom_fields: serde_json::Value = row.get("custom_fields");

    ForensicEvent {
        id: row.get("id"),
        raw_event_id: row.get("raw_event_id"),
        event_type: row.get("event_type"),
        severity: severity_from_i16(severity_val),
        occurred_at: row.get("occurred_at"),
        observed_at: row.get("observed_at"),
        received_at: row.get("received_at"),
        actor,
        subject,
        object,
        network,
        device,
        source: SourceAttribution {
            source_id: row.get("source_id"),
            source_type: row.get("source_type"),
            source_name: row.get("source_name"),
        },
        tags,
        custom_fields,
        // tsvector is not mapped back to the Rust struct; it lives only in PG.
        search_text: None,
    }
}

/// If any of the three optional fields is `Some`, construct the struct;
/// otherwise return `None`.
fn build_optional_struct<T>(
    a: Option<String>,
    b: Option<String>,
    c: Option<String>,
    ctor: impl FnOnce(Option<String>, Option<String>, Option<String>) -> T,
) -> Option<T> {
    if a.is_some() || b.is_some() || c.is_some() {
        Some(ctor(a, b, c))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let ts = Utc::now();
        let id = Uuid::now_v7();
        let encoded = encode_cursor(&ts, &id);
        let (decoded_ts, decoded_id) = decode_cursor(&encoded).unwrap();
        // RFC 3339 round-trip loses sub-nanosecond precision but that is fine;
        // compare at millisecond granularity.
        assert!(
            (decoded_ts - ts).num_milliseconds().abs() < 1,
            "timestamp mismatch: {decoded_ts} vs {ts}"
        );
        assert_eq!(decoded_id, id);
    }

    #[test]
    fn invalid_cursor_rejected() {
        assert!(decode_cursor("not-valid-base64!!!").is_err());
        // Valid base64 but wrong format (no comma separator).
        let bad = base64_encode(b"no-comma-here");
        assert!(decode_cursor(&bad).is_err());
    }

    #[test]
    fn default_timeline_query_values() {
        let json = r#"{"start":"2024-01-01T00:00:00Z","end":"2024-01-02T00:00:00Z"}"#;
        let q: TimelineQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.limit, 100);
        assert_eq!(q.order, SortOrder::Desc);
        assert!(q.cursor.is_none());
        assert!(q.event_types.is_none());
    }

    #[test]
    fn base64_encode_decode_round_trip() {
        let input = b"2024-06-15T12:30:00+00:00,01234567-89ab-cdef-0123-456789abcdef";
        let encoded = base64_encode(input);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }
}
