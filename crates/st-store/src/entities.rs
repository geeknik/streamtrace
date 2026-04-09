//! Entity graph storage -- CRUD for entities, relationships, and
//! entity-event links.
//!
//! Provides upsert-based operations so that repeated observations of the
//! same entity naturally merge into a single canonical record with updated
//! `last_seen_at` and `event_count`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use st_common::error::{StError, StResult};
use st_common::event::{Entity, EntityEvent, EntityRelationship, ForensicEvent};
use st_common::types::EntityId;
use st_common::MAX_GRAPH_DEPTH;
use uuid::Uuid;

use crate::events::forensic_event_from_row;
use crate::{map_sqlx_err, Database, Transaction};

// ---------------------------------------------------------------------------
// Composite types
// ---------------------------------------------------------------------------

/// The neighborhood of an entity in the graph: the center entity, all
/// directly (or transitively) connected entities, and the relationships
/// between them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityGraph {
    /// The entity at the center of the query.
    pub center: Entity,
    /// All entities reachable within the requested depth.
    pub entities: Vec<Entity>,
    /// All relationships between the returned entities.
    pub relationships: Vec<EntityRelationship>,
}

// ---------------------------------------------------------------------------
// Row mapping helpers
// ---------------------------------------------------------------------------

fn entity_from_row(row: &sqlx::postgres::PgRow) -> Entity {
    Entity {
        id: row.get("id"),
        entity_type: row.get("entity_type"),
        identifier: row.get("identifier"),
        display_name: row.get("display_name"),
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
        event_count: row.get("event_count"),
        attributes: row.get("attributes"),
    }
}

fn entity_relationship_from_row(row: &sqlx::postgres::PgRow) -> EntityRelationship {
    EntityRelationship {
        id: row.get("id"),
        source_entity: row.get("source_entity"),
        target_entity: row.get("target_entity"),
        relationship: row.get("relationship"),
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
        event_count: row.get("event_count"),
        sample_event_id: row.get("sample_event_id"),
    }
}

fn entity_event_from_row(row: &sqlx::postgres::PgRow) -> EntityEvent {
    EntityEvent {
        entity_id: row.get("entity_id"),
        event_id: row.get("event_id"),
        role: row.get("role"),
        occurred_at: row.get("occurred_at"),
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Allowed entity types. Rejects anything outside this set.
const VALID_ENTITY_TYPES: &[&str] = &["user", "device", "ip", "host", "session", "service"];

/// Allowed relationship labels.
const VALID_RELATIONSHIPS: &[&str] = &[
    "used_device",
    "from_ip",
    "in_session",
    "accessed",
    "authenticated_as",
    "hosted_on",
    "communicated_with",
];

/// Allowed entity-event roles.
const VALID_ROLES: &[&str] = &[
    "actor", "subject", "object", "src_ip", "dst_ip", "device", "host",
];

/// Validates that a value is in an allowed set, returning a `Validation`
/// error if not.
fn validate_enum(value: &str, allowed: &[&str], field_name: &str) -> StResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(StError::Validation(format!(
            "invalid {field_name}: {value:?}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Hard limits to bound resource usage
// ---------------------------------------------------------------------------

/// Maximum number of entity-event rows returned per query.
const MAX_ENTITY_EVENTS_LIMIT: u32 = 1000;

/// Maximum number of entities returned by search.
const MAX_SEARCH_LIMIT: u32 = 500;

/// Maximum number of relationships returned by `get_entity_relationships`.
const MAX_RELATIONSHIPS_LIMIT: i64 = 500;

// ---------------------------------------------------------------------------
// Database methods -- entities
// ---------------------------------------------------------------------------

impl Database {
    /// Upsert an entity: create if new, update `last_seen_at` and increment
    /// `event_count` if it already exists.
    ///
    /// Uses `ON CONFLICT (entity_type, identifier)` for idempotent writes.
    /// Returns the entity's UUID.
    pub async fn upsert_entity(
        &self,
        entity_type: &str,
        identifier: &str,
        display_name: Option<&str>,
        occurred_at: DateTime<Utc>,
        attributes: &serde_json::Value,
    ) -> StResult<EntityId> {
        validate_enum(entity_type, VALID_ENTITY_TYPES, "entity_type")?;

        let row = sqlx::query(
            r#"
            INSERT INTO entities (entity_type, identifier, display_name,
                                  first_seen_at, last_seen_at, attributes)
            VALUES ($1, $2, $3, $4, $4, $5)
            ON CONFLICT (entity_type, identifier) DO UPDATE
            SET last_seen_at  = GREATEST(entities.last_seen_at, EXCLUDED.last_seen_at),
                event_count   = entities.event_count + 1,
                display_name  = COALESCE(EXCLUDED.display_name, entities.display_name),
                attributes    = entities.attributes || EXCLUDED.attributes
            RETURNING id
            "#,
        )
        .bind(entity_type)
        .bind(identifier)
        .bind(display_name)
        .bind(occurred_at)
        .bind(attributes)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let id: EntityId = row.get("id");
        Ok(id)
    }

    /// Upsert an entity relationship: create if new, update `last_seen_at`
    /// and increment `event_count` if it already exists.
    ///
    /// Returns the relationship's UUID.
    pub async fn upsert_entity_relationship(
        &self,
        source_entity: EntityId,
        target_entity: EntityId,
        relationship: &str,
        occurred_at: DateTime<Utc>,
        sample_event_id: Option<Uuid>,
    ) -> StResult<Uuid> {
        validate_enum(relationship, VALID_RELATIONSHIPS, "relationship")?;

        let row = sqlx::query(
            r#"
            INSERT INTO entity_relationships
                (source_entity, target_entity, relationship,
                 first_seen_at, last_seen_at, sample_event_id)
            VALUES ($1, $2, $3, $4, $4, $5)
            ON CONFLICT (source_entity, target_entity, relationship) DO UPDATE
            SET last_seen_at    = GREATEST(entity_relationships.last_seen_at,
                                           EXCLUDED.last_seen_at),
                event_count     = entity_relationships.event_count + 1,
                sample_event_id = COALESCE(EXCLUDED.sample_event_id,
                                           entity_relationships.sample_event_id)
            RETURNING id
            "#,
        )
        .bind(source_entity)
        .bind(target_entity)
        .bind(relationship)
        .bind(occurred_at)
        .bind(sample_event_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let id: Uuid = row.get("id");
        Ok(id)
    }

    /// Link an entity to an event. Idempotent: duplicate links are silently
    /// ignored via `ON CONFLICT DO NOTHING`.
    pub async fn link_entity_event(
        &self,
        entity_id: EntityId,
        event_id: Uuid,
        role: &str,
        occurred_at: DateTime<Utc>,
    ) -> StResult<()> {
        validate_enum(role, VALID_ROLES, "role")?;

        sqlx::query(
            r#"
            INSERT INTO entity_events (entity_id, event_id, role, occurred_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(entity_id)
        .bind(event_id)
        .bind(role)
        .bind(occurred_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(())
    }

    /// Fetch an entity by its UUID.
    ///
    /// Returns `StError::NotFound` if no row exists.
    pub async fn get_entity(&self, id: EntityId) -> StResult<Entity> {
        let row = sqlx::query(
            r#"
            SELECT id, entity_type, identifier, display_name,
                   first_seen_at, last_seen_at, event_count, attributes
            FROM entities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        match row {
            Some(row) => Ok(entity_from_row(&row)),
            None => Err(StError::NotFound(format!("entity {id} not found"))),
        }
    }

    /// Fetch an entity by its type and canonical identifier.
    ///
    /// Returns `None` if no matching entity exists.
    pub async fn get_entity_by_identifier(
        &self,
        entity_type: &str,
        identifier: &str,
    ) -> StResult<Option<Entity>> {
        validate_enum(entity_type, VALID_ENTITY_TYPES, "entity_type")?;

        let row = sqlx::query(
            r#"
            SELECT id, entity_type, identifier, display_name,
                   first_seen_at, last_seen_at, event_count, attributes
            FROM entities
            WHERE entity_type = $1 AND identifier = $2
            "#,
        )
        .bind(entity_type)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(row.as_ref().map(entity_from_row))
    }

    /// List entities, optionally filtered by type.
    ///
    /// Returns entities ordered by `last_seen_at` descending (most recently
    /// active first). Results are capped at `limit` rows.
    pub async fn list_entities(
        &self,
        entity_type: Option<&str>,
        limit: u32,
    ) -> StResult<Vec<Entity>> {
        if let Some(et) = entity_type {
            validate_enum(et, VALID_ENTITY_TYPES, "entity_type")?;
        }

        let clamped_limit = limit.clamp(1, MAX_ENTITY_EVENTS_LIMIT) as i64;

        let rows = if let Some(et) = entity_type {
            sqlx::query(
                r#"
                SELECT id, entity_type, identifier, display_name,
                       first_seen_at, last_seen_at, event_count, attributes
                FROM entities
                WHERE entity_type = $1
                ORDER BY last_seen_at DESC
                LIMIT $2
                "#,
            )
            .bind(et)
            .bind(clamped_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?
        } else {
            sqlx::query(
                r#"
                SELECT id, entity_type, identifier, display_name,
                       first_seen_at, last_seen_at, event_count, attributes
                FROM entities
                ORDER BY last_seen_at DESC
                LIMIT $1
                "#,
            )
            .bind(clamped_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?
        };

        Ok(rows.iter().map(entity_from_row).collect())
    }

    /// Search entities by type and/or identifier substring.
    ///
    /// Uses case-insensitive `ILIKE` for the identifier filter. Results are
    /// ordered by `last_seen_at` descending and capped at `limit`.
    pub async fn search_entities(
        &self,
        entity_type: Option<&str>,
        identifier_contains: Option<&str>,
        limit: u32,
    ) -> StResult<Vec<Entity>> {
        if let Some(et) = entity_type {
            validate_enum(et, VALID_ENTITY_TYPES, "entity_type")?;
        }

        let clamped_limit = limit.clamp(1, MAX_SEARCH_LIMIT) as i64;

        // Build the ILIKE pattern with `%` wildcards, escaping user input.
        let like_pattern = identifier_contains.map(|s| {
            let escaped = s
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{escaped}%")
        });

        let rows = match (entity_type, like_pattern.as_deref()) {
            (Some(et), Some(pat)) => {
                sqlx::query(
                    r#"
                    SELECT id, entity_type, identifier, display_name,
                           first_seen_at, last_seen_at, event_count, attributes
                    FROM entities
                    WHERE entity_type = $1 AND identifier ILIKE $2
                    ORDER BY last_seen_at DESC
                    LIMIT $3
                    "#,
                )
                .bind(et)
                .bind(pat)
                .bind(clamped_limit)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_err)?
            }
            (Some(et), None) => {
                sqlx::query(
                    r#"
                    SELECT id, entity_type, identifier, display_name,
                           first_seen_at, last_seen_at, event_count, attributes
                    FROM entities
                    WHERE entity_type = $1
                    ORDER BY last_seen_at DESC
                    LIMIT $2
                    "#,
                )
                .bind(et)
                .bind(clamped_limit)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_err)?
            }
            (None, Some(pat)) => {
                sqlx::query(
                    r#"
                    SELECT id, entity_type, identifier, display_name,
                           first_seen_at, last_seen_at, event_count, attributes
                    FROM entities
                    WHERE identifier ILIKE $1
                    ORDER BY last_seen_at DESC
                    LIMIT $2
                    "#,
                )
                .bind(pat)
                .bind(clamped_limit)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_err)?
            }
            (None, None) => {
                sqlx::query(
                    r#"
                    SELECT id, entity_type, identifier, display_name,
                           first_seen_at, last_seen_at, event_count, attributes
                    FROM entities
                    ORDER BY last_seen_at DESC
                    LIMIT $1
                    "#,
                )
                .bind(clamped_limit)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_err)?
            }
        };

        Ok(rows.iter().map(entity_from_row).collect())
    }

    /// Get all relationships for an entity (both outbound and inbound).
    ///
    /// Results are capped at 500 rows to prevent unbounded result sets.
    pub async fn get_entity_relationships(
        &self,
        entity_id: EntityId,
    ) -> StResult<Vec<EntityRelationship>> {
        let rows = sqlx::query(
            r#"
            SELECT id, source_entity, target_entity, relationship,
                   first_seen_at, last_seen_at, event_count, sample_event_id
            FROM entity_relationships
            WHERE source_entity = $1 OR target_entity = $1
            ORDER BY last_seen_at DESC
            LIMIT $2
            "#,
        )
        .bind(entity_id)
        .bind(MAX_RELATIONSHIPS_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(entity_relationship_from_row).collect())
    }

    /// Get the entity-event links for an entity within a time range.
    pub async fn get_entity_event_links(
        &self,
        entity_id: EntityId,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: u32,
    ) -> StResult<Vec<EntityEvent>> {
        let clamped_limit = limit.clamp(1, MAX_ENTITY_EVENTS_LIMIT) as i64;

        let rows = sqlx::query(
            r#"
            SELECT entity_id, event_id, role, occurred_at
            FROM entity_events
            WHERE entity_id = $1
              AND occurred_at >= $2
              AND occurred_at < $3
            ORDER BY occurred_at DESC
            LIMIT $4
            "#,
        )
        .bind(entity_id)
        .bind(start)
        .bind(end)
        .bind(clamped_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(entity_event_from_row).collect())
    }

    /// Get full forensic events for an entity within a time range.
    ///
    /// Joins `entity_events` with `events` to return complete
    /// [`ForensicEvent`] records, ordered by `occurred_at` descending.
    pub async fn get_entity_events(
        &self,
        entity_id: EntityId,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: u32,
    ) -> StResult<Vec<ForensicEvent>> {
        let clamped_limit = limit.clamp(1, MAX_ENTITY_EVENTS_LIMIT) as i64;

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
            FROM entity_events ee
            JOIN events e ON e.id = ee.event_id
            WHERE ee.entity_id = $1
              AND ee.occurred_at >= $2
              AND ee.occurred_at < $3
            ORDER BY ee.occurred_at DESC
            LIMIT $4
            "#,
        )
        .bind(entity_id)
        .bind(start)
        .bind(end)
        .bind(clamped_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.iter().map(forensic_event_from_row).collect())
    }

    /// Get the entity graph neighborhood: the center entity and all entities
    /// reachable within `max_depth` hops.
    ///
    /// - `max_depth = 1`: direct neighbors only.
    /// - `max_depth = 2`: neighbors of neighbors.
    /// - Maximum allowed depth is [`MAX_GRAPH_DEPTH`] (to bound query cost).
    ///
    /// For depth 1 this is a simple join; for depth 2+ it uses a recursive
    /// CTE bounded by the depth parameter.
    pub async fn get_entity_graph(
        &self,
        entity_id: EntityId,
        max_depth: u32,
    ) -> StResult<EntityGraph> {
        let depth = max_depth.clamp(1, MAX_GRAPH_DEPTH) as i32;

        // Fetch the center entity first.
        let center = self.get_entity(entity_id).await?;

        // Recursive CTE to find all connected entity IDs within depth.
        let entity_rows = sqlx::query(
            r#"
            WITH RECURSIVE reachable(entity_id, depth) AS (
                -- Seed: the center entity.
                SELECT $1::UUID, 0

                UNION

                -- Expand: follow relationships in both directions.
                SELECT
                    CASE
                        WHEN r.source_entity = reachable.entity_id THEN r.target_entity
                        ELSE r.source_entity
                    END,
                    reachable.depth + 1
                FROM reachable
                JOIN entity_relationships r
                    ON r.source_entity = reachable.entity_id
                    OR r.target_entity = reachable.entity_id
                WHERE reachable.depth < $2
            )
            SELECT DISTINCT e.id, e.entity_type, e.identifier, e.display_name,
                   e.first_seen_at, e.last_seen_at, e.event_count, e.attributes
            FROM reachable rc
            JOIN entities e ON e.id = rc.entity_id
            WHERE e.id != $1
            "#,
        )
        .bind(entity_id)
        .bind(depth)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let entities: Vec<Entity> = entity_rows.iter().map(entity_from_row).collect();

        // Collect all entity IDs (center + neighbors) for relationship query.
        let mut all_ids: Vec<Uuid> = entities.iter().map(|e| e.id).collect();
        all_ids.push(entity_id);

        // Fetch all relationships between the collected entities.
        let rel_rows = sqlx::query(
            r#"
            SELECT id, source_entity, target_entity, relationship,
                   first_seen_at, last_seen_at, event_count, sample_event_id
            FROM entity_relationships
            WHERE source_entity = ANY($1)
              AND target_entity = ANY($1)
            "#,
        )
        .bind(&all_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let relationships: Vec<EntityRelationship> =
            rel_rows.iter().map(entity_relationship_from_row).collect();

        Ok(EntityGraph {
            center,
            entities,
            relationships,
        })
    }
}

// ---------------------------------------------------------------------------
// Transaction-aware variants
// ---------------------------------------------------------------------------

/// Upserts an entity within an existing transaction.
///
/// Identical SQL to [`Database::upsert_entity`] but executes against the
/// provided transaction handle.
pub async fn upsert_entity_tx(
    tx: &mut Transaction<'_>,
    entity_type: &str,
    identifier: &str,
    display_name: Option<&str>,
    occurred_at: DateTime<Utc>,
    attributes: &serde_json::Value,
) -> StResult<EntityId> {
    validate_enum(entity_type, VALID_ENTITY_TYPES, "entity_type")?;

    let row = sqlx::query(
        r#"
        INSERT INTO entities (entity_type, identifier, display_name,
                              first_seen_at, last_seen_at, attributes)
        VALUES ($1, $2, $3, $4, $4, $5)
        ON CONFLICT (entity_type, identifier) DO UPDATE
        SET last_seen_at  = GREATEST(entities.last_seen_at, EXCLUDED.last_seen_at),
            event_count   = entities.event_count + 1,
            display_name  = COALESCE(EXCLUDED.display_name, entities.display_name),
            attributes    = entities.attributes || EXCLUDED.attributes
        RETURNING id
        "#,
    )
    .bind(entity_type)
    .bind(identifier)
    .bind(display_name)
    .bind(occurred_at)
    .bind(attributes)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    let id: EntityId = row.get("id");
    Ok(id)
}

/// Links an entity to an event within an existing transaction.
///
/// Identical SQL to [`Database::link_entity_event`] but executes against
/// the provided transaction handle.
pub async fn link_entity_event_tx(
    tx: &mut Transaction<'_>,
    entity_id: EntityId,
    event_id: Uuid,
    role: &str,
    occurred_at: DateTime<Utc>,
) -> StResult<()> {
    validate_enum(role, VALID_ROLES, "role")?;

    sqlx::query(
        r#"
        INSERT INTO entity_events (entity_id, event_id, role, occurred_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(entity_id)
    .bind(event_id)
    .bind(role)
    .bind(occurred_at)
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    Ok(())
}

/// Upserts an entity relationship within an existing transaction.
///
/// Identical SQL to [`Database::upsert_entity_relationship`] but executes
/// against the provided transaction handle.
pub async fn upsert_entity_relationship_tx(
    tx: &mut Transaction<'_>,
    source_entity: EntityId,
    target_entity: EntityId,
    relationship: &str,
    occurred_at: DateTime<Utc>,
    sample_event_id: Option<Uuid>,
) -> StResult<Uuid> {
    validate_enum(relationship, VALID_RELATIONSHIPS, "relationship")?;

    let row = sqlx::query(
        r#"
        INSERT INTO entity_relationships
            (source_entity, target_entity, relationship,
             first_seen_at, last_seen_at, sample_event_id)
        VALUES ($1, $2, $3, $4, $4, $5)
        ON CONFLICT (source_entity, target_entity, relationship) DO UPDATE
        SET last_seen_at    = GREATEST(entity_relationships.last_seen_at,
                                       EXCLUDED.last_seen_at),
            event_count     = entity_relationships.event_count + 1,
            sample_event_id = COALESCE(EXCLUDED.sample_event_id,
                                       entity_relationships.sample_event_id)
        RETURNING id
        "#,
    )
    .bind(source_entity)
    .bind(target_entity)
    .bind(relationship)
    .bind(occurred_at)
    .bind(sample_event_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    let id: Uuid = row.get("id");
    Ok(id)
}
