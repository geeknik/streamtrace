//! Internal pipeline step implementations.
//!
//! Each function represents one stage of the ingestion pipeline.
//! These are called in sequence by [`IngestPipeline`] and are kept
//! separate for testability and clarity.

use chrono::Utc;
use st_common::error::StError;
use st_common::event::{CorrelationKey, ForensicEvent, SourceAttribution};
use st_common::types::{EventId, RawEventId};
use st_common::validation::validate_timestamp_not_future;
use st_correlate::extract_correlation_keys;
use st_crypto::hash;
use st_parser::ParsedEvent;
use st_store::correlation_keys::insert_correlation_keys_tx;
use st_store::entities::{link_entity_event_tx, upsert_entity_relationship_tx, upsert_entity_tx};
use st_store::events::insert_event_tx;
use st_store::raw_events::insert_raw_event_tx;
use st_store::Database;
use st_store::Transaction;
use uuid::Uuid;

/// Step 1: Compute BLAKE3 hash of raw content.
///
/// Returns the hex-encoded digest string suitable for storage.
pub fn hash_content(body: &[u8]) -> String {
    let content_hash = hash::hash_content(body);
    content_hash.hex_digest
}

/// Step 2: Store the raw event bytes in the database.
///
/// Returns the generated `RawEventId` (UUIDv7).
#[allow(clippy::too_many_arguments)]
pub async fn store_raw(
    db: &Database,
    content: &[u8],
    content_hash: &str,
    content_type: &str,
    source_id: &str,
    source_type: &str,
    source_name: Option<&str>,
    parser_id: Option<&str>,
) -> Result<RawEventId, StError> {
    db.insert_raw_event(
        content,
        content_hash,
        content_type,
        source_id,
        source_type,
        source_name,
        parser_id,
    )
    .await
}

/// Step 2 (transaction variant): Store the raw event bytes within a transaction.
#[allow(clippy::too_many_arguments)]
pub async fn store_raw_tx(
    tx: &mut Transaction<'_>,
    content: &[u8],
    content_hash: &str,
    content_type: &str,
    source_id: &str,
    source_type: &str,
    source_name: Option<&str>,
    parser_id: Option<&str>,
) -> Result<RawEventId, StError> {
    insert_raw_event_tx(
        tx,
        content,
        content_hash,
        content_type,
        source_id,
        source_type,
        source_name,
        parser_id,
    )
    .await
}

/// Step 3: Convert a [`ParsedEvent`] into a [`ForensicEvent`].
///
/// Assigns a new UUIDv7 as the event ID, sets `received_at` to the
/// current time, and copies source attribution fields.
///
/// Rejects events whose `occurred_at` is more than 60 seconds in the
/// future (clock-skew tolerance) to prevent ingestion of forged
/// timestamps.
pub fn normalize(
    parsed: &ParsedEvent,
    raw_event_id: RawEventId,
    source_id: &str,
    source_type: &str,
    source_name: Option<&str>,
) -> Result<ForensicEvent, StError> {
    // Reject events with timestamps too far in the future.
    validate_timestamp_not_future("occurred_at", &parsed.occurred_at)?;

    let id: EventId = Uuid::now_v7();
    let received_at = Utc::now();

    let source = SourceAttribution {
        source_id: source_id.to_string(),
        source_type: source_type.to_string(),
        source_name: source_name.map(|s| s.to_string()),
    };

    let mut event = ForensicEvent::new(
        id,
        raw_event_id,
        parsed.event_type.clone(),
        parsed.severity,
        parsed.occurred_at,
        received_at,
        source,
    );

    event.observed_at = parsed.observed_at;
    event.actor = parsed.actor.clone();
    event.subject = parsed.subject.clone();
    event.object = parsed.object.clone();
    event.network = parsed.network.clone();
    event.device = parsed.device.clone();
    event.tags = parsed.tags.clone();
    event.custom_fields = parsed.custom_fields.clone();

    // Generate search text for full-text indexing.
    event.generate_search_text();

    Ok(event)
}

/// Step 4: Extract correlation keys from a normalized event.
///
/// Combines keys extracted from the event structure with any
/// correlation hints the parser provided.
pub fn extract_keys(event: &ForensicEvent, parser_hints: &[CorrelationKey]) -> Vec<CorrelationKey> {
    let mut keys = extract_correlation_keys(event);

    // Merge parser-provided hints, deduplicating by (type, value).
    // Collect existing pairs as owned values to avoid borrowing `keys`.
    let existing: std::collections::HashSet<(CorrelationKeyType, String)> = keys
        .iter()
        .map(|k| (k.key_type.clone(), k.key_value.clone()))
        .collect();

    for hint in parser_hints {
        if !hint.key_value.trim().is_empty()
            && !existing.contains(&(hint.key_type.clone(), hint.key_value.clone()))
        {
            keys.push(hint.clone());
        }
    }

    keys
}

/// Step 5: Store a normalized event and its correlation keys.
///
/// Inserts the event first, then batch-inserts the correlation keys.
pub async fn store_normalized(
    db: &Database,
    event: &ForensicEvent,
    keys: &[CorrelationKey],
) -> Result<EventId, StError> {
    let event_id = db.insert_event(event).await?;
    db.insert_correlation_keys(event_id, keys, event.occurred_at)
        .await?;
    Ok(event_id)
}

/// Step 5 (transaction variant): Store a normalized event and its
/// correlation keys within an existing transaction.
pub async fn store_normalized_tx(
    tx: &mut Transaction<'_>,
    event: &ForensicEvent,
    keys: &[CorrelationKey],
) -> Result<EventId, StError> {
    let event_id = insert_event_tx(tx, event).await?;
    insert_correlation_keys_tx(tx, event_id, keys, event.occurred_at).await?;
    Ok(event_id)
}

/// Step 6: Resolve entities from a forensic event and persist them.
///
/// Extracts observed entities and relationships using the correlate crate,
/// upserts each entity, links entities to the event, and upserts
/// relationships between co-occurring entities.
///
/// Entity resolution failures are logged but do not fail the overall
/// ingest -- the event is already stored at this point.
pub async fn resolve_entities(
    db: &Database,
    event: &ForensicEvent,
    event_id: EventId,
) -> Result<(), StError> {
    let (entities, relationships) = st_correlate::extract_entities(event);

    if entities.is_empty() {
        return Ok(());
    }

    let empty_attrs = serde_json::json!({});

    // Map (entity_type, identifier) -> UUID after upsert.
    let mut entity_ids: std::collections::HashMap<(String, String), uuid::Uuid> =
        std::collections::HashMap::new();

    for observed in &entities {
        let entity_uuid = db
            .upsert_entity(
                &observed.entity_type,
                &observed.identifier,
                observed.display_name.as_deref(),
                event.occurred_at,
                &empty_attrs,
            )
            .await?;

        entity_ids.insert(
            (observed.entity_type.clone(), observed.identifier.clone()),
            entity_uuid,
        );

        // Link entity to event.
        db.link_entity_event(entity_uuid, event_id, &observed.role, event.occurred_at)
            .await?;
    }

    // Upsert relationships.
    for rel in &relationships {
        let source_key = (rel.source_type.clone(), rel.source_id.clone());
        let target_key = (rel.target_type.clone(), rel.target_id.clone());

        if let (Some(&source_uuid), Some(&target_uuid)) =
            (entity_ids.get(&source_key), entity_ids.get(&target_key))
        {
            db.upsert_entity_relationship(
                source_uuid,
                target_uuid,
                &rel.relationship,
                event.occurred_at,
                Some(event_id),
            )
            .await?;
        }
    }

    tracing::debug!(
        event_id = %event_id,
        entities = entities.len(),
        relationships = relationships.len(),
        "entity resolution completed"
    );

    Ok(())
}

/// Step 6 (transaction variant): Resolve entities within an existing
/// transaction.
///
/// Identical logic to [`resolve_entities`] but all DB operations execute
/// against the provided transaction handle.
pub async fn resolve_entities_tx(
    tx: &mut Transaction<'_>,
    event: &ForensicEvent,
    event_id: EventId,
) -> Result<(), StError> {
    let (entities, relationships) = st_correlate::extract_entities(event);

    if entities.is_empty() {
        return Ok(());
    }

    let empty_attrs = serde_json::json!({});

    let mut entity_ids: std::collections::HashMap<(String, String), uuid::Uuid> =
        std::collections::HashMap::new();

    for observed in &entities {
        let entity_uuid = upsert_entity_tx(
            tx,
            &observed.entity_type,
            &observed.identifier,
            observed.display_name.as_deref(),
            event.occurred_at,
            &empty_attrs,
        )
        .await?;

        entity_ids.insert(
            (observed.entity_type.clone(), observed.identifier.clone()),
            entity_uuid,
        );

        link_entity_event_tx(tx, entity_uuid, event_id, &observed.role, event.occurred_at).await?;
    }

    for rel in &relationships {
        let source_key = (rel.source_type.clone(), rel.source_id.clone());
        let target_key = (rel.target_type.clone(), rel.target_id.clone());

        if let (Some(&source_uuid), Some(&target_uuid)) =
            (entity_ids.get(&source_key), entity_ids.get(&target_key))
        {
            upsert_entity_relationship_tx(
                tx,
                source_uuid,
                target_uuid,
                &rel.relationship,
                event.occurred_at,
                Some(event_id),
            )
            .await?;
        }
    }

    tracing::debug!(
        event_id = %event_id,
        entities = entities.len(),
        relationships = relationships.len(),
        "entity resolution completed (tx)"
    );

    Ok(())
}

// Import needed for extract_keys
use st_common::event::CorrelationKeyType;
