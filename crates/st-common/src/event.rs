//! Forensic event model for StreamTrace.
//!
//! Defines the canonical data structures for raw ingested events and
//! normalized forensic events, plus supporting context types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{ContentHash, EntityId, EventId, RawEventId, Severity};

/// A raw event as received from an external source, before normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    /// Unique identifier assigned at ingestion time (UUIDv7).
    pub id: RawEventId,
    /// Raw event payload bytes.
    pub content: Vec<u8>,
    /// BLAKE3 hash of `content` for integrity verification.
    pub content_hash: ContentHash,
    /// MIME type or format identifier (e.g. "application/json", "text/syslog").
    pub content_type: String,
    /// Identifier of the source that produced this event.
    pub source_id: String,
    /// Category of the source (e.g. "firewall", "endpoint", "cloud").
    pub source_type: String,
    /// Optional human-readable source name.
    #[serde(default)]
    pub source_name: Option<String>,
    /// Timestamp when the event was received by StreamTrace.
    pub received_at: DateTime<Utc>,
    /// Identifier of the parser that should handle this event.
    #[serde(default)]
    pub parser_id: Option<String>,
    /// Size of the raw content in bytes.
    pub byte_size: i32,
}

/// Identity or entity that initiated an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Unique identifier for the actor.
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Category of actor (e.g. "user", "service_account", "process").
    #[serde(default)]
    pub actor_type: Option<String>,
}

/// Entity that was acted upon or affected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// Unique identifier for the subject.
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Category of subject (e.g. "user", "host", "file").
    #[serde(default)]
    pub subject_type: Option<String>,
}

/// Object or resource involved in the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventObject {
    /// Unique identifier for the object.
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Category of object (e.g. "file", "database", "endpoint").
    #[serde(default)]
    pub object_type: Option<String>,
}

/// Network-level context extracted from the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    /// Source IP address.
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Destination IP address.
    #[serde(default)]
    pub dst_ip: Option<String>,
    /// Source port number.
    #[serde(default)]
    pub src_port: Option<i32>,
    /// Destination port number.
    #[serde(default)]
    pub dst_port: Option<i32>,
    /// Network protocol (e.g. "tcp", "udp", "icmp").
    #[serde(default)]
    pub protocol: Option<String>,
}

/// Device-level context extracted from the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceContext {
    /// Unique device identifier.
    #[serde(default)]
    pub device_id: Option<String>,
    /// Human-readable device name.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Device category (e.g. "workstation", "server", "mobile").
    #[serde(default)]
    pub device_type: Option<String>,
    /// Hostname of the device.
    #[serde(default)]
    pub hostname: Option<String>,
}

/// Attribution to the original data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAttribution {
    /// Identifier of the originating source.
    pub source_id: String,
    /// Category of the originating source.
    pub source_type: String,
    /// Optional human-readable source name.
    #[serde(default)]
    pub source_name: Option<String>,
}

/// A normalized forensic event, the core unit of analysis in StreamTrace.
///
/// Produced by parsing and normalizing a [`RawEvent`] through a parser pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvent {
    /// Unique identifier for this normalized event (UUIDv7).
    pub id: EventId,
    /// Identifier of the raw event this was derived from.
    pub raw_event_id: RawEventId,
    /// Canonical event type (e.g. "auth.login.success", "file.access").
    pub event_type: String,
    /// Severity classification.
    pub severity: Severity,
    /// Timestamp when the event originally occurred.
    pub occurred_at: DateTime<Utc>,
    /// Timestamp when the event was first observed (may differ from occurred_at).
    #[serde(default)]
    pub observed_at: Option<DateTime<Utc>>,
    /// Timestamp when the raw event was received by StreamTrace.
    pub received_at: DateTime<Utc>,
    /// The actor (initiator) involved in this event.
    #[serde(default)]
    pub actor: Option<Actor>,
    /// The subject (target) involved in this event.
    #[serde(default)]
    pub subject: Option<Subject>,
    /// The object (resource) involved in this event.
    #[serde(default)]
    pub object: Option<EventObject>,
    /// Network-level context, if applicable.
    #[serde(default)]
    pub network: Option<NetworkContext>,
    /// Device-level context, if applicable.
    #[serde(default)]
    pub device: Option<DeviceContext>,
    /// Attribution to the data source.
    pub source: SourceAttribution,
    /// Free-form tags for categorization and filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Arbitrary key-value data that does not fit the canonical schema.
    #[serde(default = "default_custom_fields")]
    pub custom_fields: serde_json::Value,
    /// Pre-computed search text for full-text indexing.
    #[serde(default)]
    pub search_text: Option<String>,
}

fn default_custom_fields() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

impl ForensicEvent {
    /// Creates a new `ForensicEvent` with the required fields; optional fields
    /// are set to their defaults.
    pub fn new(
        id: EventId,
        raw_event_id: RawEventId,
        event_type: String,
        severity: Severity,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
        source: SourceAttribution,
    ) -> Self {
        Self {
            id,
            raw_event_id,
            event_type,
            severity,
            occurred_at,
            observed_at: None,
            received_at,
            actor: None,
            subject: None,
            object: None,
            network: None,
            device: None,
            source,
            tags: Vec::new(),
            custom_fields: default_custom_fields(),
            search_text: None,
        }
    }

    /// Generates a concatenated search string from key fields for full-text indexing.
    ///
    /// Includes event_type, actor id/name, subject id/name, object id/name,
    /// source attribution, and tags.
    pub fn generate_search_text(&mut self) {
        let mut parts: Vec<&str> = Vec::new();

        parts.push(&self.event_type);

        if let Some(ref actor) = self.actor {
            if let Some(ref id) = actor.id {
                parts.push(id);
            }
            if let Some(ref name) = actor.name {
                parts.push(name);
            }
        }

        if let Some(ref subject) = self.subject {
            if let Some(ref id) = subject.id {
                parts.push(id);
            }
            if let Some(ref name) = subject.name {
                parts.push(name);
            }
        }

        if let Some(ref object) = self.object {
            if let Some(ref id) = object.id {
                parts.push(id);
            }
            if let Some(ref name) = object.name {
                parts.push(name);
            }
        }

        parts.push(&self.source.source_id);
        parts.push(&self.source.source_type);
        if let Some(ref name) = self.source.source_name {
            parts.push(name);
        }

        for tag in &self.tags {
            parts.push(tag);
        }

        self.search_text = Some(parts.join(" "));
    }
}

// ---------------------------------------------------------------------------
// Entity graph types
// ---------------------------------------------------------------------------

/// Represents a resolved entity in the entity graph.
///
/// Entities are real-world objects (users, devices, IPs, hosts, sessions,
/// services) that are observed across forensic events. Entity resolution
/// merges multiple observations into a single canonical record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Unique identifier for this entity.
    pub id: EntityId,
    /// Category of entity (e.g. "user", "device", "ip").
    pub entity_type: String,
    /// Canonical identifier within its type (e.g. user ID, IP address).
    pub identifier: String,
    /// Human-readable label for display purposes.
    pub display_name: Option<String>,
    /// Timestamp when this entity was first observed.
    pub first_seen_at: DateTime<Utc>,
    /// Timestamp when this entity was most recently observed.
    pub last_seen_at: DateTime<Utc>,
    /// Number of events in which this entity has been observed.
    pub event_count: i32,
    /// Arbitrary attributes associated with this entity.
    pub attributes: serde_json::Value,
}

/// A directed relationship between two entities in the entity graph.
///
/// Relationships are discovered through co-occurrence in events
/// (e.g. user "alice" used device "macbook-42").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationship {
    /// Unique identifier for this relationship record.
    pub id: uuid::Uuid,
    /// The entity at the source end of this relationship.
    pub source_entity: EntityId,
    /// The entity at the target end of this relationship.
    pub target_entity: EntityId,
    /// Label describing the relationship (e.g. "used_device", "from_ip").
    pub relationship: String,
    /// Timestamp when this relationship was first observed.
    pub first_seen_at: DateTime<Utc>,
    /// Timestamp when this relationship was most recently observed.
    pub last_seen_at: DateTime<Utc>,
    /// Number of events supporting this relationship.
    pub event_count: i32,
    /// UUID of an example event that evidences this relationship.
    pub sample_event_id: Option<uuid::Uuid>,
}

/// A link between an entity and a specific event, recording the role
/// the entity played in that event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityEvent {
    /// The entity that was observed.
    pub entity_id: EntityId,
    /// The event in which the entity was observed.
    pub event_id: EventId,
    /// The role the entity played (e.g. "actor", "src_ip", "device").
    pub role: String,
    /// When the event occurred (partition key for the hypertable).
    pub occurred_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Correlation key types
// ---------------------------------------------------------------------------

/// Classification of correlation key used to link related events.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKeyType {
    /// Correlation by user or service identity.
    Identity,
    /// Correlation by session identifier.
    Session,
    /// Correlation by authentication token.
    Token,
    /// Correlation by IP address.
    Ip,
    /// Correlation by device identifier.
    Device,
    /// Correlation by hostname.
    Host,
    /// Application-defined correlation key.
    Custom(String),
}

/// A key used to correlate related forensic events.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationKey {
    /// The type of correlation.
    pub key_type: CorrelationKeyType,
    /// The correlation value.
    pub key_value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_source() -> SourceAttribution {
        SourceAttribution {
            source_id: "src-001".to_string(),
            source_type: "firewall".to_string(),
            source_name: Some("perimeter-fw".to_string()),
        }
    }

    fn make_event() -> ForensicEvent {
        let now = Utc::now();
        ForensicEvent::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "auth.login.success".to_string(),
            Severity::Medium,
            now,
            now,
            make_source(),
        )
    }

    #[test]
    fn new_sets_defaults() {
        let event = make_event();
        assert!(event.actor.is_none());
        assert!(event.subject.is_none());
        assert!(event.object.is_none());
        assert!(event.network.is_none());
        assert!(event.device.is_none());
        assert!(event.tags.is_empty());
        assert!(event.search_text.is_none());
        assert_eq!(
            event.custom_fields,
            serde_json::Value::Object(serde_json::Map::new())
        );
    }

    #[test]
    fn generate_search_text_includes_all_fields() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("actor-1".to_string()),
            name: Some("Alice".to_string()),
            actor_type: Some("user".to_string()),
        });
        event.subject = Some(Subject {
            id: Some("subj-1".to_string()),
            name: Some("VPN Gateway".to_string()),
            subject_type: None,
        });
        event.object = Some(EventObject {
            id: None,
            name: Some("session-file".to_string()),
            object_type: None,
        });
        event.tags = vec!["vpn".to_string(), "login".to_string()];

        event.generate_search_text();
        let text = event.search_text.as_ref().unwrap();

        assert!(text.contains("auth.login.success"));
        assert!(text.contains("actor-1"));
        assert!(text.contains("Alice"));
        assert!(text.contains("subj-1"));
        assert!(text.contains("VPN Gateway"));
        assert!(text.contains("session-file"));
        assert!(text.contains("src-001"));
        assert!(text.contains("firewall"));
        assert!(text.contains("perimeter-fw"));
        assert!(text.contains("vpn"));
        assert!(text.contains("login"));
    }

    #[test]
    fn serialization_round_trip() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("u-42".to_string()),
            name: None,
            actor_type: Some("user".to_string()),
        });
        event.tags = vec!["test".to_string()];

        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: ForensicEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.id, event.id);
        assert_eq!(deserialized.event_type, event.event_type);
        assert_eq!(deserialized.severity, event.severity);
        assert_eq!(
            deserialized.actor.as_ref().unwrap().id,
            Some("u-42".to_string())
        );
        assert_eq!(deserialized.tags, vec!["test".to_string()]);
    }

    #[test]
    fn entity_serialization_round_trip() {
        let now = Utc::now();
        let entity = Entity {
            id: Uuid::now_v7(),
            entity_type: "user".to_string(),
            identifier: "alice@example.com".to_string(),
            display_name: Some("Alice".to_string()),
            first_seen_at: now,
            last_seen_at: now,
            event_count: 42,
            attributes: serde_json::json!({"department": "engineering"}),
        };

        let json = serde_json::to_string(&entity).expect("serialize");
        let parsed: Entity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, entity.id);
        assert_eq!(parsed.entity_type, "user");
        assert_eq!(parsed.identifier, "alice@example.com");
        assert_eq!(parsed.event_count, 42);
    }

    #[test]
    fn entity_relationship_serialization_round_trip() {
        let now = Utc::now();
        let rel = EntityRelationship {
            id: Uuid::now_v7(),
            source_entity: Uuid::now_v7(),
            target_entity: Uuid::now_v7(),
            relationship: "used_device".to_string(),
            first_seen_at: now,
            last_seen_at: now,
            event_count: 5,
            sample_event_id: Some(Uuid::now_v7()),
        };

        let json = serde_json::to_string(&rel).expect("serialize");
        let parsed: EntityRelationship = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, rel.id);
        assert_eq!(parsed.relationship, "used_device");
        assert_eq!(parsed.sample_event_id, rel.sample_event_id);
    }

    #[test]
    fn entity_event_serialization_round_trip() {
        let now = Utc::now();
        let ee = EntityEvent {
            entity_id: Uuid::now_v7(),
            event_id: Uuid::now_v7(),
            role: "actor".to_string(),
            occurred_at: now,
        };

        let json = serde_json::to_string(&ee).expect("serialize");
        let parsed: EntityEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.entity_id, ee.entity_id);
        assert_eq!(parsed.role, "actor");
    }

    #[test]
    fn correlation_key_type_serde() {
        let key = CorrelationKey {
            key_type: CorrelationKeyType::Custom("tenant".to_string()),
            key_value: "t-100".to_string(),
        };
        let json = serde_json::to_string(&key).expect("serialize");
        let parsed: CorrelationKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            parsed.key_type,
            CorrelationKeyType::Custom("tenant".to_string())
        );
        assert_eq!(parsed.key_value, "t-100");

        // Standard variants use snake_case
        let ip_key = CorrelationKey {
            key_type: CorrelationKeyType::Ip,
            key_value: "10.0.0.1".to_string(),
        };
        let json = serde_json::to_string(&ip_key).expect("serialize");
        assert!(json.contains("\"ip\""));
    }

    #[test]
    fn raw_event_serde() {
        let raw = RawEvent {
            id: Uuid::now_v7(),
            content: b"test payload".to_vec(),
            content_hash: "abc123".to_string(),
            content_type: "text/plain".to_string(),
            source_id: "s1".to_string(),
            source_type: "test".to_string(),
            source_name: None,
            received_at: Utc::now(),
            parser_id: None,
            byte_size: 12,
        };
        let json = serde_json::to_string(&raw).expect("serialize");
        let parsed: RawEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, raw.id);
        assert_eq!(parsed.byte_size, 12);
    }
}
