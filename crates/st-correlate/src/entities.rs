//! Entity extraction from forensic events.
//!
//! Examines the structured fields of a [`ForensicEvent`] and produces
//! observed entities and relationships that can be upserted into the
//! entity graph for resolution and link analysis.

use std::collections::HashSet;

use st_common::event::ForensicEvent;

/// Describes an entity observed in an event, ready for upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEntity {
    /// Entity classification: "user", "ip", "device", "host".
    pub entity_type: String,
    /// Canonical identifier for the entity.
    pub identifier: String,
    /// Optional human-readable label.
    pub display_name: Option<String>,
    /// Role this entity played in the event: "actor", "subject",
    /// "src_ip", "dst_ip", "device", "host".
    pub role: String,
}

/// Describes a relationship between two observed entities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRelationship {
    pub source_type: String,
    pub source_id: String,
    pub target_type: String,
    pub target_id: String,
    /// Relationship label -- must match the CHECK constraint in the
    /// `entity_relationships` table: "from_ip", "used_device", "hosted_on".
    pub relationship: String,
}

/// Extract entities and relationships from a forensic event.
///
/// Entities are deduplicated by `(entity_type, identifier)`.
/// Values that are empty or whitespace-only are skipped.
///
/// Relationships are produced only when both sides are present:
/// - actor + src_ip  -> "from_ip"
/// - actor + device  -> "used_device"
/// - actor + host    -> "hosted_on"
/// - device + src_ip -> "from_ip"
pub fn extract_entities(event: &ForensicEvent) -> (Vec<ObservedEntity>, Vec<ObservedRelationship>) {
    let mut entities: Vec<ObservedEntity> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    let mut push_entity = |etype: &str, id: &str, display: Option<&str>, role: &str| {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return;
        }
        let key = (etype.to_string(), trimmed.to_string());
        if seen.insert(key) {
            entities.push(ObservedEntity {
                entity_type: etype.to_string(),
                identifier: trimmed.to_string(),
                display_name: display
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
                role: role.to_string(),
            });
        }
    };

    // Actor -> user entity
    let mut actor_id: Option<String> = None;
    if let Some(ref actor) = event.actor {
        if let Some(ref id) = actor.id {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                actor_id = Some(trimmed.to_string());
                push_entity("user", trimmed, actor.name.as_deref(), "actor");
            }
        }
    }

    // Network src_ip -> ip entity
    let mut src_ip: Option<String> = None;
    if let Some(ref network) = event.network {
        if let Some(ref ip) = network.src_ip {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                src_ip = Some(trimmed.to_string());
                push_entity("ip", trimmed, None, "src_ip");
            }
        }
        // Network dst_ip -> ip entity
        if let Some(ref ip) = network.dst_ip {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                push_entity("ip", trimmed, None, "dst_ip");
            }
        }
    }

    // Device -> device entity
    let mut device_id: Option<String> = None;
    if let Some(ref device) = event.device {
        if let Some(ref did) = device.device_id {
            let trimmed = did.trim();
            if !trimmed.is_empty() {
                device_id = Some(trimmed.to_string());
                push_entity("device", trimmed, device.device_name.as_deref(), "device");
            }
        }
        // Hostname -> host entity
        if let Some(ref hn) = device.hostname {
            let trimmed = hn.trim();
            if !trimmed.is_empty() {
                push_entity("host", trimmed, None, "host");
            }
        }
    }

    // Build relationships (only when both sides are present).
    let mut relationships: Vec<ObservedRelationship> = Vec::new();
    let mut host_id: Option<String> = None;
    if let Some(ref device) = event.device {
        if let Some(ref hn) = device.hostname {
            let trimmed = hn.trim();
            if !trimmed.is_empty() {
                host_id = Some(trimmed.to_string());
            }
        }
    }

    // actor + src_ip -> from_ip
    if let (Some(ref uid), Some(ref ip)) = (&actor_id, &src_ip) {
        relationships.push(ObservedRelationship {
            source_type: "user".to_string(),
            source_id: uid.clone(),
            target_type: "ip".to_string(),
            target_id: ip.clone(),
            relationship: "from_ip".to_string(),
        });
    }

    // actor + device -> used_device
    if let (Some(ref uid), Some(ref did)) = (&actor_id, &device_id) {
        relationships.push(ObservedRelationship {
            source_type: "user".to_string(),
            source_id: uid.clone(),
            target_type: "device".to_string(),
            target_id: did.clone(),
            relationship: "used_device".to_string(),
        });
    }

    // actor + host -> hosted_on  (maps to DB constraint value "hosted_on")
    if let (Some(ref uid), Some(ref hid)) = (&actor_id, &host_id) {
        relationships.push(ObservedRelationship {
            source_type: "user".to_string(),
            source_id: uid.clone(),
            target_type: "host".to_string(),
            target_id: hid.clone(),
            relationship: "hosted_on".to_string(),
        });
    }

    // device + src_ip -> from_ip
    if let (Some(ref did), Some(ref ip)) = (&device_id, &src_ip) {
        relationships.push(ObservedRelationship {
            source_type: "device".to_string(),
            source_id: did.clone(),
            target_type: "ip".to_string(),
            target_id: ip.clone(),
            relationship: "from_ip".to_string(),
        });
    }

    (entities, relationships)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use st_common::event::{
        Actor, DeviceContext, ForensicEvent, NetworkContext, SourceAttribution,
    };
    use st_common::types::Severity;

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
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            "auth.login.success".to_string(),
            Severity::Medium,
            now,
            now,
            make_source(),
        )
    }

    #[test]
    fn event_with_all_fields_extracts_all_entities() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("user-42".to_string()),
            name: Some("Alice".to_string()),
            actor_type: Some("user".to_string()),
        });
        event.network = Some(NetworkContext {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("192.168.1.1".to_string()),
            src_port: Some(12345),
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
        });
        event.device = Some(DeviceContext {
            device_id: Some("dev-99".to_string()),
            device_name: Some("workstation-a".to_string()),
            device_type: Some("workstation".to_string()),
            hostname: Some("ws-a.corp.local".to_string()),
        });

        let (entities, relationships) = extract_entities(&event);

        // user, src_ip, dst_ip, device, host = 5 entities
        assert_eq!(entities.len(), 5);

        // user entity
        let user = entities.iter().find(|e| e.entity_type == "user").unwrap();
        assert_eq!(user.identifier, "user-42");
        assert_eq!(user.display_name.as_deref(), Some("Alice"));
        assert_eq!(user.role, "actor");

        // src_ip entity
        let src = entities
            .iter()
            .find(|e| e.entity_type == "ip" && e.role == "src_ip")
            .unwrap();
        assert_eq!(src.identifier, "10.0.0.1");

        // dst_ip entity
        let dst = entities
            .iter()
            .find(|e| e.entity_type == "ip" && e.role == "dst_ip")
            .unwrap();
        assert_eq!(dst.identifier, "192.168.1.1");

        // device entity
        let dev = entities.iter().find(|e| e.entity_type == "device").unwrap();
        assert_eq!(dev.identifier, "dev-99");
        assert_eq!(dev.display_name.as_deref(), Some("workstation-a"));

        // host entity
        let host = entities.iter().find(|e| e.entity_type == "host").unwrap();
        assert_eq!(host.identifier, "ws-a.corp.local");

        // Relationships: actor+src_ip, actor+device, actor+host, device+src_ip = 4
        assert_eq!(relationships.len(), 4);

        assert!(relationships.iter().any(|r| r.source_type == "user"
            && r.source_id == "user-42"
            && r.target_type == "ip"
            && r.target_id == "10.0.0.1"
            && r.relationship == "from_ip"));

        assert!(relationships.iter().any(|r| r.source_type == "user"
            && r.source_id == "user-42"
            && r.target_type == "device"
            && r.target_id == "dev-99"
            && r.relationship == "used_device"));

        assert!(relationships.iter().any(|r| r.source_type == "user"
            && r.source_id == "user-42"
            && r.target_type == "host"
            && r.target_id == "ws-a.corp.local"
            && r.relationship == "hosted_on"));

        assert!(relationships.iter().any(|r| r.source_type == "device"
            && r.source_id == "dev-99"
            && r.target_type == "ip"
            && r.target_id == "10.0.0.1"
            && r.relationship == "from_ip"));
    }

    #[test]
    fn event_with_partial_fields_extracts_subset() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("user-7".to_string()),
            name: None,
            actor_type: None,
        });
        // No network, no device

        let (entities, relationships) = extract_entities(&event);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity_type, "user");
        assert_eq!(entities[0].identifier, "user-7");
        assert!(entities[0].display_name.is_none());

        // No relationships since only one entity side exists
        assert!(relationships.is_empty());
    }

    #[test]
    fn event_with_no_entities_returns_empty() {
        let event = make_event();
        let (entities, relationships) = extract_entities(&event);
        assert!(entities.is_empty());
        assert!(relationships.is_empty());
    }

    #[test]
    fn deduplication_by_type_and_identifier() {
        let mut event = make_event();
        // src_ip == dst_ip => should produce only one ip entity
        event.network = Some(NetworkContext {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("10.0.0.1".to_string()),
            src_port: None,
            dst_port: None,
            protocol: None,
        });

        let (entities, _) = extract_entities(&event);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity_type, "ip");
        assert_eq!(entities[0].identifier, "10.0.0.1");
    }

    #[test]
    fn empty_and_whitespace_values_are_skipped() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("".to_string()),
            name: None,
            actor_type: None,
        });
        event.network = Some(NetworkContext {
            src_ip: Some("   ".to_string()),
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
        });
        event.device = Some(DeviceContext {
            device_id: Some("  ".to_string()),
            device_name: None,
            device_type: None,
            hostname: Some("".to_string()),
        });

        let (entities, relationships) = extract_entities(&event);
        assert!(entities.is_empty());
        assert!(relationships.is_empty());
    }

    #[test]
    fn device_and_src_ip_without_actor_still_creates_relationship() {
        let mut event = make_event();
        event.device = Some(DeviceContext {
            device_id: Some("dev-1".to_string()),
            device_name: None,
            device_type: None,
            hostname: None,
        });
        event.network = Some(NetworkContext {
            src_ip: Some("10.0.0.5".to_string()),
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
        });

        let (entities, relationships) = extract_entities(&event);
        assert_eq!(entities.len(), 2);
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].relationship, "from_ip");
        assert_eq!(relationships[0].source_type, "device");
        assert_eq!(relationships[0].target_type, "ip");
    }

    #[test]
    fn display_name_whitespace_only_is_none() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("user-1".to_string()),
            name: Some("   ".to_string()),
            actor_type: None,
        });

        let (entities, _) = extract_entities(&event);
        assert_eq!(entities.len(), 1);
        assert!(entities[0].display_name.is_none());
    }
}
