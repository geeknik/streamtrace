//! Correlation key extraction from forensic events.
//!
//! Examines the structured fields of a [`ForensicEvent`] and produces
//! a deduplicated set of [`CorrelationKey`]s that can be stored in the
//! correlation index for cross-event linking.

use std::collections::HashSet;

use st_common::event::{CorrelationKey, CorrelationKeyType, ForensicEvent};

/// Extract all correlation keys from a forensic event.
///
/// Keys are extracted from:
/// - `actor.id` -> [`CorrelationKeyType::Identity`]
/// - `network.src_ip` -> [`CorrelationKeyType::Ip`]
/// - `network.dst_ip` -> [`CorrelationKeyType::Ip`]
/// - `device.device_id` -> [`CorrelationKeyType::Device`]
/// - `device.hostname` -> [`CorrelationKeyType::Host`]
/// - `custom_fields.session_id` or `custom_fields.session` -> [`CorrelationKeyType::Session`]
/// - `custom_fields.token` or `custom_fields.access_token` -> [`CorrelationKeyType::Token`]
///
/// Empty/None values are skipped. Results are deduplicated by `(key_type, key_value)`.
pub fn extract_correlation_keys(event: &ForensicEvent) -> Vec<CorrelationKey> {
    let mut seen: HashSet<(CorrelationKeyType, String)> = HashSet::new();
    let mut keys: Vec<CorrelationKey> = Vec::new();

    let mut push = |key_type: CorrelationKeyType, value: &str| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        let pair = (key_type.clone(), trimmed.to_string());
        if seen.insert(pair) {
            keys.push(CorrelationKey {
                key_type,
                key_value: trimmed.to_string(),
            });
        }
    };

    // Actor identity
    if let Some(ref actor) = event.actor {
        if let Some(ref id) = actor.id {
            push(CorrelationKeyType::Identity, id);
        }
    }

    // Network IPs
    if let Some(ref network) = event.network {
        if let Some(ref src_ip) = network.src_ip {
            push(CorrelationKeyType::Ip, src_ip);
        }
        if let Some(ref dst_ip) = network.dst_ip {
            push(CorrelationKeyType::Ip, dst_ip);
        }
    }

    // Device
    if let Some(ref device) = event.device {
        if let Some(ref device_id) = device.device_id {
            push(CorrelationKeyType::Device, device_id);
        }
        if let Some(ref hostname) = device.hostname {
            push(CorrelationKeyType::Host, hostname);
        }
    }

    // Custom fields: session
    extract_custom_string(&event.custom_fields, "session_id", |v| {
        push(CorrelationKeyType::Session, v);
    });
    extract_custom_string(&event.custom_fields, "session", |v| {
        push(CorrelationKeyType::Session, v);
    });

    // Custom fields: token
    extract_custom_string(&event.custom_fields, "token", |v| {
        push(CorrelationKeyType::Token, v);
    });
    extract_custom_string(&event.custom_fields, "access_token", |v| {
        push(CorrelationKeyType::Token, v);
    });

    keys
}

/// Extracts a string value from a JSON object by key, passing it to
/// the callback if present and non-empty.
fn extract_custom_string(
    custom_fields: &serde_json::Value,
    field_name: &str,
    mut callback: impl FnMut(&str),
) {
    if let serde_json::Value::Object(map) = custom_fields {
        if let Some(serde_json::Value::String(val)) = map.get(field_name) {
            if !val.trim().is_empty() {
                callback(val);
            }
        }
    }
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
    fn event_with_all_fields_extracts_all_key_types() {
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
        event.custom_fields = serde_json::json!({
            "session_id": "sess-abc",
            "token": "tok-xyz"
        });

        let keys = extract_correlation_keys(&event);

        // Expect: Identity(user-42), Ip(10.0.0.1), Ip(192.168.1.1),
        //         Device(dev-99), Host(ws-a.corp.local),
        //         Session(sess-abc), Token(tok-xyz)
        assert_eq!(keys.len(), 7);

        assert!(keys.iter().any(|k| k.key_type == CorrelationKeyType::Identity
            && k.key_value == "user-42"));
        assert!(keys
            .iter()
            .any(|k| k.key_type == CorrelationKeyType::Ip && k.key_value == "10.0.0.1"));
        assert!(keys
            .iter()
            .any(|k| k.key_type == CorrelationKeyType::Ip && k.key_value == "192.168.1.1"));
        assert!(keys
            .iter()
            .any(|k| k.key_type == CorrelationKeyType::Device && k.key_value == "dev-99"));
        assert!(keys.iter().any(
            |k| k.key_type == CorrelationKeyType::Host && k.key_value == "ws-a.corp.local"
        ));
        assert!(keys
            .iter()
            .any(|k| k.key_type == CorrelationKeyType::Session && k.key_value == "sess-abc"));
        assert!(keys
            .iter()
            .any(|k| k.key_type == CorrelationKeyType::Token && k.key_value == "tok-xyz"));
    }

    #[test]
    fn event_with_only_actor_extracts_identity_key() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("user-7".to_string()),
            name: None,
            actor_type: None,
        });

        let keys = extract_correlation_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, CorrelationKeyType::Identity);
        assert_eq!(keys[0].key_value, "user-7");
    }

    #[test]
    fn event_with_no_correlatable_fields_returns_empty() {
        let event = make_event();
        let keys = extract_correlation_keys(&event);
        assert!(keys.is_empty());
    }

    #[test]
    fn duplicate_ip_values_are_deduplicated() {
        let mut event = make_event();
        event.network = Some(NetworkContext {
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: Some("10.0.0.1".to_string()),
            src_port: None,
            dst_port: None,
            protocol: None,
        });

        let keys = extract_correlation_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, CorrelationKeyType::Ip);
        assert_eq!(keys[0].key_value, "10.0.0.1");
    }

    #[test]
    fn custom_field_session_extraction() {
        let mut event = make_event();
        event.custom_fields = serde_json::json!({
            "session": "sess-from-session-field"
        });

        let keys = extract_correlation_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, CorrelationKeyType::Session);
        assert_eq!(keys[0].key_value, "sess-from-session-field");
    }

    #[test]
    fn custom_field_access_token_extraction() {
        let mut event = make_event();
        event.custom_fields = serde_json::json!({
            "access_token": "at-12345"
        });

        let keys = extract_correlation_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, CorrelationKeyType::Token);
        assert_eq!(keys[0].key_value, "at-12345");
    }

    #[test]
    fn session_id_and_session_are_deduplicated_if_same_value() {
        let mut event = make_event();
        event.custom_fields = serde_json::json!({
            "session_id": "same-session",
            "session": "same-session"
        });

        let keys = extract_correlation_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, CorrelationKeyType::Session);
        assert_eq!(keys[0].key_value, "same-session");
    }

    #[test]
    fn session_id_and_session_both_kept_if_different() {
        let mut event = make_event();
        event.custom_fields = serde_json::json!({
            "session_id": "sess-a",
            "session": "sess-b"
        });

        let keys = extract_correlation_keys(&event);
        let session_keys: Vec<_> = keys
            .iter()
            .filter(|k| k.key_type == CorrelationKeyType::Session)
            .collect();
        assert_eq!(session_keys.len(), 2);
    }

    #[test]
    fn empty_string_values_are_skipped() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("".to_string()),
            name: None,
            actor_type: None,
        });
        event.custom_fields = serde_json::json!({
            "session_id": "  ",
            "token": ""
        });

        let keys = extract_correlation_keys(&event);
        assert!(keys.is_empty());
    }

    #[test]
    fn whitespace_only_values_are_skipped() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: Some("   ".to_string()),
            name: None,
            actor_type: None,
        });

        let keys = extract_correlation_keys(&event);
        assert!(keys.is_empty());
    }

    #[test]
    fn actor_without_id_produces_no_key() {
        let mut event = make_event();
        event.actor = Some(Actor {
            id: None,
            name: Some("Alice".to_string()),
            actor_type: Some("user".to_string()),
        });

        let keys = extract_correlation_keys(&event);
        assert!(keys.is_empty());
    }

    #[test]
    fn non_string_custom_fields_are_ignored() {
        let mut event = make_event();
        event.custom_fields = serde_json::json!({
            "session_id": 12345,
            "token": true
        });

        let keys = extract_correlation_keys(&event);
        assert!(keys.is_empty());
    }
}
