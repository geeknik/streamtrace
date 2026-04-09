//! Event linking helpers.
//!
//! Provides human-readable descriptions of why events are correlated.
//! The actual cross-event linking is performed via SQL joins in
//! `st-store::correlation_keys`.

use st_common::event::{CorrelationKey, CorrelationKeyType};

/// Describe which correlation key types are present in the given set.
///
/// Returns a human-readable summary string suitable for API responses
/// explaining why events are grouped together.
///
/// Returns `"no correlation keys"` when the slice is empty.
pub fn describe_correlation(keys: &[CorrelationKey]) -> String {
    if keys.is_empty() {
        return "no correlation keys".to_string();
    }

    let mut type_labels: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for key in keys {
        let label = key_type_label(&key.key_type);
        if seen.insert(label.clone()) {
            type_labels.push(label);
        }
    }

    format!("correlated by: {}", type_labels.join(", "))
}

/// Returns a human-readable label for a correlation key type.
fn key_type_label(kt: &CorrelationKeyType) -> String {
    match kt {
        CorrelationKeyType::Identity => "identity".to_string(),
        CorrelationKeyType::Session => "session".to_string(),
        CorrelationKeyType::Token => "token".to_string(),
        CorrelationKeyType::Ip => "IP address".to_string(),
        CorrelationKeyType::Device => "device".to_string(),
        CorrelationKeyType::Host => "hostname".to_string(),
        CorrelationKeyType::Custom(name) => format!("custom({name})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_keys_produces_no_correlation_message() {
        assert_eq!(describe_correlation(&[]), "no correlation keys");
    }

    #[test]
    fn single_key_type() {
        let keys = vec![CorrelationKey {
            key_type: CorrelationKeyType::Ip,
            key_value: "10.0.0.1".to_string(),
        }];
        assert_eq!(describe_correlation(&keys), "correlated by: IP address");
    }

    #[test]
    fn multiple_distinct_key_types() {
        let keys = vec![
            CorrelationKey {
                key_type: CorrelationKeyType::Identity,
                key_value: "user-1".to_string(),
            },
            CorrelationKey {
                key_type: CorrelationKeyType::Ip,
                key_value: "10.0.0.1".to_string(),
            },
            CorrelationKey {
                key_type: CorrelationKeyType::Session,
                key_value: "sess-1".to_string(),
            },
        ];
        let desc = describe_correlation(&keys);
        assert!(desc.contains("identity"));
        assert!(desc.contains("IP address"));
        assert!(desc.contains("session"));
    }

    #[test]
    fn duplicate_key_types_are_deduplicated_in_description() {
        let keys = vec![
            CorrelationKey {
                key_type: CorrelationKeyType::Ip,
                key_value: "10.0.0.1".to_string(),
            },
            CorrelationKey {
                key_type: CorrelationKeyType::Ip,
                key_value: "10.0.0.2".to_string(),
            },
        ];
        let desc = describe_correlation(&keys);
        assert_eq!(desc, "correlated by: IP address");
    }

    #[test]
    fn custom_key_type_displayed() {
        let keys = vec![CorrelationKey {
            key_type: CorrelationKeyType::Custom("tenant".to_string()),
            key_value: "t-100".to_string(),
        }];
        assert_eq!(describe_correlation(&keys), "correlated by: custom(tenant)");
    }
}
