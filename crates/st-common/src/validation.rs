//! Input validation helpers.
//!
//! These functions enforce basic constraints on untrusted input before
//! it reaches business logic or the database layer. All failures are
//! returned as [`StError::Validation`].

use chrono::{DateTime, Utc};

use crate::error::{StError, StResult};

/// Validates that a string field is not empty after trimming whitespace.
pub fn validate_not_empty(field: &str, value: &str) -> StResult<()> {
    if value.trim().is_empty() {
        return Err(StError::Validation(format!("{field} must not be empty")));
    }
    Ok(())
}

/// Validates that a string field does not exceed `max` bytes in length.
pub fn validate_max_length(field: &str, value: &str, max: usize) -> StResult<()> {
    if value.len() > max {
        return Err(StError::Validation(format!(
            "{field} exceeds maximum length of {max} bytes (actual: {} bytes)",
            value.len()
        )));
    }
    Ok(())
}

/// Validates that a timestamp is not in the future (with a 60-second tolerance
/// to accommodate clock skew).
pub fn validate_timestamp_not_future(field: &str, ts: &DateTime<Utc>) -> StResult<()> {
    let now_plus_skew = Utc::now() + chrono::Duration::seconds(60);
    if *ts > now_plus_skew {
        return Err(StError::Validation(format!(
            "{field} must not be in the future"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn not_empty_rejects_empty() {
        let result = validate_not_empty("name", "");
        assert!(result.is_err());
    }

    #[test]
    fn not_empty_rejects_whitespace() {
        let result = validate_not_empty("name", "   ");
        assert!(result.is_err());
    }

    #[test]
    fn not_empty_accepts_value() {
        let result = validate_not_empty("name", "alice");
        assert!(result.is_ok());
    }

    #[test]
    fn max_length_accepts_within_limit() {
        let result = validate_max_length("field", "short", 100);
        assert!(result.is_ok());
    }

    #[test]
    fn max_length_accepts_exact_limit() {
        let value = "a".repeat(50);
        let result = validate_max_length("field", &value, 50);
        assert!(result.is_ok());
    }

    #[test]
    fn max_length_rejects_over_limit() {
        let value = "a".repeat(51);
        let result = validate_max_length("field", &value, 50);
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_accepts_past() {
        let past = Utc::now() - Duration::hours(1);
        let result = validate_timestamp_not_future("occurred_at", &past);
        assert!(result.is_ok());
    }

    #[test]
    fn timestamp_accepts_now() {
        let now = Utc::now();
        let result = validate_timestamp_not_future("occurred_at", &now);
        assert!(result.is_ok());
    }

    #[test]
    fn timestamp_rejects_far_future() {
        let future = Utc::now() + Duration::hours(24);
        let result = validate_timestamp_not_future("occurred_at", &future);
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_accepts_slight_future_within_skew() {
        let slight_future = Utc::now() + Duration::seconds(30);
        let result = validate_timestamp_not_future("occurred_at", &slight_future);
        assert!(result.is_ok());
    }

    #[test]
    fn error_messages_include_field_name() {
        let err = validate_not_empty("source_id", "").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("source_id"), "error should name the field: {msg}");
    }
}
