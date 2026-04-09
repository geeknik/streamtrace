//! Filter construction and validation helpers.
//!
//! Provides sanitization and validation functions for search and
//! timeline query parameters. All functions operate on untrusted
//! input and fail closed on invalid data.

use chrono::{DateTime, Utc};
use st_common::error::{StError, StResult};

/// Maximum allowed length for a search query string in bytes.
const MAX_SEARCH_QUERY_LENGTH: usize = 500;

/// Sanitizes a search query string.
///
/// - Trims leading and trailing whitespace.
/// - Truncates to [`MAX_SEARCH_QUERY_LENGTH`] bytes on a char boundary.
///
/// Returns the sanitized string (may be empty).
pub fn sanitize_search_query(q: &str) -> String {
    let trimmed = q.trim();
    if trimmed.len() <= MAX_SEARCH_QUERY_LENGTH {
        trimmed.to_string()
    } else {
        // Truncate on a valid char boundary.
        let mut end = MAX_SEARCH_QUERY_LENGTH;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        trimmed[..end].to_string()
    }
}

/// Validates that `start` is strictly before `end`.
///
/// Returns `StError::Validation` if the range is invalid.
pub fn validate_time_range(start: &DateTime<Utc>, end: &DateTime<Utc>) -> StResult<()> {
    if start >= end {
        return Err(StError::Validation(
            "start must be strictly before end".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ---- sanitize_search_query ----

    #[test]
    fn sanitize_trims_whitespace() {
        assert_eq!(sanitize_search_query("  hello  "), "hello");
    }

    #[test]
    fn sanitize_empty_returns_empty() {
        assert_eq!(sanitize_search_query(""), "");
        assert_eq!(sanitize_search_query("   "), "");
    }

    #[test]
    fn sanitize_truncates_long_input() {
        let long = "a".repeat(600);
        let result = sanitize_search_query(&long);
        assert_eq!(result.len(), MAX_SEARCH_QUERY_LENGTH);
    }

    #[test]
    fn sanitize_preserves_short_input() {
        let short = "short query";
        assert_eq!(sanitize_search_query(short), short);
    }

    #[test]
    fn sanitize_truncates_on_char_boundary() {
        // Multi-byte character at the boundary.
        // U+00E9 (e-acute) is 2 bytes in UTF-8.
        let mut input = "a".repeat(499);
        input.push('\u{00E9}'); // total 501 bytes
        let result = sanitize_search_query(&input);
        assert!(result.len() <= MAX_SEARCH_QUERY_LENGTH);
        assert!(result.is_char_boundary(result.len()));
        // Should have truncated the multi-byte char.
        assert_eq!(result.len(), 499);
    }

    #[test]
    fn sanitize_exact_limit_length() {
        let exact = "b".repeat(MAX_SEARCH_QUERY_LENGTH);
        let result = sanitize_search_query(&exact);
        assert_eq!(result.len(), MAX_SEARCH_QUERY_LENGTH);
        assert_eq!(result, exact);
    }

    // ---- validate_time_range ----

    #[test]
    fn valid_range_accepted() {
        let now = Utc::now();
        let start = now - Duration::hours(1);
        assert!(validate_time_range(&start, &now).is_ok());
    }

    #[test]
    fn inverted_range_rejected() {
        let now = Utc::now();
        let start = now + Duration::hours(1);
        assert!(validate_time_range(&start, &now).is_err());
    }

    #[test]
    fn equal_timestamps_rejected() {
        let now = Utc::now();
        assert!(validate_time_range(&now, &now).is_err());
    }

    #[test]
    fn error_message_is_descriptive() {
        let now = Utc::now();
        let err = validate_time_range(&now, &now).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("start must be strictly before end"),
            "unexpected error message: {msg}"
        );
    }
}
