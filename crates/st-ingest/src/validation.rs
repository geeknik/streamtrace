//! Input validation for the ingestion pipeline.
//!
//! Enforces size and batch limits before any parsing or storage occurs.
//! All validation functions fail closed with [`StError`].

use st_common::error::StError;

/// Validate that the request body does not exceed the configured maximum.
///
/// Returns `StError::PayloadTooLarge` if the body exceeds `max_bytes`.
pub fn validate_body_size(body: &[u8], max_bytes: usize) -> Result<(), StError> {
    if body.len() > max_bytes {
        tracing::warn!(
            body_size = body.len(),
            max_bytes,
            "request body exceeds size limit"
        );
        return Err(StError::PayloadTooLarge {
            max_bytes,
            actual_bytes: body.len(),
        });
    }
    Ok(())
}

/// Validate that the batch event count does not exceed the configured maximum.
///
/// Returns `StError::Validation` if `count` exceeds `max_batch`.
pub fn validate_batch_size(count: usize, max_batch: usize) -> Result<(), StError> {
    if count > max_batch {
        tracing::warn!(batch_size = count, max_batch, "batch size exceeds limit");
        return Err(StError::Validation(format!(
            "batch contains {count} events, maximum is {max_batch}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_body_size ---

    #[test]
    fn body_size_normal() {
        let body = vec![0u8; 100];
        assert!(validate_body_size(&body, 1024).is_ok());
    }

    #[test]
    fn body_size_at_limit() {
        let body = vec![0u8; 1024];
        assert!(validate_body_size(&body, 1024).is_ok());
    }

    #[test]
    fn body_size_over_limit() {
        let body = vec![0u8; 1025];
        let result = validate_body_size(&body, 1024);
        assert!(result.is_err());
        match result.unwrap_err() {
            StError::PayloadTooLarge {
                max_bytes,
                actual_bytes,
            } => {
                assert_eq!(max_bytes, 1024);
                assert_eq!(actual_bytes, 1025);
            }
            other => panic!("expected PayloadTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn body_size_empty_body() {
        let body: &[u8] = &[];
        assert!(validate_body_size(body, 1024).is_ok());
    }

    #[test]
    fn body_size_zero_limit_rejects_nonempty() {
        let body = vec![1u8];
        assert!(validate_body_size(&body, 0).is_err());
    }

    #[test]
    fn body_size_zero_limit_accepts_empty() {
        let body: &[u8] = &[];
        assert!(validate_body_size(body, 0).is_ok());
    }

    // --- validate_batch_size ---

    #[test]
    fn batch_size_normal() {
        assert!(validate_batch_size(5, 100).is_ok());
    }

    #[test]
    fn batch_size_at_limit() {
        assert!(validate_batch_size(100, 100).is_ok());
    }

    #[test]
    fn batch_size_over_limit() {
        let result = validate_batch_size(101, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            StError::Validation(msg) => {
                assert!(msg.contains("101"));
                assert!(msg.contains("100"));
            }
            other => panic!("expected Validation, got: {other:?}"),
        }
    }

    #[test]
    fn batch_size_zero_is_ok() {
        assert!(validate_batch_size(0, 100).is_ok());
    }

    #[test]
    fn batch_size_zero_limit_rejects_any() {
        assert!(validate_batch_size(1, 0).is_err());
    }
}
