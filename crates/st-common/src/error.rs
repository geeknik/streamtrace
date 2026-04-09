//! Error types for StreamTrace.
//!
//! All crates return [`StError`] through the [`StResult`] type alias,
//! ensuring consistent error handling across trust boundaries.

use std::fmt;

/// Unified error type for all StreamTrace operations.
#[derive(Debug, thiserror::Error)]
pub enum StError {
    /// Database operation failed.
    #[error("database error: {0}")]
    Database(String),

    /// Input validation failed.
    #[error("validation error: {0}")]
    Validation(String),

    /// Requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Authentication failed.
    #[error("authentication error: {0}")]
    Authentication(String),

    /// Authorization denied.
    #[error("authorization error: {0}")]
    Authorization(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimit,

    /// Request payload exceeds the configured maximum.
    #[error("payload too large: {actual_bytes} bytes exceeds limit of {max_bytes} bytes")]
    PayloadTooLarge {
        /// Maximum allowed payload size in bytes.
        max_bytes: usize,
        /// Actual payload size in bytes.
        actual_bytes: usize,
    },

    /// Event or data parsing failed.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Internal server error. Details are logged but not exposed to clients.
    #[error("internal error: {0}")]
    Internal(String),
}

impl StError {
    /// Returns a generic, safe error message suitable for external responses.
    ///
    /// Internal details are never leaked to callers.
    pub fn external_message(&self) -> &'static str {
        match self {
            Self::Database(_) => "a database error occurred",
            Self::Validation(_) => "validation failed",
            Self::NotFound(_) => "resource not found",
            Self::Authentication(_) => "authentication failed",
            Self::Authorization(_) => "access denied",
            Self::RateLimit => "rate limit exceeded",
            Self::PayloadTooLarge { .. } => "payload too large",
            Self::ParseError(_) => "failed to parse input",
            Self::Internal(_) => "an internal error occurred",
        }
    }
}

/// Convenience result type used throughout StreamTrace.
pub type StResult<T> = Result<T, StError>;

impl fmt::Display for StErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => write!(f, "database"),
            Self::Validation => write!(f, "validation"),
            Self::NotFound => write!(f, "not_found"),
            Self::Authentication => write!(f, "authentication"),
            Self::Authorization => write!(f, "authorization"),
            Self::RateLimit => write!(f, "rate_limit"),
            Self::PayloadTooLarge => write!(f, "payload_too_large"),
            Self::ParseError => write!(f, "parse_error"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

/// Classification of error variants, useful for metrics and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StErrorKind {
    /// Database error.
    Database,
    /// Validation error.
    Validation,
    /// Not found error.
    NotFound,
    /// Authentication error.
    Authentication,
    /// Authorization error.
    Authorization,
    /// Rate limit error.
    RateLimit,
    /// Payload too large error.
    PayloadTooLarge,
    /// Parse error.
    ParseError,
    /// Internal error.
    Internal,
}

impl StError {
    /// Returns the error kind for metrics and structured logging.
    pub fn kind(&self) -> StErrorKind {
        match self {
            Self::Database(_) => StErrorKind::Database,
            Self::Validation(_) => StErrorKind::Validation,
            Self::NotFound(_) => StErrorKind::NotFound,
            Self::Authentication(_) => StErrorKind::Authentication,
            Self::Authorization(_) => StErrorKind::Authorization,
            Self::RateLimit => StErrorKind::RateLimit,
            Self::PayloadTooLarge { .. } => StErrorKind::PayloadTooLarge,
            Self::ParseError(_) => StErrorKind::ParseError,
            Self::Internal(_) => StErrorKind::Internal,
        }
    }
}
