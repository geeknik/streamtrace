//! Map [`StError`] to axum HTTP responses.
//!
//! Because of Rust's orphan rules, we cannot implement `IntoResponse`
//! directly on `StError` (defined in `st-common`). Instead, we provide
//! an [`ApiError`] newtype that wraps `StError` and implements
//! `IntoResponse`.
//!
//! Internal error details are never exposed to clients. Every error
//! response follows the structure:
//!
//! ```json
//! { "error": { "code": "VALIDATION_FAILED", "message": "..." } }
//! ```

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use st_common::error::StError;

/// Newtype wrapper around [`StError`] that implements [`IntoResponse`].
///
/// Handlers return `Result<impl IntoResponse, ApiError>` to get automatic
/// HTTP error responses.
#[derive(Debug)]
pub struct ApiError(pub StError);

impl From<StError> for ApiError {
    fn from(err: StError) -> Self {
        Self(err)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maps an [`StError`] variant to the appropriate HTTP status code.
fn status_code(err: &StError) -> StatusCode {
    match err {
        StError::Validation(_) => StatusCode::BAD_REQUEST,
        StError::NotFound(_) => StatusCode::NOT_FOUND,
        StError::Authentication(_) => StatusCode::UNAUTHORIZED,
        StError::Authorization(_) => StatusCode::FORBIDDEN,
        StError::RateLimit => StatusCode::TOO_MANY_REQUESTS,
        StError::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        StError::ParseError(_) => StatusCode::BAD_REQUEST,
        StError::Database(_) | StError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Maps an [`StError`] variant to a stable, machine-readable error code.
fn error_code(err: &StError) -> &'static str {
    match err {
        StError::Validation(_) => "VALIDATION_FAILED",
        StError::NotFound(_) => "NOT_FOUND",
        StError::Authentication(_) => "AUTHENTICATION_FAILED",
        StError::Authorization(_) => "ACCESS_DENIED",
        StError::RateLimit => "RATE_LIMIT_EXCEEDED",
        StError::PayloadTooLarge { .. } => "PAYLOAD_TOO_LARGE",
        StError::ParseError(_) => "PARSE_ERROR",
        StError::Database(_) => "INTERNAL_ERROR",
        StError::Internal(_) => "INTERNAL_ERROR",
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let err = &self.0;

        // Log internal errors at error level; client-facing errors at warn.
        match err {
            StError::Database(detail) => {
                tracing::error!(error_kind = "database", detail = %detail, "database error");
            }
            StError::Internal(detail) => {
                tracing::error!(error_kind = "internal", detail = %detail, "internal error");
            }
            StError::Authentication(_) => {
                tracing::warn!(error_kind = "authentication", "authentication failure");
            }
            StError::Authorization(_) => {
                tracing::warn!(error_kind = "authorization", "authorization failure");
            }
            StError::RateLimit => {
                tracing::warn!(error_kind = "rate_limit", "rate limit exceeded");
            }
            _ => {
                tracing::debug!(error_kind = %err.kind(), "client error");
            }
        }

        let status = status_code(err);
        let code = error_code(err);
        // Use the safe external message -- never expose internal details.
        let message = err.external_message();

        let body = json!({
            "error": {
                "code": code,
                "message": message,
            }
        });

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn response_body(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn validation_error_returns_400() {
        let err = ApiError(StError::Validation("bad field".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
        // Must not leak internal detail
        assert!(!body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bad field"));
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let err = ApiError(StError::NotFound("event abc".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn auth_error_returns_401() {
        let err = ApiError(StError::Authentication("wrong token".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        // Must not leak the internal detail
        assert!(!body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("wrong token"));
    }

    #[tokio::test]
    async fn authorization_returns_403() {
        let err = ApiError(StError::Authorization("no write perm".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rate_limit_returns_429() {
        let err = ApiError(StError::RateLimit);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn payload_too_large_returns_413() {
        let err = ApiError(StError::PayloadTooLarge {
            max_bytes: 1024,
            actual_bytes: 2048,
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn parse_error_returns_400() {
        let err = ApiError(StError::ParseError("invalid json".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn database_error_returns_500_generic() {
        let err = ApiError(StError::Database("connection refused to pg:5432".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
        // Must never leak connection details
        assert!(!body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pg:5432"));
    }

    #[tokio::test]
    async fn internal_error_returns_500_generic() {
        let err = ApiError(StError::Internal("stack overflow in parser".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_body(resp).await;
        assert!(!body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("stack overflow"));
    }
}
