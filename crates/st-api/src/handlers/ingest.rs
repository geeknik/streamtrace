//! Ingestion endpoints for raw and structured event data.
//!
//! - `POST /v1/ingest/events` -- JSON event(s)
//! - `POST /v1/ingest/raw`    -- arbitrary format with parser selection

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use st_common::error::StError;
use st_common::types::Permission;

use crate::auth::AuthenticatedKey;
use crate::error::ApiError;
use crate::state::AppState;

/// Default source ID when the caller does not provide one.
const DEFAULT_SOURCE_ID: &str = "api";

/// Default source type when the caller does not provide one.
const DEFAULT_SOURCE_TYPE: &str = "direct";

/// Maximum allowed length (in bytes) for source header values.
/// Prevents resource exhaustion from oversized headers.
const MAX_SOURCE_HEADER_BYTES: usize = 256;

/// Ingest one or more events in StreamTrace JSON format.
///
/// `POST /v1/ingest/events`
///
/// Accepts a JSON object (single event) or JSON array (batch).
/// Returns 202 Accepted with an `IngestResult` body on success.
///
/// Headers:
/// - `X-Source-Id` (optional, default "api")
/// - `X-Source-Type` (optional, default "direct")
/// - `X-Source-Name` (optional)
pub async fn ingest_events(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    // Validate source header lengths before processing.
    validate_source_headers(&headers)?;

    let source_id = header_str(&headers, "x-source-id")
        .unwrap_or(DEFAULT_SOURCE_ID);
    let source_type = header_str(&headers, "x-source-type")
        .unwrap_or(DEFAULT_SOURCE_TYPE);
    let source_name = header_str(&headers, "x-source-name");

    let result = state
        .ingest
        .ingest_events(&body, source_id, source_type, source_name)
        .await
        .map_err(ApiError::from)?;

    // Fire-and-forget audit log for write operations.
    {
        let db = state.db.clone();
        let actor = auth.key_id.to_string();
        let accepted = result.accepted;
        tokio::spawn(async move {
            if let Err(e) = db
                .log_audit(
                    "ingest.events",
                    &actor,
                    Some("events"),
                    None,
                    serde_json::json!({ "accepted": accepted }),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write audit log");
            }
        });
    }

    Ok((StatusCode::ACCEPTED, axum::Json(result)))
}

/// Ingest raw bytes with parser auto-detection or explicit parser selection.
///
/// `POST /v1/ingest/raw`
///
/// The `Content-Type` header drives parser selection. An explicit
/// `X-Parser-Id` header overrides auto-detection.
/// Returns 202 Accepted with an `IngestResult` body on success.
///
/// Headers:
/// - `Content-Type` (used for parser selection)
/// - `X-Source-Id` (optional, default "api")
/// - `X-Source-Type` (optional, default "direct")
/// - `X-Source-Name` (optional)
/// - `X-Parser-Id` (optional, overrides auto-detection)
pub async fn ingest_raw(
    auth: AuthenticatedKey,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    auth.require_permission(Permission::Write)?;

    // Validate source header lengths before processing.
    validate_source_headers(&headers)?;

    let content_type = header_str(&headers, "content-type")
        .unwrap_or("application/octet-stream");
    let source_id = header_str(&headers, "x-source-id")
        .unwrap_or(DEFAULT_SOURCE_ID);
    let source_type = header_str(&headers, "x-source-type")
        .unwrap_or(DEFAULT_SOURCE_TYPE);
    let source_name = header_str(&headers, "x-source-name");
    let parser_id = header_str(&headers, "x-parser-id");

    let result = state
        .ingest
        .ingest_raw(
            &body,
            content_type,
            source_id,
            source_type,
            source_name,
            parser_id,
        )
        .await
        .map_err(ApiError::from)?;

    Ok((StatusCode::ACCEPTED, axum::Json(result)))
}

/// Validates that source-related headers do not exceed the maximum
/// allowed length. Returns 400 if any header exceeds the limit.
fn validate_source_headers(headers: &HeaderMap) -> Result<(), ApiError> {
    for name in &["x-source-id", "x-source-type", "x-source-name"] {
        if let Some(val) = headers.get(*name) {
            if val.len() > MAX_SOURCE_HEADER_BYTES {
                return Err(ApiError::from(StError::Validation(format!(
                    "{name} header exceeds maximum length of {MAX_SOURCE_HEADER_BYTES} bytes"
                ))));
            }
        }
    }
    Ok(())
}

/// Extract a header value as a `&str`, returning `None` if missing or
/// not valid UTF-8.
///
/// The returned reference borrows from `headers`, so the lifetime is
/// tied to the `HeaderMap`. We return `Option<&str>` rather than
/// `Option<String>` to avoid allocation on the hot path.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}
