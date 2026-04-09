//! Tower middleware stack for the HTTP server.
//!
//! Configures CORS, request body size limits, request tracing,
//! request ID generation, and rate limiting.

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue};
use tower::limit::RateLimitLayer;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

/// Header name used to propagate request IDs.
static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Build the CORS middleware layer based on the configured allowed origins.
///
/// - If `allowed_origins` is empty, `AllowOrigin::any()` is used. This is
///   acceptable in development but **must not** be used in production.
/// - If `allowed_origins` is non-empty, only the listed origins are permitted.
///   Each entry must be a valid `HeaderValue` (e.g. `"https://app.example.com"`).
///   Invalid entries are skipped with a warning.
pub fn cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let allow_origin = if allowed_origins.is_empty() {
        tracing::warn!(
            "CORS configured with AllowOrigin::any() -- restrict origins in production \
             via security.cors_allowed_origins"
        );
        AllowOrigin::any()
    } else {
        let values: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|origin| {
                HeaderValue::from_str(origin)
                    .map_err(|e| {
                        tracing::warn!(
                            origin = %origin,
                            error = %e,
                            "skipping invalid CORS origin"
                        );
                        e
                    })
                    .ok()
            })
            .collect();

        if values.is_empty() {
            tracing::warn!(
                "all configured CORS origins were invalid, falling back to AllowOrigin::any()"
            );
            AllowOrigin::any()
        } else {
            tracing::info!(
                origins = ?allowed_origins,
                "CORS restricted to configured origins"
            );
            AllowOrigin::list(values)
        }
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::any())
        .allow_headers(AllowHeaders::any())
        .max_age(std::time::Duration::from_secs(3600))
}

/// Build a request body size limit layer.
pub fn body_limit_layer(max_bytes: usize) -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(max_bytes)
}

/// Build a request tracing layer using tower-http.
///
/// Logs method, URI, status, and latency for every request.
pub fn trace_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
}

/// Build the layer that assigns a UUIDv4 request ID to each request.
pub fn set_request_id_layer() -> SetRequestIdLayer<MakeRequestUuid> {
    SetRequestIdLayer::new(X_REQUEST_ID.clone(), MakeRequestUuid)
}

/// Build the layer that propagates the request ID into responses.
pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::new(X_REQUEST_ID.clone())
}

/// Build a rate limiting layer that caps requests per second.
///
/// Uses `tower::limit::RateLimitLayer` which enforces a fixed window
/// of `num_requests` per `per_duration`. Requests exceeding the limit
/// are held in a queue until capacity is available.
pub fn rate_limit_layer(requests_per_second: u64) -> RateLimitLayer {
    RateLimitLayer::new(requests_per_second, Duration::from_secs(1))
}
