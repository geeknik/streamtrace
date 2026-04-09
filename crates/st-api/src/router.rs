//! Route composition for the StreamTrace HTTP API.
//!
//! All routes are defined here and wrapped with the middleware stack.

use axum::routing::{delete, get, post};
use axum::Router;

use crate::handlers;
use crate::middleware;
use crate::state::AppState;

/// Build the complete axum router with all routes and middleware.
///
/// The returned router is ready to be served by `axum::serve`.
pub fn create_router(state: AppState) -> Router {
    build_router(state, None, &[], None)
}

/// Build the router with an explicit body size limit, CORS origins, and
/// rate limit from configuration.
///
/// This is the preferred entry point when `AppConfig` is available.
pub fn create_router_with_config(
    state: AppState,
    request_body_limit_bytes: usize,
    cors_allowed_origins: &[String],
    rate_limit_per_second: u64,
) -> Router {
    build_router(
        state,
        Some(request_body_limit_bytes),
        cors_allowed_origins,
        Some(rate_limit_per_second),
    )
}

/// Internal router builder shared by both public constructors.
fn build_router(
    state: AppState,
    body_limit: Option<usize>,
    cors_allowed_origins: &[String],
    rate_limit_rps: Option<u64>,
) -> Router {
    // Authenticated v1 API routes.
    let v1_routes = Router::new()
        // Ingest endpoints.
        .route("/ingest/events", post(handlers::ingest::ingest_events))
        .route("/ingest/raw", post(handlers::ingest::ingest_raw))
        // Timeline endpoint.
        .route("/timeline", get(handlers::timeline::get_timeline))
        // Event endpoints.
        .route("/events/{id}", get(handlers::events::get_event))
        .route("/events/{id}/raw", get(handlers::events::get_event_raw))
        .route(
            "/events/{id}/correlated",
            get(handlers::events::get_correlated_events),
        )
        // Search endpoint.
        .route("/search", get(handlers::search::search))
        // Replay endpoint (SSE).
        .route("/replay", get(handlers::replay::replay))
        // Case endpoints.
        .route(
            "/cases",
            post(handlers::cases::create_case).get(handlers::cases::list_cases),
        )
        .route(
            "/cases/{id}",
            get(handlers::cases::get_case).patch(handlers::cases::update_case),
        )
        .route("/cases/{id}/events", post(handlers::cases::add_case_event))
        .route(
            "/cases/{id}/events/{event_id}",
            delete(handlers::cases::remove_case_event).patch(handlers::cases::update_case_event),
        )
        .route("/cases/{id}/export", get(handlers::cases::export_case))
        // Evidence bundle endpoints (Phase 3).
        .route("/cases/{id}/bundle", post(handlers::bundles::create_bundle))
        .route(
            "/bundles/verify",
            post(handlers::bundles::verify_bundle_handler),
        )
        // Legal hold endpoints (Phase 3).
        .route(
            "/holds",
            post(handlers::holds::create_hold).get(handlers::holds::list_holds),
        )
        .route("/holds/{id}", get(handlers::holds::get_hold))
        .route("/holds/{id}/release", post(handlers::holds::release_hold))
        .route(
            "/holds/{id}/materialize",
            post(handlers::holds::materialize_hold),
        )
        // Audit log endpoint (Phase 3).
        .route("/audit", get(handlers::audit::query_audit))
        // Entity endpoints.
        .route("/entities", get(handlers::entities::list_entities))
        .route("/entities/{id}", get(handlers::entities::get_entity))
        .route(
            "/entities/{id}/timeline",
            get(handlers::entities::get_entity_timeline),
        )
        .route(
            "/entities/{id}/graph",
            get(handlers::entities::get_entity_graph),
        )
        // Correlation endpoints.
        .route(
            "/correlate/chain",
            get(handlers::correlate::correlation_chain),
        )
        .route(
            "/correlate/search",
            post(handlers::correlate::entity_search),
        )
        // Sequence endpoints.
        .route(
            "/sequences/patterns",
            get(handlers::sequences::list_patterns),
        )
        .route(
            "/sequences/detected",
            get(handlers::sequences::list_detected),
        )
        .route("/sequences/scan", post(handlers::sequences::scan))
        // API key management (admin only).
        .route("/admin/keys", post(handlers::keys::create_key))
        .route("/admin/keys/{id}", delete(handlers::keys::revoke_key));

    // Log rate limit configuration. Actual enforcement should be done via
    // a reverse proxy (nginx, envoy) or a compatible tower middleware that
    // implements Clone (e.g. tower-governor). tower::limit::RateLimitLayer
    // does not implement Clone and cannot be used with axum's Router::layer.
    if let Some(rps) = rate_limit_rps {
        if rps > 0 {
            tracing::info!(
                requests_per_second = rps,
                "rate limit configured (enforce via reverse proxy or per-key middleware)"
            );
        }
    }

    // Health check routes -- no authentication required.
    let health_routes = Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/readyz", get(handlers::health::readyz));

    // Compose: /v1/* (authenticated) + health (public).
    let mut app = Router::new()
        .nest("/v1", v1_routes)
        .merge(health_routes)
        .layer(middleware::propagate_request_id_layer())
        .layer(middleware::trace_layer());

    if let Some(limit) = body_limit {
        app = app.layer(middleware::body_limit_layer(limit));
    }

    app.layer(middleware::cors_layer(cors_allowed_origins))
        .layer(middleware::set_request_id_layer())
        .with_state(state)
}
