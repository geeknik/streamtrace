//! `st-api` -- HTTP API layer for StreamTrace.
//!
//! Provides the axum router, middleware stack, authentication extractors,
//! error mapping, and request handlers. This crate does not own `main`;
//! it is consumed by `st-server`.

pub mod auth;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod router;
pub mod state;

// Re-export the primary entry points.
pub use error::ApiError;
pub use router::{create_router, create_router_with_config};
pub use state::AppState;
