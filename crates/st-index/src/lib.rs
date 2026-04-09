//! `st-index` -- query and search interface over forensic events.
//!
//! Wraps `st-store` database queries with higher-level validation,
//! sanitization, and search logic. All external inputs are validated
//! before reaching the database layer.

pub mod filters;
pub mod search;
pub mod timeline;

pub use search::{SearchQuery, SearchResult};
pub use timeline::EventIndex;
