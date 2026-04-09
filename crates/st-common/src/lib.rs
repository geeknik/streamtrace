//! `st-common` -- shared types, error definitions, configuration, and validation
//! for the StreamTrace forensic runtime.
//!
//! Every other crate in the workspace depends on this crate. It defines the
//! canonical data model, error hierarchy, and input-validation primitives
//! that keep the rest of the system consistent.

pub mod config;
pub mod error;
pub mod event;
pub mod types;
pub mod validation;

// Re-export the most commonly used items for ergonomic imports.
pub use error::{StError, StResult};
pub use types::{
    CaseId, CaseStatus, ContentHash, EventId, Permission, RawEventId, Severity, SortOrder,
    MAX_GRAPH_DEPTH,
};
