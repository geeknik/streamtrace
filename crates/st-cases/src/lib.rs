//! `st-cases` -- case management, export, and evidence bundles for StreamTrace.
//!
//! Wraps `st-store` case CRUD with input validation and provides
//! export functionality in JSON, CSV, and Markdown formats, plus
//! cryptographically signed evidence bundles for Phase 3.

pub mod bundle;
pub mod case;
pub mod export;

pub use bundle::{
    build_evidence_bundle, verify_bundle, BundleManifest, BundleVerification, EvidenceBundle,
    FileIntegrity, IntegrityChain, RawBundleEntry, TimeRange,
};
pub use case::CaseManager;
pub use export::{ExportFormat, ExportedCase};
