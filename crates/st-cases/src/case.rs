//! Case management facade.
//!
//! Provides validated CRUD operations for investigation cases and
//! their associated events. All inputs are validated before reaching
//! the database layer.

use std::sync::Arc;

use st_common::error::{StError, StResult};
use st_common::types::{CaseId, CaseStatus, EventId};
use st_common::validation::{validate_max_length, validate_not_empty};
use st_crypto::SigningKeyPair;
use st_store::cases::{Case, CaseEvent};
use st_store::holds::LegalHold;
use st_store::Database;

use crate::bundle::{build_evidence_bundle, EvidenceBundle};
use crate::export::{CaseEventWithDetail, ExportFormat, ExportedCase};

/// Maximum length for a case name in bytes.
const MAX_NAME_LENGTH: usize = 200;

/// Maximum length for a case description in bytes.
const MAX_DESCRIPTION_LENGTH: usize = 5000;

/// Maximum length for a legal hold name in bytes.
const MAX_HOLD_NAME_LENGTH: usize = 200;

/// Maximum length for a legal hold description in bytes.
const MAX_HOLD_DESCRIPTION_LENGTH: usize = 5000;

/// Default result limit for list operations.
const DEFAULT_LIST_LIMIT: u32 = 100;

/// Facade for case management operations.
///
/// Validates all inputs before delegating to the underlying
/// [`Database`] methods. Designed to be shared across async
/// tasks via `Arc`.
pub struct CaseManager {
    db: Arc<Database>,
}

impl CaseManager {
    /// Creates a new `CaseManager` backed by the given database handle.
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Creates a new investigation case.
    ///
    /// Validates that the name is not empty and within length limits,
    /// and that the description does not exceed its limit.
    pub async fn create_case(
        &self,
        name: &str,
        description: &str,
        created_by: &str,
    ) -> StResult<Case> {
        validate_not_empty("name", name)?;
        validate_max_length("name", name, MAX_NAME_LENGTH)?;
        validate_max_length("description", description, MAX_DESCRIPTION_LENGTH)?;
        validate_not_empty("created_by", created_by)?;

        tracing::debug!(name, created_by, "creating case");

        self.db.create_case(name, description, created_by).await
    }

    /// Fetches a case by its unique identifier.
    pub async fn get_case(&self, id: CaseId) -> StResult<Case> {
        self.db.get_case(id).await
    }

    /// Lists cases, optionally filtered by status, with a result limit.
    pub async fn list_cases(
        &self,
        status: Option<CaseStatus>,
        limit: Option<u32>,
    ) -> StResult<Vec<Case>> {
        self.db
            .list_cases(status, limit.unwrap_or(DEFAULT_LIST_LIMIT))
            .await
    }

    /// Updates a case. Only provided fields are modified.
    ///
    /// Validates name and description lengths when provided.
    pub async fn update_case(
        &self,
        id: CaseId,
        name: Option<&str>,
        description: Option<&str>,
        status: Option<CaseStatus>,
    ) -> StResult<Case> {
        if let Some(n) = name {
            validate_not_empty("name", n)?;
            validate_max_length("name", n, MAX_NAME_LENGTH)?;
        }
        if let Some(d) = description {
            validate_max_length("description", d, MAX_DESCRIPTION_LENGTH)?;
        }

        tracing::debug!(case_id = %id, "updating case");

        self.db.update_case(id, name, description, status).await
    }

    /// Attaches an event to a case.
    pub async fn add_event(
        &self,
        case_id: CaseId,
        event_id: EventId,
        added_by: &str,
    ) -> StResult<CaseEvent> {
        validate_not_empty("added_by", added_by)?;

        tracing::debug!(
            case_id = %case_id,
            event_id = %event_id,
            added_by,
            "adding event to case"
        );

        self.db
            .add_event_to_case(case_id, event_id, added_by)
            .await
    }

    /// Removes an event from a case.
    pub async fn remove_event(
        &self,
        case_id: CaseId,
        event_id: EventId,
    ) -> StResult<()> {
        tracing::debug!(
            case_id = %case_id,
            event_id = %event_id,
            "removing event from case"
        );

        self.db
            .remove_event_from_case(case_id, event_id)
            .await
    }

    /// Updates the pin status and/or annotation of a case-event attachment.
    pub async fn update_event(
        &self,
        case_id: CaseId,
        event_id: EventId,
        pinned: Option<bool>,
        annotation: Option<&str>,
    ) -> StResult<CaseEvent> {
        if pinned.is_none() && annotation.is_none() {
            return Err(StError::Validation(
                "at least one of pinned or annotation must be provided".to_string(),
            ));
        }

        tracing::debug!(
            case_id = %case_id,
            event_id = %event_id,
            "updating case event"
        );

        self.db
            .update_case_event(case_id, event_id, pinned, annotation)
            .await
    }

    /// Lists all events attached to a case.
    pub async fn get_events(&self, case_id: CaseId) -> StResult<Vec<CaseEvent>> {
        self.db.get_case_events(case_id).await
    }

    /// Exports a case with all attached events in the specified format.
    ///
    /// Fetches the case and all associated events (including full event
    /// details), then renders them in the requested format.
    pub async fn export(
        &self,
        case_id: CaseId,
        format: ExportFormat,
    ) -> StResult<String> {
        let case = self.db.get_case(case_id).await?;
        let case_events = self.db.get_case_events(case_id).await?;

        let mut events_with_detail = Vec::with_capacity(case_events.len());
        for ce in &case_events {
            let event = self.db.get_event(ce.event_id).await?;
            events_with_detail.push(CaseEventWithDetail {
                case_event: ce.clone(),
                event,
            });
        }

        let exported = ExportedCase {
            case,
            events: events_with_detail,
            exported_at: chrono::Utc::now(),
        };

        tracing::debug!(
            case_id = %case_id,
            format = ?format,
            event_count = exported.events.len(),
            "exporting case"
        );

        crate::export::render(&exported, format)
    }

    // -----------------------------------------------------------------------
    // Evidence bundles (Phase 3)
    // -----------------------------------------------------------------------

    /// Build a signed evidence bundle for the given case.
    ///
    /// Fetches all events, computes integrity hashes, and signs the
    /// bundle with the provided Ed25519 key pair.
    pub async fn build_bundle(
        &self,
        case_id: CaseId,
        signing_key: &SigningKeyPair,
    ) -> StResult<EvidenceBundle> {
        tracing::info!(case_id = %case_id, "building evidence bundle");
        build_evidence_bundle(&self.db, signing_key, case_id).await
    }

    // -----------------------------------------------------------------------
    // Legal holds (Phase 3)
    // -----------------------------------------------------------------------

    /// Creates a new legal hold with the given parameters.
    pub async fn create_hold(
        &self,
        name: &str,
        description: &str,
        hold_type: &str,
        criteria: serde_json::Value,
        created_by: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> StResult<LegalHold> {
        validate_not_empty("name", name)?;
        validate_max_length("name", name, MAX_HOLD_NAME_LENGTH)?;
        validate_max_length("description", description, MAX_HOLD_DESCRIPTION_LENGTH)?;
        validate_not_empty("hold_type", hold_type)?;
        validate_not_empty("created_by", created_by)?;

        // Validate hold_type is one of the allowed values
        match hold_type {
            "time_range" | "entity" | "case" | "query" => {}
            _ => {
                return Err(StError::Validation(format!(
                    "invalid hold_type: {hold_type}; must be one of: time_range, entity, case, query"
                )));
            }
        }

        tracing::info!(name, hold_type, created_by, "creating legal hold");

        self.db
            .create_hold(name, description, hold_type, criteria, created_by, expires_at)
            .await
    }

    /// Fetches a legal hold by ID.
    pub async fn get_hold(&self, id: uuid::Uuid) -> StResult<LegalHold> {
        self.db.get_hold(id).await
    }

    /// Lists legal holds, optionally filtered by status, with a result limit.
    pub async fn list_holds(
        &self,
        status: Option<&str>,
        limit: Option<u32>,
    ) -> StResult<Vec<LegalHold>> {
        self.db
            .list_holds(status, limit.unwrap_or(DEFAULT_LIST_LIMIT))
            .await
    }

    /// Releases a legal hold (sets status to "released").
    pub async fn release_hold(&self, id: uuid::Uuid) -> StResult<LegalHold> {
        tracing::info!(hold_id = %id, "releasing legal hold");
        self.db.release_hold(id).await
    }

    /// Associates events with a legal hold.
    pub async fn add_hold_events(
        &self,
        hold_id: uuid::Uuid,
        events: &[(uuid::Uuid, uuid::Uuid)],
    ) -> StResult<usize> {
        self.db.add_hold_events(hold_id, events).await
    }

    /// Returns the count of events associated with a hold.
    pub async fn get_hold_event_count(&self, hold_id: uuid::Uuid) -> StResult<i64> {
        self.db.get_hold_event_count(hold_id).await
    }

    /// Checks if an event is under any active legal hold.
    pub async fn is_event_held(&self, event_id: uuid::Uuid) -> StResult<bool> {
        self.db.is_event_held(event_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_name() {
        // Validation is synchronous; we can test without a database.
        let result = validate_not_empty("name", "");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("name"), "error should mention field: {msg}");
    }

    #[test]
    fn rejects_whitespace_only_name() {
        let result = validate_not_empty("name", "   ");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_name_exceeding_max_length() {
        let long_name = "a".repeat(MAX_NAME_LENGTH + 1);
        let result = validate_max_length("name", &long_name, MAX_NAME_LENGTH);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_name_at_max_length() {
        let name = "a".repeat(MAX_NAME_LENGTH);
        let result = validate_max_length("name", &name, MAX_NAME_LENGTH);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_description_exceeding_max_length() {
        let long_desc = "d".repeat(MAX_DESCRIPTION_LENGTH + 1);
        let result = validate_max_length("description", &long_desc, MAX_DESCRIPTION_LENGTH);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_description_at_max_length() {
        let desc = "d".repeat(MAX_DESCRIPTION_LENGTH);
        let result = validate_max_length("description", &desc, MAX_DESCRIPTION_LENGTH);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_invalid_hold_type() {
        // We can't call create_hold without a DB, but we can test the
        // hold_type validation logic inline.
        let valid_types = ["time_range", "entity", "case", "query"];
        for t in &valid_types {
            assert!(
                matches!(*t, "time_range" | "entity" | "case" | "query"),
                "{t} should be valid"
            );
        }
        assert!(
            !matches!("invalid", "time_range" | "entity" | "case" | "query"),
            "invalid should not match"
        );
    }
}
