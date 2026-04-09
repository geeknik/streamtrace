//! Sequence pattern detection for forensic event streams.
//!
//! A sequence pattern defines an ordered list of event-type steps that
//! must occur chronologically within a bounded time window. The detector
//! scans a sorted slice of events and produces non-overlapping matches.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use st_common::event::ForensicEvent;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A sequence pattern: an ordered list of steps with time constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencePattern {
    /// Human-readable name used for identification.
    pub name: String,
    /// Description of what this pattern detects.
    pub description: String,
    /// Ordered steps that must match events chronologically.
    pub steps: Vec<SequenceStep>,
    /// Maximum wall-clock duration from first step to last step (seconds).
    pub max_total_duration_secs: u64,
    /// If true, all matching events must share the same `actor.id`.
    pub same_actor: bool,
}

/// A single step in a sequence pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStep {
    /// Glob-like pattern for `event_type`. Supports `*` as a wildcard
    /// segment (e.g. `"auth.*"`, `"*.export"`, `"data.export"`).
    pub event_type_pattern: String,
    /// Maximum seconds allowed between this step and the previous step.
    /// `None` means no per-step gap constraint (only total duration applies).
    pub max_gap_secs: Option<u64>,
}

/// A detected instance of a sequence pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSequence {
    /// Name of the pattern that matched.
    pub pattern_name: String,
    /// Event IDs forming the match, in chronological order.
    pub event_ids: Vec<Uuid>,
    /// Shared actor ID (if `same_actor` was true).
    pub actor_id: Option<String>,
    /// Timestamp of the first matched event.
    pub started_at: DateTime<Utc>,
    /// Timestamp of the last matched event.
    pub ended_at: DateTime<Utc>,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

/// Check whether `event_type` matches a glob-like `pattern`.
///
/// Supports `*` as a wildcard that matches any sequence of characters
/// (including the empty string). Multiple `*` segments are supported.
///
/// This is intentionally a simple implementation; we avoid pulling in
/// a full glob crate to minimize dependencies.
pub fn matches_event_type(pattern: &str, event_type: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    // No wildcards -- exact match.
    if parts.len() == 1 {
        return pattern == event_type;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Must start with this prefix.
            if !event_type.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Must end with this suffix.
            if !event_type[pos..].ends_with(part) {
                return false;
            }
            pos = event_type.len();
        } else {
            // Must contain this infix after current position.
            match event_type[pos..].find(part) {
                Some(offset) => pos += offset + part.len(),
                None => return false,
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Stateless sequence detector.
///
/// Holds no mutable state; detection is a pure function of pattern + events.
pub struct SequenceDetector;

impl SequenceDetector {
    /// Create a new detector.
    pub fn new() -> Self {
        Self
    }

    /// Detect all non-overlapping matches of `pattern` in a **chronologically
    /// sorted** slice of events.
    ///
    /// For `same_actor` patterns, events are grouped by `actor.id` first
    /// and detection runs within each group independently.
    ///
    /// Matches are greedy and non-overlapping: once a match is found, the
    /// consumed events cannot participate in another match.
    pub fn detect(
        &self,
        pattern: &SequencePattern,
        events: &[ForensicEvent],
    ) -> Vec<DetectedSequence> {
        if pattern.steps.is_empty() || events.is_empty() {
            return Vec::new();
        }

        if pattern.same_actor {
            // Group events by actor ID, skipping events without one.
            let mut groups: HashMap<String, Vec<&ForensicEvent>> = HashMap::new();
            for event in events {
                if let Some(ref actor) = event.actor {
                    if let Some(ref id) = actor.id {
                        let trimmed = id.trim();
                        if !trimmed.is_empty() {
                            groups.entry(trimmed.to_string()).or_default().push(event);
                        }
                    }
                }
            }

            let mut results: Vec<DetectedSequence> = Vec::new();
            for (actor_id, group) in &groups {
                let matches = self.detect_in_slice(pattern, group, Some(actor_id.clone()));
                results.extend(matches);
            }
            // Sort results by started_at for deterministic output.
            results.sort_by_key(|d| d.started_at);
            results
        } else {
            let refs: Vec<&ForensicEvent> = events.iter().collect();
            self.detect_in_slice(pattern, &refs, None)
        }
    }

    /// Core detection loop over a pre-filtered, sorted slice.
    fn detect_in_slice(
        &self,
        pattern: &SequencePattern,
        events: &[&ForensicEvent],
        actor_id: Option<String>,
    ) -> Vec<DetectedSequence> {
        let mut results: Vec<DetectedSequence> = Vec::new();
        let mut skip_until: usize = 0;

        let total_dur = chrono::Duration::seconds(pattern.max_total_duration_secs as i64);

        let mut idx = 0;
        while idx < events.len() {
            if idx < skip_until {
                idx += 1;
                continue;
            }

            // Try to start a match at `idx`.
            if let Some(matched) = self.try_match_from(pattern, events, idx, &total_dur) {
                // Record the end index so we skip consumed events.
                let last_idx = matched.last().copied().unwrap_or(idx);
                results.push(DetectedSequence {
                    pattern_name: pattern.name.clone(),
                    event_ids: matched.iter().map(|&i| events[i].id).collect(),
                    actor_id: actor_id.clone(),
                    started_at: events[matched[0]].occurred_at,
                    ended_at: events[*matched.last().unwrap()].occurred_at,
                    confidence: 1.0,
                });
                skip_until = last_idx + 1;
                idx = skip_until;
            } else {
                idx += 1;
            }
        }

        results
    }

    /// Attempt to greedily match all steps starting from `start_idx`.
    ///
    /// Returns `Some(vec_of_indices)` on success, or `None` on failure.
    fn try_match_from(
        &self,
        pattern: &SequencePattern,
        events: &[&ForensicEvent],
        start_idx: usize,
        total_dur: &chrono::Duration,
    ) -> Option<Vec<usize>> {
        let first_event = events[start_idx];

        // First step must match.
        if !matches_event_type(
            &pattern.steps[0].event_type_pattern,
            &first_event.event_type,
        ) {
            return None;
        }

        let mut matched_indices = vec![start_idx];
        let mut prev_time = first_event.occurred_at;
        let mut cursor = start_idx + 1;

        for step_idx in 1..pattern.steps.len() {
            let step = &pattern.steps[step_idx];
            let mut found = false;

            while cursor < events.len() {
                let candidate = events[cursor];

                // Check total duration constraint.
                let elapsed = candidate.occurred_at - first_event.occurred_at;
                if elapsed > *total_dur {
                    return None;
                }

                // Check per-step gap constraint.
                if let Some(max_gap) = step.max_gap_secs {
                    let gap = candidate.occurred_at - prev_time;
                    if gap > chrono::Duration::seconds(max_gap as i64) {
                        return None;
                    }
                }

                cursor += 1;

                if matches_event_type(&step.event_type_pattern, &candidate.event_type) {
                    matched_indices.push(cursor - 1);
                    prev_time = candidate.occurred_at;
                    found = true;
                    break;
                }
            }

            if !found {
                return None;
            }
        }

        Some(matched_indices)
    }
}

impl Default for SequenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Built-in patterns
// ---------------------------------------------------------------------------

/// Returns the built-in sequence patterns shipped with StreamTrace.
pub fn builtin_patterns() -> Vec<SequencePattern> {
    vec![
        SequencePattern {
            name: "data_exfiltration".to_string(),
            description: "Login followed by data access and export within 1 hour".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login*".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "*.access".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "data.export".to_string(),
                    max_gap_secs: None,
                },
            ],
            max_total_duration_secs: 3600,
            same_actor: true,
        },
        SequencePattern {
            name: "brute_force_success".to_string(),
            description: "Multiple login failures followed by a success within 10 minutes"
                .to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "auth.login".to_string(),
                    max_gap_secs: None,
                },
            ],
            max_total_duration_secs: 600,
            same_actor: true,
        },
        SequencePattern {
            name: "bad_deploy".to_string(),
            description: "Deploy followed by multiple errors within 30 minutes".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "deploy.*".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "error.*".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "error.*".to_string(),
                    max_gap_secs: None,
                },
            ],
            max_total_duration_secs: 1800,
            same_actor: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use st_common::event::{Actor, SourceAttribution};
    use st_common::types::Severity;

    fn make_source() -> SourceAttribution {
        SourceAttribution {
            source_id: "test".to_string(),
            source_type: "test".to_string(),
            source_name: None,
        }
    }

    fn make_event_at(
        event_type: &str,
        occurred_at: DateTime<Utc>,
        actor_id: Option<&str>,
    ) -> ForensicEvent {
        let mut event = ForensicEvent::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            event_type.to_string(),
            Severity::Medium,
            occurred_at,
            Utc::now(),
            make_source(),
        );
        if let Some(aid) = actor_id {
            event.actor = Some(Actor {
                id: Some(aid.to_string()),
                name: None,
                actor_type: None,
            });
        }
        event
    }

    // ---- matches_event_type tests ----

    #[test]
    fn exact_match() {
        assert!(matches_event_type("auth.login", "auth.login"));
        assert!(!matches_event_type("auth.login", "auth.logout"));
    }

    #[test]
    fn wildcard_suffix() {
        assert!(matches_event_type("auth.*", "auth.login"));
        assert!(matches_event_type("auth.*", "auth.login.success"));
        assert!(!matches_event_type("auth.*", "network.scan"));
    }

    #[test]
    fn wildcard_prefix() {
        assert!(matches_event_type("*.access", "file.access"));
        assert!(matches_event_type("*.access", "data.read.access"));
        assert!(!matches_event_type("*.access", "access.denied"));
    }

    #[test]
    fn wildcard_middle() {
        assert!(matches_event_type("auth.*.success", "auth.login.success"));
        assert!(matches_event_type("auth.*.success", "auth.sso.success"));
        assert!(!matches_event_type("auth.*.success", "auth.login.failure"));
    }

    #[test]
    fn wildcard_only() {
        assert!(matches_event_type("*", "anything.at.all"));
        assert!(matches_event_type("*", ""));
    }

    #[test]
    fn no_match_empty() {
        assert!(!matches_event_type("auth.login", ""));
        // Empty pattern only matches empty string.
        assert!(matches_event_type("", ""));
        assert!(!matches_event_type("", "auth"));
    }

    // ---- Single-step detection ----

    #[test]
    fn single_step_pattern_detects_matches() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login", t0, None),
            make_event_at("data.export", t0 + Duration::seconds(10), None),
            make_event_at("auth.login", t0 + Duration::seconds(20), None),
        ];

        let pattern = SequencePattern {
            name: "single".to_string(),
            description: "test".to_string(),
            steps: vec![SequenceStep {
                event_type_pattern: "auth.login".to_string(),
                max_gap_secs: None,
            }],
            max_total_duration_secs: 3600,
            same_actor: false,
        };

        let detector = SequenceDetector::new();
        let results = detector.detect(&pattern, &events);
        assert_eq!(results.len(), 2);
    }

    // ---- Multi-step with time gaps ----

    #[test]
    fn multi_step_with_gap_constraint() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login_failed", t0, Some("alice")),
            make_event_at(
                "auth.login_failed",
                t0 + Duration::seconds(5),
                Some("alice"),
            ),
            make_event_at("auth.login", t0 + Duration::seconds(10), Some("alice")),
        ];

        let pattern = SequencePattern {
            name: "brute_force".to_string(),
            description: "test".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: Some(30),
                },
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: Some(30),
                },
                SequenceStep {
                    event_type_pattern: "auth.login".to_string(),
                    max_gap_secs: Some(30),
                },
            ],
            max_total_duration_secs: 600,
            same_actor: true,
        };

        let detector = SequenceDetector::new();
        let results = detector.detect(&pattern, &events);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_ids.len(), 3);
        assert_eq!(results[0].actor_id.as_deref(), Some("alice"));
    }

    #[test]
    fn gap_constraint_exceeded_no_match() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login_failed", t0, Some("bob")),
            make_event_at(
                "auth.login_failed",
                t0 + Duration::seconds(120),
                Some("bob"),
            ),
            make_event_at("auth.login", t0 + Duration::seconds(130), Some("bob")),
        ];

        let pattern = SequencePattern {
            name: "test".to_string(),
            description: "test".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: Some(30), // Step 1: no max_gap on first step
                },
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: Some(30), // 120s gap exceeds 30s
                },
                SequenceStep {
                    event_type_pattern: "auth.login".to_string(),
                    max_gap_secs: Some(30),
                },
            ],
            max_total_duration_secs: 600,
            same_actor: true,
        };

        let detector = SequenceDetector::new();
        let results = detector.detect(&pattern, &events);
        assert!(results.is_empty());
    }

    // ---- same_actor enforcement ----

    #[test]
    fn same_actor_isolates_users() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login_failed", t0, Some("alice")),
            make_event_at("auth.login_failed", t0 + Duration::seconds(1), Some("bob")),
            make_event_at(
                "auth.login_failed",
                t0 + Duration::seconds(2),
                Some("alice"),
            ),
            make_event_at("auth.login", t0 + Duration::seconds(3), Some("alice")),
            make_event_at("auth.login", t0 + Duration::seconds(4), Some("bob")),
        ];

        let pattern = SequencePattern {
            name: "brute".to_string(),
            description: "test".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "auth.login_failed".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "auth.login".to_string(),
                    max_gap_secs: None,
                },
            ],
            max_total_duration_secs: 600,
            same_actor: true,
        };

        let detector = SequenceDetector::new();
        let results = detector.detect(&pattern, &events);
        // Alice has 2 failures + 1 success -> match.
        // Bob has only 1 failure + 1 success -> no match.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor_id.as_deref(), Some("alice"));
    }

    // ---- Non-overlapping matches ----

    #[test]
    fn non_overlapping_matches() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login", t0, None),
            make_event_at("data.access", t0 + Duration::seconds(10), None),
            make_event_at("auth.login", t0 + Duration::seconds(20), None),
            make_event_at("data.access", t0 + Duration::seconds(30), None),
        ];

        let pattern = SequencePattern {
            name: "two_step".to_string(),
            description: "test".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "data.access".to_string(),
                    max_gap_secs: None,
                },
            ],
            max_total_duration_secs: 3600,
            same_actor: false,
        };

        let detector = SequenceDetector::new();
        let results = detector.detect(&pattern, &events);
        assert_eq!(results.len(), 2);
        // Each match uses distinct events.
        let ids_0: std::collections::HashSet<_> = results[0].event_ids.iter().collect();
        let ids_1: std::collections::HashSet<_> = results[1].event_ids.iter().collect();
        assert!(ids_0.is_disjoint(&ids_1));
    }

    // ---- Total duration exceeded ----

    #[test]
    fn total_duration_exceeded_no_match() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login", t0, None),
            make_event_at("data.access", t0 + Duration::seconds(7200), None),
        ];

        let pattern = SequencePattern {
            name: "test".to_string(),
            description: "test".to_string(),
            steps: vec![
                SequenceStep {
                    event_type_pattern: "auth.login".to_string(),
                    max_gap_secs: None,
                },
                SequenceStep {
                    event_type_pattern: "data.access".to_string(),
                    max_gap_secs: None,
                },
            ],
            max_total_duration_secs: 3600,
            same_actor: false,
        };

        let detector = SequenceDetector::new();
        let results = detector.detect(&pattern, &events);
        assert!(results.is_empty());
    }

    // ---- Empty inputs ----

    #[test]
    fn empty_events_no_match() {
        let pattern = SequencePattern {
            name: "test".to_string(),
            description: "test".to_string(),
            steps: vec![SequenceStep {
                event_type_pattern: "auth.login".to_string(),
                max_gap_secs: None,
            }],
            max_total_duration_secs: 3600,
            same_actor: false,
        };

        let detector = SequenceDetector::new();
        assert!(detector.detect(&pattern, &[]).is_empty());
    }

    #[test]
    fn empty_steps_no_match() {
        let t0 = Utc::now();
        let events = vec![make_event_at("auth.login", t0, None)];

        let pattern = SequencePattern {
            name: "test".to_string(),
            description: "test".to_string(),
            steps: vec![],
            max_total_duration_secs: 3600,
            same_actor: false,
        };

        let detector = SequenceDetector::new();
        assert!(detector.detect(&pattern, &events).is_empty());
    }

    // ---- Built-in patterns validation ----

    #[test]
    fn builtin_patterns_are_valid() {
        let patterns = builtin_patterns();
        assert_eq!(patterns.len(), 3);

        for p in &patterns {
            assert!(!p.name.is_empty());
            assert!(!p.steps.is_empty());
            assert!(p.max_total_duration_secs > 0);
            for step in &p.steps {
                assert!(!step.event_type_pattern.is_empty());
            }
        }

        // Check specific patterns exist.
        assert!(patterns.iter().any(|p| p.name == "data_exfiltration"));
        assert!(patterns.iter().any(|p| p.name == "brute_force_success"));
        assert!(patterns.iter().any(|p| p.name == "bad_deploy"));

        // data_exfiltration and brute_force_success require same_actor
        let exfil = patterns
            .iter()
            .find(|p| p.name == "data_exfiltration")
            .unwrap();
        assert!(exfil.same_actor);
        assert_eq!(exfil.steps.len(), 3);

        let brute = patterns
            .iter()
            .find(|p| p.name == "brute_force_success")
            .unwrap();
        assert!(brute.same_actor);

        let deploy = patterns.iter().find(|p| p.name == "bad_deploy").unwrap();
        assert!(!deploy.same_actor);
    }

    // ---- Builtin pattern data_exfiltration end-to-end ----

    #[test]
    fn data_exfiltration_pattern_matches() {
        let t0 = Utc::now();
        let events = vec![
            make_event_at("auth.login.success", t0, Some("eve")),
            make_event_at("file.access", t0 + Duration::minutes(10), Some("eve")),
            make_event_at("data.export", t0 + Duration::minutes(30), Some("eve")),
        ];

        let pattern = &builtin_patterns()[0]; // data_exfiltration
        let detector = SequenceDetector::new();
        let results = detector.detect(pattern, &events);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_name, "data_exfiltration");
    }
}
