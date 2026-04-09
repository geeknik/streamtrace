export interface Actor {
  id?: string;
  name?: string;
  actor_type?: string;
}

export interface Subject {
  id?: string;
  name?: string;
  subject_type?: string;
}

export interface EventObject {
  id?: string;
  name?: string;
  object_type?: string;
}

export interface NetworkContext {
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
}

export interface DeviceContext {
  device_id?: string;
  device_name?: string;
  device_type?: string;
  hostname?: string;
}

export interface EventSource {
  source_id: string;
  source_type: string;
  source_name?: string;
}

export interface ForensicEvent {
  id: string;
  raw_event_id: string;
  event_type: string;
  severity: number;
  occurred_at: string;
  observed_at: string | null;
  received_at: string;
  actor: Actor | null;
  subject: Subject | null;
  object: EventObject | null;
  network: NetworkContext | null;
  device: DeviceContext | null;
  source: EventSource;
  tags: string[];
  custom_fields: Record<string, unknown>;
}

export interface TimelineResponse {
  events: ForensicEvent[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface Case {
  id: string;
  name: string;
  description: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface CaseEvent {
  event_id: string;
  annotation: string;
  pinned_at: string;
}

export interface CaseDetail extends Case {
  events: CaseEvent[];
}

export interface IngestResult {
  accepted: number;
  event_ids: string[];
  raw_event_id: string;
}

export interface SearchResult {
  events: ForensicEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface RawEventResponse {
  raw_event_id: string;
  content: string;
  hash: string;
  hash_verified: boolean;
}

export interface TimelineParams {
  start?: string;
  end?: string;
  event_type?: string;
  actor_id?: string;
  source_id?: string;
  severity_min?: number;
  search?: string;
  cursor?: string;
  limit?: number;
}

export interface ApiErrorBody {
  code: string;
  message: string;
}

/* Phase 2: Entity types */

export interface Entity {
  id: string;
  entity_type: string;
  identifier: string;
  display_name: string | null;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  attributes: Record<string, unknown>;
}

export interface EntityRelationship {
  id: string;
  source_entity: string;
  target_entity: string;
  relationship: string;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  sample_event_id: string | null;
}

export interface EntityGraph {
  center: Entity;
  entities: Entity[];
  relationships: EntityRelationship[];
}

export interface EntityDetail {
  entity: Entity;
  relationships: EntityRelationship[];
}

/* Phase 2: Sequence types */

export interface SequenceStepEntry {
  event_type_pattern: string;
  max_gap_secs: number | null;
}

export interface SequencePatternEntry {
  id: string | null;
  name: string;
  description: string;
  builtin: boolean;
  enabled: boolean;
  steps: SequenceStepEntry[];
  max_total_duration_secs: number;
  same_actor: boolean;
}

export interface DetectedSequence {
  id: string;
  pattern_id: string;
  pattern_name: string;
  event_ids: string[];
  actor_id: string | null;
  started_at: string;
  ended_at: string;
  confidence: number;
  detected_at: string;
}

export interface ScanResponse {
  events_scanned: number;
  patterns_checked: number;
  sequences_detected: number;
}

/* Phase 2: Correlation types */

export interface CorrelationChain {
  seed_event: ForensicEvent;
  chain: ForensicEvent[];
  entities: Entity[];
}

export interface EntitySearchBody {
  entity_type?: string;
  identifier_contains?: string;
  limit?: number;
}

/* Phase 3: Evidence bundle types */

export interface BundleManifest {
  bundle_version: string;
  case_id: string;
  case_name: string;
  event_count: number;
  time_range: { start: string; end: string } | null;
  generated_at: string;
  generator: string;
}

export interface FileIntegrity {
  path: string;
  hash_algorithm: string;
  hash_hex: string;
  size_bytes: number;
}

export interface IntegrityChain {
  algorithm: string;
  file_hashes: string[];
  root_hash: string;
}

export interface DetachedSignature {
  algorithm: string;
  signature_hex: string;
  public_key_hex: string;
  signed_at: string;
}

export interface PublicKeyInfo {
  algorithm: string;
  public_key_hex: string;
}

export interface RawBundleEntry {
  raw_event_id: string;
  content_hash: string;
  content_type: string;
  content_base64: string;
}

export interface EvidenceBundle {
  manifest: BundleManifest;
  events: unknown[];
  raw_events: RawBundleEntry[];
  integrity: FileIntegrity[];
  chain: IntegrityChain;
  signature: DetachedSignature;
  public_key: PublicKeyInfo;
}

export interface BundleVerification {
  integrity_valid: boolean;
  chain_valid: boolean;
  signature_valid: boolean;
  details: string[];
}

/* Phase 3: Legal hold types */

export interface LegalHold {
  id: string;
  name: string;
  description: string;
  hold_type: string;
  criteria: unknown;
  status: string;
  created_by: string;
  created_at: string;
  released_at: string | null;
  expires_at: string | null;
}

export interface HoldDetail {
  hold: LegalHold;
  event_count: number;
}

/* Phase 3: Audit log types */

export interface AuditEntry {
  id: number;
  action: string;
  actor: string;
  target_type: string | null;
  target_id: string | null;
  detail: unknown;
  occurred_at: string;
}
