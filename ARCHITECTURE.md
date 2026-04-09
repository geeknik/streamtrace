# StreamTrace Architecture

This document describes the internal architecture of StreamTrace: how data flows from ingestion to investigation, how crates relate to each other, and why key design decisions were made.

---

## Overview

StreamTrace is a forensic event reconstruction system. It ingests raw events from heterogeneous sources, preserves them immutably, normalizes them into a shared forensic model, correlates them across systems, and exposes them through a timeline-based investigation interface.

The system is built as a Rust workspace with 10 crates, backed by PostgreSQL with TimescaleDB for time-series storage, and served through a SolidJS frontend.

---

## Data Flow

```
HTTP POST -> Validate -> Hash -> Store Raw -> Parse -> Correlate -> Store Normalized -> Entity Resolution -> Query
```

Step by step:

1. **HTTP POST arrives at ingest gateway** (`st-api`). The request hits the `/v1/ingest/events` endpoint served by axum.

2. **Input validated against schema, rate limited.** The request body is checked against size limits (`max_event_size_bytes`), deserialized with strict typing (unknown fields rejected), and the client is rate-limited by API key.

3. **Raw bytes hashed with BLAKE3, stored immutably.** The `st-crypto` crate computes a BLAKE3 digest of the raw event bytes. The raw payload and its hash are written to the `raw_events` hypertable. This row is never modified after insertion -- it is the forensic evidence.

4. **Parser selected, raw bytes parsed into ForensicEvent.** The `st-parser` crate auto-detects the format (JSON, CSV, syslog) or uses the content type specified by the client. The raw bytes are parsed into a structured `ForensicEvent` with the triple timestamp model.

5. **Correlation keys extracted.** The `st-correlate` crate extracts linkable identifiers: user IDs, session tokens, IP addresses, device fingerprints, hostnames. These become the edges that connect events across systems.

6. **Normalized event stored in `events` hypertable with tsvector.** The parsed event is written to the `events` table. A PostgreSQL `tsvector` column is populated for full-text search over event content.

7. **Correlation keys stored for cross-event linking.** Each extracted key is written to the `correlation_keys` table, referencing the event ID. This enables fast lookups: "show me all events involving this IP address."

8. **Entity resolution.** The `st-correlate` crate extracts entities (users, devices, IPs, hosts) from normalized events and resolves relationships between co-occurring entities. Entities are upserted into the `entities` table, relationships into `entity_relationships`, and the event-entity link into `entity_events`. This is best-effort within the transaction -- resolution failures do not block ingestion.

9. **Timeline queries leverage TimescaleDB chunk pruning.** When an investigator queries a time range, TimescaleDB skips entire 1-day chunks that fall outside the range. This keeps queries fast even over months of data.

**Transaction boundaries.** All database mutations in steps 3-8 execute within a single PostgreSQL transaction. If any step fails, the entire transaction rolls back, preventing orphaned raw events, events without correlation keys, or partial entity state.

---

## Crate Dependency Graph

```
st-server
  └── st-api
        ├── st-ingest
        │     ├── st-parser
        │     └── st-correlate
        ├── st-index
        ├── st-cases
        ├── st-store
        └── st-crypto

All crates depend on st-common (types, errors, config)
```

### Crate Responsibilities

| Crate | What it does |
|---|---|
| **st-common** | Shared types: `ForensicEvent`, `RawEvent`, `CorrelationKey`, error types, configuration structs. Every other crate depends on this. |
| **st-crypto** | BLAKE3 and SHA-256 hashing. Content integrity verification. Argon2 password/key hashing for auth. |
| **st-store** | Database connection pool management. SQL queries for all tables. Migration runner. TimescaleDB-specific SQL (hypertable creation, chunk management). |
| **st-parser** | Pluggable parser trait. Built-in parsers for JSON, CSV, syslog. Format auto-detection. Produces `ForensicEvent` from raw bytes. |
| **st-ingest** | Orchestrates the ingestion pipeline: receive -> hash -> store raw -> parse -> correlate -> store normalized. Batch processing. |
| **st-correlate** | Extracts correlation keys from parsed events. Strategies for identity, session, network, device, and host correlation. |
| **st-index** | Timeline query builder. Full-text search. Cursor-based pagination. Time-range filtering with chunk pruning. |
| **st-cases** | Case CRUD. Linking events to cases. Evidence export (JSON bundles, integrity manifests). |
| **st-api** | axum router. Request/response types. Authentication middleware (bearer tokens). Rate limiting middleware. All HTTP endpoint handlers. |
| **st-server** | Binary entry point. Reads config from `config/default.toml` and environment. Builds the application state. Starts the server with graceful shutdown on SIGTERM/SIGINT. |

---

## Database Schema

StreamTrace uses PostgreSQL 16 with the TimescaleDB extension. Tables marked with [hypertable] are converted to TimescaleDB hypertables, partitioned by time.

### raw_events [hypertable]

Immutable storage for raw event data. Never updated or deleted during normal operation.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Time-sortable unique ID |
| received_at | TIMESTAMPTZ | When StreamTrace received the event (partition key) |
| source | TEXT | Identifier for the ingestion source |
| content_type | TEXT | MIME type of the raw payload |
| raw_data | BYTEA | Original event bytes, exactly as received |
| blake3_hash | TEXT | BLAKE3 digest of raw_data |
| size_bytes | INTEGER | Size of raw_data |

Chunk interval: 1 day. Compression enabled after 7 days.

### events [hypertable]

Normalized forensic events, parsed from raw_events.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Time-sortable unique ID |
| raw_event_id | UUID | FK to raw_events -- links back to evidence |
| occurred_at | TIMESTAMPTZ | When the event happened (partition key) |
| observed_at | TIMESTAMPTZ | When the source system recorded it |
| received_at | TIMESTAMPTZ | When StreamTrace received it |
| event_type | TEXT | Structured type (e.g., `auth.login`, `deploy.start`) |
| source | TEXT | Originating system |
| severity | TEXT | Event severity level |
| actor | JSONB | Who performed the action |
| subject | JSONB | What was acted upon |
| object | JSONB | Additional object context |
| network | JSONB | Network context (IPs, ports, protocols) |
| device | JSONB | Device context (OS, browser, fingerprint) |
| metadata | JSONB | Arbitrary additional fields |
| search_vector | TSVECTOR | Full-text search index |

Chunk interval: 1 day.

### correlation_keys

Links events to searchable identifiers for cross-system correlation.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| event_id | UUID | FK to events |
| key_type | TEXT | Category: `identity`, `session`, `ip`, `device`, `host`, `custom` |
| key_value | TEXT | The actual value (e.g., `alice`, `203.0.113.10`) |
| created_at | TIMESTAMPTZ | Insertion time |

Indexed on `(key_type, key_value)` for fast correlation lookups.

### cases

Investigation containers that group related events.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| title | TEXT | Human-readable case title |
| description | TEXT | Case description and notes |
| status | TEXT | `open`, `investigating`, `closed` |
| created_at | TIMESTAMPTZ | Creation time |
| updated_at | TIMESTAMPTZ | Last modification |

### case_events

Join table linking events to cases with investigator annotations.

| Column | Type | Description |
|---|---|---|
| case_id | UUID | FK to cases |
| event_id | UUID | FK to events |
| pinned | BOOLEAN | Whether the event is pinned as key evidence |
| annotation | TEXT | Investigator notes on this event |
| added_at | TIMESTAMPTZ | When the event was added to the case |

### api_keys

Authentication credentials for API access.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| name | TEXT | Human-readable key name |
| key_hash | TEXT | Argon2 hash of the API key (plaintext never stored) |
| permissions | TEXT[] | Array of granted permissions |
| created_at | TIMESTAMPTZ | Creation time |
| expires_at | TIMESTAMPTZ | Optional expiry |
| revoked | BOOLEAN | Whether the key has been revoked |

### audit_log

Records security-relevant actions within StreamTrace itself.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| action | TEXT | What happened (`key.created`, `case.exported`, `event.ingested`) |
| actor | TEXT | Who did it (API key name or system) |
| details | JSONB | Additional context |
| created_at | TIMESTAMPTZ | When it happened |

### entities (Phase 2)

Resolved real-world objects discovered through event correlation.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| entity_type | TEXT | Category: `user`, `device`, `ip`, `host` |
| identifier | TEXT | Unique identifier within its type (e.g., username, IP address) |
| display_name | TEXT | Human-readable label |
| first_seen_at | TIMESTAMPTZ | Earliest event referencing this entity |
| last_seen_at | TIMESTAMPTZ | Most recent event referencing this entity |
| event_count | INTEGER | Number of linked events (denormalized for query performance) |
| attributes | JSONB | Additional entity metadata |

Unique constraint on `(entity_type, identifier)`.

### entity_relationships (Phase 2)

Connections between entities discovered through co-occurrence in events.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| source_entity | UUID | FK to entities |
| target_entity | UUID | FK to entities |
| relationship | TEXT | Relationship type (e.g., `logged_in_from`, `used_device`) |
| first_seen_at | TIMESTAMPTZ | Earliest co-occurrence |
| last_seen_at | TIMESTAMPTZ | Most recent co-occurrence |
| event_count | INTEGER | Number of events establishing this relationship |
| sample_event_id | UUID | FK to events -- representative event for this relationship |

### entity_events [hypertable] (Phase 2)

Links entities to events with role context. TimescaleDB hypertable partitioned on `occurred_at`.

| Column | Type | Description |
|---|---|---|
| entity_id | UUID | FK to entities |
| event_id | UUID | FK to events |
| role | TEXT | How the entity participated (e.g., `actor`, `target`, `source_ip`) |
| occurred_at | TIMESTAMPTZ | Event timestamp (partition key, denormalized from events) |

### sequence_patterns (Phase 2)

Defined patterns for behavioral sequence detection. Includes built-in patterns and custom user-defined patterns.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| name | TEXT | Pattern name (e.g., `brute_force_login`) |
| description | TEXT | Human-readable description of what this pattern detects |
| definition | JSONB | Pattern definition: ordered event type list, time windows, thresholds |
| enabled | BOOLEAN | Whether the pattern is active for detection |

### detected_sequences (Phase 2)

Instances of sequence patterns matched against ingested events.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| pattern_id | UUID | FK to sequence_patterns |
| pattern_name | TEXT | Denormalized pattern name for query convenience |
| event_ids | UUID[] | Ordered array of event IDs that form this sequence |
| actor_id | TEXT | Identity of the actor performing the sequence |
| started_at | TIMESTAMPTZ | Timestamp of the first event in the sequence |
| ended_at | TIMESTAMPTZ | Timestamp of the last event in the sequence |
| confidence | REAL | Confidence score (0.0 to 1.0) |

### legal_holds (Phase 3)

Active legal holds that prevent data deletion during retention enforcement.

| Column | Type | Description |
|---|---|---|
| id | UUID (v7) | Primary key |
| name | TEXT | Human-readable hold name |
| description | TEXT | Reason for the hold |
| hold_type | TEXT | Hold scope: `case`, `entity`, `time_range`, `query` |
| criteria | JSONB | Hold criteria: case IDs, entity IDs, time ranges, or search queries |
| status | TEXT | `active`, `released`, `expired` |
| created_by | TEXT | Identity of the actor who created the hold |
| created_at | TIMESTAMPTZ | Creation time |
| released_at | TIMESTAMPTZ | When the hold was released (NULL if active) |
| expires_at | TIMESTAMPTZ | Optional automatic expiry |

### hold_events (Phase 3)

Junction table linking legal holds to preserved events. Prevents deletion of held events during retention pruning.

| Column | Type | Description |
|---|---|---|
| hold_id | UUID | FK to legal_holds |
| event_id | UUID | FK to events |
| raw_event_id | UUID | FK to raw_events |

---

## Triple Timestamp Model

Every event in StreamTrace carries three timestamps:

| Timestamp | Meaning | Example |
|---|---|---|
| **occurred_at** | When the event actually happened in the real world | User clicked "login" at 14:03:01 |
| **observed_at** | When the source system recorded or emitted the event | Auth service logged it at 14:03:02 |
| **received_at** | When StreamTrace received and stored the event | Ingested via API at 14:05:30 |

Why this matters:

- **Clock skew.** Source systems have different clocks. `occurred_at` may be unreliable; `received_at` is always accurate from StreamTrace's perspective.
- **Delayed ingestion.** Events may arrive hours or days after they occurred. The gap between `occurred_at` and `received_at` reveals ingestion lag.
- **Evidence integrity.** `received_at` is set by StreamTrace, never by the client. It establishes when the evidence entered the system.
- **Timeline reconstruction.** Investigators can sort by any of the three timestamps to get different views of the same events.

The `events` hypertable is partitioned on `occurred_at` because most investigative queries are "what happened between time X and time Y."

---

## Security Model

### Authentication

- API access requires a Bearer token in the `Authorization` header.
- Tokens are validated by computing their Argon2 hash and comparing against `api_keys.key_hash`.
- Comparison is timing-safe to prevent timing attacks.
- Keys can have expiry dates and can be revoked.
- Plaintext keys are never stored.

### Authorization

- Each API key has a `permissions` array (e.g., `["ingest", "query", "cases.write"]`).
- Endpoints check permissions before processing requests.
- Principle of least privilege: an ingestion-only key cannot query the timeline or export cases.

### Rate Limiting

- Per-key rate limiting using a token bucket algorithm.
- Default: 100 requests/second with burst to 200.
- Configurable per deployment in `config/default.toml`.
- Returns `429 Too Many Requests` with `Retry-After` header.

### Input Validation

- All request bodies are size-limited (`request_body_limit_bytes`).
- Individual events are size-limited (`max_event_size_bytes`).
- JSON deserialization uses strict mode: unknown fields are rejected.
- SQL queries use parameterized binds exclusively. No string interpolation.

### Immutable Evidence

- `raw_events` rows are insert-only. No UPDATE or DELETE in normal operation.
- BLAKE3 hashes provide content integrity verification.
- The `audit_log` records all significant actions for accountability.

### CORS

- Allowed origins are configurable via the `cors_allowed_origins` setting in `config/default.toml`.
- Empty list = any origin allowed (development only).
- Production deployments must restrict allowed origins to the actual frontend domain(s).
- Preflight responses include `Access-Control-Max-Age` to reduce OPTIONS overhead.

### Evidence Signing

- Ed25519 signing key loaded from the `ST_SIGNING_KEY_HEX` environment variable (hex-encoded, 32 bytes).
- If `ST_SIGNING_KEY_HEX` is not set, an ephemeral key pair is generated on each startup.
- Ephemeral keys mean evidence bundles cannot be verified after process restart.
- The public key is logged at startup so verifiers can record it.
- Evidence bundles include the signature, public key, and a BLAKE3 manifest of all included events.

### Audit Logging

- Security-relevant operations are logged to the `audit_log` table with actor identity and operation details.
- Audited operations include: case CRUD, legal hold management, evidence bundle generation, event ingestion, sequence scans, and API key lifecycle events.
- Audit entries are append-only and include the API key name (or `system` for automated operations) as the actor.
- Audit log contents are queryable via the `/v1/audit` endpoint (requires appropriate permissions).

---

## API Endpoints

StreamTrace exposes 31 HTTP endpoints. All `/v1/` endpoints require a Bearer token in the `Authorization` header. Read endpoints require `Read` permission; write endpoints require `Write` permission.

### Health (unauthenticated)

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Liveness probe. Returns 200 if the process is running. |
| GET | `/readyz` | Readiness probe. Returns 200 if the database is reachable. |

### Ingestion

| Method | Path | Description |
|---|---|---|
| POST | `/v1/ingest/events` | Ingest one or more structured events. |
| POST | `/v1/ingest/raw` | Ingest raw bytes (parser auto-detects format). |

### Timeline and Search

| Method | Path | Description |
|---|---|---|
| GET | `/v1/timeline` | Query events by time range with cursor-based pagination. |
| GET | `/v1/search` | Full-text search over event content. |
| GET | `/v1/replay` | Server-Sent Events (SSE) stream replaying events in chronological order. |

### Events

| Method | Path | Description |
|---|---|---|
| GET | `/v1/events/{id}` | Get a single normalized event by ID. |
| GET | `/v1/events/{id}/raw` | Get the raw event bytes for a normalized event. |
| GET | `/v1/events/{id}/correlated` | Get all events sharing correlation keys with this event. |

### Entities

| Method | Path | Description |
|---|---|---|
| GET | `/v1/entities` | List entities with filtering by type. |
| GET | `/v1/entities/{id}` | Get a single entity with attributes and statistics. |
| GET | `/v1/entities/{id}/timeline` | Get events associated with an entity, ordered by time. |
| GET | `/v1/entities/{id}/graph` | Get the relationship graph for an entity. |

### Correlation

| Method | Path | Description |
|---|---|---|
| GET | `/v1/correlate/chain` | Build a correlation chain from a starting event or key. |
| POST | `/v1/correlate/search` | Search for events matching multiple correlation criteria. |

### Sequences

| Method | Path | Description |
|---|---|---|
| GET | `/v1/sequences/patterns` | List all sequence patterns (built-in and custom). |
| GET | `/v1/sequences/detected` | List detected sequence instances. |
| POST | `/v1/sequences/scan` | Trigger a manual sequence scan over a time range. |

### Cases

| Method | Path | Description |
|---|---|---|
| POST | `/v1/cases` | Create a new investigation case. |
| GET | `/v1/cases` | List cases with filtering by status. |
| GET | `/v1/cases/{id}` | Get a single case with linked events. |
| PATCH | `/v1/cases/{id}` | Update case title, description, or status. |
| POST | `/v1/cases/{id}/events` | Add events to a case. |
| DELETE | `/v1/cases/{id}/events/{event_id}` | Remove an event from a case. |
| PATCH | `/v1/cases/{id}/events/{event_id}` | Update event annotation or pinned status within a case. |
| GET | `/v1/cases/{id}/export` | Export case as a structured JSON report. |

### Evidence Bundles

| Method | Path | Description |
|---|---|---|
| POST | `/v1/cases/{id}/bundle` | Generate a signed evidence bundle for a case. |
| POST | `/v1/bundles/verify` | Verify the integrity and signature of an evidence bundle. |

### Legal Holds

| Method | Path | Description |
|---|---|---|
| POST | `/v1/holds` | Create a legal hold. |
| GET | `/v1/holds` | List legal holds with filtering by status. |
| GET | `/v1/holds/{id}` | Get a single legal hold with criteria and statistics. |
| POST | `/v1/holds/{id}/release` | Release a legal hold (events become eligible for retention pruning). |
| POST | `/v1/holds/{id}/materialize` | Materialize held events into the `hold_events` junction table. |

### Audit

| Method | Path | Description |
|---|---|---|
| GET | `/v1/audit` | Query the audit log with filtering by action, actor, and time range. |

---

## Key Design Decisions

### UUIDv7 for IDs

UUIDv7 encodes a millisecond timestamp in the high bits, making IDs naturally time-sortable. This means:
- B-tree indexes on UUID columns are clustered by time.
- ID-based ordering matches chronological ordering.
- No need for a separate auto-increment column.
- IDs are globally unique across distributed deployments.

### BLAKE3 over SHA-256 for content hashing

BLAKE3 is approximately 3x faster than SHA-256 on modern hardware and supports parallelism for large inputs. It is cryptographically secure and standardized. Since StreamTrace hashes every incoming event, hashing speed directly affects ingestion throughput.

SHA-256 is also available in `st-crypto` for interoperability with systems that require it.

### Separate raw_events and events tables

`raw_events` stores the original bytes exactly as received. `events` stores the parsed, normalized representation. This separation means:
- Parsing bugs never destroy evidence.
- Re-parsing is always possible from raw data.
- Raw data integrity is independently verifiable via BLAKE3 hash.
- The normalized view can evolve without migrating evidence.

### Cursor-based pagination over offset

Offset pagination (`LIMIT 50 OFFSET 1000`) is O(n) in PostgreSQL -- the database must scan and discard 1000 rows. Cursor-based pagination (`WHERE occurred_at < $cursor ORDER BY occurred_at DESC LIMIT 50`) uses the index directly and performs consistently regardless of page depth.

For timeline queries over potentially millions of events, this is a hard requirement.

### TimescaleDB hypertables with 1-day chunks

TimescaleDB partitions hypertables into chunks by time range. With 1-day chunks:
- Queries for "last 2 hours" only scan today's chunk.
- Queries for "last week" scan 7 chunks instead of the entire table.
- Old chunks can be compressed (10x space reduction) or dropped independently.
- Maintenance operations (VACUUM, reindex) operate on small chunks.

### axum over actix-web

axum is built on tower, which provides composable middleware (rate limiting, tracing, compression, CORS) as reusable layers. The tower ecosystem is well-maintained and integrates cleanly with the broader tokio stack. axum's extractor pattern maps naturally to request validation.

### sqlx over an ORM

StreamTrace uses TimescaleDB-specific SQL features (hypertable creation, chunk management, `time_bucket` aggregations) that ORMs cannot express. sqlx provides compile-time query checking against the actual database schema while giving full control over the SQL. The trade-off is more verbose code, but the queries are explicit and auditable.
