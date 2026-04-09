-- 00002_create_raw_events.sql
--
-- Immutable evidence store for raw ingested payloads.
--
-- Every event received by StreamTrace is first persisted here in its original
-- byte-exact form before any parsing or normalization. This guarantees:
--
--   1. Chain of custody -- the original payload is always recoverable.
--   2. Re-parseability -- if parser logic changes, raw data can be replayed.
--   3. Integrity verification -- content_hash (BLAKE3) allows tamper detection.
--
-- This table is a TimescaleDB hypertable partitioned on received_at (1-day
-- chunks) to support efficient time-range scans and retention policies.
--
-- Rows in this table MUST NOT be updated or deleted under normal operation.
-- Retention is managed exclusively via TimescaleDB drop_chunks policies.

CREATE TABLE raw_events (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    content         BYTEA       NOT NULL,
    content_hash    TEXT        NOT NULL,           -- BLAKE3 hex digest
    content_type    TEXT        NOT NULL DEFAULT 'application/json',
    source_id       TEXT        NOT NULL,
    source_type     TEXT        NOT NULL,
    source_name     TEXT,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    parser_id       TEXT,
    byte_size       INTEGER     NOT NULL

    -- No CHECK on byte_size > 0 here; the application layer enforces that
    -- before insertion. Keeping the schema minimal reduces write overhead.
);

-- TimescaleDB hypertables require unique indexes to include the partitioning
-- column. We use (id, received_at) as the composite PK instead of id alone.

-- Convert to hypertable: 1-day chunks on received_at.
-- Hypertables cannot use standard foreign keys as targets, which is why
-- downstream tables (events, correlation_keys) reference raw_events.id
-- without FK enforcement where TimescaleDB restrictions apply.
SELECT create_hypertable('raw_events', 'received_at', chunk_time_interval => INTERVAL '1 day');

-- Deduplication lookups: find an existing raw event by its content hash.
CREATE INDEX idx_raw_events_content_hash
    ON raw_events (content_hash);

-- Source-based queries: list all raw events from a given source.
CREATE INDEX idx_raw_events_source
    ON raw_events (source_id, source_type);
