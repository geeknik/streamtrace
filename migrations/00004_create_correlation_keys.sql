-- 00004_create_correlation_keys.sql
--
-- Correlation keys for linking related events across sources and time.
--
-- During normalization, each event may produce zero or more correlation keys.
-- A correlation key is a typed (key_type, key_value) pair that connects events
-- sharing a common identifier. Examples:
--
--   key_type='session_id'   key_value='abc-123'
--   key_type='ip'           key_value='10.0.0.5'
--   key_type='user_email'   key_value='alice@example.com'
--   key_type='file_hash'    key_value='sha256:deadbeef...'
--
-- This is a many-to-many bridge: one event can have many keys, and one key
-- value can appear across many events. The primary query pattern is:
--   "Given key_type=X and key_value=Y, find all events in time range T."
--
-- Hypertable partitioned on occurred_at (1-day chunks) to align with the
-- events table and support efficient time-bounded correlation lookups.
--
-- NOTE: Foreign keys to hypertable columns are not supported by TimescaleDB,
-- so event_id is not constrained with REFERENCES. Referential integrity is
-- enforced at the application layer during ingestion (single transaction).

CREATE TABLE correlation_keys (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY,
    event_id    UUID        NOT NULL,
    key_type    TEXT        NOT NULL,
    key_value   TEXT        NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

-- Convert to hypertable: 1-day chunks on occurred_at.
SELECT create_hypertable('correlation_keys', 'occurred_at', chunk_time_interval => INTERVAL '1 day');

-- Primary correlation query: "find all events matching this key in a time range."
-- DESC ordering supports the common "most recent first" access pattern.
CREATE INDEX idx_correlation_keys_lookup
    ON correlation_keys (key_type, key_value, occurred_at DESC);

-- Reverse lookup: "what correlation keys does this event have?"
CREATE INDEX idx_correlation_keys_event
    ON correlation_keys (event_id);
