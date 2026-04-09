-- 00008_create_audit_log.sql
--
-- Append-only audit log for tracking administrative and security-relevant
-- actions within StreamTrace itself.
--
-- This is distinct from the events table: events store external security
-- data, while audit_log tracks internal platform operations such as:
--
--   - API key creation/revocation
--   - Case lifecycle transitions
--   - User authentication attempts
--   - Configuration changes
--   - Data export/deletion operations
--
-- Hypertable with 7-day chunks because:
--   1. Audit volume is lower than event ingestion but still unbounded.
--   2. Longer chunks reduce chunk management overhead for lower-volume data.
--   3. Retention policies can drop old chunks efficiently.
--
-- Rows in this table MUST NOT be updated or deleted under normal operation.
-- Retention is managed exclusively via TimescaleDB drop_chunks policies.
--
-- The detail column stores structured context as JSONB but is intentionally
-- NOT indexed -- audit queries filter by action and time, then inspect
-- detail in application code. This avoids index bloat on a write-heavy table.

CREATE TABLE audit_log (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY,
    action      TEXT        NOT NULL,
    actor       TEXT        NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    detail      JSONB       DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Convert to hypertable: 7-day chunks on occurred_at.
SELECT create_hypertable('audit_log', 'occurred_at', chunk_time_interval => INTERVAL '7 days');

-- Primary query pattern: filter by action type within a time window.
CREATE INDEX idx_audit_log_action_time
    ON audit_log (action, occurred_at DESC);
