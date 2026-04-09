-- 00005_create_cases.sql
--
-- Investigation cases for grouping related events into a forensic workspace.
--
-- A case represents an active investigation, incident, or export bundle.
-- Analysts create cases, attach events (via case_events), annotate them,
-- and move the case through a lifecycle:
--
--   open -> closed -> exported -> archived
--
-- Cases are a standard (non-hypertable) table because:
--   1. Volume is low (hundreds to thousands, not millions).
--   2. They are mutable (status changes, description updates).
--   3. They serve as FK targets for case_events.

CREATE TABLE cases (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    description TEXT        DEFAULT '',
    status      TEXT        NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'closed', 'exported', 'archived')),
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Filter cases by lifecycle status (most queries filter on status='open').
CREATE INDEX idx_cases_status
    ON cases (status);
