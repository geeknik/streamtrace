-- 00006_create_case_events.sql
--
-- Junction table linking events to investigation cases.
--
-- Analysts attach events to a case during investigation. Each attachment
-- can optionally be pinned (for key evidence) and annotated with free-text
-- notes explaining relevance.
--
-- Standard table (not hypertable) because:
--   1. Volume follows cases, not event ingestion rate.
--   2. Requires FK to cases for cascade deletion.
--   3. Requires UNIQUE constraint for deduplication.
--
-- NOTE: event_id cannot reference events(id) with a foreign key because
-- events is a TimescaleDB hypertable. Referential integrity for event_id
-- is enforced at the application layer.

CREATE TABLE case_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     UUID        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_id    UUID        NOT NULL,
    pinned      BOOLEAN     NOT NULL DEFAULT false,
    annotation  TEXT        DEFAULT '',
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by    TEXT        NOT NULL,

    -- Prevent the same event from being added to a case twice.
    UNIQUE (case_id, event_id)
);

-- Case detail view: list all events in a case.
CREATE INDEX idx_case_events_case
    ON case_events (case_id);
