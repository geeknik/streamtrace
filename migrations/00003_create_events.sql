-- 00003_create_events.sql
--
-- Normalized forensic events -- the central analytical table in StreamTrace.
--
-- Each row represents a single security-relevant event extracted from a raw
-- payload. The schema follows a "who did what to whom" model:
--
--   actor   -- the entity performing the action (user, service, IP)
--   subject -- the entity being acted upon (user account, resource)
--   object  -- the thing involved (file, URL, process, token)
--
-- Triple-timestamp model:
--   occurred_at  -- when the event actually happened (source clock)
--   observed_at  -- when the source system recorded it (collector clock)
--   received_at  -- when StreamTrace ingested it (our clock)
--
-- This separation is critical for forensic accuracy: source clocks may be
-- skewed or manipulated, so we preserve all three for correlation analysis.
--
-- Hypertable partitioned on occurred_at (1-day chunks) because most queries
-- filter by "when did this happen" rather than "when did we receive it".

CREATE TABLE events (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    raw_event_id    UUID        NOT NULL, -- references raw_events(id), no FK on hypertable
    event_type      TEXT        NOT NULL,
    severity        SMALLINT    NOT NULL DEFAULT 0,

    -- Triple timestamp model
    occurred_at     TIMESTAMPTZ NOT NULL,
    observed_at     TIMESTAMPTZ,
    received_at     TIMESTAMPTZ NOT NULL,

    -- Actor (who did it)
    actor_id        TEXT,
    actor_name      TEXT,
    actor_type      TEXT,

    -- Subject (who/what was acted upon)
    subject_id      TEXT,
    subject_type    TEXT,
    subject_name    TEXT,

    -- Object (the thing involved)
    object_id       TEXT,
    object_type     TEXT,
    object_name     TEXT,

    -- Network context
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,

    -- Device context
    device_id       TEXT,
    device_name     TEXT,
    device_type     TEXT,
    hostname        TEXT,

    -- Source attribution
    source_id       TEXT        NOT NULL,
    source_type     TEXT        NOT NULL,
    source_name     TEXT,

    -- Metadata
    tags            TEXT[]      DEFAULT '{}',
    custom_fields   JSONB       DEFAULT '{}',
    search_text     TSVECTOR
);

-- Convert to hypertable: 1-day chunks on occurred_at.
SELECT create_hypertable('events', 'occurred_at', chunk_time_interval => INTERVAL '1 day');

-- Primary query pattern: filter by event type within a time window.
CREATE INDEX idx_events_type_time
    ON events (event_type, occurred_at DESC);

-- Actor-centric investigations: "show me everything this actor did".
CREATE INDEX idx_events_actor_time
    ON events (actor_id, occurred_at DESC);

-- Source-centric queries: "show me everything from this log source".
CREATE INDEX idx_events_source_time
    ON events (source_id, occurred_at DESC);

-- Network investigations: partial index to avoid indexing rows without IPs.
CREATE INDEX idx_events_src_ip_time
    ON events (src_ip, occurred_at DESC)
    WHERE src_ip IS NOT NULL;

-- Full-text search on the composite tsvector column.
CREATE INDEX idx_events_search_text
    ON events USING GIN (search_text);

-- Tag-based filtering: "find all events tagged 'malware'".
CREATE INDEX idx_events_tags
    ON events USING GIN (tags);

-- JSONB path queries on custom_fields for ad-hoc filtering.
-- jsonb_path_ops is more compact and faster for containment (@>) queries.
CREATE INDEX idx_events_custom_fields
    ON events USING GIN (custom_fields jsonb_path_ops);

-- Trigger function: automatically build the search_text tsvector from
-- key identifiers. This keeps search_text in sync without application
-- logic and ensures every INSERT/UPDATE path populates it consistently.
--
-- Weight assignment:
--   A (highest) -- event_type, source_id: primary classification fields
--   B           -- actor and subject identifiers: investigation targets
--   C           -- object identifiers, hostname, source_name: supporting context
CREATE OR REPLACE FUNCTION fn_events_update_search_text()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_text :=
        setweight(to_tsvector('simple', COALESCE(NEW.event_type, '')), 'A') ||
        setweight(to_tsvector('simple', COALESCE(NEW.source_id, '')), 'A') ||
        setweight(to_tsvector('simple', COALESCE(NEW.actor_id, '')), 'B') ||
        setweight(to_tsvector('simple', COALESCE(NEW.actor_name, '')), 'B') ||
        setweight(to_tsvector('simple', COALESCE(NEW.subject_id, '')), 'B') ||
        setweight(to_tsvector('simple', COALESCE(NEW.subject_name, '')), 'B') ||
        setweight(to_tsvector('simple', COALESCE(NEW.object_id, '')), 'C') ||
        setweight(to_tsvector('simple', COALESCE(NEW.object_name, '')), 'C') ||
        setweight(to_tsvector('simple', COALESCE(NEW.source_name, '')), 'C') ||
        setweight(to_tsvector('simple', COALESCE(NEW.hostname, '')), 'C');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_events_search_text
    BEFORE INSERT OR UPDATE ON events
    FOR EACH ROW
    EXECUTE FUNCTION fn_events_update_search_text();
