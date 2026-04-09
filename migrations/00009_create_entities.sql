-- 00009_create_entities.sql
--
-- Entities represent real-world objects observed across events:
-- users, devices, IP addresses, hosts, sessions, services.
-- Entity resolution merges observations into canonical records.
--
-- This is a standard (non-hypertable) table because:
--   1. Volume is moderate (thousands to low millions).
--   2. Entities are mutable (last_seen_at, event_count updates).
--   3. They serve as FK targets for entity_relationships.

CREATE TABLE entities (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type     TEXT        NOT NULL
                                CHECK (entity_type IN (
                                    'user', 'device', 'ip', 'host',
                                    'session', 'service'
                                )),
    identifier      TEXT        NOT NULL,
    display_name    TEXT,
    first_seen_at   TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL,
    event_count     INTEGER     NOT NULL DEFAULT 1,
    attributes      JSONB       NOT NULL DEFAULT '{}',
    UNIQUE (entity_type, identifier)
);

-- Filter by type (e.g. "show all user entities").
CREATE INDEX idx_entities_type
    ON entities (entity_type);

-- Lookup by canonical identifier (e.g. "find the entity for IP 10.0.0.1").
CREATE INDEX idx_entities_identifier
    ON entities (identifier);

-- Order by most recently active.
CREATE INDEX idx_entities_last_seen
    ON entities (last_seen_at DESC);
