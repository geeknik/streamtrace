-- 00011_create_entity_events.sql
--
-- Links entities to the events where they were observed.
-- Hypertable for time-range queries: "show all events for entity X
-- in the last hour."
--
-- Uses a composite primary key including occurred_at to satisfy
-- TimescaleDB's requirement that the partitioning column appear
-- in all unique constraints.

CREATE TABLE entity_events (
    entity_id   UUID        NOT NULL,
    event_id    UUID        NOT NULL,
    role        TEXT        NOT NULL
                            CHECK (role IN (
                                'actor', 'subject', 'object',
                                'src_ip', 'dst_ip', 'device', 'host'
                            )),
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (entity_id, event_id, occurred_at)
);

SELECT create_hypertable('entity_events', 'occurred_at',
    chunk_time_interval => INTERVAL '1 day');

-- Entity timeline: all events for a given entity, newest first.
CREATE INDEX idx_entity_events_entity
    ON entity_events (entity_id, occurred_at DESC);

-- Reverse lookup: which entities are linked to a given event.
CREATE INDEX idx_entity_events_event
    ON entity_events (event_id);
