-- 00010_create_entity_relationships.sql
--
-- Tracks relationships between entities discovered through co-occurrence
-- in events. E.g., user "alice" used device "macbook-42", user "alice"
-- connected from IP "10.0.0.1".
--
-- Relationship labels are constrained to a known set to prevent unbounded
-- cardinality from adversarial input.

CREATE TABLE entity_relationships (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_entity   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship    TEXT        NOT NULL
                                CHECK (relationship IN (
                                    'used_device', 'from_ip', 'in_session',
                                    'accessed', 'authenticated_as', 'hosted_on',
                                    'communicated_with'
                                )),
    first_seen_at   TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL,
    event_count     INTEGER     NOT NULL DEFAULT 1,
    sample_event_id UUID,
    UNIQUE (source_entity, target_entity, relationship)
);

-- Traverse outbound edges from an entity.
CREATE INDEX idx_entity_rel_source
    ON entity_relationships (source_entity);

-- Traverse inbound edges to an entity.
CREATE INDEX idx_entity_rel_target
    ON entity_relationships (target_entity);

-- Filter by relationship type.
CREATE INDEX idx_entity_rel_type
    ON entity_relationships (relationship);
