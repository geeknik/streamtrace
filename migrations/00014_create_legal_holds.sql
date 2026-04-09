-- Legal holds for evidence preservation.
-- A hold prevents deletion of events matching its criteria until released.

CREATE TABLE legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    hold_type       TEXT NOT NULL CHECK (hold_type IN ('time_range', 'entity', 'case', 'query')),
    criteria        JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'released', 'expired')),
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ
);

CREATE INDEX idx_legal_holds_status ON legal_holds (status);
CREATE INDEX idx_legal_holds_created_at ON legal_holds (created_at);
