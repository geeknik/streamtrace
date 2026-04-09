-- 00012_create_sequence_patterns.sql
--
-- Sequence patterns define ordered event-type steps that, when matched
-- in chronological order within a bounded time window, indicate a
-- behavioural pattern of interest (e.g. data exfiltration, brute force).

CREATE TABLE sequence_patterns (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    definition  JSONB NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
