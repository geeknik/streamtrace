-- 00013_create_detected_sequences.sql
--
-- Records detected instances of sequence patterns found by the
-- sequence detector. Each row links back to a pattern and stores the
-- matching event IDs, actor, time range, and confidence.

CREATE TABLE detected_sequences (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_id      UUID NOT NULL REFERENCES sequence_patterns(id) ON DELETE CASCADE,
    pattern_name    TEXT NOT NULL,
    event_ids       UUID[] NOT NULL,
    actor_id        TEXT,
    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ NOT NULL,
    confidence      REAL NOT NULL DEFAULT 1.0,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_detected_seq_pattern ON detected_sequences (pattern_id);
CREATE INDEX idx_detected_seq_time    ON detected_sequences (detected_at DESC);
CREATE INDEX idx_detected_seq_actor   ON detected_sequences (actor_id)
    WHERE actor_id IS NOT NULL;
