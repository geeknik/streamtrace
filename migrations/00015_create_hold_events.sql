-- Junction table linking legal holds to specific events.
-- Prevents deletion of held events regardless of retention policy.

CREATE TABLE hold_events (
    hold_id         UUID NOT NULL REFERENCES legal_holds(id) ON DELETE CASCADE,
    event_id        UUID NOT NULL,
    raw_event_id    UUID NOT NULL,
    PRIMARY KEY (hold_id, event_id)
);

CREATE INDEX idx_hold_events_event ON hold_events (event_id);
CREATE INDEX idx_hold_events_raw_event ON hold_events (raw_event_id);
