-- 00007_create_api_keys.sql
--
-- API key management for authenticating external clients.
--
-- Keys are stored as Argon2 hashes -- the plaintext key is shown exactly
-- once at creation time and never persisted. The key_prefix (first 8 chars)
-- is stored in cleartext for identification and log correlation without
-- exposing the full key.
--
-- Permission model uses a text array for simplicity. Valid permissions are
-- enforced at the application layer (e.g., 'read', 'write', 'admin').
--
-- Standard table (not hypertable) because volume is very low and rows are
-- mutable (active flag, last_used_at updates).
--
-- Security notes:
--   - key_hash uses Argon2id (application layer) -- not stored as plaintext.
--   - key_prefix is safe to log and display; it cannot recover the full key.
--   - expires_at is nullable: NULL means no expiration (discouraged).
--   - Inactive keys (active=false) are excluded from the lookup index.

CREATE TABLE api_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    key_hash    TEXT        NOT NULL,       -- Argon2id hash of the full API key
    key_prefix  TEXT        NOT NULL,       -- First 8 characters for identification
    permissions TEXT[]      NOT NULL DEFAULT '{read,write}',
    active      BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ
);

-- Authentication lookup: find the key record by prefix, but only for active keys.
-- Partial index keeps the index small and excludes revoked keys entirely.
CREATE INDEX idx_api_keys_prefix_active
    ON api_keys (key_prefix)
    WHERE active = true;
