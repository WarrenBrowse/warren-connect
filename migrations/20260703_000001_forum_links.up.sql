-- The only persisted pubkey <-> forum-handle linkage. Support-side tool;
-- never exposed publicly. Sensitive by design: access = this service +
-- WebAuthn-gated admin lookups.
CREATE TABLE IF NOT EXISTS forum_links (
    external_id   TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    pubkey_ss58   TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
