-- Re-add the column (schema only; the dropped cleartext wallets are not
-- recoverable, by design). Nullable so the down migration runs on existing rows.
ALTER TABLE forum_links ADD COLUMN pubkey_ss58 TEXT UNIQUE;
