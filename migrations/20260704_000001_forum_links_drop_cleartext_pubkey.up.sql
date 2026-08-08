-- Drop the cleartext wallet from the only place warren-connect stored one.
-- external_id is already HMAC-SHA256(handle_secret, pubkey) in hex (see
-- src/handle.rs): a keyed, one-way, per-wallet identifier and the table's
-- primary key. It is the uniqueness gate, and the pubkey -> handle lookup
-- re-derives external_id from the wallet presented at login, so the cleartext
-- pubkey_ss58 column (never purged, reversible) is redundant. Removing it
-- means a DB seizure yields keyed hashes and public handles, never wallets.
ALTER TABLE forum_links DROP COLUMN pubkey_ss58;
