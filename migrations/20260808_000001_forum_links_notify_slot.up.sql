-- Slot each account occupies in the broadcast forum-activity digest.
--
-- Assigned at random on first login and never reused, including after the
-- retention sweep deletes the row: a freed slot handed to another account
-- would give that account the previous holder's badge. UNIQUE is what makes
-- the random allocation safe under concurrent logins.
--
-- The value is anonymous by construction. It is not derived from the wallet
-- nor from the handle, so the published digest cannot be mapped back onto a
-- forum name by anyone lacking this table.
ALTER TABLE forum_links ADD COLUMN notify_slot INTEGER UNIQUE;

-- Slots consumed by rows that no longer exist. The allocator reads this to
-- avoid handing out a slot whose previous holder may still be published in a
-- digest, or still on a device that never logged in again.
CREATE TABLE IF NOT EXISTS forum_slots_retired (
    notify_slot INTEGER PRIMARY KEY,
    retired_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
