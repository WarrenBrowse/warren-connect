//! The broadcast forum-activity digest: how many slots to publish, and how
//! to lay the unread counts out across them.
//!
//! The digest is ONE document, identical for every client, holding one
//! unread count per slot. A client reads its own slot out of it, so the
//! service never learns which account anybody is asking about. Everything
//! here is the arithmetic of that layout; the signature and the wire form
//! belong to warren-core and `warren-discovery-core`.

use std::collections::HashMap;
use std::sync::Mutex;

/// How far back an unread notification still earns a badge. Past that it
/// stops meaning anything to the reader, and the bound is also what keeps
/// the Discourse-side scan proportional to recent activity.
pub const MAX_UNREAD_AGE_DAYS: i32 = 90;

/// Slots are published in blocks, so the document's length moves in steps
/// rather than tracking the account count. A length that grew by one on
/// every registration would publish the registration itself.
const SLOT_BLOCK: usize = 1024;

/// Fraction of published slots the allocator is willing to fill. Random
/// allocation into a half-empty range costs about two attempts at worst,
/// where a nearly full range degrades into coupon collecting.
const LOAD_FACTOR: usize = 2;

/// Number of slots the digest publishes when `links` accounts are
/// registered. Always a whole number of blocks, and never zero, so a forum
/// with no accounts still publishes a well-formed document.
#[must_use]
pub fn published_slots(links: usize) -> usize {
    let wanted = links.saturating_mul(LOAD_FACTOR).max(1);
    wanted.div_ceil(SLOT_BLOCK).saturating_mul(SLOT_BLOCK)
}

/// Lays `unread` (slot -> count) out across `slots` positions.
///
/// A slot outside the published range is dropped rather than extending the
/// document: the range is chosen from the account count, so an out-of-range
/// slot means the two disagree for a moment, and a short-lived missing badge
/// is the harmless side of that.
#[must_use]
pub fn assemble(slots: usize, unread: &HashMap<i32, u32>) -> Vec<u32> {
    let mut counts = vec![0_u32; slots];
    for (slot, count) in unread {
        if let Ok(index) = usize::try_from(*slot)
            && index < slots
        {
            counts[index] = *count;
        }
    }
    counts
}

/// Maps Discourse's per-username unread counts onto digest slots.
///
/// A username Discourse reports but this service has no slot for is dropped:
/// it is an account that reached the forum by some path other than a wallet
/// login, and it has no device waiting for a badge.
#[must_use]
pub fn join_unread(slots: &[(String, i32)], unread: &[(String, i64)]) -> HashMap<i32, u32> {
    let by_username: HashMap<&str, i32> = slots
        .iter()
        .map(|(username, slot)| (username.as_str(), *slot))
        .collect();
    unread
        .iter()
        .filter_map(|(username, count)| {
            let slot = by_username.get(username.as_str())?;
            let count = u32::try_from(*count).ok()?;
            Some((*slot, count))
        })
        .collect()
}

/// Content-derived generation for the published document.
///
/// The generation only moves when the counts actually change, so a quiet
/// forum keeps answering the same document and every client's conditional
/// GET stays a bare header round trip. It is still strictly monotonic, which
/// is what stops a captured older document from resurrecting a badge the
/// reader already cleared.
#[derive(Debug, Default)]
pub struct GenerationStamp {
    last: Mutex<Option<(Vec<u32>, u64)>>,
}

impl GenerationStamp {
    /// Generation for `counts` at `now`, unchanged while the counts are.
    ///
    /// # Panics
    /// Panics only if a previous holder of the lock panicked while stamping,
    /// which this crate's `panic = "abort"` release profile makes impossible.
    #[must_use]
    pub fn stamp(&self, counts: &[u32], now: u64) -> u64 {
        let mut last = self.last.lock().expect("generation stamp lock poisoned");
        match last.as_ref() {
            Some((previous, generation)) if previous == counts => *generation,
            Some((_, generation)) => {
                // Never trust the clock to move forward: a backwards step
                // would publish a generation an client already rejects.
                let next = now.max(generation.saturating_add(1));
                *last = Some((counts.to_vec(), next));
                next
            }
            None => {
                *last = Some((counts.to_vec(), now));
                now
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_forum_still_publishes_one_whole_block() {
        assert_eq!(
            published_slots(0),
            SLOT_BLOCK,
            "a well-formed document must exist before the first account does"
        );
    }

    #[test]
    fn the_published_length_moves_in_blocks_not_per_registration() {
        assert_eq!(
            published_slots(400),
            published_slots(401),
            "a length that tracked the account count would publish each registration"
        );
    }

    #[test]
    fn the_range_grows_once_it_would_pass_the_load_factor() {
        assert_eq!(published_slots(512), SLOT_BLOCK, "512 accounts fill half");
        assert_eq!(
            published_slots(513),
            2 * SLOT_BLOCK,
            "one account past half the block opens the next one"
        );
    }

    #[test]
    fn a_slot_reads_back_the_count_it_was_given() {
        let unread = HashMap::from([(3, 5_u32), (0, 1)]);

        let counts = assemble(8, &unread);

        assert_eq!(counts[3], 5, "the slot must carry its own account's count");
        assert_eq!(counts[0], 1);
        assert_eq!(
            counts[1], 0,
            "an untouched slot must stay silent, not inherit a neighbour"
        );
        assert_eq!(
            counts.len(),
            8,
            "the document is exactly the published size"
        );
    }

    #[test]
    fn only_accounts_this_service_gave_a_slot_reach_the_document() {
        let slots = vec![("lusab-babad-dovok".to_owned(), 7)];
        let unread = vec![
            ("lusab-babad-dovok".to_owned(), 3_i64),
            ("some-staff-account".to_owned(), 9),
        ];

        let joined = join_unread(&slots, &unread);

        assert_eq!(joined, HashMap::from([(7, 3_u32)]));
    }

    #[test]
    fn a_quiet_forum_keeps_its_generation_so_clients_stay_on_a_304() {
        let stamp = GenerationStamp::default();

        let first = stamp.stamp(&[0, 1], 1_000);
        let second = stamp.stamp(&[0, 1], 2_000);

        assert_eq!(
            first, second,
            "an unchanged document must not invalidate every client's cache"
        );
    }

    #[test]
    fn a_changed_count_advances_the_generation_even_if_the_clock_went_back() {
        let stamp = GenerationStamp::default();
        let first = stamp.stamp(&[0, 1], 5_000);

        let second = stamp.stamp(&[0, 2], 4_000);

        assert!(
            second > first,
            "anti-rollback rests on a strictly monotonic generation: {first} then {second}"
        );
    }

    #[test]
    fn a_slot_outside_the_published_range_is_dropped() {
        let unread = HashMap::from([(99, 4_u32)]);

        let counts = assemble(4, &unread);

        assert_eq!(
            counts,
            vec![0, 0, 0, 0],
            "an out-of-range slot must not stretch the document"
        );
    }
}
