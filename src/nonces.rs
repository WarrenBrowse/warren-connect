//! Anti-replay nonce store, in-memory single-instance.
//!
//! A `(pubkey, nonce)` pair is admitted once; a second occurrence is a
//! replay. Only a request some route admits spends a slot
//! ([`crate::verify::VerifiedRequest::admit`]): a wallet costs nothing to
//! mint, so a store every verified signature could write to would be a store
//! anybody could fill.
//!
//! Grouped BY pubkey rather than by the flat pair, so the per-key budget below
//! is a lookup instead of a scan.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::verify::ADMISSION_HORIZON_SECS;

/// Hard cap: fail closed (refuse every admission) rather than grow unbounded
/// under a flood of admitted requests.
const MAX_ENTRIES: usize = 100_000;

/// Live nonces one wallet may hold at a time.
///
/// Without it a single admitted wallet could fill the whole store and fail
/// every other user's signed requests closed. A real client signs a handful of
/// requests a minute (a login, a notification read, a mark-seen, an attach),
/// so 64 is far above any honest burst. Reaching the global cap therefore
/// takes 1563 wallets that each pass a route's gate, and every gate asks for a
/// wallet that paid for Warren at least once or is staff: the login and the
/// report check the payment, the other routes a forum link or a topic written
/// under the wallet's forum handle, and only such a login or report creates
/// either.
const MAX_PER_PUBKEY: usize = 64;

/// Single-use `(pubkey, nonce)` registry.
#[derive(Debug)]
pub struct NonceStore {
    seen: Mutex<Seen>,
    max_entries: usize,
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::with_max_entries(MAX_ENTRIES)
    }
}

#[derive(Debug, Default)]
struct Seen {
    /// Per wallet, each nonce with the last second its request can be admitted.
    by_pubkey: HashMap<String, HashMap<String, u64>>,
    total: usize,
    /// The latest clock reading any admission brought.
    latest_now: u64,
}

impl Seen {
    fn prune(&mut self, now_unix: u64) {
        self.by_pubkey.retain(|_, nonces| {
            nonces.retain(|_, last_admissible| now_unix <= *last_admissible);
            !nonces.is_empty()
        });
        self.total = self.by_pubkey.values().map(HashMap::len).sum();
    }
}

impl NonceStore {
    /// A store that holds at most `max_entries` nonces, all wallets together.
    /// Deployments use [`NonceStore::default`]; a smaller cap lets a test
    /// reach it.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            seen: Mutex::default(),
            max_entries,
        }
    }

    /// Nonces held, all wallets together, expired ones included until the
    /// next admission drops them.
    #[must_use]
    pub fn held(&self) -> usize {
        self.seen.lock().expect("nonce mutex never poisoned").total
    }

    /// Admits the nonce of a request signed at `signed_at`, at `now_unix`.
    /// Returns `true` if the pair is fresh (and records it until the last
    /// second a replay of it could be admitted), `false` on a replay, past the
    /// request's admission horizon, when this wallet is over its own budget,
    /// or when the store is at capacity.
    pub fn check_and_store(
        &self,
        pubkey_ss58: &str,
        nonce_hex: &str,
        signed_at: u64,
        now_unix: u64,
    ) -> bool {
        let mut seen = self.seen.lock().expect("nonce mutex never poisoned");
        // Routes read the clock before they take the lock, so admissions reach
        // it out of order, and one on a later reading may already have pruned
        // a twin that this reading would still pass the horizon for. Judging
        // each admission by the latest reading keeps the horizon and the
        // prune on one clock.
        let now = now_unix.max(seen.latest_now);
        seen.latest_now = now;
        let last_admissible = signed_at.saturating_add(ADMISSION_HORIZON_SECS);
        if now > last_admissible {
            return false;
        }
        seen.prune(now);
        if seen.total >= self.max_entries {
            return false;
        }
        if let Some(nonces) = seen.by_pubkey.get(pubkey_ss58)
            && (nonces.len() >= MAX_PER_PUBKEY || nonces.contains_key(nonce_hex))
        {
            return false;
        }
        seen.by_pubkey
            .entry(pubkey_ss58.to_owned())
            .or_default()
            .insert(nonce_hex.to_owned(), last_admissible);
        seen.total += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_accepted_second_rejected() {
        let store = NonceStore::default();
        assert!(store.check_and_store("wb1", "aa", 100, 100));
        assert!(!store.check_and_store("wb1", "aa", 100, 101), "replay");
    }

    #[test]
    fn same_nonce_from_a_different_key_is_independent() {
        let store = NonceStore::default();
        assert!(store.check_and_store("wb1", "aa", 100, 100));
        assert!(store.check_and_store("wb2", "aa", 100, 100));
    }

    #[test]
    fn expired_entries_are_forgotten() {
        let store = NonceStore::default();
        assert!(store.check_and_store("wb1", "aa", 100, 100));
        let later = 100 + ADMISSION_HORIZON_SECS + 1;
        assert!(
            store.check_and_store("wb1", "aa", later, later),
            "past the horizon no replay of the first request can be admitted, \
             so only a freshly signed one can carry the pair again"
        );
        assert_eq!(store.held(), 1, "the first entry was dropped");
    }

    #[test]
    fn one_key_cannot_spend_the_whole_store() {
        // The global cap fails closed, so without a per-key budget one wallet
        // filling it would refuse every other user's requests.
        let store = NonceStore::default();
        for i in 0..MAX_PER_PUBKEY {
            assert!(
                store.check_and_store("wb-flood", &format!("{i:04x}"), 100, 100),
                "the honest burst must fit"
            );
        }

        assert!(
            !store.check_and_store("wb-flood", "ffff", 100, 100),
            "past its own budget the flooding key is refused"
        );
        assert!(
            store.check_and_store("wb-other", "ffff", 100, 100),
            "and every other wallet keeps going, which is the point"
        );
    }

    #[test]
    fn a_key_recovers_its_budget_as_the_window_slides() {
        let store = NonceStore::default();
        for i in 0..MAX_PER_PUBKEY {
            assert!(store.check_and_store("wb1", &format!("{i:04x}"), 100, 100));
        }
        assert!(!store.check_and_store("wb1", "ffff", 100, 100));

        let later = 100 + ADMISSION_HORIZON_SECS + 1;
        assert!(
            store.check_and_store("wb1", "ffff", later, later),
            "the budget is a rate, not a lifetime quota"
        );
    }

    #[test]
    fn an_admission_on_an_older_clock_reading_still_finds_the_twin_a_newer_one_pruned() {
        // Routes read the clock just before they take the lock, so two
        // admissions can reach it out of order.
        let store = NonceStore::default();
        let last = 100 + ADMISSION_HORIZON_SECS;
        assert!(store.check_and_store("wb1", "aa", 100, 100));
        assert!(store.check_and_store("wb2", "bb", 200, last + 1));

        assert!(
            !store.check_and_store("wb1", "aa", 100, last),
            "the replay read the clock one second earlier and must still be refused"
        );
    }

    #[test]
    fn the_global_cap_fails_closed_for_every_wallet() {
        let store = NonceStore::with_max_entries(3);
        for wallet in ["wb1", "wb2", "wb3"] {
            assert!(store.check_and_store(wallet, "aa", 100, 100));
        }

        assert!(!store.check_and_store("wb4", "aa", 100, 100));
        assert!(
            !store.check_and_store("wb1", "bb", 100, 100),
            "a wallet under its own budget is refused too"
        );
        assert_eq!(store.held(), 3);
    }
}
