//! Anti-replay nonce store, in-memory single-instance.
//!
//! Semantics mirror warren-core's `InMemoryNonceStore`: a `(pubkey, nonce)`
//! pair is accepted once within the retention window; a second occurrence is
//! a replay. TTL only needs to outlive the verification clock window.
//!
//! Grouped BY pubkey rather than by the flat pair, so the per-key budget below
//! is a lookup instead of a scan.

use std::collections::HashMap;
use std::sync::Mutex;

/// Retention window, seconds. Twice the clock window: a nonce outside it can
/// no longer pass timestamp validation, so it is safe to forget.
const NONCE_TTL_SECS: u64 = 120;

/// Hard cap: fail closed (reject logins) rather than grow unbounded under a
/// signature-valid flood.
const MAX_ENTRIES: usize = 100_000;

/// Live nonces one wallet may hold at a time.
///
/// Without it a single valid key could fill the whole store inside one TTL and
/// fail every other user's login closed, which is a denial of service costing
/// one wallet. A real client signs a handful of requests per window (a login,
/// a notification read, a mark-seen, an attach), so 64 is far above any honest
/// burst and 1563 distinct funded wallets are now needed to reach the global
/// cap.
const MAX_PER_PUBKEY: usize = 64;

/// Single-use `(pubkey, nonce)` registry.
#[derive(Debug, Default)]
pub struct NonceStore {
    seen: Mutex<Seen>,
}

#[derive(Debug, Default)]
struct Seen {
    by_pubkey: HashMap<String, HashMap<String, u64>>,
    total: usize,
}

impl Seen {
    fn prune(&mut self, now_unix: u64) {
        self.by_pubkey.retain(|_, nonces| {
            nonces.retain(|_, stored| now_unix.saturating_sub(*stored) < NONCE_TTL_SECS);
            !nonces.is_empty()
        });
        self.total = self.by_pubkey.values().map(HashMap::len).sum();
    }
}

impl NonceStore {
    /// Returns `true` if the pair is fresh (and records it), `false` on
    /// replay, when this wallet is over its own budget, or when the store is
    /// at capacity.
    pub fn check_and_store(&self, pubkey_ss58: &str, nonce_hex: &str, now_unix: u64) -> bool {
        let mut seen = self.seen.lock().expect("nonce mutex never poisoned");
        seen.prune(now_unix);
        if seen.total >= MAX_ENTRIES {
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
            .insert(nonce_hex.to_owned(), now_unix);
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
        assert!(store.check_and_store("wb1", "aa", 100));
        assert!(!store.check_and_store("wb1", "aa", 101), "replay");
    }

    #[test]
    fn same_nonce_from_a_different_key_is_independent() {
        let store = NonceStore::default();
        assert!(store.check_and_store("wb1", "aa", 100));
        assert!(store.check_and_store("wb2", "aa", 100));
    }

    #[test]
    fn expired_entries_are_forgotten() {
        let store = NonceStore::default();
        assert!(store.check_and_store("wb1", "aa", 100));
        assert!(
            store.check_and_store("wb1", "aa", 100 + NONCE_TTL_SECS),
            "after the TTL the pair can no longer replay a valid timestamp, \
             so re-acceptance is safe"
        );
    }

    #[test]
    fn one_key_cannot_spend_the_whole_store() {
        // The global cap fails closed, so without a per-key budget one wallet
        // filling it would refuse every other user's login for a TTL.
        let store = NonceStore::default();
        for i in 0..MAX_PER_PUBKEY {
            assert!(
                store.check_and_store("wb-flood", &format!("{i:04x}"), 100),
                "the honest burst must fit"
            );
        }

        assert!(
            !store.check_and_store("wb-flood", "ffff", 100),
            "past its own budget the flooding key is refused"
        );
        assert!(
            store.check_and_store("wb-other", "ffff", 100),
            "and every other wallet keeps logging in, which is the point"
        );
    }

    #[test]
    fn a_key_recovers_its_budget_as_the_window_slides() {
        let store = NonceStore::default();
        for i in 0..MAX_PER_PUBKEY {
            assert!(store.check_and_store("wb1", &format!("{i:04x}"), 100));
        }
        assert!(!store.check_and_store("wb1", "ffff", 100));

        assert!(
            store.check_and_store("wb1", "ffff", 100 + NONCE_TTL_SECS),
            "the budget is a rate, not a lifetime quota"
        );
    }
}
