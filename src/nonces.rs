//! Anti-replay nonce store, in-memory single-instance.
//!
//! Semantics mirror warren-core's `InMemoryNonceStore`: a `(pubkey, nonce)`
//! pair is accepted once within the retention window; a second occurrence is
//! a replay. TTL only needs to outlive the verification clock window.

use std::collections::HashMap;
use std::sync::Mutex;

/// Retention window, seconds. Twice the clock window: a nonce outside it can
/// no longer pass timestamp validation, so it is safe to forget.
const NONCE_TTL_SECS: u64 = 120;

/// Hard cap: fail closed (reject logins) rather than grow unbounded under a
/// signature-valid flood.
const MAX_ENTRIES: usize = 100_000;

/// Single-use `(pubkey, nonce)` registry.
#[derive(Debug, Default)]
pub struct NonceStore {
    seen: Mutex<HashMap<(String, String), u64>>,
}

impl NonceStore {
    /// Returns `true` if the pair is fresh (and records it), `false` on
    /// replay or when the store is at capacity.
    pub fn check_and_store(&self, pubkey_ss58: &str, nonce_hex: &str, now_unix: u64) -> bool {
        let mut seen = self.seen.lock().expect("nonce mutex never poisoned");
        seen.retain(|_, stored| now_unix.saturating_sub(*stored) < NONCE_TTL_SECS);
        if seen.len() >= MAX_ENTRIES {
            return false;
        }
        let key = (pubkey_ss58.to_owned(), nonce_hex.to_owned());
        if seen.contains_key(&key) {
            return false;
        }
        seen.insert(key, now_unix);
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
}
