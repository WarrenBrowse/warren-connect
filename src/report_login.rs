//! One-shot browser sign-in after an in-app report.
//!
//! The report answers the app with a login ticket. The app opens
//! `/report-login#t=<ticket>` in the default browser; the page trades the
//! ticket for a short-lived binding cookie and sends the browser to the
//! forum's `/session/sso`, whose DiscourseConnect round trip comes back to
//! `/sso` presenting that cookie and completes at once, as the reporter, on
//! the topic they just filed.
//!
//! Both stores keep only the SHA-256 of what they hand out, hold an entry for
//! one use, and are bounded: a full store drops its oldest entry, which costs
//! that reporter a signed-out landing on their topic and nothing else.

use std::sync::Mutex;

use base64::Engine as _;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::discourse::SsoUser;
use crate::sessions::{BrowserKey, BrowserSecret};

/// Seconds a ticket stays redeemable: the app opens the browser right after
/// the report answers, so two minutes covers a slow browser start.
pub const TICKET_TTL_SECS: u64 = 120;

/// Seconds between the redeem and the forum's round trip back to `/sso`,
/// which is two redirects in the same browser.
pub const PENDING_TTL_SECS: u64 = 60;

/// Live entries each store holds at most.
pub const MAX_ENTRIES: usize = 1024;

/// Redeem attempts admitted per minute, all callers together. A ticket is
/// 256 bits, so this bounds work, not guessing.
pub const REDEEMS_PER_MINUTE: usize = 600;

/// The cookie that carries a redeemed ticket from the page to `/sso`, under
/// the same `__Host-` guarantee as the login cookie.
pub const REPORT_LOGIN_COOKIE: &str = "__Host-warren_report_login";

const TICKET_BYTES: usize = 32;

/// Length of a ticket: 32 bytes in unpadded base64url.
pub const TICKET_CHARS: usize = 43;

/// A bearer login ticket. Rendered only into the `login_url` fragment.
pub struct LoginTicket(Zeroizing<String>);

impl LoginTicket {
    fn generate() -> Self {
        let mut raw = Zeroizing::new([0u8; TICKET_BYTES]);
        rand::rngs::OsRng.fill_bytes(raw.as_mut());
        Self(Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_ref()),
        ))
    }

    /// The ticket text, for the `login_url` and nothing else.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for LoginTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginTicket(redacted)")
    }
}

fn ticket_key(token: &str) -> Option<[u8; 32]> {
    let well_formed = token.len() == TICKET_CHARS
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    well_formed.then(|| Sha256::digest(token.as_bytes()).into())
}

/// What a ticket signs in as, exactly as the report built it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLogin {
    /// The reporter's account, never staff.
    pub user: SsoUser,
    /// The device locale the report carried.
    pub locale: Option<String>,
    /// The topic the browser lands on.
    pub topic_id: u64,
}

struct Slot<T> {
    key: [u8; 32],
    expires_at: u64,
    value: T,
}

struct Bounded<T> {
    slots: Vec<Slot<T>>,
}

impl<T> Default for Bounded<T> {
    fn default() -> Self {
        Self { slots: Vec::new() }
    }
}

impl<T> Bounded<T> {
    fn insert(&mut self, key: [u8; 32], expires_at: u64, value: T, now: u64) {
        self.slots.retain(|slot| slot.expires_at > now);
        if self.slots.len() >= MAX_ENTRIES {
            // Inserted in time order, so the first is the oldest.
            self.slots.remove(0);
        }
        self.slots.push(Slot {
            key,
            expires_at,
            value,
        });
    }

    /// Removes the entry under `key` and returns it while it is live. Every
    /// slot is compared, in constant time, whatever matches.
    fn take(&mut self, key: &[u8; 32], now: u64) -> Option<T> {
        let mut found = None;
        for (index, slot) in self.slots.iter().enumerate() {
            if bool::from(slot.key.ct_eq(key)) {
                found = Some(index);
            }
        }
        let slot = self.slots.remove(found?);
        (slot.expires_at > now).then_some(slot.value)
    }
}

/// The two single-use stores of the report sign-in.
pub struct ReportLoginStore {
    tickets: Mutex<Bounded<ReportLogin>>,
    pending: Mutex<Bounded<ReportLogin>>,
    /// Global budget of `POST /v1/report-login`. Never keyed by a client
    /// address: the stack pins `X-Forwarded-For`, and the route is public.
    pub redeems: crate::intake::RateLimiter<()>,
}

impl Default for ReportLoginStore {
    fn default() -> Self {
        Self {
            tickets: Mutex::default(),
            pending: Mutex::default(),
            redeems: crate::intake::RateLimiter::new(REDEEMS_PER_MINUTE, REDEEMS_PER_MINUTE, 60),
        }
    }
}

impl ReportLoginStore {
    /// Issues a ticket for `login`, redeemable once within
    /// [`TICKET_TTL_SECS`].
    pub fn issue(&self, login: ReportLogin, now: u64) -> LoginTicket {
        let ticket = LoginTicket::generate();
        let key = ticket_key(ticket.as_str()).expect("a generated ticket is well formed");
        self.tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, now + TICKET_TTL_SECS, login, now);
        ticket
    }

    /// Consumes the ticket `token`. `None` for a token that is malformed,
    /// unknown, expired or already used: the four answer the same.
    pub fn redeem(&self, token: &str, now: u64) -> Option<ReportLogin> {
        let key = ticket_key(token)?;
        self.tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(&key, now)
    }

    /// Parks a redeemed login for the browser's round trip through the
    /// forum, under a fresh binding secret the caller sets as a cookie.
    pub fn park(&self, login: ReportLogin, now: u64) -> BrowserSecret {
        let secret = BrowserSecret::generate();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(*secret.key().as_bytes(), now + PENDING_TTL_SECS, login, now);
        secret
    }

    /// Consumes the login parked under `browser`, if it is still live.
    pub fn take_pending(&self, browser: &BrowserKey, now: u64) -> Option<ReportLogin> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(browser.as_bytes(), now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(topic_id: u64) -> ReportLogin {
        ReportLogin {
            user: SsoUser {
                external_id: "ext".into(),
                username: "kobal-nisop-tadir".into(),
                email: "x@users.invalid".into(),
                member: true,
                subscriber: true,
                admin: false,
            },
            locale: Some("fr".into()),
            topic_id,
        }
    }

    #[test]
    fn a_ticket_is_43_chars_of_unpadded_base64url_and_unique() {
        let store = ReportLoginStore::default();
        let a = store.issue(login(1), 1_000);
        let b = store.issue(login(1), 1_000);
        assert_eq!(a.as_str().len(), TICKET_CHARS);
        assert!(
            a.as_str()
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "{}",
            a.as_str()
        );
        assert_ne!(a.as_str(), b.as_str());
        assert_eq!(format!("{a:?}"), "LoginTicket(redacted)");
    }

    #[test]
    fn a_ticket_redeems_once() {
        let store = ReportLoginStore::default();
        let ticket = store.issue(login(42), 1_000);
        assert_eq!(store.redeem(ticket.as_str(), 1_001), Some(login(42)));
        assert_eq!(store.redeem(ticket.as_str(), 1_001), None, "single use");
    }

    #[test]
    fn a_ticket_expires_after_its_ttl() {
        let store = ReportLoginStore::default();
        let live = store.issue(login(1), 1_000);
        assert!(
            store
                .redeem(live.as_str(), 1_000 + TICKET_TTL_SECS - 1)
                .is_some()
        );
        let stale = store.issue(login(2), 1_000);
        assert_eq!(store.redeem(stale.as_str(), 1_000 + TICKET_TTL_SECS), None);
    }

    #[test]
    fn an_unknown_or_malformed_token_redeems_nothing() {
        let store = ReportLoginStore::default();
        let _issued = store.issue(login(1), 1_000);
        assert_eq!(store.redeem(&"A".repeat(TICKET_CHARS), 1_001), None);
        assert_eq!(store.redeem("short", 1_001), None);
        assert_eq!(store.redeem(&"+".repeat(TICKET_CHARS), 1_001), None);
    }

    #[test]
    fn a_full_store_drops_its_oldest_ticket() {
        let store = ReportLoginStore::default();
        let oldest = store.issue(login(0), 1_000);
        let second = store.issue(login(1), 1_000);
        for topic in 2..=MAX_ENTRIES as u64 {
            let _ = store.issue(login(topic), 1_000);
        }
        assert_eq!(store.redeem(oldest.as_str(), 1_001), None);
        assert_eq!(store.redeem(second.as_str(), 1_001), Some(login(1)));
    }

    #[test]
    fn a_parked_login_is_taken_once_by_its_own_browser_only() {
        let store = ReportLoginStore::default();
        let secret = store.park(login(7), 1_000);
        let stranger = BrowserSecret::generate();
        assert_eq!(store.take_pending(&stranger.key(), 1_001), None);
        assert_eq!(store.take_pending(&secret.key(), 1_001), Some(login(7)));
        assert_eq!(store.take_pending(&secret.key(), 1_001), None);
    }

    #[test]
    fn a_parked_login_expires_after_its_ttl() {
        let store = ReportLoginStore::default();
        let secret = store.park(login(7), 1_000);
        assert_eq!(
            store.take_pending(&secret.key(), 1_000 + PENDING_TTL_SECS),
            None
        );
    }
}
