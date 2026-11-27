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

/// Seconds after its issue during which a ticket the page opened by itself
/// signs in with no question. The app opens the browser the moment the
/// report answers (about a second, measured on the live forum on
/// 2026-11-27), and a cold browser start stays well inside this. A link
/// opened later went through someone's hands: a chat app hands a link to the
/// browser exactly the way the app does, so nothing else tells an attacker's
/// own link, sent to a victim, from the reporter's.
pub const AUTO_SIGN_IN_SECS: u64 = 20;

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

/// What the report-login page asks of a ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Intent {
    /// The page opened by itself: sign in if the ticket is fresh, otherwise
    /// name the account and wait for the reader.
    Auto,
    /// Name the account without spending the ticket, for a page that asks
    /// before it signs in.
    Peek,
    /// The reader confirmed: sign in.
    Confirmed,
}

/// The answer to a redeem.
#[derive(Debug, PartialEq, Eq)]
pub enum Redeem {
    /// The ticket is spent; the browser signs in as this login.
    SignedIn(ReportLogin),
    /// The ticket is still live, and the reader decides: the forum account
    /// it signs in as, which the app showed under "Posted as".
    Confirm {
        /// The reporter's forum username.
        handle: String,
        /// The topic the sign-in lands on.
        topic_id: u64,
    },
    /// Malformed, unknown, expired or already used: the four answer the same.
    Expired,
}

/// A live ticket and the time it was issued.
struct Issued {
    login: ReportLogin,
    issued_at: u64,
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

    /// The index of the entry under `key`. Every slot is compared, in
    /// constant time, whatever matches.
    fn find(&self, key: &[u8; 32]) -> Option<usize> {
        let mut found = None;
        for (index, slot) in self.slots.iter().enumerate() {
            if bool::from(slot.key.ct_eq(key)) {
                found = Some(index);
            }
        }
        found
    }

    /// The entry under `key` while it is live, left in place.
    fn get(&self, key: &[u8; 32], now: u64) -> Option<&T> {
        let slot = &self.slots[self.find(key)?];
        (slot.expires_at > now).then_some(&slot.value)
    }

    /// Removes the entry under `key` and returns it while it is live.
    fn take(&mut self, key: &[u8; 32], now: u64) -> Option<T> {
        let slot = self.slots.remove(self.find(key)?);
        (slot.expires_at > now).then_some(slot.value)
    }
}

/// The two single-use stores of the report sign-in.
pub struct ReportLoginStore {
    tickets: Mutex<Bounded<Issued>>,
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
            .insert(
                key,
                now + TICKET_TTL_SECS,
                Issued {
                    login,
                    issued_at: now,
                },
                now,
            );
        ticket
    }

    /// Answers the page's `intent` for the ticket `token`: spends it and
    /// signs in, or names the account and leaves it live (see [`Intent`]).
    pub fn redeem(&self, token: &str, intent: Intent, now: u64) -> Redeem {
        let Some(key) = ticket_key(token) else {
            return Redeem::Expired;
        };
        let mut tickets = self
            .tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(issued) = tickets.get(&key, now) else {
            return Redeem::Expired;
        };
        let fresh = now.saturating_sub(issued.issued_at) <= AUTO_SIGN_IN_SECS;
        match intent {
            Intent::Confirmed => {}
            Intent::Auto if fresh => {}
            Intent::Auto | Intent::Peek => {
                return Redeem::Confirm {
                    handle: issued.login.user.username.clone(),
                    topic_id: issued.login.topic_id,
                };
            }
        }
        tickets
            .take(&key, now)
            .map_or(Redeem::Expired, |issued| Redeem::SignedIn(issued.login))
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
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Confirmed, 1_001),
            Redeem::SignedIn(login(42))
        );
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Confirmed, 1_001),
            Redeem::Expired,
            "single use"
        );
    }

    #[test]
    fn a_ticket_expires_after_its_ttl() {
        let store = ReportLoginStore::default();
        let live = store.issue(login(1), 1_000);
        assert_eq!(
            store.redeem(
                live.as_str(),
                Intent::Confirmed,
                1_000 + TICKET_TTL_SECS - 1
            ),
            Redeem::SignedIn(login(1))
        );
        let stale = store.issue(login(2), 1_000);
        assert_eq!(
            store.redeem(stale.as_str(), Intent::Confirmed, 1_000 + TICKET_TTL_SECS),
            Redeem::Expired
        );
    }

    #[test]
    fn an_unknown_or_malformed_token_redeems_nothing() {
        let store = ReportLoginStore::default();
        let _issued = store.issue(login(1), 1_000);
        for token in [
            "A".repeat(TICKET_CHARS),
            "short".into(),
            "+".repeat(TICKET_CHARS),
        ] {
            for intent in [Intent::Auto, Intent::Peek, Intent::Confirmed] {
                assert_eq!(store.redeem(&token, intent, 1_001), Redeem::Expired);
            }
        }
    }

    #[test]
    fn a_full_store_drops_its_oldest_ticket() {
        let store = ReportLoginStore::default();
        let oldest = store.issue(login(0), 1_000);
        let second = store.issue(login(1), 1_000);
        for topic in 2..=MAX_ENTRIES as u64 {
            let _ = store.issue(login(topic), 1_000);
        }
        assert_eq!(
            store.redeem(oldest.as_str(), Intent::Confirmed, 1_001),
            Redeem::Expired
        );
        assert_eq!(
            store.redeem(second.as_str(), Intent::Confirmed, 1_001),
            Redeem::SignedIn(login(1))
        );
    }

    #[test]
    fn an_auto_redeem_signs_in_while_the_ticket_is_fresh() {
        // The app opens the browser the moment the report answers.
        let store = ReportLoginStore::default();
        let ticket = store.issue(login(5), 1_000);
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Auto, 1_000 + AUTO_SIGN_IN_SECS),
            Redeem::SignedIn(login(5))
        );
    }

    #[test]
    fn an_auto_redeem_of_an_older_ticket_names_the_account_and_spends_nothing() {
        // A link that took longer than a browser start to be opened went
        // through someone's hands: a chat app opens it exactly the way the
        // app does, so the reader is asked, by the account's name.
        let store = ReportLoginStore::default();
        let ticket = store.issue(login(6), 1_000);
        let late = 1_000 + AUTO_SIGN_IN_SECS + 1;
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Auto, late),
            Redeem::Confirm {
                handle: "kobal-nisop-tadir".into(),
                topic_id: 6
            }
        );
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Confirmed, late),
            Redeem::SignedIn(login(6)),
            "the ticket stayed live for the confirmation"
        );
    }

    #[test]
    fn a_peek_names_the_account_and_never_spends_the_ticket() {
        let store = ReportLoginStore::default();
        let ticket = store.issue(login(8), 1_000);
        for _ in 0..2 {
            assert_eq!(
                store.redeem(ticket.as_str(), Intent::Peek, 1_001),
                Redeem::Confirm {
                    handle: "kobal-nisop-tadir".into(),
                    topic_id: 8
                }
            );
        }
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Confirmed, 1_001),
            Redeem::SignedIn(login(8))
        );
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Peek, 1_001),
            Redeem::Expired
        );
    }

    #[test]
    fn a_peek_at_an_expired_ticket_names_nothing() {
        let store = ReportLoginStore::default();
        let ticket = store.issue(login(9), 1_000);
        assert_eq!(
            store.redeem(ticket.as_str(), Intent::Peek, 1_000 + TICKET_TTL_SECS),
            Redeem::Expired
        );
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
