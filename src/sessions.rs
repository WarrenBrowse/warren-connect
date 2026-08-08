//! Browser login sessions.
//!
//! One session per DiscourseConnect round-trip: created when Discourse
//! redirects the browser to `/sso`, approved when the app's signed request
//! lands, consumed exactly once when the browser is bounced back to
//! Discourse. In-memory, single instance, short TTL.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore as _;

use crate::discourse::SsoUser;
use crate::error::AuthError;

/// How long a pending login may wait for the app's approval. Kept short to
/// bound the cross-device approval-relay (QR-phishing) window: see the threat
/// note in warren-core doc 55.
const SESSION_TTL_SECS: u64 = 300;

/// Hard cap on concurrent pending sessions (fail closed).
const MAX_SESSIONS: usize = 10_000;

/// Session state visible to the polling browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    /// Waiting for the app's signed login.
    Pending,
    /// Approved: the browser may complete the redirect to Discourse.
    Approved,
    /// The app declined (user cancelled) or the login was refused (e.g. no
    /// Warren subscription). `reason` is a short machine token for the UI.
    Cancelled {
        /// Short reason token, e.g. `user_cancelled`, `subscription_required`.
        reason: String,
    },
}

/// Which of a session's two ids an approval arrived on.
///
/// The button on the approval page hands the app the same-device id: the OS
/// gives the deep link to the app installed on the very machine that is
/// signing in. The QR hands out a second id, and reading a QR means a second
/// device by construction. The distinction is not decoration, it is the only
/// thing this service knows about how the approval reached the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approach {
    /// Approved from the deep link the same machine's browser opened.
    SameDevice,
    /// Approved from the QR, so from another device.
    CrossDevice,
}

/// The two ids of one pending login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIds {
    /// Held by the browser that started the flow: the button deep link, the
    /// status poll and the completion redirect all use this one.
    pub sid: String,
    /// Carried only by the QR.
    pub qr_sid: String,
}

#[derive(Debug, Clone)]
struct Session {
    nonce: String,
    return_sso_url: String,
    created_unix: u64,
    approved: Option<SsoUser>,
    cancelled: Option<String>,
    qr_sid: String,
}

/// A consumed, completed login: everything needed to build the signed
/// DiscourseConnect response.
#[derive(Debug, Clone)]
pub struct CompletedLogin {
    /// Discourse's nonce, echoed in the response payload.
    pub nonce: String,
    /// Redirect target back into Discourse.
    pub return_sso_url: String,
    /// The identity to assert.
    pub user: SsoUser,
}

/// In-memory session registry.
///
/// Keyed on the same-device sid. `by_qr` maps the QR's id onto it, so the two
/// ids address one session and only one of them ever says "another device".
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    by_qr: Mutex<HashMap<String, String>>,
}

/// 16 bytes of OS entropy as 32 hex chars: the shape every client validates.
fn fresh_sid() -> String {
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

impl SessionStore {
    /// Creates a pending session; returns both of its opaque ids.
    ///
    /// # Errors
    /// [`AuthError::Session`] when the store is at capacity.
    pub fn create(
        &self,
        nonce: String,
        return_sso_url: String,
        now_unix: u64,
    ) -> Result<SessionIds, AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        let mut by_qr = self.by_qr.lock().expect("qr index mutex never poisoned");
        sessions.retain(|_, s| now_unix.saturating_sub(s.created_unix) < SESSION_TTL_SECS);
        by_qr.retain(|_, primary| sessions.contains_key(primary));
        // Idempotent per DiscourseConnect nonce: a valid `sso`+`sig` payload is
        // HMAC-replayable to /sso, so minting a fresh session each time would
        // let one captured payload exhaust MAX_SESSIONS and fail every login
        // closed. Reuse the live pending session for a nonce instead (also the
        // natural behavior when a user refreshes the approval page).
        if let Some((sid, session)) = sessions
            .iter()
            .find(|(_, s)| s.nonce == nonce && s.approved.is_none() && s.cancelled.is_none())
        {
            return Ok(SessionIds {
                sid: sid.clone(),
                qr_sid: session.qr_sid.clone(),
            });
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(AuthError::Session);
        }
        let sid = fresh_sid();
        let qr_sid = fresh_sid();
        by_qr.insert(qr_sid.clone(), sid.clone());
        sessions.insert(
            sid.clone(),
            Session {
                nonce,
                return_sso_url,
                created_unix: now_unix,
                approved: None,
                cancelled: None,
                qr_sid: qr_sid.clone(),
            },
        );
        Ok(SessionIds { sid, qr_sid })
    }

    /// Resolves either id onto the session's own key, saying which one it was.
    ///
    /// # Errors
    /// [`AuthError::Session`] if the id matches no live session.
    pub fn resolve(&self, sid: &str, now_unix: u64) -> Result<(String, Approach), AuthError> {
        let sessions = self.sessions.lock().expect("session mutex never poisoned");
        let live = |key: &String| {
            sessions
                .get(key)
                .is_some_and(|s| now_unix.saturating_sub(s.created_unix) < SESSION_TTL_SECS)
        };
        let key = sid.to_owned();
        if live(&key) {
            return Ok((key, Approach::SameDevice));
        }
        let by_qr = self.by_qr.lock().expect("qr index mutex never poisoned");
        let primary = by_qr.get(sid).cloned().ok_or(AuthError::Session)?;
        if !live(&primary) {
            return Err(AuthError::Session);
        }
        Ok((primary, Approach::CrossDevice))
    }

    /// Marks a pending session cancelled with a short reason token (app
    /// declined, or login refused). Accepts either id. Idempotent; a no-op on
    /// an unknown/expired session. Never overrides an already-approved session.
    pub fn cancel(&self, sid: &str, reason: &str, now_unix: u64) {
        let Ok((primary, _)) = self.resolve(sid, now_unix) else {
            return;
        };
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        if let Some(session) = sessions.get_mut(&primary)
            && session.approved.is_none()
        {
            session.cancelled = Some(reason.to_owned());
        }
    }

    /// Attaches the proven identity to a pending session. Accepts either id;
    /// the caller decides what to put in `user` from the [`Approach`] it got
    /// out of [`Self::resolve`].
    ///
    /// # Errors
    /// [`AuthError::Session`] if the session is unknown or expired.
    pub fn approve(&self, sid: &str, user: SsoUser, now_unix: u64) -> Result<(), AuthError> {
        let (primary, _) = self.resolve(sid, now_unix)?;
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        let session = sessions.get_mut(&primary).ok_or(AuthError::Session)?;
        if session.cancelled.is_some() {
            // The browser side already gave up on this login; do not resurrect.
            return Err(AuthError::Session);
        }
        session.approved = Some(user);
        Ok(())
    }

    /// Current status, for the browser poll. Accepts either id.
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown or expired.
    pub fn status(&self, sid: &str, now_unix: u64) -> Result<SessionStatus, AuthError> {
        let (primary, _) = self.resolve(sid, now_unix)?;
        let sessions = self.sessions.lock().expect("session mutex never poisoned");
        let session = sessions.get(&primary).ok_or(AuthError::Session)?;
        Ok(if let Some(reason) = &session.cancelled {
            SessionStatus::Cancelled {
                reason: reason.clone(),
            }
        } else if session.approved.is_some() {
            SessionStatus::Approved
        } else {
            SessionStatus::Pending
        })
    }

    /// Consumes an approved session (single use). Accepts either id.
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown, expired, or not yet approved.
    pub fn consume(&self, sid: &str, now_unix: u64) -> Result<CompletedLogin, AuthError> {
        let (primary, _) = self.resolve(sid, now_unix)?;
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        if sessions.get(&primary).is_none_or(|s| s.approved.is_none()) {
            return Err(AuthError::Session);
        }
        let session = sessions.remove(&primary).ok_or(AuthError::Session)?;
        self.by_qr
            .lock()
            .expect("qr index mutex never poisoned")
            .remove(&session.qr_sid);
        let user = session.approved.ok_or(AuthError::Session)?;
        Ok(CompletedLogin {
            nonce: session.nonce,
            return_sso_url: session.return_sso_url,
            user,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> SsoUser {
        SsoUser {
            external_id: "e".into(),
            username: "u".into(),
            email: "u@users.warrenbrowse.invalid".into(),
            member: true,
            subscriber: false,
            admin: false,
        }
    }

    #[test]
    fn lifecycle_pending_approved_consumed() {
        let store = SessionStore::default();
        let sid = store
            .create("n".into(), "https://f/sso_login".into(), 0)
            .expect("create")
            .sid;

        assert_eq!(
            store.status(&sid, 1).expect("status"),
            SessionStatus::Pending
        );
        store.approve(&sid, user(), 2).expect("approve");
        assert_eq!(
            store.status(&sid, 3).expect("status"),
            SessionStatus::Approved
        );

        let done = store.consume(&sid, 4).expect("consume");
        assert_eq!(done.nonce, "n");
        assert_eq!(done.return_sso_url, "https://f/sso_login");
    }

    #[test]
    fn consume_is_single_use() {
        let store = SessionStore::default();
        let sid = store.create("n".into(), "r".into(), 0).expect("create").sid;
        store.approve(&sid, user(), 1).expect("approve");
        store.consume(&sid, 2).expect("first consume");
        assert!(
            store.consume(&sid, 3).is_err(),
            "a completed login must not be replayable into Discourse"
        );
    }

    #[test]
    fn cannot_consume_before_approval() {
        let store = SessionStore::default();
        let sid = store.create("n".into(), "r".into(), 0).expect("create").sid;
        assert!(store.consume(&sid, 1).is_err());
    }

    #[test]
    fn sessions_expire() {
        let store = SessionStore::default();
        let sid = store.create("n".into(), "r".into(), 0).expect("create").sid;
        assert!(store.status(&sid, SESSION_TTL_SECS).is_err(), "expired");
        assert!(store.approve(&sid, user(), SESSION_TTL_SECS).is_err());
    }

    #[test]
    fn unknown_sid_is_an_error() {
        let store = SessionStore::default();
        assert!(store.status("deadbeef", 0).is_err());
    }

    #[test]
    fn cancel_marks_the_session_and_blocks_later_approval() {
        let store = SessionStore::default();
        let sid = store.create("n".into(), "r".into(), 0).expect("create").sid;
        store.cancel(&sid, "user_cancelled", 1);
        assert_eq!(
            store.status(&sid, 2).expect("status"),
            SessionStatus::Cancelled {
                reason: "user_cancelled".into()
            }
        );
        // A late approval must NOT resurrect a cancelled session.
        assert!(store.approve(&sid, user(), 3).is_err());
        assert!(store.consume(&sid, 4).is_err());
    }

    #[test]
    fn cancel_does_not_override_an_approved_session() {
        let store = SessionStore::default();
        let sid = store.create("n".into(), "r".into(), 0).expect("create").sid;
        store.approve(&sid, user(), 1).expect("approve");
        store.cancel(&sid, "user_cancelled", 2);
        assert_eq!(
            store.status(&sid, 3).expect("status"),
            SessionStatus::Approved
        );
    }

    #[test]
    fn the_qr_id_addresses_the_same_session_and_says_so() {
        // The whole point: one session, two ids, and the id the approval came
        // in on is what tells the login handler whether a second device was
        // involved. Without the second id there is nothing to tell it apart.
        let store = SessionStore::default();
        let ids = store.create("n".into(), "r".into(), 0).expect("create");

        assert_ne!(ids.sid, ids.qr_sid, "a shared id would carry no signal");
        assert_eq!(ids.qr_sid.len(), 32, "clients validate 32 lowercase hex");
        assert!(ids.qr_sid.chars().all(|c| c.is_ascii_hexdigit()));

        assert_eq!(
            store.resolve(&ids.sid, 1).expect("same device"),
            (ids.sid.clone(), Approach::SameDevice)
        );
        assert_eq!(
            store.resolve(&ids.qr_sid, 1).expect("cross device"),
            (ids.sid.clone(), Approach::CrossDevice)
        );
    }

    #[test]
    fn an_approval_on_the_qr_id_completes_the_browsers_own_session() {
        // The QR path has to work end to end, or the fix would have cost a
        // feature: the phone approves on the qr id, the desktop browser polls
        // and completes on its own.
        let store = SessionStore::default();
        let ids = store.create("n".into(), "r".into(), 0).expect("create");

        store.approve(&ids.qr_sid, user(), 1).expect("phone signs");

        assert_eq!(
            store.status(&ids.sid, 2).expect("status"),
            SessionStatus::Approved,
            "the browser polls its own id and must see the approval"
        );
        store.consume(&ids.sid, 3).expect("browser completes");
        assert!(
            store.resolve(&ids.qr_sid, 4).is_err(),
            "consuming must retire the qr id too, or it outlives its session"
        );
    }

    #[test]
    fn cancelling_on_the_qr_id_stops_the_browser_polling() {
        let store = SessionStore::default();
        let ids = store.create("n".into(), "r".into(), 0).expect("create");

        store.cancel(&ids.qr_sid, "user_cancelled", 1);

        assert_eq!(
            store.status(&ids.sid, 2).expect("status"),
            SessionStatus::Cancelled {
                reason: "user_cancelled".into()
            }
        );
    }

    #[test]
    fn an_expired_qr_id_resolves_to_nothing() {
        let store = SessionStore::default();
        let ids = store.create("n".into(), "r".into(), 0).expect("create");
        assert!(store.resolve(&ids.qr_sid, SESSION_TTL_SECS).is_err());
    }

    #[test]
    fn create_is_idempotent_per_nonce() {
        // A replayed DiscourseConnect nonce must reuse the pending session, not
        // mint a new one (else one captured payload exhausts the store).
        let store = SessionStore::default();
        let a = store.create("nonceA".into(), "r".into(), 0).expect("first");
        let b = store
            .create("nonceA".into(), "r".into(), 1)
            .expect("replay");
        assert_eq!(a, b, "same nonce must map to the same session id");

        // A different nonce is a distinct session.
        let c = store.create("nonceB".into(), "r".into(), 2).expect("other");
        assert_ne!(a, c);
    }

    #[test]
    fn a_new_login_after_approval_is_a_fresh_session() {
        // Once a nonce's session is approved, a later create for the same nonce
        // starts fresh (the old one is consumed via /complete anyway).
        let store = SessionStore::default();
        let a = store.create("n".into(), "r".into(), 0).expect("first");
        store.approve(&a.sid, user(), 1).expect("approve");
        let b = store.create("n".into(), "r".into(), 2).expect("second");
        assert_ne!(a, b, "an approved session is not reused for a new login");
    }
}
