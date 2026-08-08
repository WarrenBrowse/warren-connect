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

#[derive(Debug, Clone)]
struct Session {
    nonce: String,
    return_sso_url: String,
    created_unix: u64,
    approved: Option<SsoUser>,
    cancelled: Option<String>,
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
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    /// Creates a pending session; returns its opaque id (32 hex chars).
    ///
    /// # Errors
    /// [`AuthError::Session`] when the store is at capacity.
    pub fn create(
        &self,
        nonce: String,
        return_sso_url: String,
        now_unix: u64,
    ) -> Result<String, AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        sessions.retain(|_, s| now_unix.saturating_sub(s.created_unix) < SESSION_TTL_SECS);
        // Idempotent per DiscourseConnect nonce: a valid `sso`+`sig` payload is
        // HMAC-replayable to /sso, so minting a fresh session each time would
        // let one captured payload exhaust MAX_SESSIONS and fail every login
        // closed. Reuse the live pending session for a nonce instead (also the
        // natural behavior when a user refreshes the approval page).
        if let Some((sid, _)) = sessions
            .iter()
            .find(|(_, s)| s.nonce == nonce && s.approved.is_none() && s.cancelled.is_none())
        {
            return Ok(sid.clone());
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(AuthError::Session);
        }
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let sid = hex::encode(raw);
        sessions.insert(
            sid.clone(),
            Session {
                nonce,
                return_sso_url,
                created_unix: now_unix,
                approved: None,
                cancelled: None,
            },
        );
        Ok(sid)
    }

    /// Marks a pending session cancelled with a short reason token (app
    /// declined, or login refused). Idempotent; a no-op on an unknown/expired
    /// session. Never overrides an already-approved session.
    pub fn cancel(&self, sid: &str, reason: &str, now_unix: u64) {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        if let Some(session) = sessions.get_mut(sid)
            && now_unix.saturating_sub(session.created_unix) < SESSION_TTL_SECS
            && session.approved.is_none()
        {
            session.cancelled = Some(reason.to_owned());
        }
    }

    /// Attaches the proven identity to a pending session.
    ///
    /// # Errors
    /// [`AuthError::Session`] if the session is unknown or expired.
    pub fn approve(&self, sid: &str, user: SsoUser, now_unix: u64) -> Result<(), AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        let session = sessions.get_mut(sid).ok_or(AuthError::Session)?;
        if now_unix.saturating_sub(session.created_unix) >= SESSION_TTL_SECS {
            sessions.remove(sid);
            return Err(AuthError::Session);
        }
        if session.cancelled.is_some() {
            // The browser side already gave up on this login; do not resurrect.
            return Err(AuthError::Session);
        }
        session.approved = Some(user);
        Ok(())
    }

    /// Current status, for the browser poll.
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown or expired.
    pub fn status(&self, sid: &str, now_unix: u64) -> Result<SessionStatus, AuthError> {
        let sessions = self.sessions.lock().expect("session mutex never poisoned");
        let session = sessions.get(sid).ok_or(AuthError::Session)?;
        if now_unix.saturating_sub(session.created_unix) >= SESSION_TTL_SECS {
            return Err(AuthError::Session);
        }
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

    /// Consumes an approved session (single use).
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown, expired, or not yet approved.
    pub fn consume(&self, sid: &str, now_unix: u64) -> Result<CompletedLogin, AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        let approved = sessions.get(sid).is_some_and(|s| {
            s.approved.is_some() && now_unix.saturating_sub(s.created_unix) < SESSION_TTL_SECS
        });
        if !approved {
            return Err(AuthError::Session);
        }
        let session = sessions.remove(sid).ok_or(AuthError::Session)?;
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
            .expect("create");

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
        let sid = store.create("n".into(), "r".into(), 0).expect("create");
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
        let sid = store.create("n".into(), "r".into(), 0).expect("create");
        assert!(store.consume(&sid, 1).is_err());
    }

    #[test]
    fn sessions_expire() {
        let store = SessionStore::default();
        let sid = store.create("n".into(), "r".into(), 0).expect("create");
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
        let sid = store.create("n".into(), "r".into(), 0).expect("create");
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
        let sid = store.create("n".into(), "r".into(), 0).expect("create");
        store.approve(&sid, user(), 1).expect("approve");
        store.cancel(&sid, "user_cancelled", 2);
        assert_eq!(
            store.status(&sid, 3).expect("status"),
            SessionStatus::Approved
        );
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
        store.approve(&a, user(), 1).expect("approve");
        let b = store.create("n".into(), "r".into(), 2).expect("second");
        assert_ne!(a, b, "an approved session is not reused for a new login");
    }
}
