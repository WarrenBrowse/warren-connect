//! Browser login sessions.
//!
//! One session per DiscourseConnect round-trip: created when Discourse
//! redirects the browser to `/sso`, approved when the app's signed request
//! lands, confirmed when the browser that started it types (or is handed) the
//! one-time code the approving app received, consumed exactly once when that
//! browser is bounced back to Discourse. In-memory, single instance, short TTL.
//!
//! A session id is a name, never a credential: it travels in deep links, QR
//! codes and codes typed by hand, and any of those can be relayed to somebody
//! else. So completing a login takes two proofs that cannot travel together.
//! The browser key (the `/sso` cookie, kept here hashed) says "this is the
//! browser that started the login"; the completion code, returned only to the
//! wallet that signed the approval, says "that wallet approved THIS browser".
//! A relayed approval hands the code to the victim's app and leaves the
//! attacker's browser with a cookie and no code.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::{Rng as _, RngCore as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::discourse::SsoUser;
use crate::error::AuthError;
use crate::verify::Admitted;

/// How long a login may take from the approval page to the completion,
/// confirm step included. Kept short: it bounds how long a relayed approval
/// link is worth anything (see the threat note in warren-core doc 55).
pub(crate) const SESSION_TTL_SECS: u64 = 300;

/// Hard cap on concurrent sessions. At the cap a new login displaces the
/// oldest one that ended, else the oldest one still waiting for its approval,
/// and is refused only when every login is past its approval (see
/// `SessionStore::make_room`).
const MAX_SESSIONS: usize = 10_000;

/// Logins one DiscourseConnect payload opens while the last one lives. Each
/// login buys a subscription read, and its owner reopens it without asking
/// the forum for a new payload. Three cover the reloads a user makes after a
/// refusal they can repair (a clock set right, a subscription just paid).
const MAX_OPENS_PER_PAYLOAD: u8 = 3;

/// Logins one wallet holds past their approval at once: waiting for the code,
/// or confirmed and not completed yet. A full store never displaces those, so
/// without this one paying wallet could approve logins until it held the
/// whole store; with it, that takes a third as many paying wallets as the
/// store holds logins.
const MAX_APPROVED_PER_WALLET: usize = 3;

/// Wrong codes a browser may type before its login is cancelled. The code is
/// six digits, so the holder of a cookie and a relayed approval wins with
/// probability 5 in a million per approval they manage to obtain.
const CODE_ATTEMPTS: u8 = 5;

/// Digits in a completion code: short enough to type from a phone screen.
const CODE_DIGITS: usize = 6;

/// Bytes of entropy in a binding cookie.
const BROWSER_SECRET_BYTES: usize = 32;

/// A binding cookie value (the login cookie, the attach cookie): 32 bytes of
/// OS entropy as 64 lowercase hex chars. Lives in the browser only (an
/// `HttpOnly` cookie); the store keeps its hash.
pub struct BrowserSecret(Zeroizing<String>);

impl BrowserSecret {
    /// A fresh secret for a browser that presented none.
    #[must_use]
    pub fn generate() -> Self {
        let mut raw = Zeroizing::new([0u8; BROWSER_SECRET_BYTES]);
        rand::rngs::OsRng.fill_bytes(raw.as_mut());
        Self(Zeroizing::new(hex::encode(raw.as_ref())))
    }

    /// The secret a browser presented, when it has the exact shape this
    /// service mints. Anything else is not ours and binds nothing.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let well_formed = raw.len() == BROWSER_SECRET_BYTES * 2
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        well_formed.then(|| Self(Zeroizing::new(raw.to_owned())))
    }

    /// The cookie value, for the `Set-Cookie` header and nothing else.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// What the store keeps of this secret.
    #[must_use]
    pub fn key(&self) -> BrowserKey {
        BrowserKey(Sha256::digest(self.0.as_bytes()).into())
    }
}

impl std::fmt::Debug for BrowserSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserSecret(redacted)")
    }
}

/// SHA-256 of a browser's binding cookie: what a session is bound to.
#[derive(Clone, Copy)]
pub struct BrowserKey([u8; 32]);

impl BrowserKey {
    pub(crate) fn matches(&self, other: &BrowserKey) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl std::fmt::Debug for BrowserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserKey(redacted)")
    }
}

/// The one-time code an approval returns to the signing wallet, six digits
/// from the OS RNG. Never rendered by any page and never logged.
#[derive(Clone)]
pub struct CompletionCode(Zeroizing<String>);

impl CompletionCode {
    fn generate() -> Self {
        let n: u32 = rand::rngs::OsRng.gen_range(0..1_000_000);
        Self(Zeroizing::new(format!("{n:0width$}", width = CODE_DIGITS)))
    }

    /// Whether `typed` has the shape of a code at all. A string that cannot
    /// be one costs no attempt: it cannot be a guess at this one.
    #[must_use]
    pub fn well_formed(typed: &str) -> bool {
        typed.len() == CODE_DIGITS && typed.bytes().all(|b| b.is_ascii_digit())
    }

    /// The code, for the approving app's answer and nothing else.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant time over the digits: a timing difference on the first wrong
    /// digit would turn one guess per digit into a search of ten.
    fn matches(&self, typed: &str) -> bool {
        bool::from(self.0.as_bytes().ct_eq(typed.as_bytes()))
    }
}

impl std::fmt::Debug for CompletionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompletionCode(redacted)")
    }
}

/// Why a login ended without completing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    /// The app's user declined the sign-in.
    UserCancelled,
    /// The wallet has never subscribed.
    SubscriptionRequired,
    /// The approving device's clock is outside the signature window.
    ClockSkew,
    /// The approval came in the form that predates the completion code and
    /// was refused.
    AppUpdateRequired,
    /// The browser typed the last allowed wrong code.
    CodeAttemptsExhausted,
}

impl CancelReason {
    /// The token the pages and the vector name it by.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::UserCancelled => "user_cancelled",
            Self::SubscriptionRequired => "subscription_required",
            Self::ClockSkew => "clock_skew",
            Self::AppUpdateRequired => "app_update_required",
            Self::CodeAttemptsExhausted => "code_attempts_exhausted",
        }
    }
}

/// Session state as the browser that started it sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Waiting for the app's signed approval.
    Pending,
    /// The app approved; the browser must type the code the app received.
    AwaitingCode,
    /// Ready: the browser may complete the redirect to Discourse.
    Approved,
    /// This browser already completed the login (another of its tabs did).
    Completed,
    /// The login ended without one.
    Cancelled {
        /// Why, for the page to explain.
        reason: CancelReason,
    },
}

/// Which of a session's two ids an approval arrived on.
///
/// The button on the approval page hands the app the same-device id: the OS
/// gives the deep link to the app installed on the very machine that is
/// signing in. The QR hands out a second id, and reading a QR means a second
/// device by construction. It decides two things: whether the approving app
/// is handed a handoff URL for its own browser, and whether the login may
/// assert staff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approach {
    /// Approved from the deep link the same machine's browser opened.
    SameDevice,
    /// Approved from the QR, so from another device.
    CrossDevice,
}

/// The two ids of one login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIds {
    /// Held by the browser that started the flow: the button deep link, the
    /// status poll, the confirm and the completion all use this one.
    pub sid: String,
    /// Carried only by the QR.
    pub qr_sid: String,
}

/// What a confirm attempt did to the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// The code matched: the session is ready to complete.
    Confirmed,
    /// Wrong code, with the attempts the browser has left.
    Wrong {
        /// Attempts left before the login is cancelled, at least one.
        attempts_left: u8,
    },
    /// That was the last allowed wrong code: the login is cancelled.
    Exhausted,
    /// The session is not waiting for a code; its current state.
    NotAwaitingCode(SessionStatus),
}

/// What a completion attempt found.
#[derive(Debug, Clone)]
pub enum Consumed {
    /// The login, consumed now: build the signed response from it.
    Login(CompletedLogin),
    /// This browser completed it already, from another tab.
    AlreadyCompleted,
    /// Not ready to complete; its current state.
    NotReady(SessionStatus),
}

/// A consumed login: everything needed to build the signed DiscourseConnect
/// response.
#[derive(Debug, Clone)]
pub struct CompletedLogin {
    /// Discourse's nonce, echoed in the response payload.
    pub nonce: String,
    /// Redirect target back into Discourse.
    pub return_sso_url: String,
    /// The identity to assert.
    pub user: SsoUser,
}

enum State {
    Pending,
    AwaitingCode {
        user: SsoUser,
        code: CompletionCode,
        attempts_left: u8,
    },
    Approved {
        user: SsoUser,
    },
    Completed,
    Cancelled {
        reason: CancelReason,
    },
}

impl State {
    fn status(&self) -> SessionStatus {
        match self {
            State::Pending => SessionStatus::Pending,
            State::AwaitingCode { .. } => SessionStatus::AwaitingCode,
            State::Approved { .. } => SessionStatus::Approved,
            State::Completed => SessionStatus::Completed,
            State::Cancelled { reason } => SessionStatus::Cancelled { reason: *reason },
        }
    }

    /// The wallet (its forum external id) that approved a login past its
    /// approval.
    fn approved_by(&self) -> Option<&str> {
        match self {
            State::AwaitingCode { user, .. } | State::Approved { user } => Some(&user.external_id),
            State::Pending | State::Completed | State::Cancelled { .. } => None,
        }
    }

    /// The order in which a full store displaces logins, lowest first. An
    /// ended login only still answers a page's last poll; one waiting for its
    /// approval costs its user a new sign-in from the forum. `None` past the
    /// approval: that browser holds the only way to finish, and a flood must
    /// never take it.
    fn displacement_rank(&self) -> Option<u8> {
        match self {
            State::Completed | State::Cancelled { .. } => Some(0),
            State::Pending => Some(1),
            State::AwaitingCode { .. } | State::Approved { .. } => None,
        }
    }
}

/// Whether something created at `created_unix` is still within the login TTL.
fn alive(created_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(created_unix) < SESSION_TTL_SECS
}

struct Session {
    nonce: String,
    return_sso_url: String,
    created_unix: u64,
    browser: BrowserKey,
    qr_sid: String,
    state: State,
    /// Logins opened for this nonce, this one included.
    opens: u8,
}

impl Session {
    fn live(&self, now_unix: u64) -> bool {
        alive(self.created_unix, now_unix)
    }
}

/// What a displaced login leaves behind until it would have expired, so its
/// payload keeps its owner and its count of logins opened: without it a flood
/// that displaces a payload's login would hand that payload a fresh count.
struct Displaced {
    browser: BrowserKey,
    opens: u8,
    created_unix: u64,
}

/// In-memory session registry.
///
/// Keyed on the same-device sid. `by_qr` maps the QR's id onto it, so the two
/// ids address one session and only one of them ever says "another device".
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    by_qr: Mutex<HashMap<String, String>>,
    /// Displaced logins, by nonce.
    displaced: Mutex<HashMap<String, Displaced>>,
    /// Logins held at once, and records of displaced ones kept at once.
    capacity: usize,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::with_capacity(MAX_SESSIONS)
    }
}

impl std::fmt::Debug for SessionStore {
    /// A count only: the keys are session ids, and nothing else in a session
    /// is fit to print either.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let live = self.sessions.lock().map_or(0, |sessions| sessions.len());
        f.debug_struct("SessionStore")
            .field("sessions", &live)
            .finish_non_exhaustive()
    }
}

/// 16 bytes of OS entropy as 32 hex chars: the shape every client validates.
fn fresh_sid() -> String {
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

impl SessionStore {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            sessions: Mutex::default(),
            by_qr: Mutex::default(),
            displaced: Mutex::default(),
            capacity,
        }
    }

    /// Opens a login for `browser`, or hands that browser back the one it
    /// already has for this DiscourseConnect nonce (a page refresh).
    ///
    /// One live session per nonce, owned by the browser that opened it: a
    /// valid `sso`+`sig` payload replays to `/sso` from anywhere, and another
    /// browser replaying it gets neither the pending session nor a fresh one.
    /// That also keeps one captured payload from minting sessions until the
    /// store is full. The owner reopening a cancelled or completed login gets
    /// a fresh session in its place, up to [`MAX_OPENS_PER_PAYLOAD`] logins
    /// while the latest one lives. A login displaced from a full store keeps
    /// both rules for its payload until it would have expired.
    ///
    /// # Errors
    /// [`AuthError::BrowserMismatch`] when the nonce's live or displaced
    /// login belongs to another browser, [`AuthError::Session`] when the
    /// payload has opened its last login or every login in a full store is
    /// past its approval.
    pub fn create(
        &self,
        nonce: String,
        return_sso_url: String,
        browser: &BrowserKey,
        now_unix: u64,
    ) -> Result<SessionIds, AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        let mut by_qr = self.by_qr.lock().expect("qr index mutex never poisoned");
        let mut displaced = self
            .displaced
            .lock()
            .expect("displaced mutex never poisoned");
        sessions.retain(|_, s| {
            let live = s.live(now_unix);
            if !live {
                by_qr.remove(&s.qr_sid);
            }
            live
        });
        displaced.retain(|_, d| alive(d.created_unix, now_unix));

        let mut opens = 1;
        if let Some(sid) = sessions
            .iter()
            .find(|(_, s)| s.nonce == nonce)
            .map(|(sid, _)| sid.clone())
        {
            let session = &sessions[&sid];
            if !session.browser.matches(browser) {
                return Err(AuthError::BrowserMismatch);
            }
            match session.state {
                State::Pending | State::AwaitingCode { .. } | State::Approved { .. } => {
                    return Ok(SessionIds {
                        qr_sid: session.qr_sid.clone(),
                        sid,
                    });
                }
                State::Completed | State::Cancelled { .. } => {
                    // Refused with the ended login left in place, so its
                    // count lasts until it expires.
                    if session.opens >= MAX_OPENS_PER_PAYLOAD {
                        return Err(AuthError::Session);
                    }
                    opens = session.opens + 1;
                    by_qr.remove(&session.qr_sid);
                    sessions.remove(&sid);
                }
            }
        } else if let Some(record) = displaced.get(&nonce) {
            if !record.browser.matches(browser) {
                return Err(AuthError::BrowserMismatch);
            }
            if record.opens >= MAX_OPENS_PER_PAYLOAD {
                return Err(AuthError::Session);
            }
            opens = record.opens + 1;
        }

        if sessions.len() >= self.capacity {
            self.make_room(&mut sessions, &mut by_qr, &mut displaced)?;
        }
        // Past the refusals above: a refused open leaves the record in place.
        displaced.remove(&nonce);
        let sid = fresh_sid();
        let qr_sid = fresh_sid();
        by_qr.insert(qr_sid.clone(), sid.clone());
        sessions.insert(
            sid.clone(),
            Session {
                nonce,
                return_sso_url,
                created_unix: now_unix,
                browser: *browser,
                qr_sid: qr_sid.clone(),
                state: State::Pending,
                opens,
            },
        );
        Ok(SessionIds { sid, qr_sid })
    }

    /// Frees one place in a full store: the oldest login that ended, else the
    /// oldest one still waiting for its approval.
    ///
    /// `/sso` takes any payload the forum signed and each forum visit mints
    /// one, so refusing at capacity would let a pile of harvested payloads
    /// refuse every sign-in. Displacing the oldest means a flood mostly
    /// displaces its own logins: a user's login waiting for its approval
    /// outlasts every ended login and every older waiting one, and the user
    /// who loses it signs in again from the forum.
    ///
    /// # Errors
    /// [`AuthError::Session`] when every login is past its approval, which
    /// [`MAX_APPROVED_PER_WALLET`] makes cost a third as many paying wallets
    /// as the store holds logins.
    fn make_room(
        &self,
        sessions: &mut HashMap<String, Session>,
        by_qr: &mut HashMap<String, String>,
        displaced: &mut HashMap<String, Displaced>,
    ) -> Result<(), AuthError> {
        let victim = sessions
            .iter()
            .filter_map(|(sid, s)| {
                let rank = s.state.displacement_rank()?;
                Some(((rank, s.created_unix), sid))
            })
            .min()
            .map(|(_, sid)| sid.clone())
            .ok_or(AuthError::Session)?;
        let session = sessions.remove(&victim).expect("the victim was just found");
        by_qr.remove(&session.qr_sid);
        if displaced.len() >= self.capacity
            && let Some(oldest) = displaced
                .iter()
                .min_by_key(|(_, d)| d.created_unix)
                .map(|(nonce, _)| nonce.clone())
        {
            displaced.remove(&oldest);
        }
        displaced.insert(
            session.nonce,
            Displaced {
                browser: session.browser,
                opens: session.opens,
                created_unix: session.created_unix,
            },
        );
        Ok(())
    }

    /// Resolves either id onto the session's own key, saying which one it was.
    ///
    /// # Errors
    /// [`AuthError::Session`] if the id matches no live session.
    pub fn resolve(&self, sid: &str, now_unix: u64) -> Result<(String, Approach), AuthError> {
        let sessions = self.sessions.lock().expect("session mutex never poisoned");
        let live = |key: &str| sessions.get(key).is_some_and(|s| s.live(now_unix));
        if live(sid) {
            return Ok((sid.to_owned(), Approach::SameDevice));
        }
        let by_qr = self.by_qr.lock().expect("qr index mutex never poisoned");
        let primary = by_qr.get(sid).cloned().ok_or(AuthError::Session)?;
        if !live(&primary) {
            return Err(AuthError::Session);
        }
        Ok((primary, Approach::CrossDevice))
    }

    /// Whether the session behind either id still waits for an approval.
    ///
    /// This is all a caller without the browser's cookie ever learns (the
    /// app, before it signs), and a signed approval learns as much anyway.
    #[must_use]
    pub fn awaits_approval(&self, sid: &str, now_unix: u64) -> bool {
        let Ok((primary, _)) = self.resolve(sid, now_unix) else {
            return false;
        };
        let sessions = self.sessions.lock().expect("session mutex never poisoned");
        sessions
            .get(&primary)
            .is_some_and(|s| matches!(s.state, State::Pending))
    }

    /// Cancels a login that still waits for an approval (the app declined,
    /// or the approval was refused), with a short reason token. Accepts
    /// either id. A no-op on anything else: past the approval the browser
    /// alone decides, so an id, which anybody may hold, cannot end it.
    pub fn cancel(&self, sid: &str, reason: CancelReason, now_unix: u64) {
        let Ok((primary, _)) = self.resolve(sid, now_unix) else {
            return;
        };
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        if let Some(session) = sessions.get_mut(&primary)
            && matches!(session.state, State::Pending)
        {
            session.state = State::Cancelled { reason };
        }
    }

    /// Records a bound approval: the session waits for its browser to present
    /// the code returned here. Accepts either id; the caller decides what to
    /// put in `user` from the [`Approach`] it got out of [`Self::resolve`].
    ///
    /// # Errors
    /// [`AuthError::Session`] if the session is unknown, expired, or no longer
    /// waiting for an approval: a second approval never replaces the first.
    /// [`AuthError::RateLimited`] when the wallet already holds
    /// [`MAX_APPROVED_PER_WALLET`] logins past their approval; the session
    /// keeps waiting.
    pub fn approve_bound(
        &self,
        _admitted: &Admitted,
        sid: &str,
        user: SsoUser,
        now_unix: u64,
    ) -> Result<CompletionCode, AuthError> {
        let code = CompletionCode::generate();
        self.approve(
            sid,
            State::AwaitingCode {
                user,
                code: code.clone(),
                attempts_left: CODE_ATTEMPTS,
            },
            now_unix,
        )?;
        Ok(code)
    }

    /// Records an approval from an app that predates the code: the session
    /// is ready at once, still for its own browser only.
    ///
    /// # Errors
    /// As [`Self::approve_bound`].
    pub fn approve_legacy(
        &self,
        _admitted: &Admitted,
        sid: &str,
        user: SsoUser,
        now_unix: u64,
    ) -> Result<(), AuthError> {
        self.approve(sid, State::Approved { user }, now_unix)
    }

    fn approve(&self, sid: &str, next: State, now_unix: u64) -> Result<(), AuthError> {
        let (primary, _) = self.resolve(sid, now_unix)?;
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        if !sessions
            .get(&primary)
            .is_some_and(|s| matches!(s.state, State::Pending))
        {
            return Err(AuthError::Session);
        }
        let held = next.approved_by().map_or(0, |wallet| {
            sessions
                .values()
                .filter(|s| s.live(now_unix) && s.state.approved_by() == Some(wallet))
                .count()
        });
        if held >= MAX_APPROVED_PER_WALLET {
            return Err(AuthError::RateLimited);
        }
        let session = sessions.get_mut(&primary).ok_or(AuthError::Session)?;
        session.state = next;
        Ok(())
    }

    /// The session's state, for the browser that started it. Takes the
    /// same-device id only: the QR's id is the app's, never a browser's.
    ///
    /// # Errors
    /// [`AuthError::BrowserMismatch`] when `browser` is not the one the
    /// session is bound to, or no live session has this id: both answer the
    /// same, so a browser learns nothing about a session that is not its own.
    pub fn status(
        &self,
        sid: &str,
        browser: &BrowserKey,
        now_unix: u64,
    ) -> Result<SessionStatus, AuthError> {
        let sessions = self.sessions.lock().expect("session mutex never poisoned");
        let session = owned(&sessions, sid, browser, now_unix)?;
        Ok(session.state.status())
    }

    /// The browser's attempt at the code its app received. Single use: the
    /// matching code moves the session on and is dropped; each wrong one
    /// spends an attempt, and the last one cancels the login.
    ///
    /// # Errors
    /// [`AuthError::BrowserMismatch`] as in [`Self::status`].
    pub fn confirm(
        &self,
        sid: &str,
        browser: &BrowserKey,
        typed: &str,
        now_unix: u64,
    ) -> Result<ConfirmOutcome, AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        owned(&sessions, sid, browser, now_unix)?;
        let session = sessions.get_mut(sid).ok_or(AuthError::BrowserMismatch)?;
        let state = std::mem::replace(&mut session.state, State::Pending);
        let State::AwaitingCode {
            user,
            code,
            attempts_left,
        } = state
        else {
            let status = state.status();
            session.state = state;
            return Ok(ConfirmOutcome::NotAwaitingCode(status));
        };
        if code.matches(typed) {
            session.state = State::Approved { user };
            return Ok(ConfirmOutcome::Confirmed);
        }
        let attempts_left = attempts_left.saturating_sub(1);
        if attempts_left == 0 {
            session.state = State::Cancelled {
                reason: CancelReason::CodeAttemptsExhausted,
            };
            return Ok(ConfirmOutcome::Exhausted);
        }
        session.state = State::AwaitingCode {
            user,
            code,
            attempts_left,
        };
        Ok(ConfirmOutcome::Wrong { attempts_left })
    }

    /// Completes a ready login for the browser that started it (single use).
    /// The session stays behind as completed until its TTL, so a second tab
    /// of the same browser is told so rather than refused.
    ///
    /// # Errors
    /// [`AuthError::BrowserMismatch`] as in [`Self::status`].
    pub fn consume(
        &self,
        sid: &str,
        browser: &BrowserKey,
        now_unix: u64,
    ) -> Result<Consumed, AuthError> {
        let mut sessions = self.sessions.lock().expect("session mutex never poisoned");
        owned(&sessions, sid, browser, now_unix)?;
        let session = sessions.get_mut(sid).ok_or(AuthError::BrowserMismatch)?;
        let user = match std::mem::replace(&mut session.state, State::Completed) {
            State::Approved { user } => user,
            State::Completed => return Ok(Consumed::AlreadyCompleted),
            other => {
                let status = other.status();
                session.state = other;
                return Ok(Consumed::NotReady(status));
            }
        };
        self.by_qr
            .lock()
            .expect("qr index mutex never poisoned")
            .remove(&session.qr_sid);
        Ok(Consumed::Login(CompletedLogin {
            nonce: session.nonce.clone(),
            return_sso_url: session.return_sso_url.clone(),
            user,
        }))
    }
}

/// The live session `sid` names, if `browser` is the one it is bound to.
fn owned<'a>(
    sessions: &'a HashMap<String, Session>,
    sid: &str,
    browser: &BrowserKey,
    now_unix: u64,
) -> Result<&'a Session, AuthError> {
    sessions
        .get(sid)
        .filter(|s| s.live(now_unix) && s.browser.matches(browser))
        .ok_or(AuthError::BrowserMismatch)
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

    fn browser() -> BrowserKey {
        BrowserSecret::generate().key()
    }

    fn open(store: &SessionStore, nonce: &str, browser: &BrowserKey) -> SessionIds {
        store
            .create(nonce.into(), "https://f/sso_login".into(), browser, 0)
            .expect("create")
    }

    #[test]
    fn a_bound_login_goes_pending_awaiting_code_approved_completed() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);

        assert_eq!(store.status(&ids.sid, &b, 1), Ok(SessionStatus::Pending));
        let code = store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 2)
            .expect("approve");
        assert_eq!(
            store.status(&ids.sid, &b, 3),
            Ok(SessionStatus::AwaitingCode)
        );
        assert_eq!(
            store.confirm(&ids.sid, &b, code.as_str(), 4),
            Ok(ConfirmOutcome::Confirmed)
        );
        assert_eq!(store.status(&ids.sid, &b, 5), Ok(SessionStatus::Approved));

        let Ok(Consumed::Login(done)) = store.consume(&ids.sid, &b, 6) else {
            panic!("a confirmed login completes");
        };
        assert_eq!(done.nonce, "n");
        assert_eq!(done.return_sso_url, "https://f/sso_login");
        assert_eq!(store.status(&ids.sid, &b, 7), Ok(SessionStatus::Completed));
    }

    #[test]
    fn an_approved_but_unconfirmed_login_does_not_complete() {
        // The relay in one line: the approval landed, the browser holds its
        // cookie, and without the code that is still not a login.
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");

        assert!(matches!(
            store.consume(&ids.sid, &b, 2),
            Ok(Consumed::NotReady(SessionStatus::AwaitingCode))
        ));
    }

    #[test]
    fn the_completion_code_is_six_digits_and_fresh_per_approval() {
        let store = SessionStore::default();
        let b = browser();
        let codes: Vec<String> = (0..20)
            .map(|i| {
                let ids = open(&store, &format!("n{i}"), &b);
                let mut wallet = user();
                wallet.external_id = format!("e{i}");
                store
                    .approve_bound(&Admitted::for_tests(), &ids.sid, wallet, 1)
                    .expect("approve")
                    .as_str()
                    .to_owned()
            })
            .collect();
        for code in &codes {
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
        let mut distinct = codes.clone();
        distinct.sort();
        distinct.dedup();
        assert!(
            distinct.len() > 15,
            "twenty approvals drawing near-identical codes is not an RNG: {codes:?}"
        );
    }

    #[test]
    fn nothing_but_the_browser_that_opened_the_login_can_read_confirm_or_complete_it() {
        let store = SessionStore::default();
        let owner = browser();
        let stranger = browser();
        let ids = open(&store, "n", &owner);
        let code = store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");

        assert_eq!(
            store.status(&ids.sid, &stranger, 2),
            Err(AuthError::BrowserMismatch)
        );
        assert_eq!(
            store.confirm(&ids.sid, &stranger, code.as_str(), 2),
            Err(AuthError::BrowserMismatch),
            "the right code from the wrong browser is still refused"
        );
        assert!(matches!(
            store.consume(&ids.sid, &stranger, 2),
            Err(AuthError::BrowserMismatch)
        ));
        assert_eq!(
            store.status(&ids.sid, &owner, 3),
            Ok(SessionStatus::AwaitingCode),
            "and the stranger's attempt cost the owner nothing"
        );
    }

    #[test]
    fn an_unknown_id_answers_exactly_like_a_session_of_another_browser() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);

        assert_eq!(
            store.status("deadbeef", &b, 1),
            Err(AuthError::BrowserMismatch)
        );
        assert_eq!(
            store.status(&ids.qr_sid, &b, 1),
            Err(AuthError::BrowserMismatch),
            "the QR id is the app's, never a browser's"
        );
    }

    #[test]
    fn each_wrong_code_spends_an_attempt_and_the_last_cancels_the_login() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        let code = store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");
        let wrong = if code.as_str() == "000000" {
            "000001"
        } else {
            "000000"
        };

        for left in (1..CODE_ATTEMPTS).rev() {
            assert_eq!(
                store.confirm(&ids.sid, &b, wrong, 2),
                Ok(ConfirmOutcome::Wrong {
                    attempts_left: left
                })
            );
        }
        assert_eq!(
            store.confirm(&ids.sid, &b, wrong, 2),
            Ok(ConfirmOutcome::Exhausted)
        );
        assert_eq!(
            store.status(&ids.sid, &b, 3),
            Ok(SessionStatus::Cancelled {
                reason: CancelReason::CodeAttemptsExhausted
            })
        );
        assert_eq!(
            store.confirm(&ids.sid, &b, code.as_str(), 4),
            Ok(ConfirmOutcome::NotAwaitingCode(SessionStatus::Cancelled {
                reason: CancelReason::CodeAttemptsExhausted
            })),
            "the right code after the budget opens nothing"
        );
    }

    #[test]
    fn a_code_is_single_use() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        let code = store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");
        store
            .confirm(&ids.sid, &b, code.as_str(), 2)
            .expect("first");

        assert_eq!(
            store.confirm(&ids.sid, &b, code.as_str(), 3),
            Ok(ConfirmOutcome::NotAwaitingCode(SessionStatus::Approved))
        );
    }

    #[test]
    fn a_legacy_approval_is_ready_at_once_for_its_own_browser_only() {
        let store = SessionStore::default();
        let owner = browser();
        let ids = open(&store, "n", &owner);
        store
            .approve_legacy(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");

        assert_eq!(
            store.status(&ids.sid, &owner, 2),
            Ok(SessionStatus::Approved)
        );
        assert!(matches!(
            store.consume(&ids.sid, &browser(), 3),
            Err(AuthError::BrowserMismatch)
        ));
        assert!(matches!(
            store.consume(&ids.sid, &owner, 3),
            Ok(Consumed::Login(_))
        ));
    }

    #[test]
    fn a_second_approval_never_replaces_the_first() {
        // Whoever holds the id could otherwise swap their own account in
        // under a login somebody else's wallet already approved.
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("first");

        assert_eq!(
            store
                .approve_bound(&Admitted::for_tests(), &ids.qr_sid, user(), 2)
                .map(|_| ()),
            Err(AuthError::Session)
        );
        assert_eq!(
            store.approve_legacy(&Admitted::for_tests(), &ids.sid, user(), 2),
            Err(AuthError::Session)
        );
    }

    #[test]
    fn a_completion_is_single_use_and_a_second_tab_is_told_it_happened() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        store
            .approve_legacy(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");
        assert!(matches!(
            store.consume(&ids.sid, &b, 2),
            Ok(Consumed::Login(_))
        ));

        assert!(
            matches!(
                store.consume(&ids.sid, &b, 3),
                Ok(Consumed::AlreadyCompleted)
            ),
            "a completed login must not be replayable into Discourse"
        );
        assert!(
            store.resolve(&ids.qr_sid, 4).is_err(),
            "completing retires the qr id, or it outlives its login"
        );
    }

    #[test]
    fn sessions_expire() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        assert_eq!(
            store.status(&ids.sid, &b, SESSION_TTL_SECS),
            Err(AuthError::BrowserMismatch)
        );
        assert!(
            store
                .approve_bound(&Admitted::for_tests(), &ids.sid, user(), SESSION_TTL_SECS)
                .is_err()
        );
        assert!(store.resolve(&ids.qr_sid, SESSION_TTL_SECS).is_err());
    }

    #[test]
    fn cancel_ends_a_pending_login_and_blocks_a_later_approval() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        store.cancel(&ids.qr_sid, CancelReason::UserCancelled, 1);

        assert_eq!(
            store.status(&ids.sid, &b, 2),
            Ok(SessionStatus::Cancelled {
                reason: CancelReason::UserCancelled
            }),
            "either id cancels, and the browser polling its own sees it"
        );
        assert!(
            store
                .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 3)
                .is_err()
        );
    }

    #[test]
    fn an_id_alone_cannot_cancel_a_login_past_its_approval() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");

        store.cancel(&ids.sid, CancelReason::UserCancelled, 2);

        assert_eq!(
            store.status(&ids.sid, &b, 3),
            Ok(SessionStatus::AwaitingCode)
        );
    }

    #[test]
    fn only_a_login_that_waits_for_an_approval_says_so_to_a_caller_without_the_cookie() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);
        assert!(store.awaits_approval(&ids.sid, 1));
        assert!(store.awaits_approval(&ids.qr_sid, 1), "the QR id too");
        assert!(!store.awaits_approval("deadbeef", 1));

        store
            .approve_bound(&Admitted::for_tests(), &ids.qr_sid, user(), 2)
            .expect("approve");

        assert!(!store.awaits_approval(&ids.sid, 3));
        assert!(!store.awaits_approval(&ids.qr_sid, 3));
    }

    #[test]
    fn the_qr_id_addresses_the_same_session_and_says_so() {
        let store = SessionStore::default();
        let ids = open(&store, "n", &browser());

        assert_ne!(ids.sid, ids.qr_sid, "a shared id would carry no signal");
        assert_eq!(ids.qr_sid.len(), 32, "clients validate 32 lowercase hex");
        assert!(ids.qr_sid.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            store.resolve(&ids.sid, 1),
            Ok((ids.sid.clone(), Approach::SameDevice))
        );
        assert_eq!(
            store.resolve(&ids.qr_sid, 1),
            Ok((ids.sid.clone(), Approach::CrossDevice))
        );
    }

    #[test]
    fn an_approval_on_the_qr_id_waits_for_the_code_in_the_browser_that_opened_it() {
        let store = SessionStore::default();
        let b = browser();
        let ids = open(&store, "n", &b);

        let code = store
            .approve_bound(&Admitted::for_tests(), &ids.qr_sid, user(), 1)
            .expect("phone");

        assert_eq!(
            store.status(&ids.sid, &b, 2),
            Ok(SessionStatus::AwaitingCode)
        );
        assert_eq!(
            store.confirm(&ids.sid, &b, code.as_str(), 3),
            Ok(ConfirmOutcome::Confirmed)
        );
    }

    #[test]
    fn the_browser_that_opened_a_login_gets_it_back_and_no_other_browser_does() {
        let store = SessionStore::default();
        let owner = browser();
        let first = open(&store, "nonceA", &owner);

        assert_eq!(open(&store, "nonceA", &owner), first, "a refresh keeps it");
        assert_eq!(
            store.create("nonceA".into(), "r".into(), &browser(), 1),
            Err(AuthError::BrowserMismatch),
            "a replayed payload from another browser gets nothing"
        );
        assert_ne!(
            open(&store, "nonceB", &owner),
            first,
            "another nonce is another login"
        );
    }

    #[test]
    fn a_replay_from_another_browser_is_refused_whatever_state_the_login_is_in() {
        let store = SessionStore::default();
        let owner = browser();
        let ids = open(&store, "n", &owner);
        store
            .approve_legacy(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");
        store.consume(&ids.sid, &owner, 2).expect("complete");

        assert_eq!(
            store.create("n".into(), "r".into(), &browser(), 3),
            Err(AuthError::BrowserMismatch),
            "one live session per nonce, so a payload cannot mint a second"
        );
    }

    #[test]
    fn the_owner_reopening_a_cancelled_login_gets_a_fresh_one() {
        // The clock-skew case: fix the clock, refresh the page, try again.
        let store = SessionStore::default();
        let b = browser();
        let first = open(&store, "n", &b);
        store.cancel(&first.sid, CancelReason::ClockSkew, 1);

        let second = open(&store, "n", &b);

        assert_ne!(second, first);
        assert_eq!(store.status(&second.sid, &b, 2), Ok(SessionStatus::Pending));
        assert!(
            store.resolve(&first.qr_sid, 2).is_err(),
            "the replaced login's QR must die with it"
        );
    }

    #[test]
    fn one_payload_opens_three_logins_while_they_live_and_no_more() {
        // Each login spends a subscription read, and a reopened one costs no
        // new payload from the forum: without a bound one payload would buy
        // reads for as many minted wallets as could sign.
        let store = SessionStore::default();
        let b = browser();
        for at in 0..3 {
            let ids = store
                .create("n".into(), "r".into(), &b, at)
                .unwrap_or_else(|err| panic!("open {at}: {err}"));
            store.cancel(&ids.sid, CancelReason::SubscriptionRequired, at);
        }

        assert_eq!(
            store.create("n".into(), "r".into(), &b, 3).map(|_| ()),
            Err(AuthError::Session)
        );
        assert!(
            store
                .create("n".into(), "r".into(), &b, 2 + SESSION_TTL_SECS)
                .is_ok(),
            "once the last one has expired the payload opens again"
        );
    }

    /// Opens `count` logins at `now_unix`, each from its own payload and its
    /// own browser, the way a pile of harvested payloads arrives.
    fn flood(store: &SessionStore, tag: &str, count: usize, now_unix: u64) {
        for i in 0..count {
            store
                .create(format!("{tag}-{i}"), "r".into(), &browser(), now_unix)
                .unwrap_or_else(|err| panic!("flood {tag}-{i}: {err}"));
        }
    }

    #[test]
    fn at_capacity_a_new_login_displaces_the_oldest_waiting_one() {
        // Each forum visit mints a payload `/sso` accepts, so refusing at
        // capacity would let a pile of harvested payloads refuse every
        // sign-in.
        let store = SessionStore::default();
        let first = browser();
        let oldest = store
            .create("oldest".into(), "r".into(), &first, 0)
            .expect("open");
        flood(&store, "flood", MAX_SESSIONS - 1, 1);

        let fresh = store.create("fresh".into(), "r".into(), &browser(), 2);

        assert!(fresh.is_ok(), "a full store still opens a login: {fresh:?}");
        assert_eq!(
            store.status(&oldest.sid, &first, 3),
            Err(AuthError::BrowserMismatch),
            "the oldest login still waiting for its approval made room"
        );
    }

    #[test]
    fn a_full_store_displaces_an_ended_login_before_a_waiting_one() {
        let store = SessionStore::with_capacity(3);
        let (waiting, ended, newer) = (browser(), browser(), browser());
        let older = store
            .create("waiting".into(), "r".into(), &waiting, 0)
            .expect("open");
        let cancelled = store
            .create("ended".into(), "r".into(), &ended, 1)
            .expect("open");
        store.cancel(&cancelled.sid, CancelReason::UserCancelled, 1);
        let newest = store
            .create("newer".into(), "r".into(), &newer, 2)
            .expect("open");

        store
            .create("fresh".into(), "r".into(), &browser(), 3)
            .expect("a full store makes room");

        assert_eq!(
            store.status(&cancelled.sid, &ended, 4),
            Err(AuthError::BrowserMismatch)
        );
        assert_eq!(
            store.status(&older.sid, &waiting, 4),
            Ok(SessionStatus::Pending),
            "the older login still waits for its approval, so it stays"
        );
        assert_eq!(
            store.status(&newest.sid, &newer, 4),
            Ok(SessionStatus::Pending)
        );
    }

    #[test]
    fn a_login_past_its_approval_survives_any_flood() {
        let store = SessionStore::with_capacity(4);
        let (awaiting, confirmed) = (browser(), browser());
        let awaiting_ids = open(&store, "awaiting", &awaiting);
        let code = store
            .approve_bound(&Admitted::for_tests(), &awaiting_ids.sid, user(), 1)
            .expect("approve");
        let confirmed_ids = open(&store, "confirmed", &confirmed);
        let confirmed_code = store
            .approve_bound(&Admitted::for_tests(), &confirmed_ids.sid, user(), 1)
            .expect("approve");
        store
            .confirm(&confirmed_ids.sid, &confirmed, confirmed_code.as_str(), 2)
            .expect("confirm");

        flood(&store, "flood", 40, 3);

        assert_eq!(
            store.confirm(&awaiting_ids.sid, &awaiting, code.as_str(), 4),
            Ok(ConfirmOutcome::Confirmed)
        );
        assert!(matches!(
            store.consume(&confirmed_ids.sid, &confirmed, 4),
            Ok(Consumed::Login(_))
        ));
    }

    #[test]
    fn a_store_full_of_approved_logins_refuses_a_new_one() {
        let store = SessionStore::with_capacity(MAX_APPROVED_PER_WALLET);
        for i in 0..MAX_APPROVED_PER_WALLET {
            let ids = open(&store, &format!("n{i}"), &browser());
            store
                .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
                .expect("approve");
        }

        assert_eq!(
            store
                .create("fresh".into(), "r".into(), &browser(), 2)
                .map(|_| ()),
            Err(AuthError::Session)
        );
    }

    #[test]
    fn a_displaced_login_keeps_its_payloads_owner_and_count() {
        let store = SessionStore::with_capacity(1);
        let owner = browser();
        store
            .create("p".into(), "r".into(), &owner, 0)
            .expect("first login");
        flood(&store, "displace-first", 1, 1);

        assert_eq!(
            store
                .create("p".into(), "r".into(), &browser(), 2)
                .map(|_| ()),
            Err(AuthError::BrowserMismatch),
            "a displaced payload still belongs to the browser that opened it"
        );
        let second = store
            .create("p".into(), "r".into(), &owner, 2)
            .expect("its owner opens it again");
        store.cancel(&second.sid, CancelReason::SubscriptionRequired, 2);
        store
            .create("p".into(), "r".into(), &owner, 3)
            .expect("third login");
        flood(&store, "displace-third", 1, 4);

        assert_eq!(
            store.create("p".into(), "r".into(), &owner, 5).map(|_| ()),
            Err(AuthError::Session),
            "displacing its third login did not buy the payload a fourth"
        );
        assert!(
            store
                .create("p".into(), "r".into(), &owner, 3 + SESSION_TTL_SECS)
                .is_ok(),
            "once its last login would have expired the payload opens again"
        );
    }

    #[test]
    fn a_flood_keeps_the_store_and_its_displaced_records_bounded() {
        let capacity = 4;
        let store = SessionStore::with_capacity(capacity);

        flood(&store, "flood", 10 * capacity, 0);
        flood(&store, "later", 10 * capacity, SESSION_TTL_SECS);

        let sessions = store.sessions.lock().expect("sessions").len();
        let by_qr = store.by_qr.lock().expect("qr index").len();
        let displaced = store.displaced.lock().expect("displaced").len();
        assert_eq!((sessions, by_qr, displaced), (capacity, capacity, capacity));
    }

    #[test]
    fn one_wallet_holds_three_logins_past_their_approval_and_no_more() {
        let store = SessionStore::default();
        let browsers: Vec<BrowserKey> = (0..=MAX_APPROVED_PER_WALLET).map(|_| browser()).collect();
        let logins: Vec<SessionIds> = browsers
            .iter()
            .enumerate()
            .map(|(i, b)| open(&store, &format!("n{i}"), b))
            .collect();
        let mut codes = Vec::new();
        for ids in &logins[..MAX_APPROVED_PER_WALLET] {
            codes.push(
                store
                    .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
                    .expect("approve"),
            );
        }
        let last = &logins[MAX_APPROVED_PER_WALLET];

        assert_eq!(
            store
                .approve_bound(&Admitted::for_tests(), &last.sid, user(), 2)
                .map(|_| ()),
            Err(AuthError::RateLimited)
        );
        assert!(
            store.awaits_approval(&last.sid, 2),
            "the refused one keeps waiting"
        );
        let mut stranger = user();
        stranger.external_id = "another wallet".into();
        let other = open(&store, "other", &browser());
        assert!(
            store
                .approve_legacy(&Admitted::for_tests(), &other.sid, stranger, 2)
                .is_ok(),
            "another wallet is not held back"
        );
        store
            .confirm(&logins[0].sid, &browsers[0], codes[0].as_str(), 3)
            .expect("confirm");
        store
            .consume(&logins[0].sid, &browsers[0], 3)
            .expect("complete");
        assert!(
            store
                .approve_bound(&Admitted::for_tests(), &last.sid, user(), 4)
                .is_ok(),
            "a completed login gives its place back"
        );
    }

    #[test]
    fn only_six_digits_have_the_shape_of_a_code() {
        assert!(CompletionCode::well_formed("042917"));
        for hostile in ["", "42917", "0429170", "04291a", "04 917", "\u{661}42917"] {
            assert!(!CompletionCode::well_formed(hostile), "{hostile:?}");
        }
    }

    #[test]
    fn every_cancel_reason_has_the_token_the_pages_read() {
        let tokens: Vec<&str> = [
            CancelReason::UserCancelled,
            CancelReason::SubscriptionRequired,
            CancelReason::ClockSkew,
            CancelReason::AppUpdateRequired,
            CancelReason::CodeAttemptsExhausted,
        ]
        .into_iter()
        .map(CancelReason::token)
        .collect();
        assert_eq!(
            tokens,
            [
                "user_cancelled",
                "subscription_required",
                "clock_skew",
                "app_update_required",
                "code_attempts_exhausted"
            ]
        );
    }

    #[test]
    fn a_browser_secret_is_64_lowercase_hex_and_anything_else_binds_nothing() {
        let fresh = BrowserSecret::generate();
        assert_eq!(fresh.as_str().len(), 64);
        assert!(BrowserSecret::parse(fresh.as_str()).is_some());
        for hostile in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"a".repeat(65)] {
            assert!(BrowserSecret::parse(hostile).is_none(), "{hostile:?}");
        }
        let a = BrowserSecret::parse(&"a".repeat(64)).expect("shape");
        let b = BrowserSecret::parse(&"b".repeat(64)).expect("shape");
        assert!(a.key().matches(&a.key()));
        assert!(!a.key().matches(&b.key()));
    }

    #[test]
    fn no_secret_renders_through_debug() {
        let secret = BrowserSecret::parse(&"c".repeat(64)).expect("shape");
        assert_eq!(format!("{secret:?}"), "BrowserSecret(redacted)");
        assert_eq!(format!("{:?}", secret.key()), "BrowserKey(redacted)");
        let store = SessionStore::default();
        let ids = open(&store, "n", &secret.key());
        let code = store
            .approve_bound(&Admitted::for_tests(), &ids.sid, user(), 1)
            .expect("approve");
        assert_eq!(format!("{code:?}"), "CompletionCode(redacted)");

        let rendered = format!("{store:?}");
        assert_eq!(rendered, "SessionStore { sessions: 1, .. }");
        assert!(!rendered.contains(&ids.sid) && !rendered.contains(&ids.qr_sid));
    }
}
