//! Attach-logs sessions and the size-capped log decompression.
//!
//! One session per "attach my logs to my bug topic" round-trip. Two modes:
//! topic-bound (created by `/attach?topic=<id>`, completed when the app's
//! signed upload lands and every Discourse write succeeded) and pre-topic
//! (created by `/v1/attach/new` while the user is still composing the topic;
//! the app's upload is parked in the session until the theme binds it to the
//! freshly created topic). In-memory, single instance, short TTL, modeled on
//! [`crate::sessions::SessionStore`].

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::Mutex;

use rand::RngCore as _;

use crate::error::AuthError;

/// How long the user has to approve the consent popup in the app (and maybe
/// read the report first). Longer than the login TTL on purpose.
const ATTACH_TTL_SECS: u64 = 600;

/// Pre-topic sessions span composing a whole report form, so they live longer.
const ATTACH_PRE_TTL_SECS: u64 = 1_800;

/// Hard cap on concurrent attach sessions (fail closed).
const MAX_SESSIONS: usize = 10_000;

/// Cap on sessions parking decompressed log bytes (up to [`MAX_LOG_BYTES`]
/// each); the oldest holder is evicted when a new log lands at capacity.
///
/// This number and [`MAX_LOG_BYTES`] multiply into the service's worst-case
/// resident memory, so they move together: 16 x 32 MiB is 512 MiB parked at
/// full capacity, LESS than the 100 x 8 MiB it replaces. Pre-topic sessions
/// hold their log only between the app's delivery and the topic's creation,
/// usually seconds, so a low count costs nothing in practice and the eviction
/// is graceful.
pub const MAX_LOG_SESSIONS: usize = 16;

/// Wire cap on the base64 gzip field (~12 MiB of gzip).
///
/// Sized from the decompressed ceiling below: log text gzips 10x to 20x in
/// practice, but a pessimistic 3x on 32 MiB is ~11 MiB of gzip, and base64
/// adds a third. The route's own body limit (see `router`) has to stay above
/// this or it, not this constant, becomes the real ceiling.
pub const MAX_LOG_GZ_B64_CHARS: usize = 16_000_000;

/// Cap on the decompressed log, enforced on the stream (the gzip ISIZE header
/// is attacker-controlled and never trusted).
///
/// A report carries up to about seven files (daemon, its rotation, the
/// previous install's, plus the frontend main/renderer and their rotations),
/// so this has to clear the app's per-file cap times that count, or reports
/// get refused outright, which is worse for the reporter than a truncated tail.
pub const MAX_LOG_BYTES: u64 = 32 * 1024 * 1024;

/// Attach session state visible to the polling browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachStatus {
    /// Waiting for the app's signed log upload.
    Pending,
    /// The app's upload landed and the Discourse writes are under way. Exists
    /// so the browser can show progress: those writes take several seconds,
    /// and without this the page cannot tell "the user has not approved yet"
    /// from "approved, we are working on it".
    Processing,
    /// Pre-topic only: the app delivered the report, awaiting the bind.
    Received,
    /// Logs delivered to the staff inbox.
    Done,
    /// The app declined (user cancelled). `reason` is a short machine token.
    Cancelled {
        /// Short reason token, e.g. `user_cancelled`.
        reason: String,
    },
}

/// Which flow a live session belongs to, decided at [`AttachStore::begin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// Pre-topic session: the upload is parked until the bind.
    PreTopic,
    /// Topic-bound session: immediate upload + PM + whisper.
    Topic(u64),
}

/// Parsed report metadata: (`warren-product-version`, `os`).
pub type ReportMeta = (Option<String>, Option<String>);

/// What the bind needs from a received pre-topic session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindData {
    /// Derived forum handle of the signer, checked against the topic author.
    pub username: String,
    /// Decompressed report text.
    pub log_text: String,
    /// App version parsed once at receive time (avoids re-parsing the whole
    /// report at bind), safe to publish.
    pub version: Option<String>,
    /// OS string parsed at receive time, safe to publish.
    pub os: Option<String>,
}

#[derive(Debug, Clone)]
struct ReceivedLog {
    username: String,
    // None once the bind succeeded (the bytes are freed, metadata kept).
    log_text: Option<String>,
    version: Option<String>,
    os: Option<String>,
    received_unix: u64,
}

#[derive(Debug, Clone)]
struct AttachSession {
    // None = pre-topic session.
    topic_id: Option<u64>,
    created_unix: u64,
    done: bool,
    /// Set when the app's upload lands, before the Discourse round-trips.
    processing: bool,
    cancelled: Option<String>,
    received: Option<ReceivedLog>,
}

impl AttachSession {
    fn ttl_secs(&self) -> u64 {
        if self.topic_id.is_some() {
            ATTACH_TTL_SECS
        } else {
            ATTACH_PRE_TTL_SECS
        }
    }

    fn expired(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.created_unix) >= self.ttl_secs()
    }

    fn holds_log(&self) -> bool {
        self.received.as_ref().is_some_and(|r| r.log_text.is_some())
    }
}

/// In-memory attach-session registry.
#[derive(Debug, Default)]
pub struct AttachStore {
    sessions: Mutex<HashMap<String, AttachSession>>,
}

impl AttachStore {
    /// Creates a pending session for a topic; returns its opaque id (32 hex
    /// chars). Idempotent per topic while a pending session is live (a page
    /// refresh must not mint a second deep link for the same topic).
    ///
    /// # Errors
    /// [`AuthError::Session`] when the store is at capacity.
    pub fn create(&self, topic_id: u64, now_unix: u64) -> Result<String, AuthError> {
        let mut sessions = self.sessions.lock().expect("attach mutex never poisoned");
        sessions.retain(|_, s| !s.expired(now_unix));
        if let Some((sid, _)) = sessions
            .iter()
            .find(|(_, s)| s.topic_id == Some(topic_id) && !s.done && s.cancelled.is_none())
        {
            return Ok(sid.clone());
        }
        Self::insert(&mut sessions, Some(topic_id), now_unix)
    }

    /// Creates a pre-topic session (no topic bound yet); returns its sid.
    /// Never idempotent: there is no topic to key reuse on.
    ///
    /// # Errors
    /// [`AuthError::Session`] when the store is at capacity.
    pub fn create_pre(&self, now_unix: u64) -> Result<String, AuthError> {
        let mut sessions = self.sessions.lock().expect("attach mutex never poisoned");
        sessions.retain(|_, s| !s.expired(now_unix));
        Self::insert(&mut sessions, None, now_unix)
    }

    fn insert(
        sessions: &mut HashMap<String, AttachSession>,
        topic_id: Option<u64>,
        now_unix: u64,
    ) -> Result<String, AuthError> {
        if sessions.len() >= MAX_SESSIONS {
            // At capacity, displace the oldest session that is holding no
            // report rather than refusing. Both entry points are
            // unauthenticated by design (`GET /attach?topic=`, `POST
            // /v1/attach/new`) and this vhost pins the forwarded IP to a
            // constant for the no-log guarantee, so there is no per-client
            // budget to draw. Failing closed therefore let anyone take the
            // whole attach feature down for a TTL by minting sessions;
            // displacing means a flood only ever evicts its own idle
            // sessions, since a real one is claimed within seconds.
            let oldest = sessions
                .iter()
                .filter(|(_, s)| !s.holds_log())
                .min_by_key(|(_, s)| s.created_unix)
                .map(|(sid, _)| sid.clone());
            // Every session holding a report is a user waiting on it, and
            // MAX_LOG_SESSIONS caps how many those can be, so this is
            // unreachable unless that cap is raised to the session cap.
            let Some(oldest) = oldest else {
                return Err(AuthError::Session);
            };
            sessions.remove(&oldest);
        }
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let sid = hex::encode(raw);
        sessions.insert(
            sid.clone(),
            AttachSession {
                topic_id,
                created_unix: now_unix,
                done: false,
                processing: false,
                cancelled: None,
                received: None,
            },
        );
        Ok(sid)
    }

    /// Checks that `sid` is a live pre-topic session, so `/attach?sid=` can
    /// re-render the page for it (whatever its state; the poll shows it).
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown, expired, or topic-bound.
    pub fn pre_exists(&self, sid: &str, now_unix: u64) -> Result<(), AuthError> {
        let sessions = self.sessions.lock().expect("attach mutex never poisoned");
        let session = sessions.get(sid).ok_or(AuthError::Session)?;
        if session.expired(now_unix) || session.topic_id.is_some() {
            return Err(AuthError::Session);
        }
        Ok(())
    }

    /// Current status, for the browser poll.
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown or expired.
    pub fn status(&self, sid: &str, now_unix: u64) -> Result<AttachStatus, AuthError> {
        let sessions = self.sessions.lock().expect("attach mutex never poisoned");
        let session = sessions.get(sid).ok_or(AuthError::Session)?;
        if session.expired(now_unix) {
            return Err(AuthError::Session);
        }
        Ok(if session.done {
            AttachStatus::Done
        } else if let Some(reason) = &session.cancelled {
            AttachStatus::Cancelled {
                reason: reason.clone(),
            }
        } else if session.received.is_some() {
            AttachStatus::Received
        } else if session.processing {
            AttachStatus::Processing
        } else {
            AttachStatus::Pending
        })
    }

    /// Marks a pending session cancelled. Idempotent; a no-op on an
    /// unknown/expired session. Never overrides a completed session.
    pub fn cancel(&self, sid: &str, reason: &str, now_unix: u64) {
        let mut sessions = self.sessions.lock().expect("attach mutex never poisoned");
        if let Some(session) = sessions.get_mut(sid)
            && !session.expired(now_unix)
            && !session.done
        {
            session.cancelled = Some(reason.to_owned());
        }
    }

    /// Checks that the session accepts the app's upload for `topic_id`,
    /// without transitioning it (the Discourse writes may still fail, in which
    /// case the session must stay retryable). A pre-topic session accepts only
    /// `topic_id` 0 (the "new report being composed" marker); a topic-bound
    /// session accepts only its own non-zero topic.
    ///
    /// # Errors
    /// [`AuthError::Session`] on unknown/expired/finished sid or topic
    /// mismatch.
    pub fn begin(&self, sid: &str, topic_id: u64, now_unix: u64) -> Result<AttachKind, AuthError> {
        let sessions = self.sessions.lock().expect("attach mutex never poisoned");
        let session = sessions.get(sid).ok_or(AuthError::Session)?;
        if session.expired(now_unix) || session.done || session.cancelled.is_some() {
            return Err(AuthError::Session);
        }
        match session.topic_id {
            None if topic_id == 0 => Ok(AttachKind::PreTopic),
            Some(bound) if bound == topic_id && topic_id != 0 => Ok(AttachKind::Topic(bound)),
            _ => Err(AuthError::Session),
        }
    }

    /// Flags a session as "the app approved, work in progress", so the polling
    /// browser can swap its idle copy for a live progress indicator. Silent
    /// when the session is gone: this is a display hint, never a gate.
    pub fn mark_processing(&self, sid: &str) {
        self.set_processing(sid, true);
    }

    /// Clears the progress hint after a failed delivery, so a session that
    /// stays retryable also LOOKS retryable: leaving it set would spin the
    /// page forever on "sending your logs" while nothing is in flight.
    pub fn clear_processing(&self, sid: &str) {
        self.set_processing(sid, false);
    }

    fn set_processing(&self, sid: &str, value: bool) {
        let mut sessions = self.sessions.lock().expect("attach mutex never poisoned");
        if let Some(session) = sessions.get_mut(sid) {
            session.processing = value;
        }
    }

    /// Parks the app's delivered report in a pre-topic session (state becomes
    /// Received). Enforces [`MAX_LOG_SESSIONS`]: at capacity, the oldest
    /// log-holding session is evicted (logged as a coarse count only).
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown, expired, finished, or topic-bound.
    pub fn store_received(
        &self,
        sid: &str,
        username: &str,
        log_text: String,
        version: Option<String>,
        os: Option<String>,
        now_unix: u64,
    ) -> Result<(), AuthError> {
        let mut sessions = self.sessions.lock().expect("attach mutex never poisoned");
        sessions.retain(|_, s| !s.expired(now_unix));
        {
            let session = sessions.get(sid).ok_or(AuthError::Session)?;
            if session.topic_id.is_some() || session.done || session.cancelled.is_some() {
                return Err(AuthError::Session);
            }
        }
        let holding: Vec<(String, u64)> = sessions
            .iter()
            .filter(|(other, s)| other.as_str() != sid && s.holds_log())
            .map(|(other, s)| {
                let at = s.received.as_ref().map_or(u64::MAX, |r| r.received_unix);
                (other.clone(), at)
            })
            .collect();
        if holding.len() >= MAX_LOG_SESSIONS
            && let Some((oldest, _)) = holding.iter().min_by_key(|(_, at)| *at)
        {
            sessions.remove(oldest);
            tracing::warn!(
                holding = holding.len(),
                "attach log store full: evicted the oldest log-holding session"
            );
        }
        let session = sessions.get_mut(sid).ok_or(AuthError::Session)?;
        session.received = Some(ReceivedLog {
            username: username.to_owned(),
            log_text: Some(log_text),
            version,
            os,
            received_unix: now_unix,
        });
        Ok(())
    }

    /// Report metadata for the browser poll: `None` before the app delivered,
    /// `Some((version, os))` after. Never exposes the handle or the log.
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown or expired.
    pub fn meta(&self, sid: &str, now_unix: u64) -> Result<Option<ReportMeta>, AuthError> {
        let sessions = self.sessions.lock().expect("attach mutex never poisoned");
        let session = sessions.get(sid).ok_or(AuthError::Session)?;
        if session.expired(now_unix) {
            return Err(AuthError::Session);
        }
        Ok(session
            .received
            .as_ref()
            .map(|r| (r.version.clone(), r.os.clone())))
    }

    /// The stored handle + log of a received pre-topic session, for the bind.
    /// Does not transition (a failed Discourse write must stay retryable).
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown, expired, finished, or topic-bound;
    /// [`AuthError::NoLog`] while the app has not delivered the report yet.
    pub fn bind_data(&self, sid: &str, now_unix: u64) -> Result<BindData, AuthError> {
        let sessions = self.sessions.lock().expect("attach mutex never poisoned");
        let session = sessions.get(sid).ok_or(AuthError::Session)?;
        if session.expired(now_unix)
            || session.topic_id.is_some()
            || session.done
            || session.cancelled.is_some()
        {
            return Err(AuthError::Session);
        }
        let received = session.received.as_ref().ok_or(AuthError::NoLog)?;
        let log_text = received.log_text.clone().ok_or(AuthError::NoLog)?;
        Ok(BindData {
            username: received.username.clone(),
            log_text,
            version: received.version.clone(),
            os: received.os.clone(),
        })
    }

    /// Transitions to Done, single use, and frees the parked log bytes
    /// (metadata is kept for the poll).
    ///
    /// # Errors
    /// [`AuthError::Session`] if unknown, expired, cancelled, or already done.
    pub fn complete(&self, sid: &str, now_unix: u64) -> Result<(), AuthError> {
        let mut sessions = self.sessions.lock().expect("attach mutex never poisoned");
        let session = sessions.get_mut(sid).ok_or(AuthError::Session)?;
        if session.expired(now_unix) || session.done || session.cancelled.is_some() {
            return Err(AuthError::Session);
        }
        session.done = true;
        if let Some(received) = session.received.as_mut() {
            received.log_text = None;
        }
        Ok(())
    }
}

/// Longest a report-derived fact (version, os) may be. Clamped where it is
/// PARSED, not only where it is published: the value also reaches the browser
/// through `/v1/attach/{sid}/meta` and the composer prefill, and a report is
/// client-authored, so one unbounded line was two consumers away from a
/// megabyte-long "version".
pub const MAX_FACT_CHARS: usize = 80;

/// Extracts `warren-product-version` and `os` from the report's metadata
/// section: `key: value` lines after an optional `System information:` header,
/// terminated by the first empty line (mirrors mullvad-problem-report's
/// `parse_metadata`, tolerantly: junk lines and missing keys yield `None`).
#[must_use]
pub fn parse_report_metadata(report: &str) -> ReportMeta {
    let mut version = None;
    let mut os = None;
    for line in report.lines().skip_while(|l| *l == "System information:") {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        let clamped = || value.chars().take(MAX_FACT_CHARS).collect::<String>();
        match key {
            "warren-product-version" => version = Some(clamped()),
            "os" => os = Some(clamped()),
            _ => {}
        }
    }
    (version, os)
}

/// Decompresses a gzipped log with a hard cap on the output size.
///
/// # Errors
/// [`AuthError::PayloadTooLarge`] past [`MAX_LOG_BYTES`], [`AuthError::Payload`]
/// on an invalid gzip stream or non-UTF-8 content.
pub fn gunzip_capped(gz: &[u8]) -> Result<String, AuthError> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|_| AuthError::Payload)?;
    if out.len() as u64 > MAX_LOG_BYTES {
        return Err(AuthError::PayloadTooLarge);
    }
    String::from_utf8(out).map_err(|_| AuthError::Payload)
}

#[cfg(test)]
mod tests {
    #[test]
    fn processing_is_a_display_hint_that_can_be_taken_back() {
        // Set when the app approves, cleared when the delivery fails, so the
        // page never spins on work that is no longer happening.
        let store = AttachStore::default();
        let sid = store.create(42, 100).expect("create");
        assert_eq!(
            store.status(&sid, 100).expect("status"),
            AttachStatus::Pending
        );
        store.mark_processing(&sid);
        assert_eq!(
            store.status(&sid, 100).expect("status"),
            AttachStatus::Processing
        );
        store.clear_processing(&sid);
        assert_eq!(
            store.status(&sid, 100).expect("status"),
            AttachStatus::Pending
        );
        // Unknown sid is a no-op, never a panic: it is only a hint.
        store.mark_processing("deadbeef");
    }

    use super::*;
    use std::io::Write as _;

    #[test]
    fn lifecycle_pending_begun_completed() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        assert_eq!(sid.len(), 32, "sid is 32 hex chars");

        assert_eq!(
            store.status(&sid, 1).expect("status"),
            AttachStatus::Pending
        );
        store.begin(&sid, 42, 2).expect("begin");
        assert_eq!(
            store.status(&sid, 3).expect("status"),
            AttachStatus::Pending,
            "begin must not transition: Discourse writes can still fail"
        );
        store.complete(&sid, 4).expect("complete");
        assert_eq!(store.status(&sid, 5).expect("status"), AttachStatus::Done);
    }

    #[test]
    fn complete_is_single_use() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        store.complete(&sid, 1).expect("first complete");
        assert!(store.complete(&sid, 2).is_err(), "Done is terminal");
        assert!(store.begin(&sid, 42, 3).is_err(), "no re-upload after done");
    }

    #[test]
    fn begin_rejects_a_topic_mismatch() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        assert!(store.begin(&sid, 43, 1).is_err());
        assert!(
            store
                .begin("00000000000000000000000000000000", 42, 1)
                .is_err()
        );
    }

    #[test]
    fn sessions_expire() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        assert!(store.status(&sid, ATTACH_TTL_SECS).is_err(), "expired");
        assert!(store.begin(&sid, 42, ATTACH_TTL_SECS).is_err());
        assert!(store.complete(&sid, ATTACH_TTL_SECS).is_err());
    }

    #[test]
    fn unknown_sid_is_an_error() {
        let store = AttachStore::default();
        assert!(store.status("deadbeef", 0).is_err());
    }

    #[test]
    fn cancel_marks_the_session_and_blocks_completion() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        store.cancel(&sid, "user_cancelled", 1);
        assert_eq!(
            store.status(&sid, 2).expect("status"),
            AttachStatus::Cancelled {
                reason: "user_cancelled".into()
            }
        );
        assert!(store.begin(&sid, 42, 3).is_err());
        assert!(store.complete(&sid, 4).is_err(), "cancel never resurrects");
    }

    #[test]
    fn cancel_does_not_override_done() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        store.complete(&sid, 1).expect("complete");
        store.cancel(&sid, "user_cancelled", 2);
        assert_eq!(store.status(&sid, 3).expect("status"), AttachStatus::Done);
    }

    #[test]
    fn create_is_idempotent_per_topic_while_pending() {
        let store = AttachStore::default();
        let a = store.create(42, 0).expect("first");
        let b = store.create(42, 1).expect("refresh");
        assert_eq!(a, b, "a page refresh reuses the pending session");

        let c = store.create(43, 2).expect("other topic");
        assert_ne!(a, c);
    }

    #[test]
    fn a_new_attach_after_completion_is_a_fresh_session() {
        let store = AttachStore::default();
        let a = store.create(42, 0).expect("first");
        store.complete(&a, 1).expect("complete");
        let b = store.create(42, 2).expect("second");
        assert_ne!(a, b, "a finished session is not reused");
    }

    #[test]
    fn a_flood_of_idle_sessions_displaces_itself_instead_of_the_feature() {
        // Nothing authenticates the two mint paths and the forwarded IP is
        // pinned to a constant here, so refusing at capacity handed anyone a
        // way to take attach-logs down for a whole TTL. The newcomer now
        // evicts the oldest idle session instead.
        let store = AttachStore::default();
        // One session strictly older than the rest, so "the oldest" has a
        // single answer and the assertion cannot pass by luck. Every
        // timestamp stays well inside the TTL, so nothing here expires.
        let oldest = store.create(1, 0).expect("oldest");
        for topic in 2..=MAX_SESSIONS as u64 {
            store.create(topic, 1).expect("fill");
        }

        let newcomer = store
            .create(u64::MAX, 2)
            .expect("a real user must still be able to start an attach");

        assert!(
            store.status(&oldest, 2).is_err(),
            "the oldest idle session is the one displaced"
        );
        assert_eq!(
            store.status(&newcomer, 2).expect("the newcomer is live"),
            AttachStatus::Pending
        );
    }

    #[test]
    fn a_session_holding_a_report_is_never_displaced_by_the_flood() {
        // The user behind it is waiting on that upload, and dropping it would
        // lose a report the app already sent.
        let store = AttachStore::default();
        let holder = store.create_pre(0).expect("create_pre");
        store
            .store_received(&holder, "u", "log".into(), None, None, 0)
            .expect("report delivered");
        // The holder is the OLDEST session, so only the log filter can save it.
        for topic in 1..MAX_SESSIONS as u64 {
            store.create(topic, 1).expect("fill");
        }

        store.create(u64::MAX, 2).expect("still accepted");

        assert_eq!(
            store
                .status(&holder, 2)
                .expect("the report holder survives"),
            AttachStatus::Received
        );
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    #[test]
    fn gunzip_round_trips_a_log() {
        let text = "warren log line one\nline two\n";
        assert_eq!(
            gunzip_capped(&gz(text.as_bytes())).expect("valid gzip"),
            text
        );
    }

    #[test]
    fn gunzip_rejects_an_oversized_decompression() {
        // A tiny gzip bomb: far more decompressed bytes than MAX_LOG_BYTES out
        // of a small input. The cap must trip on the output stream.
        let bomb = gz(&vec![0u8; (MAX_LOG_BYTES + 1024) as usize]);
        assert!(bomb.len() < 64 * 1024, "the bomb itself is small");
        let err = gunzip_capped(&bomb).expect_err("must cap");
        assert!(matches!(err, AuthError::PayloadTooLarge));
    }

    #[test]
    fn gunzip_accepts_exactly_the_cap() {
        let at_cap = gz(&vec![b'a'; MAX_LOG_BYTES as usize]);
        assert_eq!(
            gunzip_capped(&at_cap).expect("at cap is fine").len() as u64,
            MAX_LOG_BYTES
        );
    }

    #[test]
    fn gunzip_rejects_garbage() {
        let err = gunzip_capped(b"not a gzip stream").expect_err("garbage");
        assert!(matches!(err, AuthError::Payload));
    }

    #[test]
    fn gunzip_rejects_non_utf8_content() {
        let err = gunzip_capped(&gz(&[0xFF, 0xFE, 0x00, 0x80])).expect_err("binary");
        assert!(matches!(err, AuthError::Payload));
    }

    fn received(store: &AttachStore, sid: &str, now: u64) {
        store
            .store_received(
                sid,
                "lusab-babad-dovok",
                "log body".into(),
                Some("2026.5".into()),
                Some("macOS 15".into()),
                now,
            )
            .expect("store received");
    }

    #[test]
    fn pre_lifecycle_pending_received_done() {
        let store = AttachStore::default();
        let sid = store.create_pre(0).expect("create_pre");
        assert_eq!(sid.len(), 32, "sid is 32 hex chars");

        assert_eq!(
            store.status(&sid, 1).expect("status"),
            AttachStatus::Pending
        );
        assert_eq!(
            store.begin(&sid, 0, 2).expect("begin pre"),
            AttachKind::PreTopic
        );
        received(&store, &sid, 3);
        assert_eq!(
            store.status(&sid, 4).expect("status"),
            AttachStatus::Received
        );

        let data = store.bind_data(&sid, 5).expect("bind data");
        assert_eq!(data.username, "lusab-babad-dovok");
        assert_eq!(data.log_text, "log body");
        assert_eq!(
            store.status(&sid, 6).expect("status"),
            AttachStatus::Received,
            "bind_data must not transition: Discourse writes can still fail"
        );
        store.complete(&sid, 7).expect("complete");
        assert_eq!(store.status(&sid, 8).expect("status"), AttachStatus::Done);
        assert!(store.bind_data(&sid, 9).is_err(), "bind is single-use");
    }

    #[test]
    fn pre_begin_refuses_a_nonzero_topic() {
        let store = AttachStore::default();
        let sid = store.create_pre(0).expect("create_pre");
        assert!(store.begin(&sid, 42, 1).is_err());
    }

    #[test]
    fn topic_begin_refuses_topic_zero() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        assert!(store.begin(&sid, 0, 1).is_err());
        assert_eq!(
            store.begin(&sid, 42, 1).expect("begin"),
            AttachKind::Topic(42)
        );
    }

    #[test]
    fn bind_data_without_a_log_is_no_log() {
        let store = AttachStore::default();
        let sid = store.create_pre(0).expect("create_pre");
        let err = store.bind_data(&sid, 1).expect_err("no log yet");
        assert!(matches!(err, AuthError::NoLog));
    }

    #[test]
    fn bind_data_on_a_topic_session_is_an_error() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        assert!(matches!(
            store.bind_data(&sid, 1).expect_err("topic-bound"),
            AuthError::Session
        ));
    }

    #[test]
    fn store_received_is_pre_only() {
        let store = AttachStore::default();
        let sid = store.create(42, 0).expect("create");
        assert!(
            store
                .store_received(&sid, "u", "log".into(), None, None, 1)
                .is_err()
        );
    }

    #[test]
    fn pre_sessions_live_longer_than_topic_sessions() {
        let store = AttachStore::default();
        let topic = store.create(42, 0).expect("create");
        let pre = store.create_pre(0).expect("create_pre");
        assert!(store.status(&topic, 600).is_err(), "topic TTL is 600 s");
        assert_eq!(
            store.status(&pre, 1799).expect("still live"),
            AttachStatus::Pending
        );
        assert!(store.status(&pre, 1800).is_err(), "pre TTL is 1800 s");
    }

    #[test]
    fn meta_is_pending_then_received() {
        let store = AttachStore::default();
        let sid = store.create_pre(0).expect("create_pre");
        assert_eq!(store.meta(&sid, 1).expect("meta"), None);
        received(&store, &sid, 2);
        assert_eq!(
            store.meta(&sid, 3).expect("meta"),
            Some((Some("2026.5".into()), Some("macOS 15".into())))
        );
        assert!(store.meta("deadbeef", 4).is_err());
    }

    #[test]
    fn complete_drops_the_log_bytes_but_keeps_the_metadata() {
        let store = AttachStore::default();
        let sid = store.create_pre(0).expect("create_pre");
        received(&store, &sid, 1);
        store.complete(&sid, 2).expect("complete");
        assert_eq!(
            store.meta(&sid, 3).expect("meta"),
            Some((Some("2026.5".into()), Some("macOS 15".into())))
        );
    }

    #[test]
    fn log_holding_sessions_are_capped_with_oldest_evicted() {
        let store = AttachStore::default();
        let mut sids = Vec::new();
        for i in 0..MAX_LOG_SESSIONS as u64 {
            let sid = store.create_pre(0).expect("create_pre");
            store
                .store_received(&sid, "u", "log".into(), None, None, i)
                .expect("fill");
            sids.push(sid);
        }
        let extra = store.create_pre(0).expect("one more");
        store
            .store_received(&extra, "u", "log".into(), None, None, 500)
            .expect("101st log evicts the oldest holder");
        assert!(
            store.status(&sids[0], 501).is_err(),
            "the oldest log-holding session is gone"
        );
        assert_eq!(
            store.status(&sids[1], 501).expect("second oldest survives"),
            AttachStatus::Received
        );
        assert_eq!(
            store.status(&extra, 501).expect("newcomer holds its log"),
            AttachStatus::Received
        );
    }

    #[test]
    fn a_done_session_no_longer_holds_log_bytes() {
        let store = AttachStore::default();
        let mut sids = Vec::new();
        for i in 0..MAX_LOG_SESSIONS as u64 {
            let sid = store.create_pre(0).expect("create_pre");
            store
                .store_received(&sid, "u", "log".into(), None, None, i)
                .expect("fill");
            sids.push(sid);
        }
        store
            .complete(&sids[0], 400)
            .expect("complete frees a slot");
        let extra = store.create_pre(0).expect("one more");
        store
            .store_received(&extra, "u", "log".into(), None, None, 500)
            .expect("free slot");
        assert_eq!(
            store.status(&sids[1], 501).expect("no eviction needed"),
            AttachStatus::Received
        );
    }

    #[test]
    fn pre_create_mints_distinct_sids() {
        let store = AttachStore::default();
        let a = store.create_pre(0).expect("a");
        let b = store.create_pre(0).expect("b");
        assert_ne!(a, b, "pre sessions have no topic to be idempotent on");
    }

    const REPORT: &str = "System information:\n\
        id: 1234abcd\n\
        os: macOS 15.5\n\
        warren-product-version: 2026.5-beta1\n\
        \n\
        ==== warren.log ====\n\
        line one\nos: not-metadata\n";

    #[test]
    fn report_metadata_clamps_a_forged_field_at_the_parser() {
        // The report is client-authored and its fields reach two consumers:
        // the public note and the composer prefill the browser reads. Clamping
        // only at publication left the second one unbounded.
        let report = format!("os: {}\n\n", "x".repeat(5_000));
        let (_, os) = parse_report_metadata(&report);
        assert_eq!(
            os.expect("parsed").chars().count(),
            MAX_FACT_CHARS,
            "the cap belongs where the value is produced"
        );
    }

    #[test]
    fn report_metadata_extracts_version_and_os() {
        let (version, os) = parse_report_metadata(REPORT);
        assert_eq!(version.as_deref(), Some("2026.5-beta1"));
        assert_eq!(os.as_deref(), Some("macOS 15.5"));
    }

    #[test]
    fn report_metadata_stops_at_the_blank_separator() {
        let report = "System information:\nid: x\n\nwarren-product-version: 9.9\nos: y\n";
        assert_eq!(parse_report_metadata(report), (None, None));
    }

    #[test]
    fn report_metadata_tolerates_a_missing_header_line() {
        let report = "warren-product-version: 1.2.3\nos: Linux 6.1\n\nlogs";
        let (version, os) = parse_report_metadata(report);
        assert_eq!(version.as_deref(), Some("1.2.3"));
        assert_eq!(os.as_deref(), Some("Linux 6.1"));
    }

    #[test]
    fn report_metadata_tolerates_junk_lines_and_missing_keys() {
        let report = "System information:\nno-separator-line\nos: Windows 11\n\n";
        let (version, os) = parse_report_metadata(report);
        assert_eq!(version, None);
        assert_eq!(os.as_deref(), Some("Windows 11"));
        assert_eq!(parse_report_metadata(""), (None, None));
    }
}
