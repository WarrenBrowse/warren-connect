//! Router-level integration: the DiscourseConnect entry and the session
//! endpoints, exercised through the real axum router (no live database:
//! lazy pools, and these paths never touch Postgres).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::Mac as _;
use http_body_util::BodyExt as _;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt as _;

use warren_connect::admins::Allowlist;
use warren_connect::attach::AttachStore;
use warren_connect::nonces::NonceStore;
use warren_connect::routes::{AppState, LOGIN_COOKIE, LegacyApproval, router};
use warren_connect::sessions::{BrowserSecret, SessionStore};
use warren_connect::store::{IdentityStore, MemoryIdentity, SubscriptionStatus};

mod forum_vector;
mod forum_vector_v2;
use forum_vector::{assert_answer, assert_signed_by_the_contract, observe, verify_at_vector_clock};

const CONNECT_SECRET: &[u8] = b"a-test-connect-secret-32-bytes!!";

const HANDLE_SECRET: &[u8] = b"a-test-handle-secret-32-bytes!!!";

fn test_state() -> Arc<AppState> {
    state_with(HANDLE_SECRET, None)
}

/// A state under `handle_secret`, whose identity store knows `paid_ss58` as
/// an ever-paid wallet when one is given. Legacy approvals are denied and no
/// Discourse database is wired, as in a deployment that sets neither.
fn state_with(handle_secret: &[u8], paid_ss58: Option<&str>) -> Arc<AppState> {
    build_state(Setup {
        handle_secret,
        paid_ss58,
        ..Setup::default()
    })
}

/// The knobs the login suite turns.
struct Setup<'a> {
    handle_secret: &'a [u8],
    paid_ss58: Option<&'a str>,
    legacy: LegacyApproval,
    /// Forum staff by username; `None` is a Discourse database not wired.
    forum_staff: Option<&'a [(&'a str, bool)]>,
    /// `WARREN_ADMIN_PUBKEYS`.
    admins: &'a str,
    /// `PUBLIC_HOST`, which the handoff URL names.
    public_host: &'a str,
}

impl Default for Setup<'_> {
    fn default() -> Self {
        Self {
            handle_secret: HANDLE_SECRET,
            paid_ss58: None,
            legacy: LegacyApproval::Deny,
            forum_staff: None,
            admins: "",
            public_host: "connect.test",
        }
    }
}

fn build_state(setup: Setup<'_>) -> Arc<AppState> {
    let lazy = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time");
    let memory = MemoryIdentity::default();
    if let Some(ss58) = setup.paid_ss58 {
        memory.subscriptions.lock().expect("mutex").insert(
            ss58.to_owned(),
            SubscriptionStatus {
                ever_paid: true,
                active: true,
                expires_at_unix: Some(4_102_444_800),
            },
        );
    }
    *memory.forum_staff.lock().expect("mutex") = setup.forum_staff.map(|staff| {
        staff
            .iter()
            .map(|(name, is_staff)| ((*name).to_owned(), *is_staff))
            .collect()
    });
    Arc::new(AppState {
        connect_secret: CONNECT_SECRET.to_vec(),
        handle_secret: setup.handle_secret.to_vec(),
        public_host: setup.public_host.into(),
        internal_token: "test-internal-token".into(),
        admins: Allowlist::parse(setup.admins).expect("allowlist"),
        forum_pool: lazy.clone(),
        warren_pool: lazy,
        identity: IdentityStore::Memory(memory),
        discourse_pool: None,
        seen_pool: None,
        digest_generation: Default::default(),
        sessions: SessionStore::default(),
        legacy_approval: setup.legacy,
        nonces: NonceStore::default(),
        attach: AttachStore::default(),
        forum_api: None,
        intake: None,
        report: None,
    })
}

fn signed_sso(payload: &str) -> (String, String) {
    let sso = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        payload.as_bytes(),
    );
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(CONNECT_SECRET).expect("key");
    mac.update(sso.as_bytes());
    (sso, hex::encode(mac.finalize().into_bytes()))
}

#[tokio::test]
async fn sso_entry_renders_the_approval_page() {
    let app = router(test_state());
    let (sso, sig) = signed_sso(
        "nonce=n1&return_sso_url=https%3A%2F%2Fforum.warrenbrowse.com%2Fsession%2Fsso_login",
    );

    let response = app
        .oneshot(
            Request::get(format!("/sso?sso={}&sig={sig}", urlencoding::encode(&sso)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let html = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(html.contains("warren://forum-login?sid="));
    assert!(html.contains("connect.test"), "deep link carries our host");
}

#[tokio::test]
async fn the_approval_page_is_served_unframeable_uncached_and_under_its_own_csp() {
    // The page carries a session id and a link that opens the wallet. Framed
    // in a page of somebody else's making it becomes a clickjacking surface,
    // and cached it leaves that capability behind on a shared machine.
    let app = router(test_state());
    let (sso, sig) = signed_sso(
        "nonce=n1&return_sso_url=https%3A%2F%2Fforum.warrenbrowse.com%2Fsession%2Fsso_login",
    );

    let response = app
        .oneshot(
            Request::get(format!("/sso?sso={}&sig={sig}", urlencoding::encode(&sso)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");

    assert_eq!(response.status(), StatusCode::OK);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(header("cache-control"), "no-store");
    assert_eq!(header("x-frame-options"), "DENY");
    assert_eq!(header("x-content-type-options"), "nosniff");
    assert_eq!(header("referrer-policy"), "no-referrer");
    assert!(header("strict-transport-security").contains("max-age="));

    let csp = header("content-security-policy");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(
        !csp.contains("'unsafe-inline'"),
        "the inline style and script are admitted by nonce, never wholesale: {csp}"
    );

    // The nonce in the policy has to be the one the markup carries, or the
    // page renders blank in a compliant browser.
    let nonce = csp
        .split("script-src 'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .expect("the policy names a script nonce")
        .to_owned();
    assert_eq!(nonce.len(), 32, "16 bytes of entropy, hex");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let html = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(
        html.contains(&format!(r#"<script nonce="{nonce}">"#)),
        "the script tag must carry the policy's nonce"
    );
    assert!(html.contains(&format!(r#"<style nonce="{nonce}">"#)));
}

#[tokio::test]
async fn sso_entry_rejects_a_forged_signature() {
    let app = router(test_state());
    let (sso, _) = signed_sso("nonce=n1&return_sso_url=https%3A%2F%2Fforum.warrenbrowse.com%2Fsso");

    let response = app
        .oneshot(
            Request::get(format!(
                "/sso?sso={}&sig={}",
                urlencoding::encode(&sso),
                "00".repeat(32)
            ))
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("infallible");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_session_status_is_not_found() {
    let app = router(test_state());
    let response = app
        .oneshot(
            Request::get("/v1/session/deadbeef/status")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The sid the approval page hands the app, read the way the app reads it.
fn sid_from_page(html: &str) -> String {
    html.split("forum-login?sid=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("the approval page carries the deep link")
        .to_owned()
}

fn signed_login_request(
    key: &ed25519_dalek::SigningKey,
    sid: &str,
    timestamp: u64,
    nonce: [u8; 16],
) -> Request<Body> {
    use warren_contract::auth::{
        HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
    };
    let body = format!("{{\"sid\":\"{sid}\"}}");
    let s = sign_request(
        key,
        "POST",
        "/v1/forum/login",
        body.as_bytes(),
        timestamp,
        nonce,
    );
    Request::post("/v1/forum/login")
        .header(HEADER_PUBKEY, s.pubkey_ss58)
        .header(HEADER_SIGNATURE, s.signature_hex)
        .header(HEADER_TIMESTAMP, s.timestamp.to_string())
        .header(HEADER_NONCE, s.nonce_hex)
        .body(Body::from(body))
        .expect("request")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

#[tokio::test]
async fn a_clock_skewed_login_answers_a_machine_readable_401_and_cancels_the_session() {
    // A device whose wall clock is off by more than the accepted window signs
    // a request the server must refuse. Two things have to be true for the
    // failure to be diagnosable at all: the app gets a stable error token it
    // can turn into "fix your clock" (the 2026-08-18 failures all surfaced as
    // a generic "sign-in failed"), and the waiting browser page is told, or it
    // polls "pending" until the session dies with no explanation.
    let app = router(test_state());
    let page = open_sso(&app, "nclock", None).await;
    let sid = page.sid();

    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let response = app
        .clone()
        .oneshot(signed_login_request(&key, &sid, unix_now() - 120, [2; 16]))
        .await
        .expect("infallible");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    // Byte-exact on purpose: three clients (Android/iOS FFI, desktop) match
    // this token as a substring of the body, so a re-serialization with a
    // space or a wrapper object would silently drop them all onto the generic
    // message with every parsed-value assertion still green.
    assert_eq!(
        &body[..],
        br#"{"error":"clock_skew"}"#,
        "the app matches these exact bytes to tell the user to fix the clock"
    );

    let status = app
        .oneshot(status_request(&sid, Some(&page.cookie())))
        .await
        .expect("infallible");
    let body = status.into_body().collect().await.expect("body").to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "cancelled");
    assert_eq!(
        json["reason"], "clock_skew",
        "the polling page explains the cause instead of waiting out the TTL"
    );
}

#[tokio::test]
async fn a_skewed_login_on_an_unparseable_body_still_answers_the_clock_token() {
    // The cancel is best effort: a body that names no session must not turn
    // the diagnosable 401 into a 500 or a different error.
    let app = router(test_state());
    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    use warren_contract::auth::{
        HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
    };
    let body = "not-json";
    let s = sign_request(
        &key,
        "POST",
        "/v1/forum/login",
        body.as_bytes(),
        unix_now() - 120,
        [3; 16],
    );
    let response = app
        .oneshot(
            Request::post("/v1/forum/login")
                .header(HEADER_PUBKEY, s.pubkey_ss58)
                .header(HEADER_SIGNATURE, s.signature_hex)
                .header(HEADER_TIMESTAMP, s.timestamp.to_string())
                .header(HEADER_NONCE, s.nonce_hex)
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(&bytes[..], br#"{"error":"clock_skew"}"#);
}

#[tokio::test]
async fn the_approval_page_explains_clock_skew_and_repolls_when_brought_back_to_front() {
    // Two mobile lessons from 2026-08-18, measured on a live login: the tap
    // that opens the app backgrounds the browser, whose timers freeze, so the
    // page must re-poll the moment it becomes visible again (it sat on
    // "Waiting for approval" for ~50 s after an approval had landed); and a
    // clock_skew cancellation needs its own wording, or the user reads a
    // generic cancel and retries forever.
    let app = router(test_state());
    let (sso, sig) = signed_sso(
        "nonce=npage&return_sso_url=https%3A%2F%2Fforum.warrenbrowse.com%2Fsession%2Fsso_login",
    );
    let response = app
        .oneshot(
            Request::get(format!("/sso?sso={}&sig={sig}", urlencoding::encode(&sso)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let html = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(
        html.contains("data-clock="),
        "the page carries a clock-skew message for the poll to show"
    );
    assert!(
        html.contains("clock_skew"),
        "the poll maps the clock_skew reason onto that message"
    );
    assert!(
        html.contains("visibilitychange"),
        "the page re-polls immediately when it becomes visible again"
    );
}

#[tokio::test]
async fn login_with_garbage_headers_is_unauthorized() {
    let app = router(test_state());
    let response = app
        .oneshot(
            Request::post("/v1/forum/login")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_notification_panel_refuses_an_unsigned_request() {
    // The account read is derived from the signature. Without one there is
    // no account to derive, and answering anything would mean answering
    // about somebody.
    let app = router(test_state());
    let response = app
        .oneshot(
            Request::post("/v1/forum/notifications")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_activity_digest_is_never_served_unauthenticated() {
    // The document is anonymous, but it is still forum state: an open
    // endpoint would publish the whole forum's unread activity to anyone.
    let app = router(test_state());
    let response = app
        .oneshot(
            Request::get("/internal/forum/digest")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_activity_digest_reports_unavailable_when_discourse_is_not_wired() {
    // A deployment without the read-only Discourse role must answer plainly
    // rather than serve an all-zero document, which would read as "nobody has
    // any activity" and silently switch every badge off.
    let app = router(test_state());
    let response = app
        .oneshot(
            Request::get("/internal/forum/digest")
                .header("Authorization", "Bearer test-internal-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn internal_lookup_requires_bearer_token() {
    let app = router(test_state());
    let response = app
        .oneshot(
            Request::get("/internal/by-handle/whoever")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn the_forum_vector_carries_only_the_names_the_login_suite_replays() {
    // The control.json convention: a request or an outcome added to the
    // vector goes red here until a replay exists for it, so a stale pin can
    // never drop a golden vector silently. The report answers are guarded
    // by the report suite, the attach requests and answers by the attach
    // suite.
    let v = forum_vector::load();
    let mut requests: Vec<&str> = v.requests.iter().map(|r| r.name.as_str()).collect();
    requests.sort_unstable();
    assert_eq!(
        requests,
        [
            "attach_pre_topic",
            "attach_with_log",
            "login",
            "report_with_log",
            "report_without_log"
        ]
    );
    let mut login = v.responses.login.names();
    login.sort_unstable();
    assert_eq!(
        login,
        [
            "approved",
            "clock_skew",
            "session_unknown",
            "subscription_required"
        ]
    );
    let mut status = v.responses.session_status.names();
    status.sort_unstable();
    assert_eq!(
        status,
        [
            "approved",
            "cancelled_clock_skew",
            "cancelled_subscription_required",
            "pending",
            "unknown"
        ]
    );
}

#[test]
fn the_login_vector_is_what_the_contract_signs_and_what_the_verifier_accepts() {
    // Both ends of the wire against the same bytes: the contract's signer fed
    // the vector inputs must produce exactly the pinned headers, and this
    // verifier, with its clock at the vector timestamp, must accept them
    // over the pinned body and prove the vector key.
    let v = forum_vector::load();
    let req = forum_vector::request(&v, "login");
    assert_signed_by_the_contract(&v, req);
    let identity = verify_at_vector_clock(&v, req);

    let sid = req.sid.as_deref().expect("the login request names its sid");
    let body: serde_json::Value = serde_json::from_str(&req.body_utf8).expect("json body");
    assert_eq!(
        body["sid"], sid,
        "the body is the sid the deep link carried"
    );

    // The handle the provider answers with is the keyed derivation over the
    // proven key, under the provider secret the vector was produced with.
    let derived =
        warren_connect::handle::derive(v.provider.handle_secret_utf8.as_bytes(), &identity.pubkey);
    assert_eq!(derived.username, v.provider.handle);
    assert_eq!(derived.external_id, v.provider.external_id);
}

#[tokio::test]
async fn the_login_vector_bytes_through_the_router_land_on_the_frozen_clock_skew_answer() {
    // The vector timestamp is fixed, so at any real clock the pinned request
    // is outside the window: the router reads the pinned headers and body
    // and answers the token the clients match, byte for byte.
    let v = forum_vector::load();
    let req = forum_vector::request(&v, "login");
    let app = router(test_state());
    let answer = observe(app.oneshot(req.as_http()).await.expect("infallible")).await;
    assert_answer(
        &answer,
        &v.responses.login.get("clock_skew"),
        "login.clock_skew",
    );
}

#[tokio::test]
async fn the_login_vector_pins_the_provider_answer_per_outcome() {
    // The pinned answers, produced again by this router under the vector's
    // provider parameters, with the vector key signing inside the window.
    // v1 is the form that predates the completion code, so the provider runs
    // with legacy approvals allowed and the signer known as not staff; the
    // browser reads carry the cookie its approval page set.
    let v = forum_vector::load();
    let key = v.signer.signing_key();
    let secret = v.provider.handle_secret_utf8.as_bytes();
    let v1_provider = |paid: Option<&str>| {
        router(build_state(Setup {
            handle_secret: secret,
            paid_ss58: paid,
            legacy: LegacyApproval::Allow,
            forum_staff: Some(&[]),
            ..Setup::default()
        }))
    };
    let app = v1_provider(Some(&v.signer.pubkey_ss58));

    // Pending, then approved: the handle and the slot come back to the
    // wallet that signed, and the browser sees the approval.
    let page = open_sso(&app, "nvec-approve", None).await;
    let sid = page.sid();
    assert_answer(
        &send(&app, status_request(&sid, Some(&page.cookie()))).await,
        &v.responses.session_status.get("pending"),
        "session_status.pending",
    );
    let response = app
        .clone()
        .oneshot(signed_login_request(&key, &sid, unix_now(), [0x21; 16]))
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.login.get("approved"),
        "login.approved",
    );
    assert_answer(
        &send(&app, status_request(&sid, Some(&page.cookie()))).await,
        &v.responses.session_status.get("approved"),
        "session_status.approved",
    );

    // Clock skew: refused with the token, and the browser is told why.
    let page = open_sso(&app, "nvec-clock", None).await;
    let sid = page.sid();
    let response = app
        .clone()
        .oneshot(signed_login_request(
            &key,
            &sid,
            unix_now() - 120,
            [0x22; 16],
        ))
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.login.get("clock_skew"),
        "login.clock_skew",
    );
    assert_answer(
        &send(&app, status_request(&sid, Some(&page.cookie()))).await,
        &v.responses.session_status.get("cancelled_clock_skew"),
        "session_status.cancelled_clock_skew",
    );

    // The vector sid names no live session here.
    let unknown = forum_vector::request(&v, "login")
        .sid
        .as_deref()
        .expect("the login request names its sid");
    let response = app
        .clone()
        .oneshot(signed_login_request(&key, unknown, unix_now(), [0x23; 16]))
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.login.get("session_unknown"),
        "login.session_unknown",
    );
    assert_answer(
        &send(&app, status_request(unknown, None)).await,
        &v.responses.session_status.get("unknown"),
        "session_status.unknown",
    );

    // Never paid: the paywall, and the browser is told why.
    let never = v1_provider(None);
    let page = open_sso(&never, "nvec-unpaid", None).await;
    let sid = page.sid();
    let response = never
        .clone()
        .oneshot(signed_login_request(&key, &sid, unix_now(), [0x24; 16]))
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.login.get("subscription_required"),
        "login.subscription_required",
    );
    assert_answer(
        &send(&never, status_request(&sid, Some(&page.cookie()))).await,
        &v.responses
            .session_status
            .get("cancelled_subscription_required"),
        "session_status.cancelled_subscription_required",
    );
}

// ---------------------------------------------------------------------------
// Bound approval (forum login v2): the browser that started the login holds a
// cookie, the approving app receives a one-time code, and only both together
// complete the login.
// ---------------------------------------------------------------------------

const FORUM_RETURN: &str = "https://forum.warrenbrowse.com/session/sso_login";

/// What a browser gets back from `/sso`: the page, the sid it carries, and
/// the login cookie value the provider set, if any.
struct Opened {
    status: StatusCode,
    html: String,
    cookie: Option<String>,
}

impl Opened {
    fn sid(&self) -> String {
        sid_from_page(&self.html)
    }

    fn cookie(&self) -> String {
        self.cookie
            .clone()
            .expect("the approval page sets the login cookie")
    }
}

fn login_cookie_from(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix(&format!("{LOGIN_COOKIE}=")))
        .and_then(|rest| rest.split(';').next())
        .map(str::to_owned)
}

/// A browser opening the approval page for the DiscourseConnect nonce
/// `nonce`, presenting `cookie` when it already holds one.
async fn open_sso(app: &axum::Router, nonce: &str, cookie: Option<&str>) -> Opened {
    let (sso, sig) = signed_sso(&format!(
        "nonce={nonce}&return_sso_url={}",
        urlencoding::encode(FORUM_RETURN)
    ));
    let mut request = Request::get(format!("/sso?sso={}&sig={sig}", urlencoding::encode(&sso)));
    if let Some(cookie) = cookie {
        request = request.header("Cookie", format!("{LOGIN_COOKIE}={cookie}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("infallible");
    let status = response.status();
    let cookie = login_cookie_from(&response);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    Opened {
        status,
        html: String::from_utf8(body.to_vec()).expect("utf8"),
        cookie,
    }
}

/// The approving app's signed login in the bound form: the body names the
/// login version explicitly, keys in ascending order, as the vector pins it.
fn signed_bound_login(
    key: &ed25519_dalek::SigningKey,
    sid: &str,
    nonce: [u8; 16],
) -> Request<Body> {
    use warren_contract::auth::{
        HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
    };
    let body = format!("{{\"login_version\":2,\"sid\":\"{sid}\"}}");
    let s = sign_request(
        key,
        "POST",
        "/v1/forum/login",
        body.as_bytes(),
        unix_now(),
        nonce,
    );
    Request::post("/v1/forum/login")
        .header("Content-Type", "application/json")
        .header(HEADER_PUBKEY, s.pubkey_ss58)
        .header(HEADER_SIGNATURE, s.signature_hex)
        .header(HEADER_TIMESTAMP, s.timestamp.to_string())
        .header(HEADER_NONCE, s.nonce_hex)
        .body(Body::from(body))
        .expect("request")
}

async fn send(app: &axum::Router, request: Request<Body>) -> forum_vector::Answer {
    observe(app.clone().oneshot(request).await.expect("infallible")).await
}

fn with_cookie(
    builder: axum::http::request::Builder,
    cookie: Option<&str>,
) -> axum::http::request::Builder {
    match cookie {
        Some(cookie) => builder.header("Cookie", format!("{LOGIN_COOKIE}={cookie}")),
        None => builder,
    }
}

fn status_request(sid: &str, cookie: Option<&str>) -> Request<Body> {
    with_cookie(Request::get(format!("/v1/session/{sid}/status")), cookie)
        .body(Body::empty())
        .expect("request")
}

fn confirm_request(sid: &str, cookie: Option<&str>, code: &str) -> Request<Body> {
    with_cookie(Request::post(format!("/v1/session/{sid}/confirm")), cookie)
        .header("Content-Type", "application/json")
        .body(Body::from(format!("{{\"code\":\"{code}\"}}")))
        .expect("request")
}

fn complete_request(sid: &str, cookie: Option<&str>) -> Request<Body> {
    with_cookie(Request::get(format!("/v1/session/{sid}/complete")), cookie)
        .body(Body::empty())
        .expect("request")
}

/// Where a completion sent the browser, when it did.
async fn completion_target(app: &axum::Router, sid: &str, cookie: Option<&str>) -> (u16, String) {
    let response = app
        .clone()
        .oneshot(complete_request(sid, cookie))
        .await
        .expect("infallible");
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (status, location)
}

/// The one-time code out of an approved bound login answer.
fn completion_code(answer: &forum_vector::Answer) -> String {
    let json: serde_json::Value = serde_json::from_str(&answer.body_utf8).expect("json answer");
    json["completion"]["code"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "the approval carries a completion code: {}",
                answer.body_utf8
            )
        })
        .to_owned()
}

/// A code that is not `code`, of the same shape.
fn other_code(code: &str) -> String {
    let n: u32 = code.parse().expect("six digits");
    format!("{:06}", (n + 1) % 1_000_000)
}

const PAID_KEY: [u8; 32] = [0x11; 32];

fn paid_signer() -> (ed25519_dalek::SigningKey, String) {
    let key = ed25519_dalek::SigningKey::from_bytes(&PAID_KEY);
    let ss58 = warren_contract::ss58::encode(&key.verifying_key().to_bytes());
    (key, ss58)
}

fn paid_state() -> Arc<AppState> {
    let (_, ss58) = paid_signer();
    state_with(b"a-test-handle-secret-32-bytes!!!", Some(&ss58))
}

#[tokio::test]
async fn a_relayed_same_device_approval_does_not_complete_the_attackers_browser() {
    // The attack: somebody opens their own forum sign-in, sends the victim
    // the app link from their approval page, and the victim approves it.
    // Their browser holds the cookie; the code went to the victim's app.
    let app = router(paid_state());
    let attacker = open_sso(&app, "n-relay-same", None).await;
    let (victim_key, _) = paid_signer();

    let approval = send(
        &app,
        signed_bound_login(&victim_key, &attacker.sid(), [0x41; 16]),
    )
    .await;
    assert_eq!(approval.status, 200, "the victim's app approves");

    let (status, location) =
        completion_target(&app, &attacker.sid(), attacker.cookie.as_deref()).await;
    assert_eq!(
        status, 409,
        "the attacker's browser must not complete without the code, got {status} to {location}"
    );
    let state = send(
        &app,
        status_request(&attacker.sid(), attacker.cookie.as_deref()),
    )
    .await;
    assert_eq!(state.body_utf8, r#"{"status":"awaiting_code"}"#);
}

#[tokio::test]
async fn a_browser_without_the_login_cookie_can_neither_read_confirm_nor_complete() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-cookieless", None).await;
    let (key, _) = paid_signer();
    let approval = send(&app, signed_bound_login(&key, &browser.sid(), [0x42; 16])).await;
    assert_eq!(approval.status, 200);
    let code = completion_code(&approval);

    // No cookie: the app's own view of the session, which says only that it
    // no longer waits for an approval.
    let state = send(&app, status_request(&browser.sid(), None)).await;
    assert_eq!(
        state.status, 404,
        "a cookie-less read learns nothing past the approval"
    );
    // Even the right code is refused without the browser's cookie.
    let confirm = send(&app, confirm_request(&browser.sid(), None, &code)).await;
    assert_eq!(confirm.status, 403);
    assert_eq!(confirm.body_utf8, r#"{"error":"browser_mismatch"}"#);
    let (status, _) = completion_target(&app, &browser.sid(), None).await;
    assert_eq!(status, 403, "no cookie, no completion");
}

#[tokio::test]
async fn a_legacy_approval_is_refused_by_default_and_the_page_says_update_the_app() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-legacy-default", None).await;
    let (key, _) = paid_signer();

    let answer = send(
        &app,
        signed_login_request(&key, &browser.sid(), unix_now(), [0x43; 16]),
    )
    .await;

    assert_eq!(answer.status, 400);
    assert_eq!(answer.body_utf8, r#"{"error":"app_update_required"}"#);
    let state = send(
        &app,
        status_request(&browser.sid(), browser.cookie.as_deref()),
    )
    .await;
    assert_eq!(
        state.body_utf8,
        r#"{"reason":"app_update_required","status":"cancelled"}"#
    );
}

#[tokio::test]
async fn a_replayed_sso_payload_from_another_browser_gets_no_session() {
    let app = router(paid_state());
    let first = open_sso(&app, "n-replayed", None).await;
    assert_eq!(first.status, StatusCode::OK);
    let sid = first.sid();

    for other in [None, Some("ab".repeat(32))] {
        let replay = open_sso(&app, "n-replayed", other.as_deref()).await;
        assert_eq!(
            replay.status,
            StatusCode::FORBIDDEN,
            "another browser is refused"
        );
        assert!(
            !replay.html.contains(&sid),
            "the replay must not be handed the pending session"
        );
        assert!(replay.cookie.is_none(), "and gets no binding to it");
    }
    let refreshed = open_sso(&app, "n-replayed", first.cookie.as_deref()).await;
    assert_eq!(
        refreshed.sid(),
        sid,
        "the browser that started it keeps its session"
    );
}

/// The payload fields a completion redirect hands Discourse.
fn asserted_fields(location: &str) -> std::collections::BTreeMap<String, String> {
    let query = location.split_once('?').expect("a query").1;
    let sso = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("sso="))
        .expect("an sso parameter");
    let sso = urlencoding::decode(sso).expect("urlencoded");
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sso.as_bytes())
        .expect("base64");
    serde_urlencoded::from_bytes(&raw).expect("form fields")
}

fn paid_state_with(
    legacy: LegacyApproval,
    forum_staff: Option<&[(&str, bool)]>,
    admins: &str,
) -> Arc<AppState> {
    let (_, ss58) = paid_signer();
    build_state(Setup {
        paid_ss58: Some(&ss58),
        legacy,
        forum_staff,
        admins,
        ..Setup::default()
    })
}

/// The paid signer's forum handle under the suite's handle secret.
fn paid_handle() -> String {
    let (key, _) = paid_signer();
    warren_connect::handle::derive(HANDLE_SECRET, &key.verifying_key().to_bytes()).username
}

#[tokio::test]
async fn a_relayed_cross_device_approval_does_not_complete_the_attackers_browser() {
    // The QR variant of the relay: the victim's phone reads the attacker's
    // QR and approves on the cross-device id.
    let state = paid_state();
    let app = router(state.clone());
    let attacker = BrowserSecret::generate();
    let ids = state
        .sessions
        .create(
            "n-relay-qr".into(),
            FORUM_RETURN.into(),
            &attacker.key(),
            unix_now(),
        )
        .expect("create");
    let (victim_key, _) = paid_signer();

    let approval = send(
        &app,
        signed_bound_login(&victim_key, &ids.qr_sid, [0x44; 16]),
    )
    .await;
    assert_eq!(approval.status, 200);

    let (status, _) = completion_target(&app, &ids.sid, Some(attacker.as_str())).await;
    assert_eq!(status, 409, "no code, no login, on the QR path too");
}

#[tokio::test]
async fn wrong_codes_spend_the_budget_and_the_last_one_cancels_the_login() {
    let app = router(paid_state());
    let attacker = open_sso(&app, "n-budget", None).await;
    let (victim_key, _) = paid_signer();
    let approval = send(
        &app,
        signed_bound_login(&victim_key, &attacker.sid(), [0x45; 16]),
    )
    .await;
    let wrong = other_code(&completion_code(&approval));
    let cookie = attacker.cookie();

    for left in (1..5).rev() {
        let answer = send(
            &app,
            confirm_request(&attacker.sid(), Some(&cookie), &wrong),
        )
        .await;
        assert_eq!(answer.status, 422);
        assert_eq!(
            answer.body_utf8,
            format!(r#"{{"attempts_left":{left},"error":"code_invalid"}}"#)
        );
    }
    let last = send(
        &app,
        confirm_request(&attacker.sid(), Some(&cookie), &wrong),
    )
    .await;
    assert_eq!(last.status, 409);
    assert_eq!(
        last.body_utf8,
        r#"{"reason":"code_attempts_exhausted","status":"cancelled"}"#
    );
    let (status, _) = completion_target(&app, &attacker.sid(), Some(&cookie)).await;
    assert_eq!(status, 409, "a cancelled login stays cancelled");
}

#[tokio::test]
async fn a_legacy_approval_from_a_staff_wallet_is_refused_even_when_legacy_is_allowed() {
    let (key, ss58) = paid_signer();
    let handle = paid_handle();
    let cases: [(&str, Arc<AppState>); 3] = [
        (
            "allowlisted",
            paid_state_with(LegacyApproval::Allow, Some(&[]), &ss58),
        ),
        (
            "forum admin or moderator",
            paid_state_with(LegacyApproval::Allow, Some(&[(handle.as_str(), true)]), ""),
        ),
        (
            "staff status unreadable",
            paid_state_with(LegacyApproval::Allow, None, ""),
        ),
    ];
    for (case, state) in cases {
        let app = router(state);
        let browser = open_sso(&app, "n-legacy-staff", None).await;

        let answer = send(
            &app,
            signed_login_request(&key, &browser.sid(), unix_now(), [0x46; 16]),
        )
        .await;

        assert_eq!(answer.status, 400, "{case}");
        assert_eq!(
            answer.body_utf8, r#"{"error":"app_update_required"}"#,
            "{case}"
        );
        let state = send(
            &app,
            status_request(&browser.sid(), Some(&browser.cookie())),
        )
        .await;
        assert_eq!(
            state.body_utf8, r#"{"reason":"app_update_required","status":"cancelled"}"#,
            "{case}"
        );
    }
}

#[tokio::test]
async fn a_legacy_approval_from_a_member_is_accepted_under_the_flag_and_still_needs_the_cookie() {
    let app = router(paid_state_with(
        LegacyApproval::Allow,
        Some(&[(paid_handle().as_str(), false)]),
        "",
    ));
    let browser = open_sso(&app, "n-legacy-member", None).await;
    let (key, _) = paid_signer();

    let answer = send(
        &app,
        signed_login_request(&key, &browser.sid(), unix_now(), [0x47; 16]),
    )
    .await;

    assert_eq!(answer.status, 200);
    assert!(
        !answer.body_utf8.contains("completion"),
        "the legacy answer is the v1 answer: {}",
        answer.body_utf8
    );
    let (status, _) = completion_target(&app, &browser.sid(), None).await;
    assert_eq!(status, 403, "no cookie, no completion, whatever the form");
    let (status, location) = completion_target(&app, &browser.sid(), Some(&browser.cookie())).await;
    assert_eq!(status, 303);
    assert!(location.starts_with(FORUM_RETURN), "{location}");
}

#[tokio::test]
async fn a_same_device_login_completes_through_the_code_and_asserts_staff() {
    let (key, ss58) = paid_signer();
    let app = router(paid_state_with(LegacyApproval::Deny, None, &ss58));
    let browser = open_sso(&app, "n-happy-same", None).await;

    let approval = send(&app, signed_bound_login(&key, &browser.sid(), [0x48; 16])).await;
    assert_eq!(approval.status, 200);
    let json: serde_json::Value = serde_json::from_str(&approval.body_utf8).expect("json");
    let code = completion_code(&approval);
    assert_eq!(json["status"], "approved");
    assert_eq!(
        json["completion"]["handoff_url"],
        format!(
            "https://connect.test/handoff#sid={}&code={code}",
            browser.sid()
        ),
        "a same-device approval gets the handoff to its own browser"
    );
    let state = send(
        &app,
        status_request(&browser.sid(), Some(&browser.cookie())),
    )
    .await;
    assert_eq!(state.body_utf8, r#"{"status":"awaiting_code"}"#);

    let confirm = send(
        &app,
        confirm_request(&browser.sid(), Some(&browser.cookie()), &code),
    )
    .await;
    assert_eq!(confirm.status, 200);
    assert_eq!(confirm.body_utf8, r#"{"status":"approved"}"#);
    let (status, location) = completion_target(&app, &browser.sid(), Some(&browser.cookie())).await;

    assert_eq!(status, 303);
    assert!(location.starts_with(FORUM_RETURN), "{location}");
    let fields = asserted_fields(&location);
    assert_eq!(fields["nonce"], "n-happy-same");
    assert_eq!(
        fields.get("admin").map(String::as_str),
        Some("true"),
        "an allowlisted wallet approving on this device, confirmed in this browser, is staff"
    );
}

#[tokio::test]
async fn a_cross_device_login_completes_through_the_typed_code_and_never_asserts_staff() {
    let (key, ss58) = paid_signer();
    let state = paid_state_with(LegacyApproval::Deny, None, &ss58);
    let app = router(state.clone());
    let browser = BrowserSecret::generate();
    let ids = state
        .sessions
        .create(
            "n-happy-qr".into(),
            FORUM_RETURN.into(),
            &browser.key(),
            unix_now(),
        )
        .expect("create");

    let approval = send(&app, signed_bound_login(&key, &ids.qr_sid, [0x49; 16])).await;
    assert_eq!(approval.status, 200);
    let json: serde_json::Value = serde_json::from_str(&approval.body_utf8).expect("json");
    assert!(
        json["completion"].get("handoff_url").is_none(),
        "a phone has no business opening the desktop's session in its own browser: {json}"
    );
    let code = completion_code(&approval);

    let confirm = send(
        &app,
        confirm_request(&ids.sid, Some(browser.as_str()), &code),
    )
    .await;
    assert_eq!(confirm.status, 200);
    let (status, location) = completion_target(&app, &ids.sid, Some(browser.as_str())).await;

    assert_eq!(status, 303);
    assert!(
        !asserted_fields(&location).contains_key("admin"),
        "the QR path never mints staff"
    );
}

#[tokio::test]
async fn the_handoff_page_confirms_from_the_fragment_and_never_shows_the_code() {
    let app = router(test_state());
    let response = app
        .clone()
        .oneshot(
            Request::get("/handoff")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");

    assert_eq!(response.status(), StatusCode::OK);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(header("cache-control"), "no-store");
    assert!(header("content-security-policy").contains("default-src 'none'"));
    let html = observe(response).await.body_utf8;
    assert!(
        html.contains("window.location.hash"),
        "the id and the code come from the fragment"
    );
    assert!(
        html.contains("history.replaceState"),
        "and leave the address bar at once"
    );
    assert!(
        html.contains("'/confirm'"),
        "the page posts the confirm itself"
    );
    assert!(
        html.contains("they were trying to sign in to the forum as you"),
        "a relay victim is told what happened"
    );
    assert!(
        !html.contains("textContent = code") && !html.contains("innerHTML"),
        "the code is never written into the page"
    );
}

#[tokio::test]
async fn the_approval_page_sets_the_host_only_login_cookie_and_keeps_it_across_logins() {
    let app = router(test_state());
    let (sso, sig) = signed_sso(&format!(
        "nonce=n-cookie&return_sso_url={}",
        urlencoding::encode(FORUM_RETURN)
    ));
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/sso?sso={}&sig={sig}", urlencoding::encode(&sso)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    let set_cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("a login cookie")
        .to_owned();
    let value = login_cookie_from(&response).expect("value");

    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(
        set_cookie,
        format!("{LOGIN_COOKIE}={value}; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Lax")
    );
    let second = open_sso(&app, "n-cookie-2", Some(&value)).await;
    assert_eq!(
        second.cookie.as_deref(),
        Some(value.as_str()),
        "a browser keeps its secret, so its tabs stay bound"
    );
}

#[tokio::test]
async fn a_second_tab_finding_the_login_completed_lands_on_the_forum() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-two-tabs", None).await;
    let (key, _) = paid_signer();
    let approval = send(&app, signed_bound_login(&key, &browser.sid(), [0x4a; 16])).await;
    let code = completion_code(&approval);
    send(
        &app,
        confirm_request(&browser.sid(), Some(&browser.cookie()), &code),
    )
    .await;

    let (first, _) = completion_target(&app, &browser.sid(), Some(&browser.cookie())).await;
    let (second, location) = completion_target(&app, &browser.sid(), Some(&browser.cookie())).await;

    assert_eq!(first, 303);
    assert_eq!(second, 303);
    assert_eq!(
        location, "https://forum.warrenbrowse.com/",
        "never a second assertion"
    );
    let state = send(
        &app,
        status_request(&browser.sid(), Some(&browser.cookie())),
    )
    .await;
    assert_eq!(state.body_utf8, r#"{"status":"completed"}"#);
}

#[tokio::test]
async fn a_second_approval_cannot_replace_the_first() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-second", None).await;
    let (key, _) = paid_signer();
    send(&app, signed_bound_login(&key, &browser.sid(), [0x4b; 16])).await;

    let again = send(&app, signed_bound_login(&key, &browser.sid(), [0x4c; 16])).await;

    assert_eq!(
        again.status, 404,
        "the login no longer waits for an approval"
    );
}

#[tokio::test]
async fn an_unknown_login_version_is_refused_rather_than_served_an_older_form() {
    use warren_contract::auth::{
        HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
    };
    let app = router(paid_state());
    let browser = open_sso(&app, "n-v3", None).await;
    let (key, _) = paid_signer();
    let body = format!("{{\"login_version\":3,\"sid\":\"{}\"}}", browser.sid());
    let s = sign_request(
        &key,
        "POST",
        "/v1/forum/login",
        body.as_bytes(),
        unix_now(),
        [0x4d; 16],
    );
    let request = Request::post("/v1/forum/login")
        .header(HEADER_PUBKEY, s.pubkey_ss58)
        .header(HEADER_SIGNATURE, s.signature_hex)
        .header(HEADER_TIMESTAMP, s.timestamp.to_string())
        .header(HEADER_NONCE, s.nonce_hex)
        .body(Body::from(body))
        .expect("request");

    let answer = send(&app, request).await;

    assert_eq!(answer.status, 400);
    let state = send(
        &app,
        status_request(&browser.sid(), Some(&browser.cookie())),
    )
    .await;
    assert_eq!(
        state.body_utf8, r#"{"status":"pending"}"#,
        "nothing was spent"
    );
}

#[tokio::test]
async fn the_confirm_takes_json_only() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-json", None).await;
    let request = Request::post(format!("/v1/session/{}/confirm", browser.sid()))
        .header("Cookie", format!("{LOGIN_COOKIE}={}", browser.cookie()))
        .header("Content-Type", "text/plain")
        .body(Body::from(r#"{"code":"123456"}"#))
        .expect("request");

    assert_eq!(send(&app, request).await.status, 400);
}

#[tokio::test]
async fn the_app_view_of_the_status_says_pending_until_the_approval_and_nothing_after() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-app-view", None).await;
    let before = send(&app, status_request(&browser.sid(), None)).await;
    assert_eq!(before.status, 200);
    assert_eq!(before.body_utf8, r#"{"status":"pending"}"#);

    let (key, _) = paid_signer();
    send(&app, signed_bound_login(&key, &browser.sid(), [0x4e; 16])).await;

    let after = send(&app, status_request(&browser.sid(), None)).await;
    assert_eq!(after.status, 404);
    let stranger = send(&app, status_request(&browser.sid(), Some(&"ab".repeat(32)))).await;
    assert_eq!(
        stranger.status, 403,
        "a stranger's cookie reads nothing either"
    );
    assert_eq!(stranger.body_utf8, r#"{"error":"browser_mismatch"}"#);
}

#[tokio::test]
async fn a_browser_holding_its_own_login_cookie_cannot_touch_another_browsers_login() {
    // The attacker's shape exactly: a browser with a perfectly valid cookie
    // of its own, and a victim's session id learned from a shared screen.
    let app = router(paid_state());
    let victim = open_sso(&app, "n-victim", None).await;
    let stranger = open_sso(&app, "n-stranger", None).await;
    let (key, _) = paid_signer();
    let approval = send(&app, signed_bound_login(&key, &victim.sid(), [0x4f; 16])).await;
    let code = completion_code(&approval);
    let theirs = Some(stranger.cookie());

    let read = send(&app, status_request(&victim.sid(), theirs.as_deref())).await;
    assert_eq!(read.status, 403);
    let confirm = send(
        &app,
        confirm_request(&victim.sid(), theirs.as_deref(), &code),
    )
    .await;
    assert_eq!(confirm.status, 403, "even with the right code");
    let (status, _) = completion_target(&app, &victim.sid(), theirs.as_deref()).await;
    assert_eq!(status, 403);
    let own = send(&app, status_request(&victim.sid(), Some(&victim.cookie()))).await;
    assert_eq!(
        own.body_utf8, r#"{"status":"awaiting_code"}"#,
        "and the owner is untouched"
    );
}

// ---------------------------------------------------------------------------
// forum_login_v2: the bound approval's wire, replayed through this router.
// ---------------------------------------------------------------------------

#[test]
fn the_bound_login_vector_carries_only_the_names_this_suite_replays() {
    let v = forum_vector_v2::load();
    let requests: Vec<&str> = v.requests.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(requests, ["login_bound"]);
    let names = v.names();
    let expect = |group: &str, list: &[&str]| {
        let mut got = names[group].clone();
        got.sort_unstable();
        let mut want = list.to_vec();
        want.sort_unstable();
        assert_eq!(got, want, "responses.{group}");
    };
    assert_eq!(
        names.keys().copied().collect::<Vec<_>>(),
        [
            "cancel",
            "complete",
            "confirm",
            "login",
            "session_status",
            "session_status_app"
        ]
    );
    expect(
        "login",
        &[
            "approved_same_device",
            "approved_cross_device",
            "app_update_required",
            "login_version_unsupported",
            "clock_skew",
            "subscription_required",
            "session_unknown",
        ],
    );
    expect("session_status_app", &["pending", "gone"]);
    expect(
        "session_status",
        &[
            "pending",
            "awaiting_code",
            "approved",
            "completed",
            "cancelled_user_cancelled",
            "cancelled_clock_skew",
            "cancelled_subscription_required",
            "cancelled_app_update_required",
            "cancelled_code_attempts_exhausted",
            "browser_mismatch",
        ],
    );
    expect(
        "confirm",
        &[
            "confirmed",
            "code_invalid",
            "attempts_exhausted",
            "not_awaiting_code",
            "browser_mismatch",
            "not_json",
        ],
    );
    expect(
        "complete",
        &[
            "login",
            "already_completed",
            "not_ready",
            "browser_mismatch",
        ],
    );
    expect("cancel", &["cancelled"]);
    assert_eq!(
        v.states.status,
        [
            "pending",
            "awaiting_code",
            "approved",
            "completed",
            "cancelled"
        ]
    );
    assert_eq!(
        v.states.cancel_reasons,
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
fn the_bound_login_vector_is_what_the_contract_signs_and_what_the_verifier_accepts() {
    let v = forum_vector_v2::load();
    let req = v.request("login_bound");
    let identity = forum_vector_v2::assert_signed_and_verified(&v, req);

    assert_eq!(
        req.body_utf8,
        format!(r#"{{"login_version":2,"sid":"{}"}}"#, req.sid),
        "the version rides in the signed body, keys in ascending order"
    );
    let derived =
        warren_connect::handle::derive(v.provider.handle_secret_utf8.as_bytes(), &identity.pubkey);
    assert_eq!(derived.username, v.provider.handle);
    assert_eq!(derived.external_id, v.provider.external_id);
}

#[tokio::test]
async fn the_bound_login_vector_bytes_through_the_router_land_on_the_frozen_clock_skew_answer() {
    let v = forum_vector_v2::load();
    let app = router(test_state());
    let answer = send(&app, v.request("login_bound").as_http()).await;
    assert_answer(
        &answer,
        &v.answer("login", "clock_skew"),
        "login.clock_skew",
    );
}

/// The pinned answer with the values a live provider draws itself put back:
/// its sid, its code, its forum origin.
fn live(pinned: forum_vector::Answer, swaps: &[(&str, &str)]) -> forum_vector::Answer {
    let mut body = pinned.body_utf8;
    for (from, to) in swaps {
        body = body.replace(from, to);
    }
    forum_vector::Answer {
        body_utf8: body,
        ..pinned
    }
}

#[tokio::test]
async fn the_bound_login_vector_pins_the_provider_answer_per_outcome() {
    let v = forum_vector_v2::load();
    let key = v.signer.signing_key();
    let req = v.request("login_bound");
    let provider = |paid: Option<&str>| {
        build_state(Setup {
            handle_secret: v.provider.handle_secret_utf8.as_bytes(),
            paid_ss58: paid,
            forum_staff: Some(&[]),
            public_host: &v.signer.connect_host,
            ..Setup::default()
        })
    };
    let state = provider(Some(&v.signer.pubkey_ss58));
    let app = router(state.clone());
    let pinned = &v.provider;
    let forum = "https://forum.warrenbrowse.com";
    let bound = |sid: &str| format!(r#"{{"login_version":2,"sid":"{sid}"}}"#);
    let mut nonce = 0x60u8;
    let mut next_nonce = || {
        nonce += 1;
        [nonce; 16]
    };

    // The page sets the pinned cookie shape.
    let page = open_sso(&app, "nv2-same", None).await;
    let cookie = page.cookie();
    let sid = page.sid();
    assert_eq!(
        v.cookie
            .example_set_cookie
            .replace(&v.cookie.example_value, &cookie),
        format!(
            "{}={cookie}; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Lax",
            v.cookie.name
        )
    );
    let set_cookie = app
        .clone()
        .oneshot(
            Request::get(format!("/sso?{}", {
                let (sso, sig) = signed_sso(&format!(
                    "nonce=nv2-cookie&return_sso_url={}",
                    urlencoding::encode(FORUM_RETURN)
                ));
                format!("sso={}&sig={sig}", urlencoding::encode(&sso))
            }))
            .header("Cookie", format!("{}={cookie}", v.cookie.name))
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("infallible")
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        set_cookie.as_deref(),
        Some(
            v.cookie
                .example_set_cookie
                .replace(&v.cookie.example_value, &cookie)
                .as_str()
        ),
        "cookie.example_set_cookie"
    );

    // Before the approval: both readers see it waiting.
    assert_answer(
        &send(&app, status_request(&sid, None)).await,
        &v.answer("session_status_app", "pending"),
        "session_status_app.pending",
    );
    assert_answer(
        &send(&app, status_request(&sid, Some(&cookie))).await,
        &v.answer("session_status", "pending"),
        "session_status.pending",
    );
    assert_answer(
        &send(
            &app,
            confirm_request(&sid, Some(&cookie), &pinned.completion_code),
        )
        .await,
        &v.answer("confirm", "not_awaiting_code"),
        "confirm.not_awaiting_code",
    );

    // The same-device approval: the completion carries the handoff.
    let approval = send(
        &app,
        req.signed_body(&key, &bound(&sid), unix_now(), next_nonce()),
    )
    .await;
    let code = completion_code(&approval);
    assert_answer(
        &approval,
        &live(
            v.answer("login", "approved_same_device"),
            &[(&req.sid, &sid), (&pinned.completion_code, &code)],
        ),
        "login.approved_same_device",
    );
    assert_eq!(
        v.handoff.example,
        format!(
            "https://{}{}#sid={}&code={}",
            v.signer.connect_host, v.handoff.path, req.sid, pinned.completion_code
        ),
        "handoff.example follows the template"
    );
    assert_answer(
        &send(&app, status_request(&sid, None)).await,
        &v.answer("session_status_app", "gone"),
        "session_status_app.gone",
    );
    assert_answer(
        &send(&app, status_request(&sid, Some(&cookie))).await,
        &v.answer("session_status", "awaiting_code"),
        "session_status.awaiting_code",
    );
    assert_answer(
        &send(&app, complete_request(&sid, Some(&cookie))).await,
        &v.answer("complete", "not_ready"),
        "complete.not_ready",
    );
    let not_json = with_cookie(
        Request::post(format!("/v1/session/{sid}/confirm")),
        Some(&cookie),
    )
    .header("Content-Type", "text/plain")
    .body(Body::from(format!(r#"{{"code":"{code}"}}"#)))
    .expect("request");
    assert_answer(
        &send(&app, not_json).await,
        &v.answer("confirm", "not_json"),
        "confirm.not_json",
    );
    assert_answer(
        &send(
            &app,
            confirm_request(&sid, Some(&cookie), &other_code(&code)),
        )
        .await,
        &v.answer("confirm", "code_invalid"),
        "confirm.code_invalid",
    );
    let stranger = "cd".repeat(32);
    assert_answer(
        &send(&app, status_request(&sid, Some(&stranger))).await,
        &v.answer("session_status", "browser_mismatch"),
        "session_status.browser_mismatch",
    );
    assert_answer(
        &send(&app, confirm_request(&sid, Some(&stranger), &code)).await,
        &v.answer("confirm", "browser_mismatch"),
        "confirm.browser_mismatch",
    );
    assert_answer(
        &send(&app, complete_request(&sid, Some(&stranger))).await,
        &v.answer("complete", "browser_mismatch"),
        "complete.browser_mismatch",
    );
    assert_answer(
        &send(&app, confirm_request(&sid, Some(&cookie), &code)).await,
        &v.answer("confirm", "confirmed"),
        "confirm.confirmed",
    );
    assert_answer(
        &send(&app, status_request(&sid, Some(&cookie))).await,
        &v.answer("session_status", "approved"),
        "session_status.approved",
    );

    // Completion, then a second tab.
    let pinned_prefix = v.entry("complete", "login")["location_prefix"]
        .as_str()
        .expect("location_prefix")
        .replace(&pinned.forum_public_url, forum);
    let (status, location) = completion_target(&app, &sid, Some(&cookie)).await;
    assert_eq!(u64::from(status), v.entry("complete", "login")["status"]);
    assert!(
        location.starts_with(&pinned_prefix),
        "complete.login: {location}"
    );
    let (status, location) = completion_target(&app, &sid, Some(&cookie)).await;
    assert_eq!(
        u64::from(status),
        v.entry("complete", "already_completed")["status"]
    );
    assert_eq!(
        location,
        v.entry("complete", "already_completed")["location"]
            .as_str()
            .expect("location")
            .replace(&pinned.forum_public_url, forum),
        "complete.already_completed"
    );
    assert_answer(
        &send(&app, status_request(&sid, Some(&cookie))).await,
        &v.answer("session_status", "completed"),
        "session_status.completed",
    );

    // The cross-device approval: the code alone.
    let browser = BrowserSecret::generate();
    let ids = state
        .sessions
        .create(
            "nv2-qr".into(),
            FORUM_RETURN.into(),
            &browser.key(),
            unix_now(),
        )
        .expect("create");
    let approval = send(
        &app,
        req.signed_body(&key, &bound(&ids.qr_sid), unix_now(), next_nonce()),
    )
    .await;
    let qr_code = completion_code(&approval);
    assert_answer(
        &approval,
        &live(
            v.answer("login", "approved_cross_device"),
            &[(&pinned.completion_code, &qr_code)],
        ),
        "login.approved_cross_device",
    );

    // Five wrong codes.
    let wrong = other_code(&qr_code);
    for _ in 0..4 {
        send(
            &app,
            confirm_request(&ids.sid, Some(browser.as_str()), &wrong),
        )
        .await;
    }
    assert_answer(
        &send(
            &app,
            confirm_request(&ids.sid, Some(browser.as_str()), &wrong),
        )
        .await,
        &v.answer("confirm", "attempts_exhausted"),
        "confirm.attempts_exhausted",
    );
    assert_answer(
        &send(&app, status_request(&ids.sid, Some(browser.as_str()))).await,
        &v.answer("session_status", "cancelled_code_attempts_exhausted"),
        "session_status.cancelled_code_attempts_exhausted",
    );

    // The v1 form, refused, and the page told why.
    let page = open_sso(&app, "nv2-legacy", None).await;
    let legacy = format!(r#"{{"sid":"{}"}}"#, page.sid());
    assert_answer(
        &send(
            &app,
            req.signed_body(&key, &legacy, unix_now(), next_nonce()),
        )
        .await,
        &v.answer("login", "app_update_required"),
        "login.app_update_required",
    );
    assert_answer(
        &send(&app, status_request(&page.sid(), Some(&page.cookie()))).await,
        &v.answer("session_status", "cancelled_app_update_required"),
        "session_status.cancelled_app_update_required",
    );

    // A version this provider does not speak.
    let page = open_sso(&app, "nv2-v3", None).await;
    let v3 = format!(r#"{{"login_version":3,"sid":"{}"}}"#, page.sid());
    assert_answer(
        &send(&app, req.signed_body(&key, &v3, unix_now(), next_nonce())).await,
        &v.answer("login", "login_version_unsupported"),
        "login.login_version_unsupported",
    );

    // Clock skew.
    let page = open_sso(&app, "nv2-clock", None).await;
    assert_answer(
        &send(
            &app,
            req.signed_body(&key, &bound(&page.sid()), unix_now() - 120, next_nonce()),
        )
        .await,
        &v.answer("login", "clock_skew"),
        "login.clock_skew",
    );
    assert_answer(
        &send(&app, status_request(&page.sid(), Some(&page.cookie()))).await,
        &v.answer("session_status", "cancelled_clock_skew"),
        "session_status.cancelled_clock_skew",
    );

    // The app's decline.
    let page = open_sso(&app, "nv2-cancel", None).await;
    let cancel = Request::post(format!("/v1/session/{}/cancel", page.sid()))
        .body(Body::empty())
        .expect("request");
    assert_answer(
        &send(&app, cancel).await,
        &v.answer("cancel", "cancelled"),
        "cancel.cancelled",
    );
    assert_answer(
        &send(&app, status_request(&page.sid(), Some(&page.cookie()))).await,
        &v.answer("session_status", "cancelled_user_cancelled"),
        "session_status.cancelled_user_cancelled",
    );

    // An id naming nothing.
    assert_answer(
        &send(
            &app,
            req.signed_body(&key, &bound(&req.sid), unix_now(), next_nonce()),
        )
        .await,
        &v.answer("login", "session_unknown"),
        "login.session_unknown",
    );

    // Never paid.
    let unpaid = router(provider(None));
    let page = open_sso(&unpaid, "nv2-unpaid", None).await;
    assert_answer(
        &send(
            &unpaid,
            req.signed_body(&key, &bound(&page.sid()), unix_now(), next_nonce()),
        )
        .await,
        &v.answer("login", "subscription_required"),
        "login.subscription_required",
    );
    assert_answer(
        &send(&unpaid, status_request(&page.sid(), Some(&page.cookie()))).await,
        &v.answer("session_status", "cancelled_subscription_required"),
        "session_status.cancelled_subscription_required",
    );
    assert_eq!(pinned.notify_slot, 1);
    assert_ne!(pinned.qr_sid, req.sid, "the vector's two ids differ");
}

#[tokio::test]
async fn a_linked_wallet_whose_forum_account_is_not_under_its_handle_counts_as_staff() {
    // Discourse can hold the account under another name (renamed from the
    // admin UI, or suffixed at creation), and staff status is read by the
    // derived handle. A wallet that has signed in before and whose handle
    // names no account is one whose standing cannot be read: refused. A
    // wallet that never signed in has no account at all, and is let through.
    let (key, ss58) = paid_signer();
    let state = build_state(Setup {
        paid_ss58: Some(&ss58),
        legacy: LegacyApproval::Allow,
        forum_staff: Some(&[]),
        ..Setup::default()
    });
    let app = router(state.clone());
    let first = open_sso(&app, "n-first-sign-in", None).await;
    let answer = send(
        &app,
        signed_login_request(&key, &first.sid(), unix_now(), [0x50; 16]),
    )
    .await;
    assert_eq!(
        answer.status, 200,
        "a first sign-in has no account to be staff on"
    );

    let again = open_sso(&app, "n-renamed", None).await;
    let answer = send(
        &app,
        signed_login_request(&key, &again.sid(), unix_now(), [0x51; 16]),
    )
    .await;

    assert_eq!(answer.status, 400);
    assert_eq!(answer.body_utf8, r#"{"error":"app_update_required"}"#);
}

#[tokio::test]
async fn a_code_of_the_wrong_shape_is_refused_without_spending_an_attempt() {
    let app = router(paid_state());
    let browser = open_sso(&app, "n-shape", None).await;
    let (key, _) = paid_signer();
    let approval = send(&app, signed_bound_login(&key, &browser.sid(), [0x52; 16])).await;
    let wrong = other_code(&completion_code(&approval));

    for shape in ["12345", "1234567", "12a456", ""] {
        let answer = send(
            &app,
            confirm_request(&browser.sid(), Some(&browser.cookie()), shape),
        )
        .await;
        assert_eq!(answer.status, 400, "{shape:?}");
    }
    let answer = send(
        &app,
        confirm_request(&browser.sid(), Some(&browser.cookie()), &wrong),
    )
    .await;
    assert_eq!(
        answer.body_utf8, r#"{"attempts_left":4,"error":"code_invalid"}"#,
        "the malformed codes cost nothing"
    );
}
