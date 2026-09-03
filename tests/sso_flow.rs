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

use warren_connect::attach::AttachStore;
use warren_connect::nonces::NonceStore;
use warren_connect::routes::{AppState, router};
use warren_connect::sessions::SessionStore;
use warren_connect::store::{IdentityStore, MemoryIdentity, SubscriptionStatus};

mod forum_vector;
use forum_vector::{assert_answer, assert_signed_by_the_contract, observe, verify_at_vector_clock};

const CONNECT_SECRET: &[u8] = b"a-test-connect-secret-32-bytes!!";

fn test_state() -> Arc<AppState> {
    state_with(b"a-test-handle-secret-32-bytes!!!", None)
}

/// A state under `handle_secret`, whose identity store knows `paid_ss58` as
/// an ever-paid wallet when one is given.
fn state_with(handle_secret: &[u8], paid_ss58: Option<&str>) -> Arc<AppState> {
    let lazy = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time");
    let memory = MemoryIdentity::default();
    if let Some(ss58) = paid_ss58 {
        memory.subscriptions.lock().expect("mutex").insert(
            ss58.to_owned(),
            SubscriptionStatus {
                ever_paid: true,
                active: true,
                expires_at_unix: Some(4_102_444_800),
            },
        );
    }
    Arc::new(AppState {
        connect_secret: CONNECT_SECRET.to_vec(),
        handle_secret: handle_secret.to_vec(),
        public_host: "connect.test".into(),
        internal_token: "test-internal-token".into(),
        admins: Default::default(),
        forum_pool: lazy.clone(),
        warren_pool: lazy,
        identity: IdentityStore::Memory(memory),
        discourse_pool: None,
        seen_pool: None,
        digest_generation: Default::default(),
        sessions: SessionStore::default(),
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

async fn approval_page_sid(app: &axum::Router) -> String {
    page_sid(app, "nclock").await
}

/// The sid of the approval page opened under the DiscourseConnect nonce
/// `nonce` (a live pending session is reused per nonce, so a test that needs
/// a fresh one names a fresh nonce).
async fn page_sid(app: &axum::Router, nonce: &str) -> String {
    let (sso, sig) = signed_sso(&format!(
        "nonce={nonce}&return_sso_url=https%3A%2F%2Fforum.warrenbrowse.com%2Fsession%2Fsso_login"
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    sid_from_page(std::str::from_utf8(&body).expect("utf8"))
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
    let sid = approval_page_sid(&app).await;

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
        .oneshot(
            Request::get(format!("/v1/session/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
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
    // by the report suite.
    let v = forum_vector::load();
    let mut requests: Vec<&str> = v.requests.iter().map(|r| r.name.as_str()).collect();
    requests.sort_unstable();
    assert_eq!(requests, ["login", "report_with_log", "report_without_log"]);
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

async fn session_status_answer(app: &axum::Router, sid: &str) -> forum_vector::Answer {
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/v1/session/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    observe(response).await
}

#[tokio::test]
async fn the_login_vector_pins_the_provider_answer_per_outcome() {
    // The pinned answers, produced again by this router under the vector's
    // provider parameters, with the vector key signing inside the window.
    let v = forum_vector::load();
    let key = v.signer.signing_key();
    let secret = v.provider.handle_secret_utf8.as_bytes();
    let app = router(state_with(secret, Some(&v.signer.pubkey_ss58)));

    // Pending, then approved: the handle and the slot come back to the
    // wallet that signed, and the browser sees the approval.
    let sid = page_sid(&app, "nvec-approve").await;
    assert_answer(
        &session_status_answer(&app, &sid).await,
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
        &session_status_answer(&app, &sid).await,
        &v.responses.session_status.get("approved"),
        "session_status.approved",
    );

    // Clock skew: refused with the token, and the browser is told why.
    let sid = page_sid(&app, "nvec-clock").await;
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
        &session_status_answer(&app, &sid).await,
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
        &session_status_answer(&app, unknown).await,
        &v.responses.session_status.get("unknown"),
        "session_status.unknown",
    );

    // Never paid: the paywall, and the browser is told why.
    let never = router(state_with(secret, None));
    let sid = page_sid(&never, "nvec-unpaid").await;
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
        &session_status_answer(&never, &sid).await,
        &v.responses
            .session_status
            .get("cancelled_subscription_required"),
        "session_status.cancelled_subscription_required",
    );
}
