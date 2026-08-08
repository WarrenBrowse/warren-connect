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

const CONNECT_SECRET: &[u8] = b"a-test-connect-secret-32-bytes!!";

fn test_state() -> Arc<AppState> {
    let lazy = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time");
    Arc::new(AppState {
        connect_secret: CONNECT_SECRET.to_vec(),
        handle_secret: b"a-test-handle-secret-32-bytes!!!".to_vec(),
        public_host: "connect.test".into(),
        internal_token: "test-internal-token".into(),
        admins: Default::default(),
        forum_pool: lazy.clone(),
        warren_pool: lazy,
        discourse_pool: None,
        seen_pool: None,
        digest_generation: Default::default(),
        sessions: SessionStore::default(),
        nonces: NonceStore::default(),
        attach: AttachStore::default(),
        forum_api: None,
        intake: None,
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
    let (sso, sig) = signed_sso("nonce=n1&return_sso_url=https%3A%2F%2Ff%2Fsession%2Fsso_login");

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
async fn sso_entry_rejects_a_forged_signature() {
    let app = router(test_state());
    let (sso, _) = signed_sso("nonce=n1&return_sso_url=https%3A%2F%2Ff%2Fsso");

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
