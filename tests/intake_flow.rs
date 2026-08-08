//! Guest help intake through the real axum router, with Discourse stubbed by
//! a local axum server (topic creation as the intake bot user).

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse as _;
use axum::routing::post;
use base64::Engine as _;
use http_body_util::BodyExt as _;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt as _;

use warren_connect::attach::AttachStore;
use warren_connect::forum_api::ForumApi;
use warren_connect::intake::RateLimiter;
use warren_connect::nonces::NonceStore;
use warren_connect::routes::{AppState, IntakeState, router};
use warren_connect::sessions::SessionStore;
use warren_connect::ticket::TicketKey;

/// The handle secret every test state is built with; the ticket key derives
/// from it, so a code issued by one router verifies on another.
const TEST_HANDLE_SECRET: &[u8] = b"a-test-handle-secret-32-bytes!!!";

#[derive(Debug)]
struct StubCall {
    api_username: String,
    body: serde_json::Value,
}

#[derive(Default)]
struct StubState {
    calls: Mutex<Vec<StubCall>>,
    /// Raw multipart bodies received on `/uploads.json`.
    uploads: Mutex<Vec<Vec<u8>>>,
    /// Makes every upload answer 422, to exercise the abort path.
    uploads_fail: bool,
    /// Author `GET /t/{id}.json` reports; the intake bot unless overridden.
    topic_author: Option<String>,
    /// Makes every topic fetch answer 404, as a deleted topic would.
    topic_missing: bool,
    /// Answers post creations without a `post_number`, as an older or a
    /// changed Discourse could.
    omit_post_number: bool,
}

async fn stub_posts(
    State(s): State<Arc<StubState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    s.calls.lock().expect("stub mutex").push(StubCall {
        api_username: headers
            .get("Api-Username")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        body,
    });
    if s.omit_post_number {
        return Json(serde_json::json!({ "id": 100, "topic_id": 4242 }));
    }
    Json(serde_json::json!({ "id": 100, "topic_id": 4242, "post_number": 7 }))
}

/// Discourse's topic endpoint, enough of it for the author check.
async fn stub_topic(
    State(s): State<Arc<StubState>>,
    axum::extract::Path(topic_id): axum::extract::Path<String>,
) -> axum::response::Response {
    if s.topic_missing {
        return (StatusCode::NOT_FOUND, "deleted").into_response();
    }
    let author = s.topic_author.as_deref().unwrap_or("warren-intake");
    Json(serde_json::json!({
        "title": format!("[Install] guest report ({topic_id})"),
        "details": { "created_by": { "username": author } },
        "tags": [],
    }))
    .into_response()
}

/// Discourse's upload endpoint: records the multipart body and hands back a
/// short url, or fails when the stub is built to.
async fn stub_uploads(
    State(s): State<Arc<StubState>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let n = {
        let mut uploads = s.uploads.lock().expect("stub mutex");
        uploads.push(body.to_vec());
        uploads.len()
    };
    if s.uploads_fail {
        return (StatusCode::UNPROCESSABLE_ENTITY, "rejected").into_response();
    }
    Json(serde_json::json!({ "short_url": format!("upload://stub{n}.bin") })).into_response()
}

async fn spawn_stub() -> (String, Arc<StubState>) {
    spawn_stub_with(Arc::new(StubState::default())).await
}

async fn spawn_stub_with(state: Arc<StubState>) -> (String, Arc<StubState>) {
    let app = axum::Router::new()
        .route("/posts.json", post(stub_posts))
        .route("/uploads.json", post(stub_uploads))
        // The whole segment is one parameter (axum allows no more), so the
        // captured value is `<id>.json`; the stub only echoes it.
        .route("/t/{topic}", axum::routing::get(stub_topic))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serves");
    });
    (format!("http://{addr}"), state)
}

fn test_state(intake: Option<IntakeState>) -> Arc<AppState> {
    let lazy = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time");
    Arc::new(AppState {
        connect_secret: b"a-test-connect-secret-32-bytes!!".to_vec(),
        handle_secret: TEST_HANDLE_SECRET.to_vec(),
        public_host: "connect.test".into(),
        internal_token: String::new(),
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
        intake,
    })
}

fn intake_state(url: &str, limiter: RateLimiter) -> IntakeState {
    intake_state_with(url, limiter, RateLimiter::new(10, 60, 3_600))
}

fn intake_state_with(url: &str, limiter: RateLimiter, reply_limiter: RateLimiter) -> IntakeState {
    IntakeState {
        api: ForumApi::new(url, "k".into(), "warren-intake".into(), "staff".into()),
        category_id: 7,
        limiter,
        reply_limiter,
        ticket: TicketKey::derive(TEST_HANDLE_SECRET),
    }
}

fn intake_request(body: &str, forwarded_for: Option<&str>) -> Request<Body> {
    guest_request("/v1/help/intake", body, forwarded_for)
}

fn reply_request(body: &str, forwarded_for: Option<&str>) -> Request<Body> {
    guest_request("/v1/help/reply", body, forwarded_for)
}

fn guest_request(path: &str, body: &str, forwarded_for: Option<&str>) -> Request<Body> {
    let mut builder = Request::post(path).header("content-type", "application/json");
    if let Some(xff) = forwarded_for {
        builder = builder.header("x-forwarded-for", xff);
    }
    builder.body(Body::from(body.to_owned())).expect("request")
}

fn reply_body(code: &str, message: &str) -> String {
    serde_json::json!({ "code": code, "message": message, "website": "" }).to_string()
}

/// Files a report through the real router and returns the follow-up code the
/// guest is handed. Every reply test starts from the code the product issues,
/// never from one hand-built in the test.
async fn file_report(state: Arc<AppState>, ip: &str) -> String {
    let response = router(state)
        .oneshot(intake_request(&valid_body(), Some(ip)))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);
    body_json(response).await["code"]
        .as_str()
        .expect("the intake hands back a follow-up code")
        .to_owned()
}

fn valid_body() -> String {
    serde_json::json!({
        "kind": "payment",
        "message": "My card keeps being declined at the checkout step.",
        "platform": "windows",
        "website": "",
    })
    .to_string()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn intake_is_503_when_not_configured() {
    let state = test_state(None);
    let response = router(state)
        .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn intake_happy_path_creates_a_public_topic_as_the_bot() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let response = router(state)
        .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    assert_eq!(
        json["topic_url"].as_str().expect("topic_url"),
        "https://forum.warrenbrowse.com/t/4242"
    );
    let reference = json["reference"].as_str().expect("reference");
    assert_eq!(reference.len(), 6);
    let code = json["code"].as_str().expect("follow-up code");
    assert!(
        code.starts_with("WRN-") && code.len() == 23,
        "the guest leaves with a code they can read back: {code}"
    );

    let calls = stub.calls.lock().expect("stub mutex");
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].api_username, "warren-intake",
        "topics are authored by the low-privilege bot, not system"
    );
    assert_eq!(calls[0].body["category"], 7);
    let title = calls[0].body["title"].as_str().expect("title");
    assert!(title.starts_with("[Payment] guest report "));
    assert!(title.ends_with(&format!("#{reference}")));
    let raw = calls[0].body["raw"].as_str().expect("raw");
    assert!(raw.contains("My card keeps being declined"));
    assert!(raw.contains("kind: payment"));
    assert!(raw.contains("platform: windows"));
    assert!(
        !raw.contains("203.0.113.1"),
        "the client IP must never reach Discourse"
    );
}

#[tokio::test]
async fn the_code_from_a_report_posts_a_follow_up_into_that_same_topic() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let code = file_report(state.clone(), "203.0.113.1").await;

    let response = router(state)
        .oneshot(reply_request(
            &reply_body(&code, "It still fails after the reinstall, same error."),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        body_json(response).await["topic_url"]
            .as_str()
            .expect("topic_url"),
        "https://forum.warrenbrowse.com/t/4242/7",
        "the guest is sent straight to their own new post"
    );

    let calls = stub.calls.lock().expect("stub mutex");
    assert_eq!(calls.len(), 2, "the report, then the follow-up");
    assert_eq!(calls[1].body["topic_id"], 4242);
    assert!(calls[1].body["title"].is_null(), "a reply opens no topic");
    assert_eq!(
        calls[1].api_username, "warren-intake",
        "the follow-up speaks with the same voice as the report"
    );
    let raw = calls[1].body["raw"].as_str().expect("raw");
    assert!(raw.contains("It still fails after the reinstall"));
    assert!(
        !raw.contains(&code),
        "the code never lands in a public post"
    );
}

#[tokio::test]
async fn a_follow_up_still_links_the_topic_when_discourse_reports_no_post_number() {
    // The anchor is a nicety; losing it must not cost the guest their link.
    let (url, _stub) = spawn_stub_with(Arc::new(StubState {
        omit_post_number: true,
        ..Default::default()
    }))
    .await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let code = file_report(state.clone(), "203.0.113.1").await;

    let response = router(state)
        .oneshot(reply_request(
            &reply_body(&code, "Adding one more detail to my report."),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        body_json(response).await["topic_url"]
            .as_str()
            .expect("topic_url"),
        "https://forum.warrenbrowse.com/t/4242"
    );
}

#[tokio::test]
async fn a_code_this_service_never_issued_is_404_and_writes_nothing() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let real = file_report(state.clone(), "203.0.113.1").await;
    // A plausible-looking forgery, and the real code with one character of
    // its body swapped.
    let tampered = format!("{}{}", &real[..real.len() - 1], {
        let last = real.chars().last().expect("non-empty");
        if last == '2' { '3' } else { '2' }
    });

    for code in ["WRN-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "not-a-code", "", &tampered] {
        let response = router(state.clone())
            .oneshot(reply_request(
                &reply_body(code, "Please have another look at my report."),
                Some("203.0.113.1"),
            ))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "code {code}");
        assert_eq!(
            body_json(response).await["error"],
            "unknown_code",
            "the form needs to tell a wrong code from a broken service"
        );
    }
    assert_eq!(
        stub.calls.lock().expect("stub mutex").len(),
        1,
        "only the original report reached Discourse"
    );
}

#[tokio::test]
async fn a_valid_code_pointing_at_a_topic_the_bot_does_not_own_is_refused() {
    // Defence in depth: even if code issuance ever pointed somewhere else,
    // a guest may only ever post into a topic the intake bot opened.
    let (url, stub) = spawn_stub_with(Arc::new(StubState {
        topic_author: Some("some-member".to_owned()),
        ..Default::default()
    }))
    .await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let code = file_report(state.clone(), "203.0.113.1").await;

    let response = router(state)
        .oneshot(reply_request(
            &reply_body(&code, "Adding a note to this report of mine."),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        stub.calls.lock().expect("stub mutex").len(),
        1,
        "nothing was posted into a topic that is not the bot's"
    );
}

#[tokio::test]
async fn a_code_whose_topic_is_gone_reads_as_an_unknown_code() {
    // A deleted topic is a dead code, not a backend outage: the guest must
    // be told to open a new report rather than retry a 502.
    let (url, _stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let code = file_report(state, "203.0.113.1").await;

    let (url, _stub) = spawn_stub_with(Arc::new(StubState {
        topic_missing: true,
        ..Default::default()
    }))
    .await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let response = router(state)
        .oneshot(reply_request(
            &reply_body(&code, "Any news on my report from last week?"),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_follow_up_carries_its_screenshots_like_a_report() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));
    let code = file_report(state.clone(), "203.0.113.1").await;

    let body = serde_json::json!({
        "code": code,
        "message": "Here is the screen I get after the update.",
        "website": "",
        "attachments": [{
            "name": "after-update.png",
            "type": "image/png",
            "size": PNG.len(),
            "data": base64::engine::general_purpose::STANDARD.encode(PNG),
        }],
    })
    .to_string();
    let response = router(state)
        .oneshot(reply_request(&body, Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);

    assert_eq!(stub.uploads.lock().expect("stub mutex").len(), 1);
    let calls = stub.calls.lock().expect("stub mutex");
    let raw = calls[1].body["raw"].as_str().expect("raw");
    assert!(
        raw.contains("![after-update.png](upload://stub1.bin)"),
        "{raw}"
    );
}

#[tokio::test]
async fn follow_ups_have_their_own_budget_and_do_not_spend_the_report_one() {
    // A reporter mid-conversation must not be locked out by the tight
    // open-a-report budget, and must not be able to spend it either.
    let (url, _stub) = spawn_stub().await;
    let state = test_state(Some(intake_state_with(
        &url,
        RateLimiter::new(1, 30, 3_600),
        RateLimiter::new(2, 60, 3_600),
    )));
    let code = file_report(state.clone(), "203.0.113.1").await;
    let app = router(state);

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(reply_request(
                &reply_body(&code, "One more detail about this problem."),
                Some("203.0.113.1"),
            ))
            .await
            .expect("infallible");
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "the report budget was already spent, the follow-up budget is its own"
        );
    }
    let response = app
        .oneshot(reply_request(
            &reply_body(&code, "One more detail about this problem."),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "brute-forcing a code stays bounded"
    );
}

#[tokio::test]
async fn the_follow_up_route_answers_cors_for_the_form_origins_only() {
    let (url, _stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/help/reply")
                .header("origin", "https://warren.ro")
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "content-type")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("the help form origin is granted"),
        "https://warren.ro"
    );

    let response = router(state)
        .oneshot(
            Request::post("/v1/help/reply")
                .header("origin", "https://evil.example")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.1")
                .body(Body::from(reply_body("WRN-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "message")))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test]
async fn the_follow_up_route_is_503_when_the_intake_is_not_configured() {
    let state = test_state(None);
    let response = router(state)
        .oneshot(reply_request(
            &reply_body("WRN-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "a long enough message here"),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_filled_honeypot_is_422_and_writes_nothing() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let body = serde_json::json!({
        "kind": "install",
        "message": "This message is long enough to pass validation.",
        "website": "https://spam.example",
    })
    .to_string();
    let response = router(state)
        .oneshot(intake_request(&body, Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

#[tokio::test]
async fn limit_violations_and_malformed_json_are_422() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::new(100, 100, 3_600))));

    let short = serde_json::json!({"kind": "payment", "message": "too short"}).to_string();
    let long = serde_json::json!({"kind": "payment", "message": "a".repeat(4_001)}).to_string();
    let bad_kind =
        serde_json::json!({"kind": "billing", "message": "long enough message body here"})
            .to_string();
    for body in [short.as_str(), long.as_str(), bad_kind.as_str(), "not json"] {
        let response = router(state.clone())
            .oneshot(intake_request(body, Some("203.0.113.1")))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

#[tokio::test]
async fn the_fourth_intake_from_one_ip_is_429() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    for _ in 0..3 {
        let response = router(state.clone())
            .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = router(state.clone())
        .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Another client (behind Caddy, XFF first value is the client) still gets in.
    let response = router(state)
        .oneshot(intake_request(&valid_body(), Some("203.0.113.2, 10.0.0.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(stub.calls.lock().expect("stub mutex").len(), 4);
}

#[tokio::test]
async fn requests_without_forwarded_for_share_one_bucket() {
    let (url, _stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    for _ in 0..3 {
        let response = router(state.clone())
            .oneshot(intake_request(&valid_body(), None))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = router(state)
        .oneshot(intake_request(&valid_body(), None))
        .await
        .expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a missing XFF fails closed instead of bypassing the limit"
    );
}

#[tokio::test]
async fn intake_answers_cors_for_the_two_form_origins_only() {
    let (url, _stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    for origin in ["https://warren.ro", "https://checkout.warrenbrowse.com"] {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/help/intake")
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .expect("preflight must allow the form origin"),
            origin
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-methods")
                .expect("methods advertised")
                .to_str()
                .expect("ascii")
                .contains("POST")
        );
    }

    let response = router(state)
        .oneshot(
            Request::post("/v1/help/intake")
                .header("origin", "https://evil.example")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.1")
                .body(Body::from(valid_body()))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "a foreign origin must not be granted"
    );
}

#[tokio::test]
async fn a_discourse_failure_is_502() {
    // Point the client at a closed port: the topic write fails, the guest
    // gets an opaque 502.
    let state = test_state(Some(intake_state(
        "http://127.0.0.1:1",
        RateLimiter::default(),
    )));
    let response = router(state)
        .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_spoofed_leftmost_xff_does_not_dodge_the_per_ip_budget() {
    // One attacker host rotating fake leftmost XFF entries: the proxy-added
    // rightmost entry is the one that buckets, so the 4th call still 429s.
    let (url, _stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::new(3, 30, 3_600))));
    let app = router(state);
    for i in 0..3 {
        let response = app
            .clone()
            .oneshot(intake_request(
                &valid_body(),
                Some(&format!("10.0.0.{i}, 198.51.100.7")),
            ))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::CREATED, "call {i} admitted");
    }
    let response = app
        .oneshot(intake_request(
            &valid_body(),
            Some("10.0.0.99, 198.51.100.7"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_non_json_content_type_is_rejected_before_any_side_effect() {
    // text/plain is a CORS "simple request": rejecting it forces cross-origin
    // browsers through a preflight, which only the allowlisted origins pass.
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::new(3, 30, 3_600))));
    let request = Request::post("/v1/help/intake")
        .header("content-type", "text/plain")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(valid_body()))
        .expect("request");
    let response = router(state).oneshot(request).await.expect("infallible");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR-fake-pixels";
const PDF: &[u8] = b"%PDF-1.4\n%fake-document";

fn body_with_attachments(items: &[(&str, &str, &[u8])]) -> String {
    let attachments: Vec<_> = items
        .iter()
        .map(|(name, mime, bytes)| {
            serde_json::json!({
                "name": name,
                "type": mime,
                "size": bytes.len(),
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            })
        })
        .collect();
    serde_json::json!({
        "kind": "install",
        "message": "The installer stops at step two, screenshot attached.",
        "platform": "macOS",
        "website": "",
        "attachments": attachments,
    })
    .to_string()
}

#[tokio::test]
async fn attachments_are_uploaded_then_linked_in_the_topic() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let body = body_with_attachments(&[
        ("capture.png", "image/png", PNG),
        ("rapport.pdf", "application/pdf", PDF),
    ]);
    let response = router(state)
        .oneshot(intake_request(&body, Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);

    let uploads = stub.uploads.lock().expect("stub mutex");
    assert_eq!(uploads.len(), 2, "one upload per attachment");
    assert!(
        uploads[0].windows(PNG.len()).any(|w| w == PNG),
        "the decoded image bytes reach Discourse unaltered"
    );
    assert!(
        uploads[0].windows(11).any(|w| w == b"capture.png"),
        "the sanitized filename is sent as the multipart file name"
    );

    let calls = stub.calls.lock().expect("stub mutex");
    assert_eq!(calls.len(), 1, "one topic, created after the uploads");
    let raw = calls[0].body["raw"].as_str().expect("raw");
    assert!(
        raw.contains("![capture.png](upload://stub1.bin)"),
        "an image is linked so Discourse renders it inline: {raw}"
    );
    assert!(
        raw.contains("[rapport.pdf|attachment](upload://stub2.bin)"),
        "a document is linked as a download: {raw}"
    );
}

#[tokio::test]
async fn an_attachment_lying_about_its_type_is_422_and_writes_nothing() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    // PDF bytes declared as a PNG, and a payload that is no accepted format
    // at all. Neither may reach Discourse.
    for body in [
        body_with_attachments(&[("x.png", "image/png", PDF)]),
        body_with_attachments(&[("x.png", "image/png", b"#!/bin/sh")]),
        body_with_attachments(&[("x.txt", "text/plain", b"plain text")]),
    ] {
        let response = router(state.clone())
            .oneshot(intake_request(&body, Some("203.0.113.1")))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(stub.uploads.lock().expect("stub mutex").is_empty());
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

#[tokio::test]
async fn a_hostile_filename_is_rebuilt_before_it_reaches_the_public_topic() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let body = body_with_attachments(&[("../../etc/[evil](x).png", "image/png", PNG)]);
    let response = router(state)
        .oneshot(intake_request(&body, Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);

    let calls = stub.calls.lock().expect("stub mutex");
    let raw = calls[0].body["raw"].as_str().expect("raw");
    assert!(raw.contains("![evil-x.png](upload://stub1.bin)"), "{raw}");
    assert!(!raw.contains(".."), "no traversal fragment survives");
}

#[tokio::test]
async fn more_attachments_than_the_cap_are_422() {
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let body = body_with_attachments(&[
        ("a.png", "image/png", PNG),
        ("b.png", "image/png", PNG),
        ("c.png", "image/png", PNG),
    ]);
    let response = router(state)
        .oneshot(intake_request(&body, Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(stub.uploads.lock().expect("stub mutex").is_empty());
}

#[tokio::test]
async fn a_failed_upload_aborts_the_intake_instead_of_losing_the_file() {
    // The guest is told the screenshots get published: a topic without them
    // would be a silent loss, so the whole intake fails and they can retry.
    let (url, stub) = spawn_stub_with(Arc::new(StubState {
        uploads_fail: true,
        ..Default::default()
    }))
    .await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let body = body_with_attachments(&[("capture.png", "image/png", PNG)]);
    let response = router(state)
        .oneshot(intake_request(&body, Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        stub.calls.lock().expect("stub mutex").is_empty(),
        "no topic is created when an upload failed"
    );
}

#[tokio::test]
async fn a_body_declaring_an_over_cap_length_is_413_and_costs_no_slot() {
    // The form's fetch() always sets Content-Length, so this is the path a
    // real visitor who picked a too-big file takes: refused on the header
    // alone, nothing read, and they are not locked out of retrying.
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::new(3, 30, 3_600))));
    let app = router(state);

    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/help/intake")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.1")
                .header("content-length", (13 * 1024 * 1024).to_string())
                .body(Body::from(valid_body()))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::CREATED, "all slots intact");
    }
    assert_eq!(stub.calls.lock().expect("stub mutex").len(), 3);
}

#[tokio::test]
async fn an_over_cap_body_hiding_its_length_is_413_and_is_charged_a_slot() {
    // No declared length: the cap can only be found by starting to read, so
    // the sender pays for it. That is what stops an unlimited stream of
    // oversized bodies from being free.
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::new(3, 30, 3_600))));
    let app = router(state);

    let response = app
        .clone()
        .oneshot(intake_request(
            &body_with_attachments(&[("x.png", "image/png", &vec![0u8; 13 * 1024 * 1024])]),
            Some("203.0.113.1"),
        ))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(stub.uploads.lock().expect("stub mutex").is_empty());

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = app
        .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "exactly one slot was consumed by the oversized body"
    );
}

#[tokio::test]
async fn a_client_predating_the_feature_still_creates_a_topic() {
    // No `attachments` key at all: the field defaults, nothing is uploaded.
    let (url, stub) = spawn_stub().await;
    let state = test_state(Some(intake_state(&url, RateLimiter::default())));

    let response = router(state)
        .oneshot(intake_request(&valid_body(), Some("203.0.113.1")))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(stub.uploads.lock().expect("stub mutex").is_empty());
    let calls = stub.calls.lock().expect("stub mutex");
    assert!(
        !calls[0].body["raw"]
            .as_str()
            .expect("raw")
            .contains("upload://")
    );
}
