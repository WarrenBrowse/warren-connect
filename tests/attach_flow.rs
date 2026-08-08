//! Attach-logs flow through the real axum router, with Discourse stubbed by a
//! local axum server (topic fetch, upload, PM, whisper).

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt as _;

use warren_connect::attach::AttachStore;
use warren_connect::forum_api::ForumApi;
use warren_connect::handle;
use warren_connect::nonces::NonceStore;
use warren_connect::routes::{AppState, router};
use warren_connect::sessions::SessionStore;

use warren_contract::auth::{
    HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
};

const HANDLE_SECRET: &[u8] = b"a-test-handle-secret-32-bytes!!!";

#[derive(Debug)]
struct StubCall {
    op: String,
    body: String,
}

struct StubState {
    author: String,
    upload_ok: bool,
    /// Tags the topic already carries, echoed back by the topic endpoint.
    existing_tags: Vec<String>,
    calls: Mutex<Vec<StubCall>>,
}

async fn stub_topic(State(s): State<Arc<StubState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "title": "Connexion impossible",
        "details": { "created_by": { "username": s.author } },
        "post_stream": { "posts": [ { "username": s.author } ] },
        "tags": s.existing_tags,
    }))
}

/// Discourse's topic update, used here only to set tags.
async fn stub_topic_update(
    State(s): State<Arc<StubState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: "tag".into(),
        body: body.to_string(),
    });
    Json(serde_json::json!({ "basic_topic": { "id": 42 } }))
}

async fn stub_upload(
    State(s): State<Arc<StubState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !s.upload_ok {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: "upload".into(),
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    Ok(Json(serde_json::json!({
        "url": "/uploads/default/original/1X/stub.log",
        "short_url": "upload://stubshorturl.log",
    })))
}

async fn stub_posts(
    State(s): State<Arc<StubState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let op = if body.get("archetype").and_then(|v| v.as_str()) == Some("private_message") {
        // Both the staff PM and the reporter's receipt are private messages;
        // only the recipient tells them apart.
        if body.get("target_recipients").and_then(|v| v.as_str()) == Some("staff") {
            "pm"
        } else {
            "author_pm"
        }
    } else if body.get("whisper").and_then(|v| v.as_str()) == Some("true") {
        "whisper"
    } else {
        "reply"
    };
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: op.into(),
        body: body.to_string(),
    });
    Json(serde_json::json!({ "id": 100, "topic_id": 999 }))
}

async fn spawn_stub(author: &str, upload_ok: bool) -> (String, Arc<StubState>) {
    spawn_stub_tagged(author, upload_ok, Vec::new()).await
}

async fn spawn_stub_tagged(
    author: &str,
    upload_ok: bool,
    existing_tags: Vec<String>,
) -> (String, Arc<StubState>) {
    let state = Arc::new(StubState {
        author: author.to_owned(),
        upload_ok,
        existing_tags,
        calls: Mutex::new(Vec::new()),
    });
    let app = axum::Router::new()
        .route("/t/{topic_json}", get(stub_topic))
        .route("/t/-/{topic_id}", axum::routing::put(stub_topic_update))
        .route("/uploads.json", post(stub_upload))
        .route("/posts.json", post(stub_posts))
        // Applied after the routes, or it covers none of them. The stub stands
        // in for Discourse, which accepts far more than axum's 2 MiB default;
        // without this the stub, not the code under test, rejects a big report.
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024))
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

fn test_state(forum_api: Option<ForumApi>) -> Arc<AppState> {
    let lazy = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time");
    Arc::new(AppState {
        connect_secret: b"a-test-connect-secret-32-bytes!!".to_vec(),
        handle_secret: HANDLE_SECRET.to_vec(),
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
        forum_api,
        intake: None,
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn gz_b64(text: &str) -> String {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(text.as_bytes()).expect("gzip write");
    let gz = enc.finish().expect("gzip finish");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, gz)
}

fn signed_attach_request(key: &SigningKey, body: &str, nonce: [u8; 16]) -> Request<Body> {
    let s = sign_request(
        key,
        "POST",
        "/v1/forum/attach-logs",
        body.as_bytes(),
        now_unix(),
        nonce,
    );
    Request::post("/v1/forum/attach-logs")
        .header(HEADER_PUBKEY, s.pubkey_ss58)
        .header(HEADER_SIGNATURE, s.signature_hex)
        .header(HEADER_TIMESTAMP, s.timestamp.to_string())
        .header(HEADER_NONCE, s.nonce_hex)
        .body(Body::from(body.to_owned()))
        .expect("request")
}

fn author_username(key: &SigningKey) -> String {
    handle::derive(HANDLE_SECRET, &key.verifying_key().to_bytes()).username
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
async fn attach_page_renders_deep_link_and_poll() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let response = router(state.clone())
        .oneshot(
            Request::get("/attach?topic=42")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec(),
    )
    .expect("utf8");
    assert!(html.contains("warren://attach-logs?sid="));
    assert!(html.contains("&topic=42&host=connect.test"));

    // The embedded sid is a live pending session.
    let sid_start = html.find("warren://attach-logs?sid=").expect("link") + 25;
    let sid = &html[sid_start..sid_start + 32];
    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "pending"})
    );
}

#[tokio::test]
async fn attach_endpoints_are_503_without_api_key() {
    let state = test_state(None);
    for req in [
        Request::get("/attach?topic=1").body(Body::empty()),
        Request::get("/attach?sid=deadbeef").body(Body::empty()),
        Request::post("/v1/forum/attach-logs").body(Body::from("{}")),
        Request::post("/v1/attach/new").body(Body::empty()),
        Request::get("/v1/attach/deadbeef/meta").body(Body::empty()),
        Request::post("/v1/attach/deadbeef/bind").body(Body::from("{}")),
        Request::get("/v1/attach/deadbeef/status").body(Body::empty()),
        Request::post("/v1/attach/deadbeef/cancel").body(Body::empty()),
    ] {
        let response = router(state.clone())
            .oneshot(req.expect("request"))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[tokio::test]
async fn attach_logs_happy_path_uploads_pms_and_whispers() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 42,
        "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [1; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "attached"})
    );

    {
        let calls = stub.calls.lock().expect("stub mutex");
        let ops: Vec<&str> = calls.iter().map(|c| c.op.as_str()).collect();
        assert_eq!(ops, ["upload", "pm", "whisper", "author_pm", "tag"]);
        assert!(
            calls[0].body.contains("warren-report-topic42-"),
            "upload carries the report filename"
        );
        assert!(
            calls[0].body.contains("warren log line"),
            "upload carries the decompressed log"
        );
        assert!(calls[1].body.contains("upload://stubshorturl.log"));
        assert!(calls[1].body.contains("forum.warrenbrowse.com/t/42"));
        assert!(
            calls[2].body.contains("forum.warrenbrowse.com/t/999"),
            "whisper links the PM topic returned by Discourse"
        );
        assert!(calls[2].body.contains("\"whisper\":\"true\""));
    }

    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "done"})
    );
}

#[tokio::test]
async fn a_non_author_is_rejected_with_not_author() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub("someone-else", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 42,
        "log_gz_b64": gz_b64("log"),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [2; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"error": "not_author"})
    );
    assert!(
        stub.calls.lock().expect("stub mutex").is_empty(),
        "no Discourse write may happen for a non-author"
    );

    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "pending"})
    );
}

#[tokio::test]
async fn an_unknown_sid_is_not_found() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let body = serde_json::json!({
        "sid": "00000000000000000000000000000000",
        "topic_id": 42,
        "log_gz_b64": gz_b64("log"),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [3; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_topic_mismatch_is_not_found() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 43,
        "log_gz_b64": gz_b64("log"),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [4; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_oversized_b64_field_is_413() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = format!(
        r#"{{"sid":"{sid}","topic_id":42,"log_gz_b64":"{}"}}"#,
        // From the constant, not a frozen literal: a raised cap must not
        // quietly turn this guard into a test of nothing.
        "A".repeat(warren_connect::attach::MAX_LOG_GZ_B64_CHARS + 1)
    );
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [5; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

/// The three malformed-payload refusals (bad base64, bad gzip, non-UTF-8
/// content) all answer 400 without touching Discourse. They are refusals the
/// reporter sees as a generic failure, so the handler traces each branch;
/// these tests pin that the wire contract stays a plain 400 while it does.
#[tokio::test]
async fn a_malformed_payload_is_400_and_never_reaches_discourse() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let bad_gzip = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"not a gzip stream",
    );
    let non_utf8 = {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&[0xff, 0xfe, 0x80, 0x00])
            .expect("gzip write");
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            enc.finish().expect("gzip finish"),
        )
    };
    for (nonce, log_gz_b64) in [
        ([20u8; 16], "%%%not-base64%%%".to_owned()),
        ([21u8; 16], bad_gzip),
        ([22u8; 16], non_utf8),
    ] {
        let sid = state.attach.create(42, now_unix()).expect("create");
        let body = format!(r#"{{"sid":"{sid}","topic_id":42,"log_gz_b64":"{log_gz_b64}"}}"#);
        let response = router(state.clone())
            .oneshot(signed_attach_request(&key, &body, nonce))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

#[tokio::test]
async fn garbage_headers_are_unauthorized() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let response = router(state)
        .oneshot(
            Request::post("/v1/forum/attach-logs")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cancel_marks_the_session_cancelled() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let response = router(state.clone())
        .oneshot(
            Request::post(format!("/v1/attach/{sid}/cancel"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "cancelled", "reason": "user_cancelled"})
    );
}

const REPORT: &str = "System information:\nos: macOS 15.5\nwarren-product-version: 2026.5-beta1\n\n==== warren.log ====\nwarren log line\n";

const FORUM_ORIGIN: &str = "https://forum.warrenbrowse.com";

async fn new_pre_sid(state: Arc<warren_connect::routes::AppState>) -> String {
    let response = router(state)
        .oneshot(
            Request::post("/v1/attach/new")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let sid = json["sid"].as_str().expect("sid string").to_owned();
    assert_eq!(sid.len(), 32);
    sid
}

fn bind_request(sid: &str, topic_id: u64) -> Request<Body> {
    Request::post(format!("/v1/attach/{sid}/bind"))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"topic_id":{topic_id}}}"#)))
        .expect("request")
}

#[tokio::test]
async fn pre_mode_happy_path_receives_then_binds() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let sid = new_pre_sid(state.clone()).await;

    // The pre-topic attach page reuses the session and deep-links topic 0.
    let response = router(state.clone())
        .oneshot(
            Request::get(format!("/attach?sid={sid}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec(),
    )
    .expect("utf8");
    assert!(html.contains(&format!(
        "warren://attach-logs?sid={sid}&topic=0&host=connect.test"
    )));

    // Before the app delivers: meta is pending, no Discourse write happened.
    let response = router(state.clone())
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/meta"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "pending"})
    );

    // The app's signed upload with topic_id 0 parks the report.
    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 0,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [10; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "received"})
    );
    assert!(
        stub.calls.lock().expect("stub mutex").is_empty(),
        "no Discourse write before the bind"
    );

    // Meta now carries the parsed report metadata; status says received.
    let response = router(state.clone())
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/meta"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({
            "status": "received",
            "version": "2026.5-beta1",
            "os": "macOS 15.5",
        })
    );
    let response = router(state.clone())
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "received"})
    );

    // Bind to the freshly created topic: author check + the three writes.
    let response = router(state.clone())
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "attached"})
    );
    {
        let calls = stub.calls.lock().expect("stub mutex");
        let ops: Vec<&str> = calls.iter().map(|c| c.op.as_str()).collect();
        assert_eq!(
            ops,
            ["upload", "pm", "whisper", "reply", "author_pm", "tag"],
            "the pre-mode REPORT carries metadata, so the public note follows"
        );
        assert!(calls[0].body.contains("warren-report-topic42-"));
        assert!(calls[0].body.contains("warren log line"));
        assert!(calls[1].body.contains("upload://stubshorturl.log"));
        assert!(calls[2].body.contains("forum.warrenbrowse.com/t/999"));
        // Values are markdown-escaped in the note; assert on chars that survive.
        assert!(calls[3].body.contains("2026") && calls[3].body.contains("beta1"));
    }

    let response = router(state.clone())
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "done"})
    );

    // Single use: a second bind is gone.
    let response = router(state)
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bind_before_the_app_delivered_is_409_no_log() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    let response = router(state)
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"error": "no_log"})
    );
    assert!(stub.calls.lock().expect("stub mutex").is_empty());
}

#[tokio::test]
async fn bind_by_a_non_author_is_403_and_stays_received() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub("someone-else", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 0,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [11; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router(state.clone())
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"error": "not_author"})
    );
    let writes: Vec<String> = stub
        .calls
        .lock()
        .expect("stub mutex")
        .iter()
        .map(|c| c.op.clone())
        .collect();
    assert!(writes.is_empty(), "author check precedes every write");

    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "received"})
    );
}

#[tokio::test]
async fn bind_discourse_failure_is_502_and_stays_received() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), false).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 0,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [12; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router(state.clone())
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "received"}),
        "a failed bind must stay retryable"
    );
}

#[tokio::test]
async fn bind_topic_zero_is_400_and_unknown_sid_404() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    let response = router(state.clone())
        .oneshot(bind_request(&sid, 0))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router(state)
        .oneshot(bind_request("00000000000000000000000000000000", 42))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_pre_session_refuses_a_nonzero_topic_upload() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 42,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [13; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_topic_session_refuses_topic_zero() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 0,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [14; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unknown_pre_sid_page_is_404() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let response = router(state)
        .oneshot(
            Request::get("/attach?sid=00000000000000000000000000000000")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn attach_api_answers_cors_for_the_forum_origin_only() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    // Preflight from the forum origin.
    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/attach/new")
                .header("origin", FORUM_ORIGIN)
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "content-type")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let allow_origin = response
        .headers()
        .get("access-control-allow-origin")
        .expect("preflight must allow the forum origin");
    assert_eq!(allow_origin, FORUM_ORIGIN);
    let allow_methods = response
        .headers()
        .get("access-control-allow-methods")
        .expect("methods advertised")
        .to_str()
        .expect("ascii");
    assert!(allow_methods.contains("POST"));
    assert!(allow_methods.contains("GET"));
    assert!(
        response
            .headers()
            .get("access-control-allow-headers")
            .expect("headers advertised")
            .to_str()
            .expect("ascii")
            .to_ascii_lowercase()
            .contains("content-type")
    );

    // Actual request from the forum origin carries the header too.
    let response = router(state.clone())
        .oneshot(
            Request::post("/v1/attach/new")
                .header("origin", FORUM_ORIGIN)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("allowed origin echoed"),
        FORUM_ORIGIN
    );

    // A foreign origin gets no CORS grant.
    let response = router(state.clone())
        .oneshot(
            Request::post("/v1/attach/new")
                .header("origin", "https://evil.example")
                .body(Body::empty())
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

    // Non-CORS routes stay CORS-free even for the forum origin.
    let response = router(state)
        .oneshot(
            Request::post("/v1/forum/attach-logs")
                .header("origin", FORUM_ORIGIN)
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "the signed app endpoint is not a browser surface"
    );
}

#[tokio::test]
async fn a_discourse_write_failure_leaves_the_session_retryable() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), false).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 42,
        "log_gz_b64": gz_b64("log"),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [6; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "pending"}),
        "a failed Discourse write must not consume the session"
    );
}

#[tokio::test]
async fn attach_with_metadata_posts_a_public_note_after_the_whisper() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 42,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [1; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    let ops: Vec<&str> = calls.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(
        ops,
        ["upload", "pm", "whisper", "reply", "author_pm", "tag"],
        "a report carrying metadata must add one public reply"
    );
    let reply = &calls[3].body;
    assert!(reply.contains("beta1"), "public note names the version");
    assert!(reply.contains("macOS"), "public note names the os");
    assert!(
        !reply.contains("warren log line"),
        "the log content itself must never reach the public note"
    );
    assert!(
        !reply.contains("\"whisper\""),
        "the note is a plain public reply"
    );
}

#[tokio::test]
async fn attach_without_metadata_posts_no_public_note() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 42,
        "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [1; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    let ops: Vec<&str> = calls.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(
        ops,
        ["upload", "pm", "whisper", "author_pm", "tag"],
        "nothing public to say"
    );
}

#[tokio::test]
async fn tagging_preserves_the_tags_the_topic_already_carries() {
    // Discourse's topic update REPLACES the tag list, so appending has to send
    // the existing ones back. Losing a reporter's "android" tag just to record
    // that logs arrived would be a bad trade.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (url, stub) = spawn_stub_tagged(
        &author_username(&key),
        true,
        vec!["android".into(), "wallet".into()],
    )
    .await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");
    let body = serde_json::json!({
        "sid": sid, "topic_id": 42, "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [21; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    let tag_call = calls.iter().find(|c| c.op == "tag").expect("topic tagged");
    let sent: serde_json::Value = serde_json::from_str(&tag_call.body).expect("json");
    let tags: Vec<String> = sent["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(tags.contains(&"android".to_owned()), "{tags:?}");
    assert!(tags.contains(&"wallet".to_owned()), "{tags:?}");
    assert!(tags.contains(&"logs-attached".to_owned()), "{tags:?}");
}

#[tokio::test]
async fn a_second_log_version_does_not_rewrite_the_tags() {
    // Re-attaching is explicitly allowed (a reporter may send a newer log) and
    // the tag is already there on that second pass: no topic write at all,
    // while the logs themselves still reach the staff.
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let (url, stub) =
        spawn_stub_tagged(&author_username(&key), true, vec!["logs-attached".into()]).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");
    let body = serde_json::json!({
        "sid": sid, "topic_id": 42, "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [22; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    assert!(
        calls.iter().all(|c| c.op != "tag"),
        "already tagged, nothing to write: {:?}",
        calls.iter().map(|c| &c.op).collect::<Vec<_>>()
    );
    assert!(
        calls.iter().any(|c| c.op == "upload"),
        "the logs themselves still go through"
    );
}

#[tokio::test]
async fn the_reporter_gets_a_private_receipt_naming_their_topic() {
    // The public topic shows no trace of the logs and the whisper is
    // staff-only, so this PM is the only way the author learns their upload
    // landed. It must go to them, not to the staff group.
    let key = SigningKey::from_bytes(&[13u8; 32]);
    let author = author_username(&key);
    let (url, stub) = spawn_stub(&author, true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");
    let body = serde_json::json!({
        "sid": sid, "topic_id": 42, "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [31; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    let receipt = calls
        .iter()
        .find(|c| c.op == "author_pm")
        .expect("the reporter is told");
    let sent: serde_json::Value = serde_json::from_str(&receipt.body).expect("json");
    assert_eq!(sent["target_recipients"].as_str(), Some(author.as_str()));
    let raw = sent["raw"].as_str().expect("raw");
    assert!(raw.contains("/t/42"), "links back to the topic: {raw}");
    assert!(
        raw.contains("uniquement par l\u{2019}\u{e9}quipe support")
            || raw.contains("uniquement par l'\u{e9}quipe support"),
        "states the logs stay private: {raw}"
    );
}

#[tokio::test]
async fn a_report_far_larger_than_the_old_ceiling_is_accepted() {
    // The route used to inherit axum's 2 MiB default, which capped reports
    // regardless of what the documented constants said. A body well past it
    // must now go through.
    let key = SigningKey::from_bytes(&[17u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = state.attach.create(42, now_unix()).expect("create");

    // ~12 MiB of realistic, repetitive log text: past the old 2 MiB body
    // ceiling once base64'd, and past the old 8 MiB decompressed cap.
    let line = "[2026-07-28 08:20:05.121]  INFO warrenguard_transport_core::path_probe: path probe                 probe=\"client-mh\" conn=0 cwnd=75548 rtt_ms=44.9 mtu=1452\n";
    let big: String = line.repeat(12 * 1024 * 1024 / line.len());
    assert!(big.len() > 8 * 1024 * 1024, "past the old decompressed cap");
    let body = serde_json::json!({
        "sid": sid, "topic_id": 42, "log_gz_b64": gz_b64(&big),
    })
    .to_string();

    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [41; 16]))
        .await
        .expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the report must go through"
    );
    let calls = stub.calls.lock().expect("stub mutex");
    let upload = calls.iter().find(|c| c.op == "upload").expect("uploaded");
    assert!(
        upload.body.len() > 8 * 1024 * 1024,
        "the whole log reached Discourse, not a truncated head"
    );
}
