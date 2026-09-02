//! The in-app bug report route against a stub Discourse: the account is
//! synced, the log is uploaded before anything public exists, the topic is
//! created as the reporter with the platform tag, and the staff is notified
//! exactly the way attach-logs notifies it.

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use warren_connect::attach::AttachStore;
use warren_connect::forum_api::ForumApi;
use warren_connect::handle;
use warren_connect::intake::RateLimiter;
use warren_connect::nonces::NonceStore;
use warren_connect::routes::{AppState, ReportState};
use warren_connect::sessions::SessionStore;
use warren_connect::store::{IdentityStore, MemoryIdentity, SubscriptionStatus};
use warren_contract::auth::{
    HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
};

const HANDLE_SECRET: &[u8] = b"a-test-handle-secret-32-bytes!!!";
const CONNECT_SECRET: &[u8] = b"a-test-connect-secret-32-bytes!!";

#[derive(Debug)]
struct StubCall {
    op: String,
    api_username: String,
    body: serde_json::Value,
}

#[derive(Default)]
struct StubState {
    calls: Mutex<Vec<StubCall>>,
    /// Makes `sync_sso` answer with this username instead of the one in the
    /// payload, as a suffixed collision would.
    sync_username_override: Option<String>,
    /// Makes the upload answer 422.
    upload_fails: bool,
    /// Makes the topic creation answer 500.
    topic_fails: bool,
    /// Makes the whisper answer 500, after the topic exists.
    whisper_fails: bool,
}

fn api_username(headers: &HeaderMap) -> String {
    headers
        .get("Api-Username")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

async fn stub_sync_sso(
    State(s): State<Arc<StubState>>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    // Form-encoded `sso=<b64>&sig=<hex>`; the stub reads the username back
    // out of the payload the way Discourse would settle on it.
    let fields: Vec<(String, String)> = serde_urlencoded::from_str(&body).expect("form body");
    let sso = fields
        .iter()
        .find(|(k, _)| k == "sso")
        .map(|(_, v)| v.clone())
        .expect("sso field");
    let raw =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sso).expect("b64");
    let payload: Vec<(String, String)> = serde_urlencoded::from_bytes(&raw).expect("payload");
    let username = payload
        .iter()
        .find(|(k, _)| k == "username")
        .map(|(_, v)| v.clone())
        .expect("username in payload");
    let has_nonce = payload.iter().any(|(k, _)| k == "nonce");
    let admin = payload.iter().any(|(k, _)| k == "admin");
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: "sync_sso".into(),
        api_username: api_username(&headers),
        body: serde_json::json!({"username": username, "has_nonce": has_nonce, "admin": admin}),
    });
    let settled = s.sync_username_override.clone().unwrap_or(username);
    Json(serde_json::json!({"id": 77, "username": settled, "admin": false})).into_response()
}

async fn stub_upload(
    State(s): State<Arc<StubState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let text = String::from_utf8_lossy(&body).into_owned();
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: "upload".into(),
        api_username: api_username(&headers),
        body: serde_json::json!({"contains_report": text.contains("System information:")}),
    });
    if s.upload_fails {
        return (StatusCode::UNPROCESSABLE_ENTITY, "rejected").into_response();
    }
    Json(serde_json::json!({"short_url": "upload://report.log"})).into_response()
}

async fn stub_posts(
    State(s): State<Arc<StubState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let op = if body.get("archetype").and_then(|v| v.as_str()) == Some("private_message") {
        if body.get("target_recipients").and_then(|v| v.as_str()) == Some("staff") {
            "pm"
        } else {
            "author_pm"
        }
    } else if body.get("whisper").and_then(|v| v.as_str()) == Some("true") {
        "whisper"
    } else if body.get("category").is_some() {
        "topic_create"
    } else {
        "reply"
    };
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: op.into(),
        api_username: api_username(&headers),
        body: body.clone(),
    });
    if op == "topic_create" && s.topic_fails {
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    if op == "whisper" && s.whisper_fails {
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    let topic_id = if op == "topic_create" { 4242 } else { 999 };
    Json(serde_json::json!({"id": 100, "topic_id": topic_id, "post_number": 2})).into_response()
}

async fn stub_topic_update(
    State(s): State<Arc<StubState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    s.calls.lock().expect("stub mutex").push(StubCall {
        op: "tag".into(),
        api_username: api_username(&headers),
        body,
    });
    Json(serde_json::json!({"basic_topic": {"id": 4242}}))
}

async fn spawn_stub(state: Arc<StubState>) -> String {
    let app = axum::Router::new()
        .route("/admin/users/sync_sso", post(stub_sync_sso))
        .route("/uploads.json", post(stub_upload))
        .route("/posts.json", post(stub_posts))
        .route("/t/-/{topic_id}", axum::routing::put(stub_topic_update))
        .route("/t/{topic_json}", get(|| async { StatusCode::NOT_FOUND }))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serves");
    });
    format!("http://{addr}")
}

/// A state whose identity store knows `paid` as an ever-paid wallet.
fn test_state(
    stub_url: Option<&str>,
    paid: Option<&SigningKey>,
    per_wallet: usize,
) -> Arc<AppState> {
    let lazy = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time");
    let memory = MemoryIdentity::default();
    if let Some(key) = paid {
        let ss58 = warren_contract::ss58::encode(&key.verifying_key().to_bytes());
        memory.subscriptions.lock().expect("mutex").insert(
            ss58,
            SubscriptionStatus {
                ever_paid: true,
                active: true,
                expires_at_unix: Some(4_102_444_800),
            },
        );
    }
    let (forum_api, report) = match stub_url {
        Some(url) => (
            Some(ForumApi::new(
                url,
                "system-key".into(),
                "system".into(),
                "staff".into(),
            )),
            Some(ReportState {
                topic_api: ForumApi::new(url, "report-key".into(), "system".into(), "staff".into()),
                category_id: 13,
                limiter: RateLimiter::new(per_wallet, 20, 3_600),
                decode_failures: RateLimiter::new(3, 20, 3_600),
            }),
        ),
        None => (None, None),
    };
    Arc::new(AppState {
        connect_secret: CONNECT_SECRET.to_vec(),
        handle_secret: HANDLE_SECRET.to_vec(),
        public_host: "connect.test".into(),
        internal_token: String::new(),
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
        forum_api,
        intake: None,
        report,
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

fn signed_report(key: &SigningKey, body: &str, nonce: [u8; 16], timestamp: u64) -> Request<Body> {
    let s = sign_request(
        key,
        "POST",
        "/v1/forum/report",
        body.as_bytes(),
        timestamp,
        nonce,
    );
    Request::post("/v1/forum/report")
        .header(HEADER_PUBKEY, s.pubkey_ss58)
        .header(HEADER_SIGNATURE, s.signature_hex)
        .header(HEADER_TIMESTAMP, s.timestamp.to_string())
        .header(HEADER_NONCE, s.nonce_hex)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

fn report_body(log: Option<&str>) -> String {
    let mut v = serde_json::json!({
        "platform": "android",
        "area": "other",
        "frequency": "always",
        "what_happened": "The forum sign-in button in Firefox does nothing at all.",
        "steps": "Open the forum\nTap Log in\nTap the button",
        "app_version": "1.1.20",
        "os_version": "Android 15 (API 35)",
        "locale": "fr",
    });
    if let Some(text) = log {
        v["log_gz_b64"] = serde_json::Value::String(gz_b64(text));
    }
    v.to_string()
}

const REPORT: &str = "System information:\nid: 1\nos: Android 15 (API 35)\nwarren-product-version: 1.1.20\n\n====\nLog: app\n====\nhello\n";

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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

fn ops(stub: &StubState) -> Vec<String> {
    stub.calls
        .lock()
        .expect("stub mutex")
        .iter()
        .map(|c| c.op.clone())
        .collect()
}

#[tokio::test]
async fn a_report_with_logs_syncs_uploads_creates_the_topic_as_the_reporter_and_notifies_staff() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(1);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(Some(REPORT)),
            [1; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    let handle = handle::derive(HANDLE_SECRET, &key.verifying_key().to_bytes()).username;
    assert_eq!(body["status"], "created");
    assert_eq!(body["topic_id"], 4242);
    assert_eq!(body["topic_url"], "https://forum.warrenbrowse.com/t/4242");
    assert_eq!(body["handle"], handle);
    assert!(
        body["notify_slot"].is_u64(),
        "the slot is drawn at report time: {body}"
    );
    assert_eq!(body["logs"], "attached");

    // Nothing public exists before the account and the upload succeeded, and
    // the staff writes are the attach-logs sequence, in its order.
    assert_eq!(
        ops(&stub),
        vec![
            "sync_sso",
            "upload",
            "topic_create",
            "pm",
            "whisper",
            "reply",
            "author_pm",
            "tag"
        ]
    );
    let calls = stub.calls.lock().expect("stub mutex");
    let sync = &calls[0];
    assert_eq!(sync.body["username"], handle);
    assert_eq!(sync.body["has_nonce"], false, "sync_sso checks no nonce");
    assert_eq!(sync.body["admin"], false, "a report never asserts staff");
    let upload = &calls[1];
    assert_eq!(upload.body["contains_report"], true);
    let topic = &calls[2];
    assert_eq!(
        topic.api_username, handle,
        "the topic is the reporter's own"
    );
    assert_eq!(topic.body["category"], 13);
    assert_eq!(topic.body["tags"], serde_json::json!(["android"]));
    let title = topic.body["title"].as_str().expect("title");
    assert!(title.starts_with("[Android] Other: "), "{title}");
    let raw = topic.body["raw"].as_str().expect("raw");
    assert!(raw.contains("### Your device\nandroid"));
    assert!(raw.contains("> Open the forum"));
    let pm = &calls[3];
    assert_eq!(
        pm.api_username, "system",
        "the staff PM comes from the system account"
    );
    assert!(
        pm.body["raw"]
            .as_str()
            .expect("pm raw")
            .contains(&format!("@{handle}"))
    );
    assert!(
        pm.body["raw"]
            .as_str()
            .expect("pm raw")
            .contains("upload://report.log")
    );
    let whisper = &calls[4];
    assert_eq!(whisper.body["topic_id"], 4242);
    let note = &calls[5];
    let note_raw = note.body["raw"].as_str().expect("note raw");
    assert!(
        note_raw.contains("1\\.1\\.20"),
        "the public note carries the version: {note_raw}"
    );
    let author_pm = &calls[6];
    assert_eq!(author_pm.body["target_recipients"], handle);
    let tag = &calls[7];
    assert_eq!(
        tag.body["tags"],
        serde_json::json!(["android", "logs-attached"]),
        "the platform tag survives the logs-attached update"
    );
}

#[tokio::test]
async fn a_report_without_logs_creates_only_the_topic() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(2);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(&key, &report_body(None), [2; 16], now_unix()))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    assert_eq!(body["logs"], "none");
    assert_eq!(ops(&stub), vec!["sync_sso", "topic_create"]);
}

#[tokio::test]
async fn a_never_paid_wallet_is_refused_before_any_forum_write() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(3);
    let state = test_state(Some(&url), None, 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(&key, &report_body(None), [3; 16], now_unix()))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        ops(&stub).is_empty(),
        "no Discourse call for a refused wallet"
    );
}

#[tokio::test]
async fn a_malformed_report_is_422_with_its_token_and_costs_no_forum_call() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(4);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state.clone());

    let short = serde_json::json!({
        "platform": "android", "area": "other", "frequency": "always",
        "what_happened": "too short"
    })
    .to_string();
    let response = app
        .oneshot(signed_report(&key, &short, [4; 16], now_unix()))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body_json(response).await["error"], "invalid_report");

    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(&key, "not json", [5; 16], now_unix()))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(ops(&stub).is_empty());
}

#[tokio::test]
async fn a_clock_outside_the_window_is_refused_with_the_frozen_token() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(5);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [6; 16],
            now_unix() - 120,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "clock_skew");
    assert!(ops(&stub).is_empty());
}

#[tokio::test]
async fn the_fourth_report_of_a_wallet_in_the_window_is_rate_limited() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(6);
    let other = signer(7);
    let state = test_state(Some(&url), Some(&key), 3);
    state
        .identity
        .subscription_status("")
        .await
        .expect("memory store never fails");
    if let IdentityStore::Memory(m) = &state.identity {
        m.subscriptions.lock().expect("mutex").insert(
            warren_contract::ss58::encode(&other.verifying_key().to_bytes()),
            SubscriptionStatus {
                ever_paid: true,
                active: false,
                expires_at_unix: Some(1),
            },
        );
    }

    for n in 0..3u8 {
        let app = warren_connect::routes::router(state.clone());
        let response = app
            .oneshot(signed_report(
                &key,
                &report_body(None),
                [10 + n; 16],
                now_unix(),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "report {n} admitted"
        );
    }
    let app = warren_connect::routes::router(state.clone());
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [20; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // The budget is per wallet: another member is still admitted.
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &other,
            &report_body(None),
            [21; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        ops(&stub).iter().filter(|op| *op == "topic_create").count(),
        4
    );
}

#[tokio::test]
async fn a_forum_that_settles_on_another_username_gets_no_topic() {
    let stub = Arc::new(StubState {
        sync_username_override: Some("lusab-babad-dovok1".into()),
        ..Default::default()
    });
    let url = spawn_stub(stub.clone()).await;
    let key = signer(8);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(Some(REPORT)),
            [8; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        ops(&stub),
        vec!["sync_sso"],
        "nothing uploaded, nothing created"
    );
}

#[tokio::test]
async fn a_failed_upload_creates_no_topic_and_a_failed_topic_is_a_502() {
    let stub = Arc::new(StubState {
        upload_fails: true,
        ..Default::default()
    });
    let url = spawn_stub(stub.clone()).await;
    let key = signer(9);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(Some(REPORT)),
            [9; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(ops(&stub), vec!["sync_sso", "upload"]);

    let stub = Arc::new(StubState {
        topic_fails: true,
        ..Default::default()
    });
    let url = spawn_stub(stub.clone()).await;
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [19; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(ops(&stub), vec!["sync_sso", "topic_create"]);
}

#[tokio::test]
async fn a_staff_write_failing_after_the_topic_exists_is_reported_as_partial() {
    let stub = Arc::new(StubState {
        whisper_fails: true,
        ..Default::default()
    });
    let url = spawn_stub(stub.clone()).await;
    let key = signer(10);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(Some(REPORT)),
            [11; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "the topic exists, so the client must not retry into a duplicate"
    );
    assert_eq!(body_json(response).await["logs"], "partial");
    assert_eq!(
        ops(&stub),
        vec!["sync_sso", "upload", "topic_create", "pm", "whisper"]
    );
}

#[tokio::test]
async fn the_route_answers_503_when_not_configured() {
    let key = signer(12);
    let state = test_state(None, Some(&key), 3);
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [12; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_replayed_nonce_is_refused() {
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(13);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state.clone());
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [13; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [13; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(ops(&stub).len(), 2, "the replay reached no forum write");
}

/// A `log_gz_b64` that is valid base64 of something that is not a gzip
/// stream: the JSON shape is fine, so the only thing that can refuse it is
/// the decoder.
fn corrupt_report_body() -> String {
    let mut v: serde_json::Value = serde_json::from_str(&report_body(None)).expect("report json");
    v["log_gz_b64"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"this is not a gzip stream",
    ));
    v.to_string()
}

#[tokio::test]
async fn a_never_paid_wallet_with_a_corrupt_log_is_refused_by_the_gate_not_the_decoder() {
    // Inflating a log is the most expensive thing this handler does before
    // its first Discourse call (up to 32 MiB per request), and a wallet is
    // free to mint. The gate has to answer before any of that work, or a
    // never-paid wallet buys the server's CPU for the price of a signature.
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(30);
    let state = test_state(Some(&url), None, 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(
            &key,
            &corrupt_report_body(),
            [30; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the subscription gate answers, not the decoder"
    );
    assert!(
        ops(&stub).is_empty(),
        "no Discourse call for a refused wallet"
    );
}

#[tokio::test]
async fn a_rate_limited_wallet_with_a_corrupt_log_is_refused_by_the_budget_not_the_decoder() {
    // Same order one step further: a member who is out of budget pays no
    // inflate either, so the per-wallet budget bounds the decode work too.
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(31);
    let state = test_state(Some(&url), Some(&key), 3);

    for n in 0..3u8 {
        let app = warren_connect::routes::router(state.clone());
        let response = app
            .oneshot(signed_report(
                &key,
                &report_body(None),
                [40 + n; 16],
                now_unix(),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "report {n} admitted"
        );
    }
    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &corrupt_report_body(),
            [50; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the budget answers, not the decoder"
    );
    assert_eq!(
        ops(&stub).iter().filter(|op| *op == "topic_create").count(),
        3,
        "the refused report reached the forum no more than the admitted ones"
    );
}

#[tokio::test]
async fn a_corrupt_log_from_an_admitted_member_costs_no_forum_write() {
    // The decode sits past the gate and the budget, and still before the
    // first Discourse call: a broken payload is refused with nothing created.
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(32);
    let state = test_state(Some(&url), Some(&key), 3);
    let app = warren_connect::routes::router(state);

    let response = app
        .oneshot(signed_report(
            &key,
            &corrupt_report_body(),
            [60; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        ops(&stub).is_empty(),
        "nothing reaches Discourse for a corrupt log"
    );
}

#[tokio::test]
async fn a_refused_decode_hands_the_topic_slot_back_so_a_log_free_report_still_files() {
    // The decode is charged to the wallet's topic budget before it runs, so
    // the budget bounds the inflate work; a payload that does not decode
    // creates nothing, so it must hand the slot back. This endpoint is the
    // only channel of the user who cannot sign in: a corrupt log must not
    // lock their log-free report out for the rest of the hour.
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(33);
    let state = test_state(Some(&url), Some(&key), 1);

    let app = warren_connect::routes::router(state.clone());
    let response = app
        .oneshot(signed_report(
            &key,
            &corrupt_report_body(),
            [70; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let app = warren_connect::routes::router(state);
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(None),
            [71; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "the refused decode left the wallet's only topic slot free"
    );
    assert_eq!(
        ops(&stub).iter().filter(|op| *op == "topic_create").count(),
        1
    );
}

#[tokio::test]
async fn the_fourth_failed_decode_of_a_wallet_is_refused_by_its_own_budget() {
    // The refund above must not turn the inflate into free work: failed
    // decodes have a budget of their own (3 per wallet per hour here), past
    // which a log-bearing report is refused before anything is inflated,
    // while a log-free report from the same wallet still files.
    let stub = Arc::new(StubState::default());
    let url = spawn_stub(stub.clone()).await;
    let key = signer(34);
    let state = test_state(Some(&url), Some(&key), 3);

    for n in 0..3u8 {
        let app = warren_connect::routes::router(state.clone());
        let response = app
            .oneshot(signed_report(
                &key,
                &corrupt_report_body(),
                [80 + n; 16],
                now_unix(),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "failed decode {n} is answered by the decoder"
        );
    }
    let app = warren_connect::routes::router(state.clone());
    let response = app
        .oneshot(signed_report(
            &key,
            &corrupt_report_body(),
            [90; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the decode budget answers before the decoder"
    );
    let app = warren_connect::routes::router(state.clone());
    let response = app
        .oneshot(signed_report(
            &key,
            &report_body(Some(REPORT)),
            [91; 16],
            now_unix(),
        ))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a valid log is not inflated either once the decode budget is spent"
    );
    assert!(
        ops(&stub).is_empty(),
        "nothing reached Discourse while every attempt was refused"
    );

    for n in 0..3u8 {
        let app = warren_connect::routes::router(state.clone());
        let response = app
            .oneshot(signed_report(
                &key,
                &report_body(None),
                [100 + n; 16],
                now_unix(),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "log-free report {n} still files: no refused attempt spent a topic slot"
        );
    }
    assert_eq!(
        ops(&stub).iter().filter(|op| *op == "topic_create").count(),
        3
    );
}
