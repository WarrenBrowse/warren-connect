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
use warren_connect::routes::{ATTACH_COOKIE, AppState, router};
use warren_connect::sessions::{BrowserKey, BrowserSecret, SessionStore};
use warren_connect::store::IdentityStore;

mod forum_vector;
use forum_vector::{assert_answer, assert_signed_by_the_contract, observe, verify_at_vector_clock};
use warren_contract::auth::{
    HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request,
};

const HANDLE_SECRET: &[u8] = b"a-test-handle-secret-32-bytes!!!";

/// A point where a stub endpoint stops until the test releases it, so the
/// test acts while a request is provably inside that call.
#[derive(Default)]
struct Gate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Gate {
    async fn pass(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

#[derive(Debug)]
struct StubCall {
    op: String,
    body: String,
}

struct StubState {
    author: String,
    /// Topics authored by somebody other than `author`.
    other_authors: Mutex<std::collections::HashMap<u64, String>>,
    /// How long the topic endpoint takes to answer, so requests overlap.
    topic_delay: Mutex<Option<std::time::Duration>>,
    /// Holds the topic fetch until the test lets it go.
    topic_gate: Mutex<Option<Arc<Gate>>>,
    /// Holds the upload until the test lets it go.
    upload_gate: Mutex<Option<Arc<Gate>>>,
    upload_ok: bool,
    /// Tags the topic already carries, echoed back by the topic endpoint.
    existing_tags: Vec<String>,
    /// Serialize those tags the way Discourse 2026.7 does, as `{id, name,
    /// slug}` objects, rather than as the bare names older releases sent.
    tags_as_objects: bool,
    calls: Mutex<Vec<StubCall>>,
    /// Topic fetches that reached the stub.
    topic_fetches: std::sync::atomic::AtomicUsize,
}

async fn stub_topic(
    State(s): State<Arc<StubState>>,
    axum::extract::Path(topic_json): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    s.topic_fetches
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let delay = *s.topic_delay.lock().expect("stub mutex");
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    }
    let gate = s.topic_gate.lock().expect("stub mutex").clone();
    if let Some(gate) = gate {
        gate.pass().await;
    }
    let topic: u64 = topic_json
        .trim_end_matches(".json")
        .parse()
        .unwrap_or_default();
    let author = s
        .other_authors
        .lock()
        .expect("stub mutex")
        .get(&topic)
        .cloned()
        .unwrap_or_else(|| s.author.clone());
    let tags = if s.tags_as_objects {
        s.existing_tags
            .iter()
            .enumerate()
            .map(|(i, name)| serde_json::json!({"id": i + 1, "name": name, "slug": name}))
            .collect::<Vec<_>>()
    } else {
        s.existing_tags
            .iter()
            .map(|name| serde_json::json!(name))
            .collect::<Vec<_>>()
    };
    Json(serde_json::json!({
        "title": "[macOS] Connection: cannot connect after update #a1b2c3",
        "details": { "created_by": { "username": author } },
        "post_stream": { "posts": [ { "username": author } ] },
        "tags": tags,
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
    let gate = s.upload_gate.lock().expect("stub mutex").clone();
    if let Some(gate) = gate {
        gate.pass().await;
    }
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

/// Default stub: the tag shape the LIVE forum sends. A stub that kept speaking
/// the older dialect is what let this suite stay green while every attach on a
/// tagged topic failed in production.
async fn spawn_stub_tagged(
    author: &str,
    upload_ok: bool,
    existing_tags: Vec<String>,
) -> (String, Arc<StubState>) {
    spawn_stub_with_tag_shape(author, upload_ok, existing_tags, true).await
}

async fn spawn_stub_with_tag_shape(
    author: &str,
    upload_ok: bool,
    existing_tags: Vec<String>,
    tags_as_objects: bool,
) -> (String, Arc<StubState>) {
    let state = Arc::new(StubState {
        author: author.to_owned(),
        other_authors: Mutex::new(std::collections::HashMap::new()),
        topic_delay: Mutex::new(None),
        topic_gate: Mutex::new(None),
        upload_gate: Mutex::new(None),
        upload_ok,
        existing_tags,
        tags_as_objects,
        calls: Mutex::new(Vec::new()),
        topic_fetches: std::sync::atomic::AtomicUsize::new(0),
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

/// A pool that never reaches a database, and gives up on it quickly.
fn unreachable_pool() -> sqlx::PgPool {
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool never dials at build time")
}

fn test_state(forum_api: Option<ForumApi>) -> Arc<AppState> {
    test_state_with_identity(forum_api, IdentityStore::Memory(Box::default()))
}

fn test_state_with_identity(forum_api: Option<ForumApi>, identity: IdentityStore) -> Arc<AppState> {
    build_state(forum_api, identity, NonceStore::default())
}

fn build_state(
    forum_api: Option<ForumApi>,
    identity: IdentityStore,
    nonces: NonceStore,
) -> Arc<AppState> {
    let lazy = unreachable_pool();
    Arc::new(AppState {
        connect_secret: b"a-test-connect-secret-32-bytes!!".to_vec(),
        handle_secret: HANDLE_SECRET.to_vec(),
        public_host: "connect.test".into(),
        internal_token: String::new(),
        admins: Default::default(),
        forum_pool: lazy.clone(),
        warren_pool: lazy,
        identity,
        discourse_pool: None,
        seen_pool: None,
        digest_generation: Default::default(),
        sessions: SessionStore::default(),
        legacy_approval: Default::default(),
        nonces,
        attach: AttachStore::default(),
        gates: Default::default(),
        forum_api,
        intake: None,
        report: None,
    })
}

/// The browser a session minted straight in the store belongs to.
fn a_browser() -> BrowserKey {
    BrowserSecret::generate().key()
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
    signed_attach_request_at(key, body, now_unix(), nonce)
}

fn signed_attach_request_at(
    key: &SigningKey,
    body: &str,
    timestamp: u64,
    nonce: [u8; 16],
) -> Request<Body> {
    let s = sign_request(
        key,
        "POST",
        "/v1/forum/attach-logs",
        body.as_bytes(),
        timestamp,
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

/// Records the wallet's forum link the way its forum sign-in does. The
/// composer that mints a pre-topic session is only open to a signed-in user,
/// so a real pre-topic reporter holds one.
async fn link(state: &AppState, key: &SigningKey) {
    let forum = handle::derive(HANDLE_SECRET, &key.verifying_key().to_bytes());
    state
        .identity
        .upsert_link(&forum.external_id, &forum.username)
        .await
        .expect("the in-memory link store never fails");
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

/// One browser opening the topic attach page.
struct AttachVisit {
    html: String,
    sid: String,
    /// The whole `Set-Cookie` line for the attach cookie, when one was set.
    set_cookie: Option<String>,
}

impl AttachVisit {
    /// The attach cookie's value, as the browser keeps it.
    fn cookie(&self) -> Option<String> {
        self.set_cookie
            .as_deref()
            .and_then(|line| line.strip_prefix(&format!("{ATTACH_COOKIE}=")))
            .and_then(|rest| rest.split(';').next())
            .map(str::to_owned)
    }
}

/// A browser opening `/attach?topic=<topic>`, presenting `cookie` as its
/// attach cookie when it holds one.
async fn visit_attach_page(state: Arc<AppState>, topic: u64, cookie: Option<&str>) -> AttachVisit {
    let mut request = Request::get(format!("/attach?topic={topic}"));
    if let Some(cookie) = cookie {
        request = request.header("Cookie", format!("{ATTACH_COOKIE}={cookie}"));
    }
    let response = router(state)
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{ATTACH_COOKIE}=")))
        .map(str::to_owned);
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
    let sid_start = html.find("warren://attach-logs?sid=").expect("link") + 25;
    let sid = html[sid_start..sid_start + 32].to_owned();
    AttachVisit {
        html,
        sid,
        set_cookie,
    }
}

#[tokio::test]
async fn another_browser_opening_the_same_topic_gets_nothing_of_the_authors_session() {
    // A topic id is public, so anybody can open this page for any topic, and
    // the sid alone polls and cancels a session: the page hands a visitor
    // only a session of its own.
    let v = forum_vector::load();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let author = visit_attach_page(state.clone(), 42, None).await;

    let stranger = visit_attach_page(state.clone(), 42, None).await;
    let other_browser = visit_attach_page(state.clone(), 42, Some(&"b".repeat(64))).await;
    for (who, visit) in [
        ("a visitor without a cookie", &stranger),
        ("another browser", &other_browser),
    ] {
        assert_ne!(visit.sid, author.sid, "{who} gets a session of its own");
        assert!(
            !visit.html.contains(&author.sid),
            "{who} reads nothing of the author's session"
        );
    }
    let response = router(state.clone())
        .oneshot(cancel_request(&stranger.sid))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    assert_answer(
        &read_status(state.clone(), &author.sid).await,
        &v.responses.attach_status.get("pending"),
        "the stranger's cancel leaves the author's session waiting",
    );
    let cookie = author
        .cookie()
        .expect("the page binds the author's browser");
    let again = visit_attach_page(state.clone(), 42, Some(&cookie)).await;
    assert_eq!(
        again.sid, author.sid,
        "a refresh in the author's browser keeps its session"
    );
    assert_answer(
        &upload(state.clone(), &key, &author.sid, 42, REPORT, [1; 16]).await,
        &v.responses.attach.get("attached"),
        "the author's app completes the author's session",
    );
    assert_answer(
        &read_status(state, &author.sid).await,
        &v.responses.attach_status.get("done"),
        "and the author's page sees it done",
    );
}

#[tokio::test]
async fn the_topic_attach_page_binds_its_browser_with_a_host_only_cookie() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let first = visit_attach_page(state.clone(), 42, None).await;

    let value = first.cookie().expect("an attach cookie");
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(
        first.set_cookie.as_deref(),
        Some(
            format!(
                "{ATTACH_COOKIE}={value}; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax"
            )
            .as_str()
        ),
        "HttpOnly and host-only, and alive exactly as long as a session"
    );
    let other_topic = visit_attach_page(state, 43, Some(&value)).await;
    assert_eq!(
        other_topic.cookie(),
        Some(value),
        "a browser keeps its secret across the topics it opens"
    );
}

#[tokio::test]
async fn an_attach_cookie_of_another_shape_binds_nothing() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let first = visit_attach_page(state.clone(), 42, None).await;

    let forged = visit_attach_page(state, 42, Some("forged")).await;

    assert_ne!(forged.sid, first.sid, "it fetches no session");
    assert!(
        forged.cookie().is_some_and(|fresh| fresh.len() == 64),
        "and is replaced by a secret of our own"
    );
}

#[tokio::test]
async fn attach_page_on_android_routes_to_the_in_app_report() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let response = router(state)
        .oneshot(
            Request::get("/attach?topic=42")
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Linux; Android 15; FP3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
                )
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
    assert!(
        html.contains("Report a problem"),
        "the fallback for an app that predates the link"
    );
    assert!(html.contains("https://forum.warrenbrowse.com/t/42"));
    assert!(
        html.contains("warren://attach-logs?sid="),
        "an updated app takes the link"
    );
    assert!(
        !html.contains("<code>"),
        "no session id to mistake for a sign-in code"
    );
}

#[tokio::test]
async fn a_desktop_user_agent_with_an_android_platform_hint_is_a_phone() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));

    let response = router(state)
        .oneshot(
            Request::get("/attach?topic=42")
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                )
                .header("Sec-CH-UA-Platform", "\"Android\"")
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
    assert!(html.contains("Report a problem"));
    assert!(html.contains("data-intent=\"intent://attach-logs?sid="));
}

#[tokio::test]
async fn attach_page_pre_on_a_phone_keeps_the_link_and_shows_the_fallback() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    for (ua, expected) in [
        (
            "Mozilla/5.0 (Linux; Android 15; FP3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
            "Report a problem",
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
            "without logs",
        ),
    ] {
        let response = router(state.clone())
            .oneshot(
                Request::get(format!("/attach?sid={sid}"))
                    .header("User-Agent", ua)
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
        assert!(html.contains(expected), "{ua}");
        assert!(
            html.contains(&format!("warren://attach-logs?sid={sid}&topic=0")),
            "{ua}"
        );
        assert!(
            !html.contains("<code>"),
            "{ua}: no session id to mistake for a code"
        );
    }
}

#[tokio::test]
async fn a_reader_query_override_routes_a_mac_user_agent_to_the_phone_page() {
    let (url, _stub) = spawn_stub("whoever", true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15";
    let sid = new_pre_sid(state.clone()).await;

    for (path, expected) in [
        (
            "/attach?topic=42&reader=ios".to_string(),
            "Reply on your topic",
        ),
        (
            format!("/attach?sid={sid}&reader=android"),
            "Report a problem",
        ),
    ] {
        let response = router(state.clone())
            .oneshot(
                Request::get(&path)
                    .header("User-Agent", mac)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
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
        assert!(html.contains(expected), "{path}");
        assert!(html.contains("warren://attach-logs?sid="), "{path}");
        assert!(!html.contains("<code>"), "{path}");
    }
}

#[tokio::test]
async fn attach_meta_names_the_bound_topic_and_null_for_a_pre_topic_session() {
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
    let sid_start = html.find("warren://attach-logs?sid=").expect("link") + 25;
    let bound = html[sid_start..sid_start + 32].to_string();
    let pre = new_pre_sid(state.clone()).await;

    for (sid, expected) in [
        (bound, serde_json::json!(42)),
        (pre, serde_json::Value::Null),
    ] {
        let response = router(state.clone())
            .oneshot(
                Request::get(format!("/v1/attach/{sid}/meta"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "pending");
        assert_eq!(json["topic_id"], expected, "{sid}");
    }
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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    link(&state, &key).await;

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
        let sid = state
            .attach
            .create(42, &a_browser(), now_unix())
            .expect("create");
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
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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

fn cancel_request(sid: &str) -> Request<Body> {
    Request::post(format!("/v1/attach/{sid}/cancel"))
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn a_cancel_after_the_app_delivered_leaves_the_report_to_its_bind() {
    // The cancel is the app's decline, sent before it uploads anything. Past
    // the upload it would only let whoever holds the sid drop a report the
    // user already sent.
    let v = forum_vector::load();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = new_pre_sid(state.clone()).await;
    assert_answer(
        &upload(state.clone(), &key, &sid, 0, REPORT, [13; 16]).await,
        &v.responses.attach.get("received"),
        "the app delivered",
    );

    let response = router(state.clone())
        .oneshot(cancel_request(&sid))
        .await
        .expect("infallible");

    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "cancelled"}),
        "the answer does not say what the cancel did"
    );
    assert_answer(
        &read_status(state.clone(), &sid).await,
        &v.responses.attach_status.get("received"),
        "the report is still parked",
    );
    let response = router(state)
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "attached"}),
        "and the forum still binds it"
    );
}

#[tokio::test]
async fn a_cancel_during_the_delivery_never_turns_delivered_logs_into_an_error() {
    let v = forum_vector::load();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let gate = Arc::new(Gate::default());
    *stub.upload_gate.lock().expect("stub mutex") = Some(gate.clone());
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    let delivery = tokio::spawn({
        let (state, key, sid) = (state.clone(), key.clone(), sid.clone());
        async move { upload(state, &key, &sid, 42, REPORT, [14; 16]).await }
    });
    gate.entered.notified().await;

    router(state.clone())
        .oneshot(cancel_request(&sid))
        .await
        .expect("infallible");

    assert_answer(
        &read_status(state.clone(), &sid).await,
        &v.responses.attach_status.get("processing"),
        "the cancel leaves a delivery in flight alone",
    );
    gate.release.notify_one();
    assert_answer(
        &delivery.await.expect("the upload task"),
        &v.responses.attach.get("attached"),
        "the app is told its logs landed, because they did",
    );
    assert_answer(
        &read_status(state, &sid).await,
        &v.responses.attach_status.get("done"),
        "and the page sees them done",
    );
}

#[tokio::test]
async fn a_cancel_landing_before_the_delivery_starts_stops_it() {
    // The decline and the upload race only when both are in flight, and the
    // first one to reach the session wins: here the decline lands while the
    // topic is still being fetched, so nothing is written.
    let v = forum_vector::load();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let gate = Arc::new(Gate::default());
    *stub.topic_gate.lock().expect("stub mutex") = Some(gate.clone());
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    let delivery = tokio::spawn({
        let (state, key, sid) = (state.clone(), key.clone(), sid.clone());
        async move { upload(state, &key, &sid, 42, REPORT, [15; 16]).await }
    });
    gate.entered.notified().await;

    router(state.clone())
        .oneshot(cancel_request(&sid))
        .await
        .expect("infallible");
    gate.release.notify_one();

    assert_answer(
        &delivery.await.expect("the upload task"),
        &v.responses.attach.get("session_unknown"),
        "the declined session takes no upload",
    );
    assert!(
        stub.calls.lock().expect("stub mutex").is_empty(),
        "nothing reached Discourse"
    );
    assert_answer(
        &read_status(state, &sid).await,
        &v.responses.attach_status.get("cancelled_user"),
        "and the page shows the decline",
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

    link(&state, &key).await;
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
        serde_json::json!({"status": "pending", "topic_id": null})
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
            "topic_id": null,
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
async fn a_refused_bind_spends_the_session_so_no_second_topic_answers() {
    // Anybody holding a pre-topic sid can call bind, and a success says the
    // report's signer wrote that topic. Relay the attach link to somebody,
    // let them approve, then bind topic after topic: without a one-shot
    // bind that walks the forum until it names their pseudonymous account.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    stub.other_authors
        .lock()
        .expect("stub mutex")
        .insert(42, "someone-else".to_owned());
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
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

    let response = router(state.clone())
        .oneshot(bind_request(&sid, 43))
        .await
        .expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the signer's own topic must not answer after a refused guess"
    );
    assert!(
        stub.calls.lock().expect("stub mutex").is_empty(),
        "nothing was written for either bind"
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
        serde_json::json!({"reason": "not_author", "status": "cancelled"})
    );
}

#[tokio::test]
async fn binds_in_flight_together_get_one_answer_between_them() {
    // The one-shot bind has to hold for binds sent at once, or a batch of
    // guesses all pass the session check before the first refusal lands.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    stub.other_authors
        .lock()
        .expect("stub mutex")
        .insert(42, "someone-else".to_owned());
    *stub.topic_delay.lock().expect("stub mutex") = Some(std::time::Duration::from_millis(300));
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = new_pre_sid(state.clone()).await;
    let body = serde_json::json!({
        "sid": sid,
        "topic_id": 0,
        "log_gz_b64": gz_b64(REPORT),
    })
    .to_string();
    router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [12; 16]))
        .await
        .expect("infallible");

    let (wrong, right) = tokio::join!(
        router(state.clone()).oneshot(bind_request(&sid, 42)),
        router(state.clone()).oneshot(bind_request(&sid, 43)),
    );
    let right = observe(right.expect("infallible")).await;

    assert_eq!(wrong.expect("infallible").status(), StatusCode::FORBIDDEN);
    assert_eq!(
        (right.status, right.body_utf8.as_str()),
        (409, r#"{"error":"bind_in_progress"}"#),
        "the second bind in flight is turned away"
    );
    assert!(
        stub.calls.lock().expect("stub mutex").is_empty(),
        "the signer's topic got nothing"
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
    link(&state, &key).await;
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
        serde_json::json!({"status": "received"}),
        "a failed bind must stay retryable"
    );
    let retry = router(state)
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    assert_eq!(
        retry.status(),
        StatusCode::BAD_GATEWAY,
        "the retry reaches Discourse again: the failed bind gave its claim back"
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
async fn a_pre_topic_upload_from_a_wallet_with_no_forum_link_is_refused_and_parks_nothing() {
    // A wallet costs nothing to mint and a parked report holds one of the
    // MAX_LOG_SESSIONS slots until its bind, so a signature alone must not
    // buy one. The composer's own user always has the link: signing in to
    // the forum is what records it.
    let v = forum_vector::load();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    let sid = new_pre_sid(state.clone()).await;

    let answer = upload(state.clone(), &key, &sid, 0, REPORT, [20; 16]).await;

    assert_answer(
        &answer,
        &v.responses.attach.get("not_author"),
        "refused with the answer the app already knows",
    );
    assert_answer(
        &read_status(state, &sid).await,
        &v.responses.attach_status.get("pending"),
        "and nothing was parked",
    );
}

#[tokio::test]
async fn a_flood_of_unlinked_wallets_cannot_evict_a_linked_wallets_parked_report() {
    // Throwaway keys cost nothing: sixteen mint-and-upload pairs would fill
    // the log store, and the next would evict the oldest parked report, the
    // one of a user still writing the topic it belongs to.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = new_pre_sid(state.clone()).await;
    let parked = upload(state.clone(), &key, &sid, 0, REPORT, [21; 16]).await;
    assert_eq!(parked.status, 200, "the linked wallet parks its report");
    // The store dates reports to the second: one second later the linked
    // report is strictly the oldest, so no tie in the eviction order can
    // spare it.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let mut flood = Vec::new();
    for seed in 0..=warren_connect::attach::MAX_LOG_SESSIONS {
        let seed = u8::try_from(100 + seed).expect("one key byte per throwaway wallet");
        let throwaway = SigningKey::from_bytes(&[seed; 32]);
        let flood_sid = new_pre_sid(state.clone()).await;
        flood.push(upload(state.clone(), &throwaway, &flood_sid, 0, REPORT, [22; 16]).await);
    }

    let response = router(state)
        .oneshot(bind_request(&sid, 42))
        .await
        .expect("infallible");
    let bound = observe(response).await;
    assert_eq!(
        (bound.status, bound.body_utf8.as_str()),
        (200, r#"{"status":"attached"}"#),
        "the linked report outlived the flood and binds"
    );
    assert!(
        flood
            .iter()
            .all(|a| (a.status, a.body_utf8.as_str()) == (403, r#"{"error":"not_author"}"#)),
        "the forum-link gate is what turned the flood away"
    );
}

#[tokio::test]
async fn a_pre_topic_upload_is_refused_while_the_forum_links_cannot_be_read() {
    // Fails closed, and as the forum being unavailable: the reporter is told
    // to try again, where "not the author" would tell them to stop.
    let v = forum_vector::load();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state_with_identity(
        Some(ForumApi::new(
            &url,
            "k".into(),
            "system".into(),
            "staff".into(),
        )),
        IdentityStore::Postgres {
            forum: unreachable_pool(),
            warren: unreachable_pool(),
            discourse: None,
        },
    );
    let sid = new_pre_sid(state.clone()).await;

    let answer = upload(state.clone(), &key, &sid, 0, REPORT, [23; 16]).await;

    assert_answer(
        &answer,
        &v.responses.attach.get("forum_unavailable"),
        "refused as a transient failure",
    );
    assert_answer(
        &read_status(state, &sid).await,
        &v.responses.attach_status.get("pending"),
        "and nothing was parked",
    );
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
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
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
async fn a_forum_that_still_sends_bare_tag_names_attaches_too() {
    // The forum's tag shape changed under us once; it must be able to change
    // back, or a Discourse rollback becomes a second outage.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (url, stub) =
        spawn_stub_with_tag_shape(&author_username(&key), true, vec!["macos".into()], false).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    let body = serde_json::json!({
        "sid": sid, "topic_id": 42, "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [22; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    let tag_call = calls.iter().find(|c| c.op == "tag").expect("topic tagged");
    assert!(tag_call.body.contains("macos"), "{}", tag_call.body);
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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
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
async fn the_staff_pm_subject_carries_the_topic_title_unescaped() {
    // A Discourse subject is rendered verbatim, so the escaping that defangs
    // the PM body must not reach the subject: PM 176 reached the staff inbox
    // reading "Journaux Warren pour le sujet #175 : \\[macOS\\] Connection\\: ...".
    let key = SigningKey::from_bytes(&[17u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    let body = serde_json::json!({
        "sid": sid, "topic_id": 42, "log_gz_b64": gz_b64("warren log line\n"),
    })
    .to_string();
    let response = router(state)
        .oneshot(signed_attach_request(&key, &body, [37; 16]))
        .await
        .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let calls = stub.calls.lock().expect("stub mutex");
    let pm = calls.iter().find(|c| c.op == "pm").expect("staff PM sent");
    let sent: serde_json::Value = serde_json::from_str(&pm.body).expect("json");
    let title = sent["title"].as_str().expect("title");
    assert!(
        title.ends_with("[macOS] Connection: cannot connect after update #a1b2c3"),
        "{title}"
    );
    assert!(!title.contains('\\'), "no escape in a subject: {title}");
    assert!(
        sent["raw"].as_str().expect("raw").contains("\\[macOS\\]"),
        "the body stays defanged, it IS markdown"
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
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

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

// ---------------------------------------------------------------------------
// The shared golden vector, `vectors/forum_login_v1.json`: the attach-logs
// wire both mobile apps freeze, replayed against THIS provider. A client and
// this router meet on these bytes and nowhere else.

#[test]
fn the_forum_vector_carries_only_the_attach_answers_this_suite_replays() {
    // An answer added to the vector goes red here until a replay exists for
    // it (`processing` is the one transient answer, pinned by shape below).
    let v = forum_vector::load();
    let mut attach = v.responses.attach.names();
    attach.sort_unstable();
    assert_eq!(
        attach,
        [
            "attached",
            "clock_skew",
            "feature_disabled",
            "forum_unavailable",
            "not_author",
            "payload_too_large",
            "received",
            "session_unknown"
        ]
    );
    let mut status = v.responses.attach_status.names();
    status.sort_unstable();
    assert_eq!(
        status,
        [
            "cancelled_user",
            "done",
            "pending",
            "processing",
            "received",
            "unknown"
        ]
    );
    let mut meta = v.responses.attach_meta.names();
    meta.sort_unstable();
    assert_eq!(
        meta,
        [
            "pending_pre_topic",
            "pending_topic",
            "received_pre_topic",
            "unknown"
        ]
    );
    let processing = v.responses.attach_status.get("processing");
    assert_eq!(processing.status, 200);
    assert_eq!(processing.body_utf8, r#"{"status":"processing"}"#);
}

#[test]
fn the_attach_vectors_are_what_the_contract_signs_and_what_the_verifier_accepts() {
    // Both ends of the wire against the same bytes, for the topic-bound
    // upload and the pre-topic one: the contract's signer reproduces the
    // pinned headers, the verifier accepts them at the vector clock, and the
    // body is exactly the three fields this route reads, within every cap.
    let v = forum_vector::load();
    for name in ["attach_with_log", "attach_pre_topic"] {
        let req = forum_vector::request(&v, name);
        assert_signed_by_the_contract(&v, req);
        verify_at_vector_clock(&v, req);

        let body: serde_json::Value = serde_json::from_str(&req.body_utf8).expect("json");
        let object = body.as_object().expect("an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["log_gz_b64", "sid", "topic_id"],
            "{name}: exactly this route's fields"
        );
        assert_eq!(
            body["sid"].as_str(),
            req.sid.as_deref(),
            "{name}: the declared sid"
        );
        let topic = req.topic_id.expect("an attach request declares its topic");
        assert_eq!(
            body["topic_id"].as_u64(),
            Some(topic),
            "{name}: the declared topic"
        );
        assert_eq!(
            name == "attach_pre_topic",
            topic == 0,
            "{name}: topic 0 is the pre-topic marker and nothing else"
        );

        let gz = hex::decode(
            req.log_gz_hex
                .as_deref()
                .expect("an attach upload carries its gzip"),
        )
        .expect("hex");
        assert_eq!(
            body["log_gz_b64"],
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &gz),
            "{name}: the log rides as standard base64 of the pinned gzip"
        );
        assert!(
            body["log_gz_b64"]
                .as_str()
                .map(str::len)
                .unwrap_or(usize::MAX)
                <= warren_connect::attach::MAX_LOG_GZ_B64_CHARS,
            "{name}: within the provider's base64 cap"
        );
        let text = warren_connect::attach::gunzip_capped(&gz)
            .expect("the pinned gzip inflates within the cap");
        assert_eq!(Some(text.as_str()), req.log_utf8.as_deref(), "{name}");
    }
}

/// The three lifecycle reads of one session, as this router answers them.
async fn read_status(state: Arc<AppState>, sid: &str) -> forum_vector::Answer {
    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/status"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    observe(response).await
}

async fn read_meta(state: Arc<AppState>, sid: &str) -> forum_vector::Answer {
    let response = router(state)
        .oneshot(
            Request::get(format!("/v1/attach/{sid}/meta"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    observe(response).await
}

async fn upload(
    state: Arc<AppState>,
    key: &SigningKey,
    sid: &str,
    topic_id: u64,
    log: &str,
    nonce: [u8; 16],
) -> forum_vector::Answer {
    let body = format!(
        r#"{{"sid":"{sid}","topic_id":{topic_id},"log_gz_b64":"{}"}}"#,
        gz_b64(log)
    );
    let response = router(state)
        .oneshot(signed_attach_request(key, &body, nonce))
        .await
        .expect("infallible");
    observe(response).await
}

#[tokio::test]
async fn every_pinned_attach_answer_is_what_this_router_sends() {
    // The vector's log is the report both mobile clients freeze; its header
    // names the version and OS the meta must echo once delivered.
    let v = forum_vector::load();
    let log = forum_vector::request(&v, "attach_with_log")
        .log_utf8
        .clone()
        .expect("the pinned upload carries a log");
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;

    // A topic-bound session: pending, its meta names the topic, then attached.
    let bound = state
        .attach
        .create(4242, &a_browser(), now_unix())
        .expect("create");
    assert_answer(
        &read_status(state.clone(), &bound).await,
        &v.responses.attach_status.get("pending"),
        "attach_status.pending",
    );
    assert_answer(
        &read_meta(state.clone(), &bound).await,
        &v.responses.attach_meta.get("pending_topic"),
        "attach_meta.pending_topic",
    );
    assert_answer(
        &upload(state.clone(), &key, &bound, 4242, &log, [1; 16]).await,
        &v.responses.attach.get("attached"),
        "attach.attached",
    );
    assert_answer(
        &read_status(state.clone(), &bound).await,
        &v.responses.attach_status.get("done"),
        "attach_status.done",
    );

    // A pre-topic session: its meta has no topic, the upload parks the
    // report (received), and the meta then names what the app delivered.
    link(&state, &key).await;
    let pre = new_pre_sid(state.clone()).await;
    assert_answer(
        &read_meta(state.clone(), &pre).await,
        &v.responses.attach_meta.get("pending_pre_topic"),
        "attach_meta.pending_pre_topic",
    );
    assert_answer(
        &upload(state.clone(), &key, &pre, 0, &log, [2; 16]).await,
        &v.responses.attach.get("received"),
        "attach.received",
    );
    assert_answer(
        &read_status(state.clone(), &pre).await,
        &v.responses.attach_status.get("received"),
        "attach_status.received",
    );
    assert_answer(
        &read_meta(state.clone(), &pre).await,
        &v.responses.attach_meta.get("received_pre_topic"),
        "attach_meta.received_pre_topic",
    );

    // A cancelled session, and a session nobody minted.
    let cancelled = state
        .attach
        .create(7, &a_browser(), now_unix())
        .expect("create");
    let response = router(state.clone())
        .oneshot(
            Request::post(format!("/v1/attach/{cancelled}/cancel"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert!(response.status().is_success(), "cancel answers success");
    assert_answer(
        &read_status(state.clone(), &cancelled).await,
        &v.responses.attach_status.get("cancelled_user"),
        "attach_status.cancelled_user",
    );
    let nobody = "ffffffffffffffffffffffffffffffff";
    assert_answer(
        &read_status(state.clone(), nobody).await,
        &v.responses.attach_status.get("unknown"),
        "attach_status.unknown",
    );
    assert_answer(
        &read_meta(state.clone(), nobody).await,
        &v.responses.attach_meta.get("unknown"),
        "attach_meta.unknown",
    );

    // The pinned request itself, re-signed inside the clock window: its sid
    // was never minted by this store, which is the session_unknown answer.
    let pinned = forum_vector::request(&v, "attach_with_log");
    let response = router(state.clone())
        .oneshot(pinned.resigned_at(&v.signer.signing_key(), now_unix(), [3; 16]))
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.attach.get("session_unknown"),
        "attach.session_unknown",
    );

    // A signature stamped an hour ago, on a live session.
    let skewed = state
        .attach
        .create(8, &a_browser(), now_unix())
        .expect("create");
    let body = format!(
        r#"{{"sid":"{skewed}","topic_id":8,"log_gz_b64":"{}"}}"#,
        gz_b64(&log)
    );
    let s = sign_request(
        &key,
        "POST",
        "/v1/forum/attach-logs",
        body.as_bytes(),
        now_unix() - 3600,
        [4; 16],
    );
    let response = router(state.clone())
        .oneshot(
            Request::post("/v1/forum/attach-logs")
                .header(HEADER_PUBKEY, s.pubkey_ss58)
                .header(HEADER_SIGNATURE, s.signature_hex)
                .header(HEADER_TIMESTAMP, s.timestamp.to_string())
                .header(HEADER_NONCE, s.nonce_hex)
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.attach.get("clock_skew"),
        "attach.clock_skew",
    );

    // A base64 field past the cap.
    let big = state
        .attach
        .create(9, &a_browser(), now_unix())
        .expect("create");
    let body = format!(
        r#"{{"sid":"{big}","topic_id":9,"log_gz_b64":"{}"}}"#,
        "A".repeat(warren_connect::attach::MAX_LOG_GZ_B64_CHARS + 1)
    );
    let response = router(state.clone())
        .oneshot(signed_attach_request(&key, &body, [5; 16]))
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.attach.get("payload_too_large"),
        "attach.payload_too_large",
    );

    // Somebody else's topic, and a forum that fails the upload.
    let (other_url, _other) = spawn_stub("somebody-else", true).await;
    let other = test_state(Some(ForumApi::new(
        &other_url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&other, &key).await;
    let theirs = other
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    assert_answer(
        &upload(other, &key, &theirs, 42, &log, [6; 16]).await,
        &v.responses.attach.get("not_author"),
        "attach.not_author",
    );
    let (down_url, _down) = spawn_stub(&author_username(&key), false).await;
    let down = test_state(Some(ForumApi::new(
        &down_url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&down, &key).await;
    let mine = down
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    assert_answer(
        &upload(down, &key, &mine, 42, &log, [7; 16]).await,
        &v.responses.attach.get("forum_unavailable"),
        "attach.forum_unavailable",
    );

    // No forum API key at all: the feature is off before anything is read.
    let off = test_state(None);
    let response = router(off)
        .oneshot(pinned.as_http())
        .await
        .expect("infallible");
    assert_answer(
        &observe(response).await,
        &v.responses.attach.get("feature_disabled"),
        "attach.feature_disabled",
    );
}

// ---------------------------------------------------------------------------
// Replay store: only an upload the route admits (a linked wallet parking its
// report, the topic's author delivering) spends a nonce.
// ---------------------------------------------------------------------------

fn upload_body(sid: &str, topic_id: u64) -> String {
    format!(
        r#"{{"sid":"{sid}","topic_id":{topic_id},"log_gz_b64":"{}"}}"#,
        gz_b64(REPORT)
    )
}

/// The same signed upload, byte for byte, each time it is called.
fn replayable_upload(key: &SigningKey, sid: &str, topic_id: u64) -> impl Fn() -> Request<Body> {
    let (key, body, at) = (key.clone(), upload_body(sid, topic_id), now_unix());
    move || signed_attach_request_at(&key, &body, at, [0x55; 16])
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> forum_vector::Answer {
    observe(
        router(state.clone())
            .oneshot(request)
            .await
            .expect("infallible"),
    )
    .await
}

#[tokio::test]
async fn uploads_the_route_refuses_spend_no_nonce() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = build_state(
        Some(ForumApi::new(
            &url,
            "k".into(),
            "system".into(),
            "staff".into(),
        )),
        IdentityStore::Memory(Box::default()),
        NonceStore::with_max_entries(4),
    );
    link(&state, &key).await;
    let topic_sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

    let mut answers = Vec::new();
    for i in 0..8u8 {
        let stranger = SigningKey::from_bytes(&[0x70 + i; 32]);
        let pre_sid = new_pre_sid(state.clone()).await;
        let unlinked = signed_attach_request(&stranger, &upload_body(&pre_sid, 0), [i; 16]);
        answers.push(send(&state, unlinked).await.body_utf8);
        let not_author =
            signed_attach_request(&stranger, &upload_body(&topic_sid, 42), [0x40 + i; 16]);
        answers.push(send(&state, not_author).await.body_utf8);
    }

    assert_eq!(
        answers,
        vec![r#"{"error":"not_author"}"#; 16],
        "an unlinked uploader and a non-author are refused by their gate, never by a full store"
    );
    assert_eq!(state.nonces.held(), 0);
    let sid = new_pre_sid(state.clone()).await;
    let parked = send(
        &state,
        signed_attach_request(&key, &upload_body(&sid, 0), [0x50; 16]),
    )
    .await;
    assert_eq!(
        parked.body_utf8, r#"{"status":"received"}"#,
        "and a linked wallet still parks its report"
    );
}

#[tokio::test]
async fn a_replayed_pre_topic_upload_is_refused() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = new_pre_sid(state.clone()).await;
    let request = replayable_upload(&key, &sid, 0);

    let first = send(&state, request()).await;
    let replay = send(&state, request()).await;

    assert_eq!(first.body_utf8, r#"{"status":"received"}"#);
    assert_eq!(
        (replay.status, replay.body_utf8.as_str()),
        (401, "nonce rejected")
    );
}

#[tokio::test]
async fn a_replayed_topic_upload_is_refused_while_its_session_stays_retryable() {
    // A delivery Discourse failed leaves the session open for the app's own
    // retry, which signs afresh. The captured request does not get a second go.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, _stub) = spawn_stub(&author_username(&key), false).await;
    let state = test_state(Some(ForumApi::new(
        &url,
        "k".into(),
        "system".into(),
        "staff".into(),
    )));
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");
    let request = replayable_upload(&key, &sid, 42);

    let first = send(&state, request()).await;
    let replay = send(&state, request()).await;

    assert_eq!(first.status, 502, "{}", first.body_utf8);
    assert_eq!(
        (replay.status, replay.body_utf8.as_str()),
        (401, "nonce rejected")
    );
    let retry = send(
        &state,
        signed_attach_request(&key, &upload_body(&sid, 42), [0x56; 16]),
    )
    .await;
    assert_eq!(
        retry.status, 502,
        "a freshly signed retry is still admitted"
    );
}

// ---------------------------------------------------------------------------
// The topic fetch is the one gate read that reaches Discourse, on a session
// anybody can open for any topic. It is bounded three ways: only a wallet with
// a forum link reaches it, a session pays for a few, and a bulkhead caps how
// many run at once.
// ---------------------------------------------------------------------------

fn topic_fetches(stub: &StubState) -> usize {
    stub.topic_fetches.load(std::sync::atomic::Ordering::SeqCst)
}

fn stub_api(url: &str) -> ForumApi {
    ForumApi::new(url, "k".into(), "system".into(), "staff".into())
}

#[tokio::test]
async fn a_topic_upload_from_a_wallet_with_no_forum_link_never_reaches_discourse() {
    // The topic author has a forum account, and so a forum link: a wallet
    // without one cannot be the author, whatever the topic says.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub(&author_username(&key), true).await;
    let state = test_state(Some(stub_api(&url)));
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

    let answer = send(
        &state,
        signed_attach_request(&key, &upload_body(&sid, 42), [1; 16]),
    )
    .await;

    assert_eq!(answer.status, 403, "{}", answer.body_utf8);
    assert_eq!(answer.body_utf8, r#"{"error":"not_author"}"#);
    assert_eq!(topic_fetches(&stub), 0);
    assert_eq!(state.nonces.held(), 0);
}

#[tokio::test]
async fn a_topic_session_pays_for_a_bounded_number_of_topic_fetches() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub("someone-else", true).await;
    let state = test_state(Some(stub_api(&url)));
    link(&state, &key).await;
    let sid = state
        .attach
        .create(42, &a_browser(), now_unix())
        .expect("create");

    let mut answers = Vec::new();
    for i in 0..6u8 {
        let request = signed_attach_request(&key, &upload_body(&sid, 42), [i; 16]);
        answers.push(send(&state, request).await.status);
    }

    assert_eq!(answers, [403, 403, 403, 403, 404, 404]);
    assert_eq!(topic_fetches(&stub), 4, "the session paid for four");
    assert_eq!(
        read_status(state.clone(), &sid).await.body_utf8,
        r#"{"reason":"attempts_exhausted","status":"cancelled"}"#,
        "the page stops waiting, and its next visit opens a fresh session"
    );
}

#[tokio::test]
async fn a_topic_fetch_past_a_full_topic_gate_is_refused_at_once() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (url, stub) = spawn_stub("someone-else", true).await;
    *stub.topic_delay.lock().expect("stub mutex") = Some(std::time::Duration::from_secs(3));
    let state = test_state(Some(stub_api(&url)));
    link(&state, &key).await;
    let upload = |i: u8| {
        let sid = state
            .attach
            .create(42, &a_browser(), now_unix())
            .expect("create");
        signed_attach_request(&key, &upload_body(&sid, 42), [i; 16])
    };
    let in_flight: Vec<_> = (0..10u8)
        .map(|i| {
            let (state, request) = (state.clone(), upload(i));
            tokio::spawn(async move { send(&state, request).await })
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while state.gates.topic.queued() < 8 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let started = std::time::Instant::now();

    let turned_away = send(&state, upload(0x10)).await;

    assert_eq!(turned_away.status, 502, "{}", turned_away.body_utf8);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "refused without waiting for a fetch: {:?}",
        started.elapsed()
    );
    for task in in_flight {
        task.await.expect("task");
    }
    assert_eq!(
        topic_fetches(&stub),
        2,
        "two fetches ran; the eight queued behind them gave up after two seconds"
    );
}
