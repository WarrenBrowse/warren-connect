//! HTTP surface. Handlers stay thin: all decision logic lives in the tested
//! core modules (`discourse`, `verify`, `sessions`, `handle`, `store`).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;

use warren_contract::auth::{HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
use warren_contract::redact;

use crate::attach::{self, AttachKind, AttachStatus, AttachStore};
use crate::discourse::{self, SsoUser};
use crate::error::AuthError;
use crate::forum_api::{self, ForumApi};
use crate::nonces::NonceStore;
use crate::sessions::{SessionStatus, SessionStore};
use crate::ticket::TicketKey;
use crate::verify::{SignedHeaders, verify_signed_request};
use crate::{handle, pages, store};

/// Shared application state.
pub struct AppState {
    /// HMAC secret shared with Discourse (`discourse_connect_secret`).
    pub connect_secret: Vec<u8>,
    /// Keyed-derivation secret for pairwise handles.
    pub handle_secret: Vec<u8>,
    /// Public host of this service, embedded in deep links.
    pub public_host: String,
    /// Bearer token for the internal support-lookup endpoints. When empty,
    /// those endpoints are disabled.
    pub internal_token: String,
    /// Forum staff allowlist, from `WARREN_ADMIN_PUBKEYS`.
    pub admins: crate::admins::Allowlist,
    /// `forum_auth` database.
    pub forum_pool: PgPool,
    /// Warren API database, read-only role (subscription check).
    pub warren_pool: PgPool,
    /// The admission seam over the two pools above: subscription standing,
    /// link upsert and digest slot, shared by the login and the in-app
    /// report so the two can never apply different gates.
    pub identity: store::IdentityStore,
    /// Discourse's own database, read-only role. `None` disables the
    /// broadcast activity digest (503 on its endpoint); everything else
    /// keeps working.
    pub discourse_pool: Option<PgPool>,
    /// Discourse's own database again, through a role whose only privilege is
    /// `UPDATE (seen_notification_id) ON users`. Separate from the pool above
    /// so the count and the panel keep reading through a role that cannot
    /// write at all. `None` disables marking the list seen (503) and nothing
    /// else.
    pub seen_pool: Option<PgPool>,
    /// Content-derived generation of the published digest.
    pub digest_generation: crate::digest::GenerationStamp,
    /// Pending browser logins.
    pub sessions: SessionStore,
    /// Anti-replay registry.
    pub nonces: NonceStore,
    /// Pending attach-logs sessions.
    pub attach: AttachStore,
    /// Discourse admin API client; `None` disables the attach-logs feature.
    pub forum_api: Option<ForumApi>,
    /// Guest help intake; `None` disables the intake endpoint (503).
    pub intake: Option<IntakeState>,
    /// In-app bug reports; `None` disables the report endpoint (503).
    pub report: Option<ReportState>,
}

/// Everything the in-app report endpoint needs; absent = feature disabled.
pub struct ReportState {
    /// Discourse client on an all-users key scoped to topic writes, acting as
    /// the reporter per request (`ForumApi::as_user`), so the topic is owned
    /// by the wallet's own account. The log delivery keeps using the system
    /// client in [`AppState::forum_api`].
    pub topic_api: ForumApi,
    /// Category the reports are created in (the forum's bug-reports category).
    pub category_id: u64,
    /// Per-wallet + global sliding-window limiter, keyed by the keyed forum
    /// id: a signed route must never see a client IP, so the wallet is the
    /// only per-identity budget it can have.
    pub limiter: crate::intake::RateLimiter<String>,
}

/// Everything the guest intake endpoint needs; absent = feature disabled.
pub struct IntakeState {
    /// Discourse client acting as the low-privilege intake bot user.
    pub api: ForumApi,
    /// Category the guest topics are created in.
    pub category_id: u64,
    /// Per-IP + global sliding-window limiter (front line; the bot user's own
    /// Discourse rate limits are the second, server-side circuit breaker).
    pub limiter: crate::intake::RateLimiter,
    /// Budget of the follow-up route, deliberately separate from the one
    /// above: a spam wave of new reports must not lock a reporter out of the
    /// conversation they already started, and a follow-up is a legitimately
    /// repeated action where opening a report is not.
    pub reply_limiter: crate::intake::RateLimiter,
    /// Issues and verifies the follow-up codes.
    pub ticket: TicketKey,
}

fn now_unix() -> u64 {
    // Truncation is fine until year 292 billion.
    chrono::Utc::now().timestamp().max(0) as u64
}

use crate::store::error_kind as sqlx_error_kind;

/// Forum access policy. A login is allowed when the wallet has paid for Warren
/// at least once (the anti-sybil paywall: a free wallet is unlimited and there
/// is no email/IP to throttle) OR the wallet is staff. Admins are operators,
/// not necessarily paying customers, so the paywall must never lock them out of
/// their own forum.
fn login_allowed(ever_paid: bool, is_admin: bool) -> bool {
    ever_paid || is_admin
}

/// Whether this login may assert staff to Discourse.
///
/// The allowlist is a bootstrap floor, and Discourse keeps a grant it already
/// holds because an ordinary login omits the field entirely. So withholding
/// the claim on a cross-device approval costs an operator nothing: signing in
/// from their phone still logs them in, still passes the paywall, and still
/// finds them admin on the forum. What it removes is the ability to MINT staff
/// through a link somebody else relayed to them, which is the whole payload of
/// the QR-phishing path.
fn staff_claim(is_admin: bool, approach: crate::sessions::Approach) -> bool {
    is_admin && approach == crate::sessions::Approach::SameDevice
}

/// Content-Security-Policy of the server-rendered pages.
///
/// `default-src 'none'` is affordable because the pages are self-contained by
/// design: no web font, no CDN, the QR is an inline SVG element. What is left
/// is exactly the style block, the poll script and the poll itself, so the
/// style and the script are admitted by a per-response nonce rather than by
/// `'unsafe-inline'`. `frame-ancestors 'none'` is the load-bearing one: it
/// stops the approval page being wrapped in a page of somebody else's making.
fn content_security_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; \
         connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'"
    )
}

/// A per-response CSP nonce: 16 bytes of OS entropy, hex.
fn csp_nonce() -> String {
    use rand::RngCore as _;
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Renders an HTML page and serves it with its own CSP.
///
/// `cacheable` is false for anything carrying a session id: the approval and
/// attach pages put theirs in the markup, and a stored copy would leave that
/// capability in the browser cache after the login is over.
fn html_page(render: impl FnOnce(&str) -> String, cacheable: bool) -> Response {
    let nonce = csp_nonce();
    let body = render(&nonce);
    let mut response = Html(body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        content_security_policy(&nonce)
            .parse()
            .expect("the policy is ASCII by construction"),
    );
    if !cacheable {
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
    }
    response
}

/// Headers every response carries, HTML or JSON.
///
/// `X-Frame-Options` duplicates the CSP `frame-ancestors` for browsers that
/// predate it. HSTS is emitted here rather than only at the edge so it
/// survives an edge config that drifts; a browser ignores it over plain HTTP,
/// so a local run is unaffected.
async fn base_security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("strict-transport-security", "max-age=31536000"),
    ] {
        headers.insert(name, axum::http::HeaderValue::from_static(value));
    }
    response
}

/// The only browser origin allowed to call the attach session API (the forum
/// theme's composer integration).
const ATTACH_CORS_ORIGIN: &str = crate::FORUM_PUBLIC_URL;

/// CORS for the attach session endpoints, scoped to the forum origin only.
/// Handles the OPTIONS preflight itself. A predicate (not `exact`) so a
/// foreign origin receives NO allow-origin header at all.
fn attach_cors() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _| {
            origin.as_bytes() == ATTACH_CORS_ORIGIN.as_bytes()
        }))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}

/// The only browser origins allowed to call the guest intake endpoint. Today
/// exactly one of them has a form: `warren.ro/aide`. The checkout only links
/// to that page, so its grant covers a form that does not exist yet; keep it
/// only as long as that is the plan. `beta.warren.ro` is deliberately absent:
/// the beta build redirects `/aide` to its landing and points explorers at
/// the main site's form, so granting it would be a dead entry. Adding `/aide`
/// to the website's `BETA_ALLOWED` means adding the beta origin here in the
/// same change, or the form there is CORS-dead on arrival.
const INTAKE_CORS_ORIGINS: [&str; 2] = ["https://warren.ro", "https://checkout.warrenbrowse.com"];

/// CORS for the intake endpoint: exactly the two form origins, POST only.
/// A predicate (not a list) so a foreign origin receives NO allow-origin
/// header at all; the matching origin is echoed back by tower-http.
fn intake_cors() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _| {
            INTAKE_CORS_ORIGINS
                .iter()
                .any(|o| origin.as_bytes() == o.as_bytes())
        }))
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}

/// Builds the router.
pub fn router(state: Arc<AppState>) -> axum::Router {
    // The attach session API is called by fetch() from the forum theme, so
    // exactly these routes carry the forum-origin CORS layer.
    let attach_api = axum::Router::new()
        .route("/v1/attach/new", post(attach_new))
        .route("/v1/attach/{sid}/meta", get(attach_meta))
        .route("/v1/attach/{sid}/bind", post(attach_bind))
        .route("/v1/attach/{sid}/status", get(attach_status))
        .route("/v1/attach/{sid}/cancel", post(attach_cancel))
        .layer(attach_cors());
    // The intake endpoints are called by fetch() from the public help forms.
    // No DefaultBodyLimit layer on purpose: the body cap is applied inside
    // the handlers, AFTER the rate limiter, so a flood cannot make this
    // service buffer megabytes per request for free (see `guest_body`).
    let intake_api = axum::Router::new()
        .route("/v1/help/intake", post(help_intake))
        .route("/v1/help/reply", post(help_reply))
        .layer(intake_cors());
    axum::Router::new()
        .route("/sso", get(sso_entry))
        .route(
            "/v1/forum/login",
            // The body is `{"sid":"<32 hex>"}` and it is now parsed BEFORE the
            // signature verifies (the clock-skew cancel), so the cap is stated
            // rather than inherited (repo rule: every route with a body).
            post(forum_login).layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .route("/v1/session/{sid}/status", get(session_status))
        .route("/v1/session/{sid}/cancel", post(session_cancel))
        .route("/v1/session/{sid}/complete", get(session_complete))
        .route("/attach", get(attach_entry))
        .route(
            "/v1/forum/attach-logs",
            // Explicit, because axum's DEFAULT is 2 MiB and that silently was
            // the real ceiling on report size: the documented base64 cap sat
            // just under it by luck, and raising the cap alone would have
            // changed nothing. Must stay above MAX_LOG_GZ_B64_CHARS.
            post(forum_attach_logs).layer(axum::extract::DefaultBodyLimit::max(20 * 1024 * 1024)),
        )
        .route(
            "/v1/forum/report",
            // Same figure and same reason as attach-logs: the report carries
            // the same base64 gzip field, and the layer has to sit above
            // MAX_LOG_GZ_B64_CHARS or it, not the constant, is the ceiling.
            post(forum_report).layer(axum::extract::DefaultBodyLimit::max(20 * 1024 * 1024)),
        )
        .route(
            "/v1/forum/notifications",
            // Explicit, per the repo rule: the signed body is an empty JSON
            // object and nothing here ever grows, so the cap is tight rather
            // than inherited from axum's silent 2 MiB default.
            post(forum_notifications).layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .route(
            "/v1/forum/notifications/seen",
            post(forum_notifications_seen).layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .merge(attach_api)
        .merge(intake_api)
        .route("/transparency", get(transparency))
        .route("/internal/by-pubkey/{ss58}", get(lookup_by_pubkey))
        .route("/internal/by-handle/{username}", get(lookup_by_handle))
        .route("/internal/forum/digest", get(forum_digest))
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(base_security_headers))
        .with_state(state)
}

#[derive(Deserialize)]
struct SsoParams {
    sso: String,
    sig: String,
}

async fn sso_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<SsoParams>,
) -> Result<Response, AuthError> {
    let incoming = discourse::verify_incoming(
        &params.sso,
        &params.sig,
        &state.connect_secret,
        crate::FORUM_PUBLIC_URL,
    )?;
    let ids = state
        .sessions
        .create(incoming.nonce, incoming.return_sso_url, now_unix())?;
    let lang = crate::i18n::Lang::from_accept_language(accept_language(&headers));
    Ok(html_page(
        |nonce| pages::approval_page(lang, &ids, &state.public_host, nonce),
        false,
    ))
}

/// Extracts the raw `Accept-Language` header value, if present and valid UTF-8.
fn accept_language(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
}

#[derive(Deserialize)]
struct LoginBody {
    sid: String,
}

async fn forum_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let signed = extract_signed_headers(&headers)?;
    let now = now_unix();
    let identity = match verify_signed_request(
        &signed,
        "POST",
        "/v1/forum/login",
        &body,
        now,
        &state.nonces,
    ) {
        Ok(identity) => identity,
        Err(err) => {
            if matches!(err, AuthError::Clock) {
                // Best effort: without this the browser polls "pending" until
                // the TTL and the user never learns their clock is the cause.
                // The signature is NOT verified at this point, and that is
                // acceptable for the same reason `session_cancel` below takes
                // no signature at all: the sid is a 128-bit capability held by
                // the browser and the app, and the only power here is picking
                // which of two benign messages that browser shows.
                if let Ok(login) = serde_json::from_slice::<LoginBody>(&body) {
                    state.sessions.cancel(&login.sid, "clock_skew", now);
                }
                // The drift is a duration, not an identifier: logging it is
                // what turns a 100%-failure day into a one-grep diagnosis
                // (2026-08-18 left no application-side trace at all).
                tracing::info!(
                    drift_secs = now.abs_diff(signed.timestamp),
                    "forum login refused: client clock outside window"
                );
            } else {
                // Debug, not info: this route is public and unauthenticated,
                // so an info line per garbage request is a log amplifier.
                tracing::debug!(error = %err, "forum login auth refused");
            }
            return Err(err);
        }
    };

    let login: LoginBody = serde_json::from_slice(&body).map_err(|_| AuthError::Session)?;

    // Which of the session's two ids this approval arrived on. The QR is read
    // from a second device, which is exactly the shape of a relayed
    // (phished) approval, so nothing that GRANTS anything may ride on it.
    let (primary_sid, approach) = state.sessions.resolve(&login.sid, now)?;
    // A cancelled session cannot be approved (the browser already gave up on
    // it), so refuse here rather than after the lookup and the link upsert:
    // a corrected retry after a clock-skew cancel is the common shape.
    if state.sessions.is_cancelled(&primary_sid, now) {
        return Err(AuthError::Session);
    }

    let admitted = match admit_forum_identity(&state, &identity).await {
        Ok(admitted) => admitted,
        Err(AdmitError::NeverPaid) => {
            // Tell the browser so its approval page stops polling and explains why.
            state
                .sessions
                .cancel(&login.sid, "subscription_required", now);
            return Err(AuthError::SubscriptionRequired);
        }
        Err(AdmitError::Store) => return Err(AuthError::Session),
    };

    // Kept before the payload moves `username` into the session: the approving
    // client gets its own handle back (see `login_approved_body`).
    let handle_for_client = admitted.forum.username.clone();
    state.sessions.approve(
        &primary_sid,
        SsoUser {
            external_id: admitted.forum.external_id,
            username: admitted.forum.username,
            email: admitted.forum.email,
            member: admitted.status.ever_paid,
            subscriber: admitted.status.active,
            admin: staff_claim(admitted.admin, approach),
        },
        now,
    )?;

    tracing::info!(pubkey = %redact(&identity.pubkey_ss58), "forum login approved");
    Ok((
        StatusCode::OK,
        Json(login_approved_body(
            &handle_for_client,
            admitted.notify_slot,
        )),
    )
        .into_response())
}

/// A wallet that passed the forum gate, with everything the two admitting
/// routes need afterwards.
struct AdmittedIdentity {
    /// The derived pairwise forum identity.
    forum: handle::ForumHandle,
    /// Subscription standing, which decides the Discourse groups.
    status: store::SubscriptionStatus,
    /// On the bootstrap staff allowlist.
    admin: bool,
    /// The digest slot, absent when the allocator had no room.
    notify_slot: Option<i32>,
}

/// Why an admission was refused. The callers map it: the login cancels the
/// browser session with a reason, the report answers the app directly.
enum AdmitError {
    /// Never paid and not staff: the anti-sybil paywall.
    NeverPaid,
    /// The link could not be recorded (database).
    Store,
}

/// The one admission path of a wallet-signed forum identity, shared by the
/// login and the in-app report: the ever-paid gate, the link upsert and the
/// digest slot. Two routes with two copies of this block would be two gates
/// that can drift apart.
async fn admit_forum_identity(
    state: &AppState,
    identity: &crate::verify::VerifiedIdentity,
) -> Result<AdmittedIdentity, AdmitError> {
    // Staff is an allowlist, independent of payment: admins are operators and
    // must not be locked out of their own forum by the paywall.
    let admin = state.admins.is_admin(&identity.pubkey_ss58);

    // Access control: a forum account requires having paid for Warren at least
    // once (a wallet is free to mint, so with no email/no IP, payment is the
    // only sybil cost) unless the wallet is staff. A subscription-lookup failure
    // is treated as "never paid" so an outage fails closed rather than opening
    // the gate (an admin still passes on the allowlist).
    let status = state
        .identity
        .subscription_status(&identity.pubkey_ss58)
        .await
        .unwrap_or_else(|e| {
            // Log the sqlx error KIND only, never `%e` (a Postgres error detail
            // on the identity columns could echo a pubkey; no-log policy).
            tracing::error!(kind = ?sqlx_error_kind(&e), "subscription lookup failed");
            store::SubscriptionStatus::default()
        });
    if !login_allowed(status.ever_paid, admin) {
        tracing::info!(pubkey = %redact(&identity.pubkey_ss58), "forum admission refused: never paid");
        return Err(AdmitError::NeverPaid);
    }

    let forum = handle::derive(&state.handle_secret, &identity.pubkey);
    state
        .identity
        .upsert_link(&forum.external_id, &forum.username)
        .await
        .map_err(|e| {
            // Never `%e` here: a unique-constraint violation puts the offending
            // pubkey/handle in the Postgres error detail. Log the kind + a redacted
            // pubkey prefix only.
            tracing::error!(kind = ?sqlx_error_kind(&e), pubkey = %redact(&identity.pubkey_ss58), "link upsert failed");
            AdmitError::Store
        })?;

    // Best effort: an admission that cannot get a digest slot is still an
    // admission. The device simply shows no forum badge until the next one.
    let notify_slot = match state.identity.assign_notify_slot(&forum.external_id).await {
        Ok(slot) => slot,
        Err(e) => {
            tracing::error!(kind = ?sqlx_error_kind(&e), "notify slot assignment failed");
            None
        }
    };

    Ok(AdmittedIdentity {
        forum,
        status,
        admin,
        notify_slot,
    })
}

/// The identity fields an admitting route hands back to the wallet: the
/// handle (keyed derivation, so this is the only place a client learns it)
/// and the digest slot, omitted rather than null when none was drawn.
fn identity_fields(
    handle: &str,
    notify_slot: Option<i32>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "handle".into(),
        serde_json::Value::String(handle.to_owned()),
    );
    if let Some(slot) = notify_slot {
        fields.insert("notify_slot".into(), serde_json::Value::from(slot));
    }
    fields
}

/// Body of an approved login. Carries the handle back to the wallet that just
/// signed: the derivation is keyed by `FORUM_HANDLE_SECRET`, so a client cannot
/// compute its own forum name and this is the only place it learns it. Nothing
/// is stored to make this possible, the value is already in hand.
///
/// The digest slot rides along for the same reason: it is drawn server side
/// and the device has no other way to learn which position of the broadcast
/// document is its own. It is absent when the allocator had no room, which
/// costs the device its badge until the next login and nothing else.
fn login_approved_body(handle: &str, notify_slot: Option<i32>) -> serde_json::Value {
    let mut body = identity_fields(handle, notify_slot);
    body.insert("status".into(), "approved".into());
    serde_json::Value::Object(body)
}

/// The caller's own forum notifications, for the app's activity panel.
///
/// Wallet-signed like the login, and the account read is derived from that
/// signature rather than named in the request, so this endpoint cannot be
/// pointed at anyone else. It is called when the user opens the panel, never
/// on a timer: the badge itself comes from the broadcast digest, which asks
/// the server nothing about anybody.
///
/// A wallet with no forum link gets an empty list without Discourse being
/// touched at all.
async fn forum_notifications(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let signed = extract_signed_headers(&headers)?;
    let identity = verify_signed_request(
        &signed,
        "POST",
        "/v1/forum/notifications",
        &body,
        now_unix(),
        &state.nonces,
    )?;
    let discourse_pool = state
        .discourse_pool
        .as_ref()
        .ok_or(AuthError::FeatureDisabled)?;

    let forum = handle::derive(&state.handle_secret, &identity.pubkey);
    let registered = store::username_for_external_id(&state.forum_pool, &forum.external_id)
        .await
        .map_err(|e| {
            tracing::error!(kind = ?sqlx_error_kind(&e), "notifications: link lookup failed");
            AuthError::Session
        })?;
    if registered.is_none() {
        return Ok(Json(serde_json::json!({ "notifications": [] })).into_response());
    }

    let rows = store::notifications_for_username(
        discourse_pool,
        &forum.username,
        crate::digest::MAX_UNREAD_AGE_DAYS,
        crate::notifications::MAX_NOTIFICATIONS,
    )
    .await
    .map_err(|e| {
        tracing::error!(kind = ?sqlx_error_kind(&e), "notifications: query failed");
        AuthError::Session
    })?;

    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "kind": crate::notifications::kind_for(r.notification_type),
                "unread": r.unread,
                "created_at": r.created_unix,
                "title": r.title,
                "actor": r.actor,
                "excerpt": crate::notifications::excerpt(r.raw.as_deref()),
                "path": crate::notifications::path_for(
                    r.notification_type,
                    r.topic_id,
                    r.post_number,
                    &forum.username,
                    r.group_name.as_deref(),
                ),
            })
        })
        .collect();

    // The count is operator-useful and carries no identity; the handle, the
    // titles and the bodies never reach a log line.
    tracing::info!(count = items.len(), "forum notifications served");
    Ok(Json(serde_json::json!({ "notifications": items })).into_response())
}

/// Marks the caller's own notification list as seen, which is exactly what
/// the forum does when a reader opens their own bell.
///
/// The only write this service makes into Discourse, and the narrowest one
/// available: a single integer column that can only move forward, on a row
/// selected by a username derived from the signature. It carries no content,
/// so nothing can be lost, edited or published through it. The database
/// grant is `UPDATE (seen_notification_id) ON users` and nothing more, so
/// that bound holds even if this handler is wrong.
///
/// Uses its own connection, `seen_pool`, rather than the SELECT-only pool the
/// count and the panel read through: leaving those two unable to write is
/// worth a second pool. Unset disables this endpoint and nothing else.
async fn forum_notifications_seen(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let signed = extract_signed_headers(&headers)?;
    let identity = verify_signed_request(
        &signed,
        "POST",
        "/v1/forum/notifications/seen",
        &body,
        now_unix(),
        &state.nonces,
    )?;
    let seen_pool = state.seen_pool.as_ref().ok_or(AuthError::FeatureDisabled)?;

    let forum = handle::derive(&state.handle_secret, &identity.pubkey);
    let registered = store::username_for_external_id(&state.forum_pool, &forum.external_id)
        .await
        .map_err(|e| {
            tracing::error!(kind = ?sqlx_error_kind(&e), "seen: link lookup failed");
            AuthError::Session
        })?;
    if registered.is_none() {
        // A wallet that never logged in to the forum has no list to mark, and
        // Discourse is not touched at all.
        return Ok(Json(serde_json::json!({ "seen": false })).into_response());
    }

    store::mark_seen_for_username(seen_pool, &forum.username)
        .await
        .map_err(|e| {
            tracing::error!(kind = ?sqlx_error_kind(&e), "seen: update failed");
            AuthError::Session
        })?;

    // No handle and no bookmark value: both identify the account.
    tracing::info!("forum notification list marked seen");
    Ok(Json(serde_json::json!({ "seen": true })).into_response())
}

/// The broadcast forum-activity digest, in its unsigned internal form:
/// one unread count per slot, plus the generation warren-core signs it under.
///
/// Internal-only. warren-core is the single caller: it packs, signs with the
/// online server key and serves the result to clients. Splitting it that way
/// keeps the signing key on the API host and keeps this service out of the
/// client's trust path.
async fn forum_digest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !internal_authorized(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let discourse_pool = state
        .discourse_pool
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let links = store::link_count(&state.forum_pool).await.map_err(|e| {
        tracing::error!(kind = ?sqlx_error_kind(&e), "digest: link count failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let slots = store::slots_by_username(&state.forum_pool)
        .await
        .map_err(|e| {
            tracing::error!(kind = ?sqlx_error_kind(&e), "digest: slot map failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let unread = store::unread_by_username(discourse_pool, crate::digest::MAX_UNREAD_AGE_DAYS)
        .await
        .map_err(|e| {
            tracing::error!(kind = ?sqlx_error_kind(&e), "digest: unread query failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let published = crate::digest::published_slots(usize::try_from(links).unwrap_or(0));
    let counts = crate::digest::assemble(published, &crate::digest::join_unread(&slots, &unread));
    let generation = state.digest_generation.stamp(&counts, now_unix());

    Ok(Json(
        serde_json::json!({ "generation": generation, "counts": counts }),
    ))
}

/// App-initiated cancel (the user declined the consent popup). No signature:
/// the `sid` is a 128-bit opaque secret held only by the browser and the app,
/// so cancelling by sid is not a meaningful attack surface.
async fn session_cancel(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Json<serde_json::Value> {
    state.sessions.cancel(&sid, "user_cancelled", now_unix());
    Json(serde_json::json!({"status": "cancelled"}))
}

async fn session_status(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let status = state.sessions.status(&sid, now_unix())?;
    Ok(Json(match status {
        SessionStatus::Pending => serde_json::json!({ "status": "pending" }),
        SessionStatus::Approved => serde_json::json!({ "status": "approved" }),
        SessionStatus::Cancelled { reason } => {
            serde_json::json!({ "status": "cancelled", "reason": reason })
        }
    }))
}

async fn session_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Result<Redirect, AuthError> {
    let done = state.sessions.consume(&sid, now_unix())?;
    // This endpoint is hit by the user's browser, so its Accept-Language is
    // the user's real preference: forwarded so Discourse creates the account
    // in that interface language (first login only, never overrides later
    // user choice).
    let locale = crate::i18n::preferred_locale_subtag(accept_language(&headers));
    let (sso, sig) = discourse::build_outgoing(
        &done.nonce,
        &done.user,
        locale.as_deref(),
        &state.connect_secret,
    );
    let url = format!(
        "{}?sso={}&sig={}",
        done.return_sso_url,
        urlencoding::encode(&sso),
        sig
    );
    Ok(Redirect::to(&url))
}

/// Requires the Discourse admin API to be configured; every attach-logs
/// surface is disabled as a unit when the key is absent.
fn forum_api_enabled(state: &AppState) -> Result<&ForumApi, AuthError> {
    state.forum_api.as_ref().ok_or(AuthError::FeatureDisabled)
}

#[derive(Deserialize)]
struct AttachParams {
    topic: Option<u64>,
    sid: Option<String>,
}

async fn attach_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<AttachParams>,
) -> Result<Response, AuthError> {
    forum_api_enabled(&state)?;
    let lang = crate::i18n::Lang::from_accept_language(accept_language(&headers));
    match (params.topic, params.sid) {
        // Topic mode: mints (or reuses) a session bound to an existing topic.
        (Some(topic), _) if topic >= 1 => {
            let sid = state.attach.create(topic, now_unix())?;
            Ok(html_page(
                |nonce| pages::attach_page(lang, &sid, topic, &state.public_host, nonce),
                false,
            ))
        }
        // Pre-topic mode: reuses the session minted by /v1/attach/new.
        (None, Some(sid)) => {
            state.attach.pre_exists(&sid, now_unix())?;
            Ok(html_page(
                |nonce| pages::attach_page_pre(lang, &sid, &state.public_host, nonce),
                false,
            ))
        }
        _ => Err(AuthError::Payload),
    }
}

async fn attach_new(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AuthError> {
    forum_api_enabled(&state)?;
    let sid = state.attach.create_pre(now_unix())?;
    Ok(Json(serde_json::json!({"sid": sid})))
}

#[derive(Deserialize)]
struct AttachLogsBody {
    sid: String,
    topic_id: u64,
    log_gz_b64: String,
}

async fn forum_attach_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let api = forum_api_enabled(&state)?;
    let signed = extract_signed_headers(&headers)?;
    let now = now_unix();
    let identity = verify_signed_request(
        &signed,
        "POST",
        "/v1/forum/attach-logs",
        &body,
        now,
        &state.nonces,
    )?;

    // Every refusal below reaches the reporter as a generic failure, so each
    // branch names itself here: without this, four attach attempts against a
    // live service left zero server-side trace and the incident was
    // reconstructed from Discourse's request log alone.
    let req: AttachLogsBody = serde_json::from_slice(&body).map_err(|_| {
        tracing::info!(
            pubkey = %redact(&identity.pubkey_ss58),
            "attach-logs refused: body is not valid JSON"
        );
        AuthError::Payload
    })?;
    if req.log_gz_b64.len() > attach::MAX_LOG_GZ_B64_CHARS {
        tracing::info!(
            pubkey = %redact(&identity.pubkey_ss58),
            b64_chars = req.log_gz_b64.len(),
            "attach-logs refused: base64 field over the size cap"
        );
        return Err(AuthError::PayloadTooLarge);
    }
    let kind = state.attach.begin(&req.sid, req.topic_id, now)?;
    let forum = handle::derive(&state.handle_secret, &identity.pubkey);

    // Pre-topic session: no topic exists yet, so the report is parked in the
    // session (with the signer's handle for the author check at bind time).
    if kind == AttachKind::PreTopic {
        let (log_text, (version, os)) =
            decode_report(&req.log_gz_b64, &identity.pubkey_ss58, None)?;
        state
            .attach
            .store_received(&req.sid, &forum.username, log_text, version, os, now)?;
        tracing::info!(
            pubkey = %redact(&identity.pubkey_ss58),
            "pre-topic report received"
        );
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({"status": "received"})),
        )
            .into_response());
    }

    // Only the topic author may attach logs to it: the wallet proves itself
    // via the signature, the topic proves its author via Discourse, and the
    // deterministic handle bridges the two.
    let topic = api.topic(req.topic_id).await?;
    if !topic.author_username.eq_ignore_ascii_case(&forum.username) {
        tracing::info!(
            pubkey = %redact(&identity.pubkey_ss58),
            topic_id = req.topic_id,
            "attach-logs refused: signer is not the topic author"
        );
        return Err(AuthError::NotAuthor);
    }

    let (log_text, meta) =
        decode_report(&req.log_gz_b64, &identity.pubkey_ss58, Some(req.topic_id))?;

    // Discourse writes; the session is marked done only after all of them, so
    // a mid-flight failure leaves it retryable. A retry re-runs every write:
    // acceptable because a partial Discourse failure is rare and a manual
    // re-attach that duplicates a staff PM is preferable to losing the logs.
    // Flagged only past the author check, and cleared if the writes fail: the
    // page shows progress exactly while there is progress to show.
    state.attach.mark_processing(&req.sid);
    if let Err(err) = deliver_to_staff(api, req.topic_id, &topic, log_text, meta, now).await {
        state.attach.clear_processing(&req.sid);
        return Err(err);
    }

    state.attach.complete(&req.sid, now_unix())?;
    tracing::info!(
        pubkey = %redact(&identity.pubkey_ss58),
        topic_id = req.topic_id,
        "forum logs attached"
    );
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "attached"})),
    )
        .into_response())
}

/// The Discourse writes shared by the topic-mode upload and the pre-topic
/// bind: upload the log, PM the staff group, whisper on the topic, and post a
/// public note with the safe facts. `meta` is the already-parsed
/// (version, os); the caller parses it once so bind does not re-parse the
/// whole report.
async fn deliver_to_staff(
    api: &ForumApi,
    topic_id: u64,
    topic: &forum_api::TopicInfo,
    log_text: String,
    meta: attach::ReportMeta,
    now: u64,
) -> Result<(), AuthError> {
    let upload = upload_report(api, log_text, now, Some(topic_id)).await?;
    notify_staff(api, topic_id, topic, &upload, meta).await
}

/// A report uploaded to Discourse, not yet linked from anywhere.
struct UploadedReport {
    filename: String,
    upload: forum_api::UploadedFile,
}

/// Uploads the decompressed report as a `.log` attachment. Separate from the
/// writes that link it because the in-app report uploads BEFORE it creates
/// the topic: a topic must never be published having silently lost the logs
/// the reporter was told would come with it.
async fn upload_report(
    api: &ForumApi,
    log_text: String,
    now: u64,
    topic_id: Option<u64>,
) -> Result<UploadedReport, AuthError> {
    // The topic id is in the name when it exists: staff sort attachments by
    // it. The in-app report uploads first, so its file carries the time only.
    let filename = match topic_id {
        Some(id) => format!("warren-report-topic{id}-{now}.log"),
        None => format!("warren-report-{now}.log"),
    };
    let upload = api
        .upload_file(&filename, "text/plain", log_text.into_bytes())
        .await?;
    Ok(UploadedReport { filename, upload })
}

/// The writes that put an uploaded report in front of the staff: PM to the
/// staff group, whisper on the topic, public note with the safe facts, then
/// the best-effort receipt and tag.
async fn notify_staff(
    api: &ForumApi,
    topic_id: u64,
    topic: &forum_api::TopicInfo,
    uploaded: &UploadedReport,
    meta: attach::ReportMeta,
) -> Result<(), AuthError> {
    let filename = &uploaded.filename;
    let upload = &uploaded.upload;
    let pm_topic_id = api
        .create_staff_pm(
            &forum_api::pm_title(topic_id, &topic.title),
            &forum_api::pm_raw(
                topic_id,
                &topic.title,
                &topic.author_username,
                filename,
                &upload.short_url,
            ),
        )
        .await?;
    api.post_whisper(topic_id, &forum_api::whisper_raw(pm_topic_id))
        .await?;
    // Publish only the safe-to-publish facts (app version, OS) so the public
    // thread carries the context the form would have asked for, while the
    // note itself states that the full logs stay staff-only.
    let (version, os) = meta;
    if let Some(note) = forum_api::public_note_raw(version.as_deref(), os.as_deref()) {
        api.post_reply(topic_id, &note).await?;
    }
    // Receipt to the reporter. The public topic shows no trace of the logs and
    // the whisper is staff-only, so without this the author has no way to know
    // their upload landed. Best effort like the tag: a failed receipt must not
    // fail a delivered report.
    if let Err(err) = api
        .create_author_pm(
            &topic.author_username,
            &forum_api::author_pm_title(topic_id),
            &forum_api::author_pm_raw(topic_id, &topic.title),
        )
        .await
    {
        tracing::warn!(
            error = %err,
            topic_id,
            "logs delivered but the author receipt could not be sent"
        );
    }

    // Best effort, and deliberately last: the logs are already with the staff,
    // so a tagging failure must not turn a delivered report into an error the
    // reporter would retry. It only costs the theme its quiet-button signal.
    if let Err(err) = api.tag_logs_attached(topic_id, &topic.tags).await {
        tracing::warn!(
            error = %err,
            topic_id,
            "logs delivered but the topic could not be tagged"
        );
    }
    Ok(())
}

/// Decodes and inflates a signed report field, naming the refusal in the log
/// (every one reaches the reporter as a generic failure otherwise). `topic_id`
/// is `None` for a report that has no topic yet.
fn decode_report(
    log_gz_b64: &str,
    pubkey_ss58: &str,
    topic_id: Option<u64>,
) -> Result<(String, attach::ReportMeta), AuthError> {
    let gz = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, log_gz_b64)
        .map_err(|_| {
            tracing::info!(
                pubkey = %redact(pubkey_ss58),
                topic_id,
                "report refused: log_gz_b64 is not valid base64"
            );
            AuthError::Payload
        })?;
    let log_text = attach::gunzip_capped(&gz).inspect_err(|_| {
        tracing::info!(
            pubkey = %redact(pubkey_ss58),
            topic_id,
            gz_bytes = gz.len(),
            "report refused: payload does not gunzip to UTF-8 under the cap"
        );
    })?;
    let meta = attach::parse_report_metadata(&log_text);
    Ok((log_text, meta))
}

/// Wallet-signed in-app bug report: a topic in the bug-reports category owned
/// by the reporter's own forum account (created through `sync_sso` when it
/// does not exist yet), plus the redacted logs delivered to the staff exactly
/// as attach-logs delivers them. For the user who cannot complete the browser
/// sign-in, and therefore cannot file the report from the forum.
///
/// Order before the first Discourse call: validate, gate, budget, decode.
/// The JSON shape and the field caps are checked first because they are
/// cheap; the subscription gate and the per-wallet budget come next because a
/// wallet is free to mint; the gunzip comes last because it is the expensive
/// step (up to 32 MiB per request) and only an admitted member in budget may
/// make the server do it.
///
/// Order of the Discourse writes: account sync, upload, topic, then the staff
/// notifications. Nothing public exists until the parts that can fail cheaply
/// have succeeded; past the topic a failure is answered as `partial` rather
/// than as an error the client would retry into a duplicate topic.
async fn forum_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let report_state = state.report.as_ref().ok_or(AuthError::FeatureDisabled)?;
    let api = forum_api_enabled(&state)?;
    let signed = extract_signed_headers(&headers)?;
    let now = now_unix();
    let identity = verify_signed_request(
        &signed,
        "POST",
        "/v1/forum/report",
        &body,
        now,
        &state.nonces,
    )
    .inspect_err(|err| {
        if matches!(err, AuthError::Clock) {
            tracing::info!(
                drift_secs = now.abs_diff(signed.timestamp),
                "report refused: client clock outside window"
            );
        } else {
            tracing::debug!(error = %err, "report auth refused");
        }
    })?;

    let req: crate::report::ReportRequest = serde_json::from_slice(&body).map_err(|_| {
        tracing::info!(pubkey = %redact(&identity.pubkey_ss58), "report refused: body is not valid JSON");
        AuthError::InvalidReport
    })?;
    crate::report::validate(&req)?;

    let admitted = admit_forum_identity(&state, &identity)
        .await
        .map_err(|err| match err {
            AdmitError::NeverPaid => AuthError::SubscriptionRequired,
            AdmitError::Store => AuthError::Forum,
        })?;
    // Charged after the signature and the gate: a forged or never-paid
    // request must not burn a member's budget.
    report_state
        .limiter
        .admit(admitted.forum.external_id.clone(), now)?;

    // Inflated only past the gate and the budget: the gunzip is the costly
    // step and a never-paid wallet must not be able to buy it for the price
    // of a signature. Still before any write, so a broken payload costs no
    // Discourse call.
    let decoded = match req.log_gz_b64.as_deref() {
        Some(b64) => Some(decode_report(b64, &identity.pubkey_ss58, None)?),
        None => None,
    };

    // The account the topic will belong to. Never staff on this path: no
    // browser is involved, so nothing proves the same-device approval that
    // `staff_claim` requires, and a report must not be able to mint staff.
    let user = SsoUser {
        external_id: admitted.forum.external_id.clone(),
        username: admitted.forum.username.clone(),
        email: admitted.forum.email.clone(),
        member: admitted.status.ever_paid,
        subscriber: admitted.status.active,
        admin: false,
    };
    let (sso, sig) =
        discourse::build_sync_payload(&user, req.locale.as_deref(), &state.connect_secret);
    let synced = api.sync_sso(&sso, &sig).await?;
    if !synced
        .username
        .eq_ignore_ascii_case(&admitted.forum.username)
    {
        // A suffixed or renamed account would fail every later author check
        // (attach-logs, bind) for this wallet: refuse rather than publish
        // under a name the derivation does not produce.
        tracing::error!(
            pubkey = %redact(&identity.pubkey_ss58),
            "report refused: forum settled on a username other than the derived handle"
        );
        return Err(AuthError::Forum);
    }

    let uploaded = match decoded {
        Some((log_text, meta)) => Some((upload_report(api, log_text, now, None).await?, meta)),
        None => None,
    };

    let reference = crate::intake::short_id();
    let title = crate::report::topic_title(&req, &reference);
    let raw = crate::report::topic_raw(&req);
    let platform = req.platform.tag();
    let topic_id = report_state
        .topic_api
        .as_user(&admitted.forum.username)
        .create_topic(&title, &raw, report_state.category_id, &[platform])
        .await?;

    // From here the topic exists: a staff-side failure is reported, never
    // answered as an error (the client would file the same topic twice).
    let logs = match uploaded {
        None => "none",
        Some((upload, meta)) => {
            let topic = forum_api::TopicInfo {
                title: title.clone(),
                author_username: admitted.forum.username.clone(),
                tags: vec![platform.to_owned()],
                locked: false,
            };
            // The client-declared facts fill in for a report whose header
            // carried none, so the public note is never empty for lack of
            // metadata the app knew.
            let (version, os) = meta;
            let meta = (
                version.or_else(|| req.app_version.clone()),
                os.or_else(|| req.os_version.clone()),
            );
            match notify_staff(api, topic_id, &topic, &upload, meta).await {
                Ok(()) => "attached",
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        topic_id,
                        "report topic created but the staff delivery did not complete"
                    );
                    "partial"
                }
            }
        }
    };

    tracing::info!(
        pubkey = %redact(&identity.pubkey_ss58),
        topic_id,
        platform,
        area = req.area.short(),
        logs,
        "in-app report topic created"
    );
    let mut body = identity_fields(&admitted.forum.username, admitted.notify_slot);
    body.insert("status".into(), "created".into());
    body.insert("topic_id".into(), topic_id.into());
    body.insert(
        "topic_url".into(),
        format!("{}/t/{topic_id}", crate::forum_api::FORUM_PUBLIC_URL).into(),
    );
    body.insert("logs".into(), logs.into());
    Ok((StatusCode::CREATED, Json(serde_json::Value::Object(body))).into_response())
}

#[derive(Deserialize)]
struct BindBody {
    topic_id: u64,
}

/// Binds a received pre-topic session to the topic the forum theme just
/// created: author check, then the three Discourse writes, then done.
async fn attach_bind(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
    body: Result<Json<BindBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AuthError> {
    let api = forum_api_enabled(&state)?;
    let Json(bind) = body.map_err(|_| AuthError::Payload)?;
    if bind.topic_id == 0 {
        return Err(AuthError::Payload);
    }
    let now = now_unix();
    let data = state.attach.bind_data(&sid, now)?;

    let topic = api.topic(bind.topic_id).await?;
    if !topic.author_username.eq_ignore_ascii_case(&data.username) {
        tracing::info!(
            topic_id = bind.topic_id,
            "bind refused: not the topic author"
        );
        return Err(AuthError::NotAuthor);
    }

    // On failure the session stays Received (log still parked), retryable.
    let meta = (data.version, data.os);
    deliver_to_staff(api, bind.topic_id, &topic, data.log_text, meta, now).await?;

    state.attach.complete(&sid, now_unix())?;
    tracing::info!(
        topic_id = bind.topic_id,
        "pre-topic logs bound and attached"
    );
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "attached"})),
    )
        .into_response())
}

/// Report metadata for the composer prefill. Exposes only the parsed version
/// and os strings, never the handle or the log content.
async fn attach_meta(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    forum_api_enabled(&state)?;
    Ok(Json(match state.attach.meta(&sid, now_unix())? {
        None => serde_json::json!({"status": "pending"}),
        Some((version, os)) => {
            serde_json::json!({"status": "received", "version": version, "os": os})
        }
    }))
}

async fn attach_status(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    forum_api_enabled(&state)?;
    let status = state.attach.status(&sid, now_unix())?;
    Ok(Json(match status {
        AttachStatus::Pending => serde_json::json!({ "status": "pending" }),
        AttachStatus::Processing => serde_json::json!({ "status": "processing" }),
        AttachStatus::Received => serde_json::json!({ "status": "received" }),
        AttachStatus::Done => serde_json::json!({ "status": "done" }),
        AttachStatus::Cancelled { reason } => {
            serde_json::json!({ "status": "cancelled", "reason": reason })
        }
    }))
}

/// App-initiated cancel. No signature for the same reason as
/// [`session_cancel`]: the sid is an opaque 128-bit capability.
async fn attach_cancel(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    forum_api_enabled(&state)?;
    state.attach.cancel(&sid, "user_cancelled", now_unix());
    Ok(Json(serde_json::json!({"status": "cancelled"})))
}

/// Client IP for the intake rate limiter: rightmost `X-Forwarded-For` entry
/// (the service sits behind the shared Caddy, which appends it). When the header is
/// missing or unparseable (direct hit on the container port), `None` puts the
/// request in one shared fail-closed bucket rather than bypassing the limit.
/// The IP goes to the in-memory limiter window ONLY: never logged, never
/// persisted, never forwarded to Discourse (no-log doctrine).
fn intake_client_ip(headers: &HeaderMap) -> Option<std::net::IpAddr> {
    // Rightmost entry: proxies APPEND the peer they saw, so the last value
    // is the one our own Caddy wrote (the real client), while the leftmost
    // is attacker-controlled. Trusting the left end would let one host
    // rotate fake IPs and dodge the per-IP budget entirely.
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse().ok())
}

/// Largest intake body accepted. Sized for the form's ceiling: two files of
/// [`crate::intake::MAX_ATTACHMENT_BYTES`], which base64 inflates by a third,
/// plus the message and JSON overhead.
const MAX_INTAKE_BODY: usize = 12 * 1024 * 1024;

/// Admits, caps and buffers the body of a public guest request.
///
/// Shared by the two guest endpoints so a rule can never hold on one and not
/// the other: JSON media type (the CSRF boundary), declared length refused
/// before a byte is read, rate limit charged BEFORE buffering, then the read
/// itself bounded again for a body that hid its length.
async fn guest_body(
    request: axum::extract::Request,
    limiter: &crate::intake::RateLimiter,
) -> Result<axum::body::Bytes, AuthError> {
    let headers = request.headers();
    // Require the JSON media type. Beyond hygiene this is a CSRF boundary:
    // application/json is NOT a CORS "simple request" content type, so a
    // cross-origin browser call must preflight, and the preflight is only
    // granted to the allowlisted origins. Without this check any web page
    // could fire text/plain POSTs from its visitors' browsers (side effects
    // land even though the response stays unreadable).
    let is_json = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        });
    if !is_json {
        return Err(AuthError::InvalidIntake);
    }
    // Refuse an over-cap body on its declared length alone, before reading a
    // single byte of it.
    let declared_len = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared_len.is_some_and(|len| len > MAX_INTAKE_BODY) {
        return Err(AuthError::PayloadTooLarge);
    }
    let client_ip = intake_client_ip(headers);

    // Rate-limit before buffering, not just before parsing: attachments took
    // the cap from 32 KiB to megabytes, and admitting the body first would
    // let one unlimited sender make this service allocate that much per
    // request. Past the limit nothing is read at all.
    limiter.admit(client_ip, now_unix())?;

    // A body that outgrows the cap without declaring it (chunked) dies here
    // instead. The pre-check above makes the size the only realistic cause.
    axum::body::to_bytes(request.into_body(), MAX_INTAKE_BODY)
        .await
        .map_err(|_| AuthError::PayloadTooLarge)
}

/// Uploads the decoded attachments and returns them as topic links.
///
/// Upload first, link second: a failed upload aborts the whole request so the
/// guest retries, instead of publishing a post that silently lost the
/// screenshots they were told would be published.
async fn upload_attachments(
    api: &ForumApi,
    attachments: Vec<crate::intake::DecodedAttachment>,
) -> Result<Vec<crate::intake::LinkedAttachment>, AuthError> {
    let mut linked = Vec::with_capacity(attachments.len());
    for att in attachments {
        let upload = api
            .upload_file(&att.filename, att.kind.mime, att.bytes)
            .await?;
        linked.push(crate::intake::LinkedAttachment {
            filename: att.filename,
            short_url: upload.short_url,
            is_image: att.kind.is_image,
        });
    }
    Ok(linked)
}

/// Public, unauthenticated guest help intake: opens a PUBLIC Discourse topic
/// on the guest's behalf (they cannot pass the ever-paid SSO gate) and
/// returns its URL so the guest can follow the staff answer without an
/// account, plus the follow-up code that lets them answer it. Design record:
/// warren-core `docs/58-SUPPORT-STAFF-GUIDE.md` 9.1.
async fn help_intake(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
) -> Result<Response, AuthError> {
    let intake = state.intake.as_ref().ok_or(AuthError::FeatureDisabled)?;
    let body = guest_body(request, &intake.limiter).await?;

    // Malformed JSON and an unknown `kind` get the same 422 as a limit
    // violation: one uniform rejection for everything the form never sends.
    let req: crate::intake::IntakeRequest =
        serde_json::from_slice(&body).map_err(|_| AuthError::InvalidIntake)?;
    crate::intake::validate(&req)?;
    let attachments = crate::intake::decode_attachments(&req.attachments)?;
    let linked = upload_attachments(&intake.api, attachments).await?;

    let reference = crate::intake::short_id();
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let title = crate::intake::topic_title(req.kind, &date, &reference);
    let raw = crate::intake::topic_raw(req.kind, &req.message, req.platform.as_deref(), &linked);
    let topic_id = intake
        .api
        .create_topic(&title, &raw, intake.category_id, &[])
        .await?;

    // The reference is random and guest-chosen content stays out of the log.
    // The code is NOT logged: it is the credential that lets its holder post
    // as this reporter, and it exists in exactly one place, their screen.
    tracing::info!(
        kind = req.kind.token(),
        reference = %reference,
        attachments = linked.len(),
        "guest intake topic created"
    );
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "topic_url": format!("{}/t/{topic_id}", crate::forum_api::FORUM_PUBLIC_URL),
            "reference": reference,
            "code": intake.ticket.issue(topic_id)?,
        })),
    )
        .into_response())
}

/// Public, unauthenticated guest follow-up: posts into the topic the code was
/// issued for, as the same intake bot that opened it. This is the only way a
/// guest can answer staff, since they have no forum account and the ever-paid
/// SSO gate is what they failed in the first place.
async fn help_reply(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
) -> Result<Response, AuthError> {
    let intake = state.intake.as_ref().ok_or(AuthError::FeatureDisabled)?;
    let body = guest_body(request, &intake.reply_limiter).await?;

    let req: crate::intake::ReplyRequest =
        serde_json::from_slice(&body).map_err(|_| AuthError::InvalidIntake)?;
    crate::intake::validate_reply(&req)?;
    // Before decoding attachments: a wrong code must cost nothing beyond the
    // rate-limit slot it already paid.
    let topic_id = intake.ticket.verify(&req.code)?;
    let attachments = crate::intake::decode_attachments(&req.attachments)?;

    // The code is unforgeable, so this check is defence in depth: it makes a
    // bug in code issuance unable to turn into a post in a topic the intake
    // bot does not own (a staff PM, another member's report).
    let topic = intake.api.topic(topic_id).await.map_err(dead_topic)?;
    if !topic
        .author_username
        .eq_ignore_ascii_case(intake.api.api_username())
    {
        return Err(AuthError::InvalidTicket);
    }
    // A closed or archived topic refuses a post from the low-privilege intake
    // bot, so without this the guest would meet a 502 and retry it forever.
    // Answering with the code error instead is both the truthful outcome (the
    // code no longer opens anything) and the one the help form already
    // renders, and it hands staff the only revocation lever these codes have:
    // closing the conversation ends it.
    if topic.locked {
        return Err(AuthError::InvalidTicket);
    }

    let linked = upload_attachments(&intake.api, attachments).await?;
    let raw = crate::intake::reply_raw(&req.message, &linked);
    let post_number = intake.api.post_reply(topic_id, &raw).await?;

    // Straight to their own post when Discourse says where it landed, to the
    // topic otherwise: the guest is never left without a link.
    let base = crate::forum_api::FORUM_PUBLIC_URL;
    let topic_url = match post_number {
        Some(n) => format!("{base}/t/{topic_id}/{n}"),
        None => format!("{base}/t/{topic_id}"),
    };
    tracing::info!(attachments = linked.len(), "guest follow-up posted");
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "topic_url": topic_url })),
    )
        .into_response())
}

/// A topic a valid code points at but Discourse will not serve (deleted,
/// moved out of reach) is a dead code, not a backend failure: the guest is
/// told their code is unknown rather than to retry a 502 forever.
fn dead_topic(err: forum_api::ForumApiError) -> AuthError {
    match err {
        forum_api::ForumApiError::Status {
            status: 403 | 404 | 410,
            ..
        } => AuthError::InvalidTicket,
        other => other.into(),
    }
}

async fn transparency(headers: HeaderMap) -> Response {
    let lang = crate::i18n::Lang::from_accept_language(accept_language(&headers));
    // No session id in the markup, so this one may be cached.
    html_page(|nonce| pages::transparency_page(lang, nonce), true)
}

/// Constant-time-ish bearer check for the internal support endpoints. Empty
/// configured token = feature disabled (always rejects).
fn internal_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    if state.internal_token.is_empty() {
        return false;
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| {
            // Length-independent equality via HMAC would be overkill here; the
            // token is a 32-byte random secret on a private network.
            bool::from(t.as_bytes().ct_eq(state.internal_token.as_bytes()))
        })
}

async fn lookup_by_pubkey(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ss58): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !internal_authorized(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let pubkey = warren_contract::ss58::decode(&ss58).map_err(|_| StatusCode::BAD_REQUEST)?;
    // Handle is deterministic: recompute it even for a wallet that never
    // logged in, so support can answer "what is this customer's handle".
    let derived = handle::derive(&state.handle_secret, &pubkey);
    // external_id (the keyed hash of the pubkey) is the join key now; no
    // cleartext pubkey is stored, so we look up by the re-derived external_id.
    let registered = store::username_for_external_id(&state.forum_pool, &derived.external_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Subscription standing for support diagnostics (admins are backend admins
    // anyway). Payment amounts stay out of reach by design (payment_ledger has
    // no identity columns), so this exposes only ever-paid / active / expiry.
    let sub = store::subscription_status(&state.warren_pool, &ss58)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "pubkey_ss58": ss58,
        "handle": derived.username,
        "registered": registered.is_some(),
        "ever_paid": sub.ever_paid,
        "active": sub.active,
        "expires_at_unix": sub.expires_at_unix,
    })))
}

async fn lookup_by_handle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !internal_authorized(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // The reverse handle -> pubkey lookup is gone by design: warren-connect no
    // longer stores a cleartext wallet, only the keyed external_id. Support can
    // confirm the handle exists but cannot resolve it back to a wallet.
    let exists = store::username_exists(&state.forum_pool, &username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "username": username,
        "registered": exists,
        "pubkey_ss58": serde_json::Value::Null,
    })))
}

fn extract_signed_headers(headers: &HeaderMap) -> Result<SignedHeaders, AuthError> {
    let text = |name: &str| -> Result<String, AuthError> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or(AuthError::Header)
    };
    let timestamp: u64 = text(HEADER_TIMESTAMP)?
        .parse()
        .map_err(|_| AuthError::Header)?;
    Ok(SignedHeaders {
        pubkey_ss58: text(HEADER_PUBKEY)?,
        signature_hex: text(HEADER_SIGNATURE)?,
        timestamp,
        nonce_hex: text(HEADER_NONCE)?,
    })
}

#[cfg(test)]
mod tests {
    use super::{login_allowed, login_approved_body, staff_claim};

    #[test]
    fn approved_login_echoes_the_handle_and_slot_and_nothing_else() {
        // The app can derive neither of these itself (the HMAC key is
        // server-side, the slot is drawn here), so this response is the only
        // channel that tells a wallet its own forum name and its own position
        // in the broadcast digest. Both key names are a contract with the
        // desktop and mobile clients.
        let body = login_approved_body("lusab-babad-dovok", Some(42));
        assert_eq!(body["status"], "approved");
        assert_eq!(body["handle"], "lusab-babad-dovok");
        assert_eq!(body["notify_slot"], 42);
        let object = body.as_object().expect("the body is a JSON object");
        assert_eq!(
            object.len(),
            3,
            "no fourth field may creep in: the response goes to a client that only proved key control"
        );
    }

    #[test]
    fn an_approved_login_with_no_slot_omits_the_field_rather_than_nulling_it() {
        let body = login_approved_body("lusab-babad-dovok", None);

        assert_eq!(body["status"], "approved");
        assert!(
            body.as_object()
                .expect("object")
                .get("notify_slot")
                .is_none(),
            "an absent slot must read as absent, so a client cannot mistake it for slot 0"
        );
    }

    #[test]
    fn paying_wallet_is_allowed() {
        assert!(login_allowed(true, false));
    }

    #[test]
    fn never_paid_non_admin_is_refused() {
        assert!(!login_allowed(false, false));
    }

    #[test]
    fn admin_that_never_paid_is_still_allowed() {
        // An operator must never be locked out of their own forum by the
        // anti-sybil paywall, even with no subscription row.
        assert!(login_allowed(false, true));
    }

    #[test]
    fn staff_is_asserted_only_on_a_same_device_approval() {
        use crate::sessions::Approach;

        assert!(staff_claim(true, Approach::SameDevice));
        assert!(
            !staff_claim(true, Approach::CrossDevice),
            "a QR is read from another device, which is the exact shape of a relayed approval: \
             no grant may ride on it"
        );
        assert!(!staff_claim(false, Approach::SameDevice));
        assert!(!staff_claim(false, Approach::CrossDevice));
    }

    #[test]
    fn a_cross_device_login_still_signs_in() {
        use crate::sessions::Approach;

        // The fix must not cost the feature: an operator signing in from their
        // phone is still let through the paywall and still logs in. Only the
        // staff CLAIM is withheld, and Discourse keeps the grant it holds.
        assert!(
            login_allowed(false, true),
            "the gate reads the allowlist, not the approach"
        );
        let body = login_approved_body("lusab-babad-dovok", Some(1));
        assert_eq!(body["status"], "approved");
        assert!(!staff_claim(true, Approach::CrossDevice));
    }
}
