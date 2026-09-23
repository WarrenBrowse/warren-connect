//! Typed error surface. No secret material (pubkey, nonce, signature) ever
//! appears in a rendered message; identifiers are redacted to a short prefix.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Login/SSO failures. Rendered messages are deliberately generic: the
/// distinction matters for logs (redacted) and tests, not for the caller.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The DiscourseConnect HMAC on an incoming `sso` payload is wrong.
    #[error("sso payload signature mismatch")]
    SsoSignature,
    /// The `sso` payload is not valid base64/urlencoded form data.
    #[error("sso payload malformed")]
    SsoMalformed,
    /// The `sso` payload asks for the signed response to be delivered
    /// somewhere other than the forum origin.
    #[error("sso return url is not on the forum origin")]
    SsoReturnUrl,
    /// A required `X-Warren-*` header is missing or malformed.
    #[error("missing or malformed auth header")]
    Header,
    /// The SS58 pubkey failed to decode or is not a valid Ed25519 point.
    #[error("invalid public key")]
    Pubkey,
    /// The Ed25519 signature does not verify against the canonical message.
    #[error("signature verification failed")]
    Signature,
    /// The request timestamp is outside the accepted clock window.
    #[error("timestamp outside accepted window")]
    Clock,
    /// The nonce was already consumed (replay) or is malformed.
    #[error("nonce rejected")]
    Nonce,
    /// The login session does not exist, expired, or was already consumed.
    #[error("unknown or expired session")]
    Session,
    /// A browser-side login call did not present the cookie of the browser
    /// that opened the session, or named no live session: the two answer the
    /// same on purpose.
    #[error("browser_mismatch")]
    BrowserMismatch,
    /// A login approval in the form that predates the completion code, from
    /// a wallet or a deployment that no longer accepts it.
    #[error("app_update_required")]
    AppUpdateRequired,
    /// The wallet is valid but has never paid for Warren: forum accounts
    /// require a Warren subscription (past or present).
    #[error("forum access requires a Warren subscription")]
    SubscriptionRequired,
    /// The request body is not the expected JSON/base64/gzip payload.
    #[error("malformed payload")]
    Payload,
    /// The payload exceeds a size cap (compressed or decompressed).
    #[error("payload too large")]
    PayloadTooLarge,
    /// The signer is not the author of the targeted forum topic.
    #[error("not_author")]
    NotAuthor,
    /// Bind requested before the app delivered the report to the session.
    #[error("no_log")]
    NoLog,
    /// Another bind holds the pre-topic session.
    #[error("bind_in_progress")]
    BindInProgress,
    /// The Discourse-backed feature is not configured (no API key).
    #[error("feature disabled")]
    FeatureDisabled,
    /// The guest intake payload is outside limits or tripped the honeypot
    /// (deliberately the same error for both, so the honeypot cannot be
    /// fingerprinted by probing).
    #[error("invalid intake payload")]
    InvalidIntake,
    /// An in-app bug report is outside its field caps or malformed. Distinct
    /// from [`Self::InvalidIntake`]: the app renders "fix the form" from the
    /// token, where the guest form only ever sees a generic 422.
    #[error("invalid_report")]
    InvalidReport,
    /// The guest follow-up code is malformed or does not verify: nothing
    /// distinguishes "never existed" from "no longer exists", on purpose.
    #[error("unknown_code")]
    InvalidTicket,
    /// Too many guest intakes from this client or globally in the window.
    #[error("rate limited")]
    RateLimited,
    /// A backend call failed (Discourse, or a database a gate or an
    /// admission reads or writes), a gate is full, or another approval of the
    /// same login is being admitted. Nothing was granted or marked done, and
    /// a retry can succeed.
    #[error("forum backend error")]
    Forum,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Frozen wire detail: the app and the forum theme match these exact
        // JSON error tokens.
        if matches!(self, AuthError::NotAuthor) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "not_author"})),
            )
                .into_response();
        }
        // The help form tells the guest their code is wrong rather than
        // dropping them on the generic failure path, so this token is a
        // contract with it.
        if matches!(self, AuthError::InvalidTicket) {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "unknown_code"})),
            )
                .into_response();
        }
        if matches!(self, AuthError::InvalidReport) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(serde_json::json!({"error": "invalid_report"})),
            )
                .into_response();
        }
        // The approval page and the handoff page render these two, and the
        // browser mismatch must read the same whether or not the id exists.
        if matches!(self, AuthError::BrowserMismatch) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "browser_mismatch"})),
            )
                .into_response();
        }
        if matches!(self, AuthError::AppUpdateRequired) {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "app_update_required"})),
            )
                .into_response();
        }
        if matches!(self, AuthError::NoLog) {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({"error": "no_log"})),
            )
                .into_response();
        }
        if matches!(self, AuthError::BindInProgress) {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({"error": "bind_in_progress"})),
            )
                .into_response();
        }
        // The one auth failure the CLIENT can repair itself: the app matches
        // this token to tell the user to fix the device clock, so it must stay
        // machine-readable where the other 401s stay deliberately generic.
        if matches!(self, AuthError::Clock) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "clock_skew"})),
            )
                .into_response();
        }
        let status = match self {
            AuthError::Session => StatusCode::NOT_FOUND,
            AuthError::SubscriptionRequired => StatusCode::FORBIDDEN,
            AuthError::Payload => StatusCode::BAD_REQUEST,
            AuthError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AuthError::InvalidIntake => StatusCode::UNPROCESSABLE_ENTITY,
            AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AuthError::FeatureDisabled => StatusCode::SERVICE_UNAVAILABLE,
            AuthError::Forum => StatusCode::BAD_GATEWAY,
            _ => StatusCode::UNAUTHORIZED,
        };
        (status, self.to_string()).into_response()
    }
}
