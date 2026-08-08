//! Typed error surface. No secret material (pubkey, nonce, signature) ever
//! appears in a rendered message; identifiers are redacted to a short prefix.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Login/SSO failures. Rendered messages are deliberately generic: the
/// distinction matters for logs (redacted) and tests, not for the caller.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The DiscourseConnect HMAC on an incoming `sso` payload is wrong.
    #[error("sso payload signature mismatch")]
    SsoSignature,
    /// The `sso` payload is not valid base64/urlencoded form data.
    #[error("sso payload malformed")]
    SsoMalformed,
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
    /// The Discourse-backed feature is not configured (no API key).
    #[error("feature disabled")]
    FeatureDisabled,
    /// The guest intake payload is outside limits or tripped the honeypot
    /// (deliberately the same error for both, so the honeypot cannot be
    /// fingerprinted by probing).
    #[error("invalid intake payload")]
    InvalidIntake,
    /// The guest follow-up code is malformed or does not verify: nothing
    /// distinguishes "never existed" from "no longer exists", on purpose.
    #[error("unknown_code")]
    InvalidTicket,
    /// Too many guest intakes from this client or globally in the window.
    #[error("rate limited")]
    RateLimited,
    /// A Discourse API call failed; nothing was or will be marked done.
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
        if matches!(self, AuthError::NoLog) {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({"error": "no_log"})),
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
