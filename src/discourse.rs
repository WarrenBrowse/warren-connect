//! DiscourseConnect payload codec.
//!
//! Wire shape (Discourse "DiscourseConnect" official SSO): the `sso` request
//! parameter is a base64-encoded urlencoded form, and `sig` is the hex
//! HMAC-SHA256 of the *raw base64 string exactly as transmitted* (Discourse's
//! Ruby `Base64.encode64` inserts trailing newlines; they are part of the
//! signed bytes, so verification never re-canonicalizes).

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use std::collections::BTreeMap;

use crate::error::AuthError;

type HmacSha256 = Hmac<Sha256>;

/// Parsed fields of an incoming login request from Discourse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingSso {
    /// Discourse's single-use login nonce; echoed back in the response payload.
    pub nonce: String,
    /// Where to send the user (with the signed response) once authenticated.
    pub return_sso_url: String,
}

/// Identity fields returned to Discourse after a successful wallet login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoUser {
    /// Stable private key for the account (never publicly visible).
    pub external_id: String,
    /// Public forum username (locked via `auth_overrides_username`).
    pub username: String,
    /// Synthetic `.invalid` address (never emailed, admin-only visibility).
    pub email: String,
    /// Whether the wallet has paid at least once, ever (the public
    /// "Member"/"Adhérent" badge = the `members` group). Every forum account
    /// has this, since login requires ever-paid.
    pub member: bool,
    /// Whether the wallet has an active subscription right now (the
    /// `subscribers` group).
    pub subscriber: bool,
    /// Whether the wallet is on the bootstrap staff allowlist (see
    /// [`crate::admins`]). When true the payload carries `admin`/`moderator`,
    /// which Discourse applies; when false it carries neither, leaving the
    /// forum's own staff state untouched.
    pub admin: bool,
}

/// Whether `url` lives on `origin` (scheme, host and port all equal).
///
/// A prefix test with the separator included, so `https://forum.example.com`
/// does not match `https://forum.example.com.attacker.test/`, and no userinfo
/// (`https://forum.example.com@attacker.test/`) can slip a different host past
/// it either: both put a character other than `/` where the separator has to be.
fn on_origin(url: &str, origin: &str) -> bool {
    url.len() == origin.len() && url == origin
        || url.len() > origin.len()
            && url.starts_with(origin)
            && url.as_bytes().get(origin.len()) == Some(&b'/')
}

/// Verifies `sig` against the raw `sso` parameter and decodes the payload.
///
/// `allowed_return_origin` pins where the signed response may be sent. Only
/// the holder of the shared secret can craft a payload at all, so this is
/// defence in depth: it turns a leak of `DISCOURSE_CONNECT_SECRET` from "a
/// signed open redirect carrying a valid identity assertion" into nothing.
///
/// # Errors
/// [`AuthError::SsoSignature`] on HMAC mismatch, [`AuthError::SsoMalformed`]
/// if the payload is not base64 urlencoded form data with the two required
/// fields, [`AuthError::SsoReturnUrl`] if it points off the forum origin.
pub fn verify_incoming(
    sso_b64: &str,
    sig_hex: &str,
    connect_secret: &[u8],
    allowed_return_origin: &str,
) -> Result<IncomingSso, AuthError> {
    // Constant-time comparison via HMAC's own verify (never a plain `==` on the
    // recomputed hex, which would leak the MAC through timing).
    let provided = sig_hex.trim().to_ascii_lowercase();
    let mut mac = HmacSha256::new_from_slice(connect_secret).expect("any key length");
    mac.update(sso_b64.as_bytes());
    let provided_bytes = hex::decode(&provided).map_err(|_| AuthError::SsoSignature)?;
    mac.verify_slice(&provided_bytes)
        .map_err(|_| AuthError::SsoSignature)?;

    // Ruby's Base64.encode64 wraps lines; strip whitespace before decoding.
    let compact: String = sso_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, compact)
        .map_err(|_| AuthError::SsoMalformed)?;
    let fields: BTreeMap<String, String> =
        serde_urlencoded::from_bytes(&raw).map_err(|_| AuthError::SsoMalformed)?;

    let nonce = fields
        .get("nonce")
        .cloned()
        .ok_or(AuthError::SsoMalformed)?;
    let return_sso_url = fields
        .get("return_sso_url")
        .cloned()
        .ok_or(AuthError::SsoMalformed)?;
    if !on_origin(&return_sso_url, allowed_return_origin) {
        return Err(AuthError::SsoReturnUrl);
    }
    Ok(IncomingSso {
        nonce,
        return_sso_url,
    })
}

/// Builds the signed response: `(sso_b64, sig_hex)` to append to the
/// `return_sso_url` as query parameters.
///
/// `locale` is the browser's preferred language subtag: Discourse applies it
/// only at account creation (never overriding a locale the user later picks),
/// and silently drops values it does not support, so it is passed unfiltered.
#[must_use]
pub fn build_outgoing(
    nonce: &str,
    user: &SsoUser,
    locale: Option<&str>,
    connect_secret: &[u8],
) -> (String, String) {
    // `discourse_connect_overrides_groups` is enabled, so Discourse reads ONLY
    // `groups` as the authoritative full manual-group list per login (empty =
    // member of none); add_groups/remove_groups are ignored in that mode.
    // `members` = ever-paid (public badge), `subscribers` = active.
    let mut group_list: Vec<&str> = Vec::new();
    if user.member {
        group_list.push("members");
    }
    if user.subscriber {
        group_list.push("subscribers");
    }
    let groups = group_list.join(",");
    let groups = groups.as_str();
    let mut pairs = vec![
        ("nonce", nonce),
        ("external_id", &user.external_id),
        ("username", &user.username),
        ("email", &user.email),
        // The synthetic address must never trigger a confirmation mail.
        ("require_activation", "false"),
        ("suppress_welcome_message", "true"),
        ("groups", groups),
    ];
    // Staff is promoted, never demoted. Discourse applies
    // `user.admin = admin unless admin.nil?`, so OMITTING the field leaves the
    // forum's own state alone and a grant made in the admin UI survives every
    // later login. The allowlist is a bootstrap floor (a fresh forum has no
    // admin and no local login to make one), so it only ever adds.
    if user.admin {
        pairs.push(("admin", "true"));
        pairs.push(("moderator", "true"));
    }
    if let Some(locale) = locale {
        pairs.push(("locale", locale));
    }
    let payload = serde_urlencoded::to_string(pairs).expect("static string pairs always urlencode");

    let sso_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        payload.as_bytes(),
    );
    let sig_hex = hmac_hex(connect_secret, sso_b64.as_bytes());
    (sso_b64, sig_hex)
}

fn hmac_hex(secret: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORUM: &str = crate::FORUM_PUBLIC_URL;

    #[test]
    fn a_return_url_off_the_forum_origin_is_refused() {
        // Reached only by the holder of the shared secret, so this is the
        // barrier that keeps a leaked secret from turning this endpoint into a
        // redirector that hands a valid identity assertion to a stranger.
        let secret = b"a-connect-secret";
        for hostile in [
            "https://attacker.test/session/sso_login",
            // Suffix: the naive `starts_with` without the separator lets this
            // through, and it is a domain anyone can register.
            "https://forum.warrenbrowse.com.attacker.test/session/sso_login",
            // Userinfo: the real host is `attacker.test`.
            "https://forum.warrenbrowse.com@attacker.test/session/sso_login",
            // Scheme downgrade on the right host still leaves TLS behind.
            "http://forum.warrenbrowse.com/session/sso_login",
        ] {
            let payload = format!(
                "nonce=abc123&return_sso_url={}",
                urlencoding::encode(hostile)
            );
            let sso = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                payload.as_bytes(),
            );
            let sig = hmac_hex(secret, sso.as_bytes());

            let err = verify_incoming(&sso, &sig, secret, FORUM)
                .expect_err("a correctly signed payload is still refused off-origin");
            assert!(
                matches!(err, AuthError::SsoReturnUrl),
                "{hostile} gave {err:?}"
            );
        }
    }

    #[test]
    fn the_origin_test_accepts_only_the_forum_itself() {
        assert!(on_origin(FORUM, FORUM), "the bare origin is the origin");
        assert!(on_origin(
            "https://forum.warrenbrowse.com/session/sso_login",
            FORUM
        ));
        assert!(!on_origin(
            "https://forum.warrenbrowse.com.attacker.test/",
            FORUM
        ));
        assert!(!on_origin(
            "https://forum.warrenbrowse.com@attacker.test/",
            FORUM
        ));
        assert!(!on_origin("http://forum.warrenbrowse.com/", FORUM));
        assert!(!on_origin("https://attacker.test/", FORUM));
        assert!(!on_origin("", FORUM));
    }

    /// The exact example published in the official DiscourseConnect spec
    /// (meta.discourse.org topic 13045): payload with Ruby's trailing
    /// newline, secret `d836444a9e4084d5b224a60c208dce14`.
    #[test]
    fn official_spec_vector_verifies() {
        let sso = "bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGI=\n";
        let sig = "2828aa29899722b35a2f191d34ef9b3ce695e0e6eeec47deb46d588d70c7cb56";
        // The example payload has no return_sso_url, so decode stops at
        // signature verification success + missing-field error.
        let err = verify_incoming(sso, sig, b"d836444a9e4084d5b224a60c208dce14", FORUM)
            .expect_err("payload lacks return_sso_url");
        assert!(matches!(err, AuthError::SsoMalformed));
    }

    #[test]
    fn tampered_signature_is_rejected_before_decoding() {
        let sso = "bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGI=\n";
        let bad = "0000aa29899722b35a2f191d34ef9b3ce695e0e6eeec47deb46d588d70c7cb56";
        let err = verify_incoming(sso, bad, b"d836444a9e4084d5b224a60c208dce14", FORUM)
            .expect_err("wrong HMAC must be rejected");
        assert!(matches!(err, AuthError::SsoSignature));
    }

    #[test]
    fn full_round_trip_incoming() {
        let secret = b"a-connect-secret";
        let payload = "nonce=abc123&return_sso_url=https%3A%2F%2Fforum.warrenbrowse.com%2Fsession%2Fsso_login";
        let sso = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload.as_bytes(),
        );
        let sig = hmac_hex(secret, sso.as_bytes());

        let parsed = verify_incoming(&sso, &sig, secret, FORUM).expect("valid payload");
        assert_eq!(parsed.nonce, "abc123");
        assert_eq!(
            parsed.return_sso_url,
            "https://forum.warrenbrowse.com/session/sso_login"
        );
    }

    #[test]
    fn outgoing_payload_carries_identity_and_signs() {
        let secret = b"a-connect-secret";
        let user = SsoUser {
            external_id: "ext123".into(),
            username: "w2vymx2f4nlp4e".into(),
            email: "w2vymx2f4nlp4e@users.warrenbrowse.invalid".into(),
            member: true,
            subscriber: true,
            admin: false,
        };
        let (sso, sig) = build_outgoing("abc123", &user, None, secret);

        assert_eq!(sig, hmac_hex(secret, sso.as_bytes()), "sig covers the b64");
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sso)
            .expect("valid base64");
        let fields: BTreeMap<String, String> =
            serde_urlencoded::from_bytes(&raw).expect("valid form");
        assert_eq!(fields["nonce"], "abc123");
        assert_eq!(fields["external_id"], "ext123");
        assert_eq!(fields["username"], "w2vymx2f4nlp4e");
        assert_eq!(fields["require_activation"], "false");
        // Override mode: the full manual-group list. An ever-paid + active
        // wallet is in both `members` (badge) and `subscribers`.
        assert_eq!(fields["groups"], "members,subscribers");
        assert!(!fields.contains_key("add_groups"));
        assert!(!fields.contains_key("remove_groups"));
        // Discourse skips a nil field, so an ordinary login leaves whatever
        // staff state the forum holds.
        assert!(!fields.contains_key("admin"));
        assert!(!fields.contains_key("moderator"));
        // No browser language known: the field is omitted entirely, so
        // Discourse falls back to its own default_locale.
        assert!(!fields.contains_key("locale"));
    }

    #[test]
    fn browser_locale_is_forwarded_for_account_creation() {
        let user = SsoUser {
            external_id: "e".into(),
            username: "u".into(),
            email: "u@users.warrenbrowse.invalid".into(),
            member: true,
            subscriber: true,
            admin: false,
        };
        let (sso, _) = build_outgoing("n", &user, Some("ro"), b"s");
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sso)
            .expect("valid base64");
        let fields: BTreeMap<String, String> =
            serde_urlencoded::from_bytes(&raw).expect("valid form");
        assert_eq!(fields["locale"], "ro");
    }

    #[test]
    fn admin_wallet_is_promoted_to_staff() {
        let user = SsoUser {
            external_id: "e".into(),
            username: "wadmin".into(),
            email: "wadmin@users.warrenbrowse.invalid".into(),
            member: true,
            subscriber: true,
            admin: true,
        };
        let (sso, _) = build_outgoing("n", &user, None, b"s");
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sso)
            .expect("valid base64");
        let fields: BTreeMap<String, String> =
            serde_urlencoded::from_bytes(&raw).expect("valid form");
        assert_eq!(fields["admin"], "true");
        assert_eq!(fields["moderator"], "true");
    }

    #[test]
    fn an_ordinary_login_never_clears_a_grant_made_in_the_admin_ui() {
        // The forum owns staff: an operator promotes someone from the Discourse
        // admin UI and that grant must outlive every later login of that
        // account, so the payload of a non-allowlisted wallet carries neither
        // field.
        let user = SsoUser {
            external_id: "e".into(),
            username: "u".into(),
            email: "u@users.warrenbrowse.invalid".into(),
            member: true,
            subscriber: true,
            admin: false,
        };
        let (sso, _) = build_outgoing("n", &user, None, b"s");
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sso)
            .expect("valid base64");
        let fields: BTreeMap<String, String> =
            serde_urlencoded::from_bytes(&raw).expect("valid form");
        assert!(
            !fields.contains_key("admin"),
            "an explicit admin=false would revoke the grant on this very login"
        );
        assert!(
            !fields.contains_key("moderator"),
            "moderation is cleared by the same field and must be left alone too"
        );
    }

    #[test]
    fn lapsed_member_keeps_members_but_not_subscribers() {
        // Paid once, not active now: stays in `members` (keeps the badge and
        // ever-paid category access), removed from `subscribers`.
        let user = SsoUser {
            external_id: "e".into(),
            username: "u".into(),
            email: "u@users.warrenbrowse.invalid".into(),
            member: true,
            subscriber: false,
            admin: false,
        };
        let (sso, _) = build_outgoing("n", &user, None, b"s");
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sso)
            .expect("valid base64");
        let fields: BTreeMap<String, String> =
            serde_urlencoded::from_bytes(&raw).expect("valid form");
        assert_eq!(fields["groups"], "members");
    }
}
