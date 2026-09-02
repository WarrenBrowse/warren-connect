//! Guest help intake: a public, unauthenticated form-to-forum bridge.
//!
//! Non-clients (payment blocked, install failures) cannot pass the ever-paid
//! SSO gate, so a web form on the marketing/checkout sites posts here and the
//! service opens a PUBLIC Discourse topic on the guest's behalf (as a
//! dedicated low-privilege bot user). Staff answers publicly; the guest
//! follows the returned topic URL without an account.
//!
//! No-log doctrine: the topic body carries only what the guest typed (kind,
//! message, optional platform, optional screenshots). No IP, no user-agent,
//! nothing derived from the transport ever reaches Discourse. The rate limiter
//! holds client IPs in memory only, for at most one window, and they are never
//! logged or persisted (see [`RateLimiter`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use base64::Engine as _;
use rand::RngCore as _;
use serde::Deserialize;

use crate::error::AuthError;

/// Shortest guest message accepted (filters empty/near-empty spam).
pub const MIN_MESSAGE_CHARS: usize = 20;
/// Longest guest message accepted.
pub const MAX_MESSAGE_CHARS: usize = 4_000;
/// Cap on the platform string.
pub const MAX_PLATFORM_CHARS: usize = 40;
/// Most files a guest may attach. Matches the help form, and bounds both the
/// body cap and the number of Discourse writes one intake can trigger.
pub const MAX_ATTACHMENTS: usize = 2;
/// Largest decoded attachment accepted, per file.
pub const MAX_ATTACHMENT_BYTES: usize = 4 * 1024 * 1024;
/// Longest sanitized filename stem kept (the extension is appended after).
const MAX_FILENAME_STEM: usize = 60;

/// What kind of problem the guest reports; selects the topic-title tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntakeKind {
    /// Payment/checkout problem.
    Payment,
    /// Installation/first-run problem.
    Install,
}

impl IntakeKind {
    /// Title tag, e.g. `[Payment]`.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            IntakeKind::Payment => "Payment",
            IntakeKind::Install => "Install",
        }
    }

    /// Lowercase token used in the topic metadata block.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            IntakeKind::Payment => "payment",
            IntakeKind::Install => "install",
        }
    }
}

/// The public intake form body.
#[derive(Debug, Deserialize)]
pub struct IntakeRequest {
    /// Problem category.
    pub kind: IntakeKind,
    /// The guest's free-form message.
    pub message: String,
    /// Optional platform, e.g. "windows".
    #[serde(default)]
    pub platform: Option<String>,
    /// Honeypot: a hidden form field a human never fills. Must be empty.
    #[serde(default)]
    pub website: Option<String>,
    /// Optional screenshots, base64 in the JSON body. Absent on every client
    /// predating the feature, hence the default.
    #[serde(default)]
    pub attachments: Vec<IntakeAttachment>,
}

/// A guest follow-up on a report they already filed.
///
/// The `code` is the only credential: the guest has no account, so proving
/// they own the topic is proving they hold the code issued when it was
/// created. There is deliberately no `kind` or `platform`, both already
/// recorded on the first post.
#[derive(Debug, Deserialize)]
pub struct ReplyRequest {
    /// Follow-up code, in any form a human retypes it.
    pub code: String,
    /// The guest's free-form message.
    pub message: String,
    /// Honeypot: a hidden form field a human never fills. Must be empty.
    #[serde(default)]
    pub website: Option<String>,
    /// Optional screenshots, base64 in the JSON body.
    #[serde(default)]
    pub attachments: Vec<IntakeAttachment>,
}

/// One attachment as the browser sends it. The form also sends a `size`
/// field; it is ignored on purpose, the decoded length is the only size this
/// service trusts.
#[derive(Debug, Deserialize)]
pub struct IntakeAttachment {
    /// Filename as picked on the guest's machine. Untrusted.
    pub name: String,
    /// MIME type the browser reported. Untrusted, checked against the bytes.
    #[serde(rename = "type")]
    pub mime: String,
    /// Standard-alphabet base64 of the file bytes.
    pub data: String,
}

/// An attachment kind this endpoint accepts, keyed by its magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentType {
    /// Canonical MIME sent to Discourse.
    pub mime: &'static str,
    /// Canonical extension forced onto the filename.
    pub ext: &'static str,
    /// Images are linked so Discourse renders them inline.
    pub is_image: bool,
}

/// The accepted formats: what a screenshot or an exported report actually is.
/// Anything whose bytes do not match one of these is refused, whatever the
/// browser declared.
const ATTACHMENT_TYPES: &[AttachmentType] = &[
    AttachmentType {
        mime: "image/png",
        ext: "png",
        is_image: true,
    },
    AttachmentType {
        mime: "image/jpeg",
        ext: "jpg",
        is_image: true,
    },
    AttachmentType {
        mime: "image/webp",
        ext: "webp",
        is_image: true,
    },
    AttachmentType {
        mime: "image/gif",
        ext: "gif",
        is_image: true,
    },
    AttachmentType {
        mime: "application/pdf",
        ext: "pdf",
        is_image: false,
    },
];

/// A validated attachment, ready to be uploaded to Discourse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAttachment {
    /// Sanitized filename, extension forced to match the sniffed bytes.
    pub filename: String,
    /// The sniffed format, never the declared one.
    pub kind: AttachmentType,
    /// Decoded file bytes.
    pub bytes: Vec<u8>,
}

/// An attachment already uploaded, ready to be linked from the topic body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedAttachment {
    /// Sanitized filename, used as the link label.
    pub filename: String,
    /// Discourse `upload://` short url.
    pub short_url: String,
    /// Images render inline, other files render as a download link.
    pub is_image: bool,
}

/// Identifies a byte payload by its magic bytes. The declared MIME is a
/// client-controlled string: only the content decides what the file is, so a
/// script renamed `.png` never reaches the forum as an image.
#[must_use]
fn sniff(bytes: &[u8]) -> Option<AttachmentType> {
    let matched = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "image/gif"
    } else if bytes.starts_with(b"%PDF-") {
        "application/pdf"
    } else {
        return None;
    };
    ATTACHMENT_TYPES.iter().copied().find(|t| t.mime == matched)
}

/// Builds a filename safe to interpolate into the bot's own markdown.
///
/// The guest's name reaches a public post as a link label, so it is rebuilt
/// from an allowlist rather than escaped: every path separator, markdown
/// metacharacter, control char and dot is gone, which also makes `../` and
/// double-extension tricks unrepresentable. The extension then comes from the
/// sniffed type, so the label can never disagree with the bytes.
#[must_use]
fn safe_filename(raw: &str, kind: AttachmentType, index: usize) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let stem = base.rsplit_once('.').map_or(base, |(s, _)| s);
    let mut out = String::with_capacity(stem.len());
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '-' | '_') {
            out.push(ch);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let cleaned: String = out
        .trim_matches(|c: char| c == '-' || c == ' ')
        .chars()
        .take(MAX_FILENAME_STEM)
        .collect();
    let cleaned = cleaned.trim_end_matches([' ', '-']);
    if cleaned.is_empty() {
        format!("capture-{}.{}", index + 1, kind.ext)
    } else {
        format!("{cleaned}.{}", kind.ext)
    }
}

/// Decodes and validates the attachments of one intake.
///
/// # Errors
/// [`AuthError::InvalidIntake`] on too many files, undecodable base64, an
/// empty or oversized file, a format outside [`ATTACHMENT_TYPES`], or a
/// declared MIME that disagrees with the bytes.
pub fn decode_attachments(items: &[IntakeAttachment]) -> Result<Vec<DecodedAttachment>, AuthError> {
    if items.len() > MAX_ATTACHMENTS {
        return Err(AuthError::InvalidIntake);
    }
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        // Cheap gate before spending CPU on a megabyte of base64.
        if !ATTACHMENT_TYPES.iter().any(|t| t.mime == item.mime) {
            return Err(AuthError::InvalidIntake);
        }
        // A base64 string longer than the ceiling cannot decode to anything
        // under it, so this rejects an oversized file before allocating it.
        if item.data.len() > MAX_ATTACHMENT_BYTES.saturating_mul(4).div_ceil(3) + 4 {
            return Err(AuthError::InvalidIntake);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(item.data.as_bytes())
            .map_err(|_| AuthError::InvalidIntake)?;
        if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(AuthError::InvalidIntake);
        }
        let kind = sniff(&bytes).ok_or(AuthError::InvalidIntake)?;
        // Declared type must agree with the content: a mismatch is either a
        // broken client or a probe, and neither should reach the forum.
        if kind.mime != item.mime {
            return Err(AuthError::InvalidIntake);
        }
        out.push(DecodedAttachment {
            filename: safe_filename(&item.name, kind, index),
            kind,
            bytes,
        });
    }
    Ok(out)
}

/// Validates the intake payload limits and the honeypot.
///
/// The honeypot rejection is deliberately the SAME 422 as a length violation:
/// a distinct status or message would let a bot fingerprint which field is
/// the trap by probing, while an identical response keeps the honeypot
/// indistinguishable from ordinary validation (and an honest typed error fits
/// this API better than fabricating a fake-success topic URL).
///
/// # Errors
/// [`AuthError::InvalidIntake`] on any limit violation or a non-empty
/// honeypot.
pub fn validate(req: &IntakeRequest) -> Result<(), AuthError> {
    validate_message(&req.message, req.website.as_deref())?;
    if req
        .platform
        .as_deref()
        .is_some_and(|p| p.chars().count() > MAX_PLATFORM_CHARS)
    {
        return Err(AuthError::InvalidIntake);
    }
    Ok(())
}

/// Validates a follow-up payload: same message limits and same honeypot as a
/// first report, so a guest never hits a different rule for the same field.
///
/// # Errors
/// [`AuthError::InvalidIntake`] on a limit violation or a non-empty honeypot.
pub fn validate_reply(req: &ReplyRequest) -> Result<(), AuthError> {
    validate_message(&req.message, req.website.as_deref())
}

fn validate_message(message: &str, honeypot: Option<&str>) -> Result<(), AuthError> {
    let message_chars = message.chars().count();
    if !(MIN_MESSAGE_CHARS..=MAX_MESSAGE_CHARS).contains(&message_chars) {
        return Err(AuthError::InvalidIntake);
    }
    if honeypot.is_some_and(|w| !w.is_empty()) {
        return Err(AuthError::InvalidIntake);
    }
    Ok(())
}

/// A 6-hex-char random reference, echoed to the guest and put in the title so
/// support can match a follow-up email to the topic.
#[must_use]
pub fn short_id() -> String {
    let mut raw = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Topic title, e.g. `[Payment] guest report 2026-07-10 #a1b2c3`.
#[must_use]
pub fn topic_title(kind: IntakeKind, date_ymd: &str, shortid: &str) -> String {
    format!("[{}] guest report {date_ymd} #{shortid}", kind.tag())
}

/// Breaks Discourse mention tokens: the markdown backslash escape is NOT
/// enough there (the mention parser still matches a literal `@` followed by
/// a word), so a zero-width space after each `@` keeps the glyph visually
/// intact while making the token unmatchable. Applied to every
/// guest-controlled value that ends up in the topic.
pub(crate) fn defang_mentions(text: &str) -> String {
    text.replace('@', "@\u{200B}")
}

/// Renders `text` as a blockquote whose every line is markdown-escaped.
/// A quote reads better than a code fence for prose, but it would leave the
/// guest's markdown LIVE (mentions ping members, links/images can exfiltrate
/// reader data in a public topic), so each line goes through
/// `escape_md_inline` first: the render stays plain quoted text.
pub(crate) fn quote_block(text: &str) -> String {
    text.lines()
        .map(|line| {
            let neutral = line.replace(['\u{2028}', '\u{2029}'], " ");
            let escaped = defang_mentions(&crate::forum_api::escape_md_inline(&neutral));
            if escaped.is_empty() {
                ">".to_owned()
            } else {
                format!("> {escaped}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Topic body: the quoted guest message, a small metadata block, then one
/// link per uploaded attachment. The platform value is markdown-defanged the
/// same way. There is deliberately NO contact field: the topic is public (a
/// volunteered email would be exposed to everyone) and Warren has no mail
/// infrastructure to answer through anyway; the topic_url handed back to the
/// guest IS the follow-up channel. By design nothing transport-derived (IP,
/// user-agent) is included either.
///
/// Attachment labels are NOT escaped here: they come from
/// [`safe_filename`], which rebuilds them from an allowlist that excludes
/// every markdown metacharacter, so escaping would only mangle the link.
#[must_use]
pub fn topic_raw(
    kind: IntakeKind,
    message: &str,
    platform: Option<&str>,
    attachments: &[LinkedAttachment],
) -> String {
    let mut meta = format!("kind: {}", kind.token());
    if let Some(p) = platform.filter(|p| !p.is_empty()) {
        meta.push_str(&format!(
            "\nplatform: {}",
            defang_mentions(&crate::forum_api::escape_md_inline(p))
        ));
    }
    let mut body = format!("{}\n\n{meta}", quote_block(message));
    append_attachments(&mut body, attachments);
    body
}

/// Body of a guest follow-up post: the quoted message and its attachments,
/// nothing else. The bot authoring it is the same one that opened the topic,
/// which is what tells staff the post is the reporter speaking.
///
/// Attachment labels are NOT escaped, for the same reason as in
/// [`topic_raw`]: [`safe_filename`] already rebuilt them from an allowlist.
#[must_use]
pub fn reply_raw(message: &str, attachments: &[LinkedAttachment]) -> String {
    let mut body = quote_block(message);
    append_attachments(&mut body, attachments);
    body
}

fn append_attachments(body: &mut String, attachments: &[LinkedAttachment]) {
    if attachments.is_empty() {
        return;
    }
    body.push('\n');
    for a in attachments {
        // Frozen Discourse shapes: `![..](upload://..)` renders an image
        // inline, `[..|attachment](upload://..)` renders a download link.
        if a.is_image {
            body.push_str(&format!("\n![{}]({})", a.filename, a.short_url));
        } else {
            body.push_str(&format!("\n[{}|attachment]({})", a.filename, a.short_url));
        }
    }
}

/// Sliding-window rate limiter, keyed by client.
///
/// The intake keys it on the client IP; the in-app report keys it on the
/// wallet's keyed forum id, because that route must never see an IP at all.
///
/// Privacy: the per-key map is the ONLY place a client IP exists in this
/// service, it lives in memory only, entries are pruned as soon as they fall
/// out of the window, and the key is never logged, persisted, or forwarded.
/// The map stays bounded without an explicit cap: a key is recorded only when
/// its attempt is admitted, and admissions are bounded by the global limit
/// per window.
#[derive(Debug)]
pub struct RateLimiter<K = Option<IpAddr>>
where
    K: std::hash::Hash + Eq,
{
    per_key_max: usize,
    global_max: usize,
    window_secs: u64,
    inner: Mutex<Windows<K>>,
}

#[derive(Debug)]
struct Windows<K> {
    // For the IP form, key None = client IP unknown (no X-Forwarded-For):
    // all such requests share one bucket, so the fallback fails closed
    // instead of unlimited.
    per_key: HashMap<K, Vec<u64>>,
    global: Vec<u64>,
}

impl<K> Default for Windows<K> {
    fn default() -> Self {
        Self {
            per_key: HashMap::new(),
            global: Vec::new(),
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(3, 30, 3_600)
    }
}

impl<K> RateLimiter<K>
where
    K: std::hash::Hash + Eq,
{
    /// Builds a limiter admitting `per_key_max` per key and `global_max` in
    /// total per sliding `window_secs`.
    #[must_use]
    pub fn new(per_key_max: usize, global_max: usize, window_secs: u64) -> Self {
        Self {
            per_key_max,
            global_max,
            window_secs,
            inner: Mutex::new(Windows::default()),
        }
    }

    /// Admits or rejects one attempt at `now_unix`. An admitted attempt is
    /// recorded in both windows; a rejected one is recorded in neither, so a
    /// single hammering client consumes at most `per_key_max` global slots
    /// per window and cannot trip the circuit breaker alone.
    ///
    /// # Errors
    /// [`AuthError::RateLimited`] past either limit.
    pub fn admit(&self, key: K, now_unix: u64) -> Result<(), AuthError> {
        // A hit at `t` expires once `now - t >= window` (avoids the
        // saturating-subtraction off-by-one that would expire hits at t=0).
        let live = |t: u64| now_unix.saturating_sub(t) < self.window_secs;
        let mut w = self
            .inner
            .lock()
            // The state is a plain counter window, not integrity-sensitive:
            // recovering from a poisoned lock beats 500ing the endpoint
            // forever after a single panic under the lock.
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        w.global.retain(|&t| live(t));
        w.per_key.retain(|_, hits| {
            hits.retain(|&t| live(t));
            !hits.is_empty()
        });
        if w.global.len() >= self.global_max {
            return Err(AuthError::RateLimited);
        }
        let hits = w.per_key.entry(key).or_default();
        if hits.len() >= self.per_key_max {
            return Err(AuthError::RateLimited);
        }
        hits.push(now_unix);
        w.global.push(now_unix);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> IntakeRequest {
        IntakeRequest {
            kind: IntakeKind::Payment,
            message: "My card is declined at checkout, help please.".into(),
            platform: None,
            website: None,
            attachments: Vec::new(),
        }
    }

    #[test]
    fn a_plain_valid_request_passes() {
        validate(&base_request()).expect("valid");
    }

    #[test]
    fn message_shorter_than_20_chars_is_rejected() {
        let mut req = base_request();
        req.message = "a".repeat(MIN_MESSAGE_CHARS - 1);
        assert!(matches!(
            validate(&req).expect_err("too short"),
            AuthError::InvalidIntake
        ));
        req.message = "a".repeat(MIN_MESSAGE_CHARS);
        validate(&req).expect("at the floor is fine");
    }

    #[test]
    fn message_longer_than_4000_chars_is_rejected() {
        let mut req = base_request();
        req.message = "a".repeat(MAX_MESSAGE_CHARS + 1);
        assert!(validate(&req).is_err());
        req.message = "a".repeat(MAX_MESSAGE_CHARS);
        validate(&req).expect("at the cap is fine");
    }

    #[test]
    fn limits_count_characters_not_bytes() {
        // 4000 multibyte chars are within the limit even though the byte
        // length is far past it.
        let mut req = base_request();
        req.message = "\u{e9}".repeat(MAX_MESSAGE_CHARS);
        validate(&req).expect("chars, not bytes");
    }

    #[test]
    fn oversized_platform_is_rejected() {
        let mut req = base_request();
        req.platform = Some("p".repeat(MAX_PLATFORM_CHARS + 1));
        assert!(validate(&req).is_err());
        req.platform = Some("p".repeat(MAX_PLATFORM_CHARS));
        validate(&req).expect("platform at cap");
    }

    #[test]
    fn a_filled_honeypot_is_rejected() {
        let mut req = base_request();
        req.website = Some("https://spam.example".into());
        assert!(matches!(
            validate(&req).expect_err("honeypot"),
            AuthError::InvalidIntake
        ));
        req.website = Some(String::new());
        validate(&req).expect("an empty honeypot field is a human");
    }

    #[test]
    fn a_follow_up_body_is_the_quoted_message_alone() {
        // No metadata block: kind and platform were recorded on the first
        // post and repeating them on every follow-up is noise for the staff.
        let raw = reply_raw("It still fails after the reinstall.", &[]);
        assert_eq!(raw, "> It still fails after the reinstall\\.");
    }

    #[test]
    fn a_follow_up_defangs_markdown_and_links_its_attachments() {
        let raw = reply_raw(
            "@everyone [x](https://evil)",
            &[LinkedAttachment {
                filename: "shot.png".to_owned(),
                short_url: "upload://abc.png".to_owned(),
                is_image: true,
            }],
        );
        assert!(raw.contains("\\@\u{200B}everyone"), "{raw}");
        assert!(!raw.contains("](https://evil)"));
        assert!(raw.ends_with("\n\n![shot.png](upload://abc.png)"), "{raw}");
    }

    #[test]
    fn a_follow_up_holds_the_message_to_the_same_limits_as_a_report() {
        let reply = |message: &str, website: Option<&str>| ReplyRequest {
            code: "WRN-SC0X-Y8GE-JG7J-2EG7".to_owned(),
            message: message.to_owned(),
            website: website.map(str::to_owned),
            attachments: Vec::new(),
        };
        validate_reply(&reply(&"a".repeat(MIN_MESSAGE_CHARS), None)).expect("at the floor");
        validate_reply(&reply(&"a".repeat(MAX_MESSAGE_CHARS), None)).expect("at the cap");
        assert!(validate_reply(&reply(&"a".repeat(MIN_MESSAGE_CHARS - 1), None)).is_err());
        assert!(validate_reply(&reply(&"a".repeat(MAX_MESSAGE_CHARS + 1), None)).is_err());
        assert!(
            validate_reply(&reply("a long enough follow-up", Some("bot"))).is_err(),
            "the honeypot guards the follow-up too"
        );
    }

    #[test]
    fn short_id_is_6_hex_chars() {
        let id = short_id();
        assert_eq!(id.len(), 6);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn title_shape_is_pinned() {
        assert_eq!(
            topic_title(IntakeKind::Payment, "2026-07-10", "a1b2c3"),
            "[Payment] guest report 2026-07-10 #a1b2c3"
        );
        assert_eq!(
            topic_title(IntakeKind::Install, "2026-07-10", "ffffff"),
            "[Install] guest report 2026-07-10 #ffffff"
        );
    }

    #[test]
    fn body_shape_is_pinned() {
        let raw = topic_raw(
            IntakeKind::Install,
            "Installer fails at step 2.",
            Some("windows"),
            &[],
        );
        assert_eq!(
            raw,
            "> Installer fails at step 2\\.\n\n\
             kind: install\nplatform: windows"
        );
    }

    #[test]
    fn body_omits_an_absent_or_empty_platform() {
        let raw = topic_raw(IntakeKind::Payment, "msg", None, &[]);
        assert!(!raw.contains("platform:"));
        assert!(raw.contains("kind: payment"));
        let raw = topic_raw(IntakeKind::Payment, "msg", Some(""), &[]);
        assert!(!raw.contains("platform:"));
    }

    #[test]
    fn a_hostile_message_is_quoted_with_no_live_markdown() {
        let hostile = "before\n\n@everyone [x](https://evil)\nafter";
        let raw = topic_raw(IntakeKind::Payment, hostile, None, &[]);
        // Every message line is a quote line, empty lines included (an
        // unquoted blank line would end the blockquote and let the rest of
        // the message escape into the bot's own markdown context).
        let body = raw.split("\n\nkind:").next().expect("quoted body");
        assert!(body.lines().all(|l| l == ">" || l.starts_with("> ")));
        // Mentions and links are defanged by the per-line escaping.
        assert!(
            raw.contains("\\@\u{200B}everyone"),
            "mention token is broken by the zero-width space"
        );
        assert!(!raw.contains("@everyone"), "no raw mention survives");
        assert!(!raw.contains("[x](https://evil)"), "link cannot render");
        assert!(raw.contains("before"), "the prose itself is preserved");
    }

    #[test]
    fn platform_markdown_is_defanged() {
        let raw = topic_raw(
            IntakeKind::Payment,
            "some long enough message",
            Some("@admin [x](https://evil)"),
            &[],
        );
        assert!(raw.contains("\\@\u{200B}admin"));
        assert!(!raw.contains("@admin"));
        assert!(!raw.contains("](https://evil)"));
    }

    #[test]
    fn per_ip_limit_admits_3_then_rejects_within_the_window() {
        let limiter: RateLimiter = RateLimiter::new(3, 30, 3_600);
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        for t in 0..3 {
            limiter.admit(Some(ip), t).expect("under the limit");
        }
        assert!(limiter.admit(Some(ip), 100).is_err(), "4th within window");
        // The window slides: once the t=0 hit ages out, one slot frees up
        // (the t=1 and t=2 hits are still live at now=3600).
        limiter.admit(Some(ip), 3_600).expect("first hit aged out");
        assert!(limiter.admit(Some(ip), 3_600).is_err());
    }

    #[test]
    fn distinct_ips_have_independent_budgets() {
        let limiter: RateLimiter = RateLimiter::new(3, 30, 3_600);
        let a: IpAddr = "203.0.113.1".parse().expect("ip");
        let b: IpAddr = "203.0.113.2".parse().expect("ip");
        for t in 0..3 {
            limiter.admit(Some(a), t).expect("a under limit");
        }
        assert!(limiter.admit(Some(a), 10).is_err());
        limiter.admit(Some(b), 10).expect("b is unaffected");
    }

    #[test]
    fn unknown_ips_share_one_fail_closed_bucket() {
        let limiter: RateLimiter = RateLimiter::new(3, 30, 3_600);
        for t in 0..3 {
            limiter.admit(None, t).expect("under the limit");
        }
        assert!(
            limiter.admit(None, 10).is_err(),
            "no XFF means one shared bucket, not unlimited"
        );
    }

    #[test]
    fn global_circuit_breaker_trips_across_ips() {
        let limiter: RateLimiter = RateLimiter::new(3, 30, 3_600);
        for i in 0..10u32 {
            let ip: IpAddr = format!("203.0.113.{}", i + 1).parse().expect("ip");
            for t in 0..3 {
                limiter.admit(Some(ip), u64::from(i * 3 + t)).expect("fill");
            }
        }
        let fresh: IpAddr = "198.51.100.1".parse().expect("ip");
        assert!(
            limiter.admit(Some(fresh), 100).is_err(),
            "30 admissions trip the breaker even for a fresh IP"
        );
        limiter
            .admit(Some(fresh), 3_700)
            .expect("the breaker resets as the window slides");
    }

    #[test]
    fn rejected_attempts_do_not_consume_global_slots() {
        let limiter: RateLimiter = RateLimiter::new(3, 30, 3_600);
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        for t in 0..3 {
            limiter.admit(Some(ip), t).expect("fill");
        }
        // Hammering past the per-IP limit must not eat the global budget.
        for t in 3..100 {
            assert!(limiter.admit(Some(ip), t).is_err());
        }
        let other: IpAddr = "203.0.113.10".parse().expect("ip");
        limiter
            .admit(Some(other), 100)
            .expect("global budget untouched by the rejected flood");
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    const JPEG: &[u8] = b"\xff\xd8\xff\xe0\x00\x10JFIF";
    const WEBP: &[u8] = b"RIFF\x24\x00\x00\x00WEBPVP8 ";
    const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00";
    const PDF: &[u8] = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3";

    fn attachment(name: &str, mime: &str, bytes: &[u8]) -> IntakeAttachment {
        IntakeAttachment {
            name: name.to_owned(),
            mime: mime.to_owned(),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    #[test]
    fn every_accepted_format_is_sniffed_and_keeps_its_canonical_extension() {
        for (bytes, mime, ext, is_image) in [
            (PNG, "image/png", "png", true),
            (JPEG, "image/jpeg", "jpg", true),
            (WEBP, "image/webp", "webp", true),
            (GIF, "image/gif", "gif", true),
            (PDF, "application/pdf", "pdf", false),
        ] {
            let out = decode_attachments(&[attachment("shot", mime, bytes)])
                .unwrap_or_else(|_| panic!("{mime} is accepted"));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].kind.mime, mime);
            assert_eq!(out[0].kind.is_image, is_image);
            assert_eq!(out[0].filename, format!("shot.{ext}"));
            assert_eq!(out[0].bytes, bytes, "the decoded bytes are passed through");
        }
    }

    #[test]
    fn a_declared_type_that_disagrees_with_the_bytes_is_rejected() {
        // The browser-declared MIME is attacker-controlled: a PDF (or worse)
        // renamed and declared as a PNG must never reach the forum.
        let err = decode_attachments(&[attachment("x.png", "image/png", PDF)])
            .expect_err("declared png, actually pdf");
        assert!(matches!(err, AuthError::InvalidIntake));
    }

    #[test]
    fn bytes_matching_no_accepted_format_are_rejected() {
        // A shell script declared as an image: no magic bytes match, so the
        // allowlist cannot be bypassed by lying about the type.
        assert!(
            decode_attachments(&[attachment("x.png", "image/png", b"#!/bin/sh\nrm -rf /")])
                .is_err()
        );
        // An SVG is a script container; it is not in the allowlist at all.
        assert!(
            decode_attachments(&[attachment(
                "x.svg",
                "image/svg+xml",
                b"<svg onload=alert(1)>"
            )])
            .is_err()
        );
    }

    #[test]
    fn undecodable_base64_is_rejected() {
        let bad = IntakeAttachment {
            name: "x.png".to_owned(),
            mime: "image/png".to_owned(),
            data: "!!!! not base64 !!!!".to_owned(),
        };
        assert!(decode_attachments(&[bad]).is_err());
    }

    #[test]
    fn an_empty_file_is_rejected() {
        assert!(decode_attachments(&[attachment("x.png", "image/png", b"")]).is_err());
    }

    #[test]
    fn a_file_over_the_size_cap_is_rejected_at_the_decoded_length() {
        let mut big = PNG.to_vec();
        big.resize(MAX_ATTACHMENT_BYTES + 1, 0);
        assert!(decode_attachments(&[attachment("x.png", "image/png", &big)]).is_err());
        let mut at_cap = PNG.to_vec();
        at_cap.resize(MAX_ATTACHMENT_BYTES, 0);
        decode_attachments(&[attachment("x.png", "image/png", &at_cap)]).expect("at the cap");
    }

    #[test]
    fn more_than_two_attachments_are_rejected() {
        let three: Vec<_> = (0..3)
            .map(|i| attachment(&format!("s{i}.png"), "image/png", PNG))
            .collect();
        assert!(decode_attachments(&three).is_err());
        decode_attachments(&three[..MAX_ATTACHMENTS]).expect("two is the cap");
    }

    #[test]
    fn no_attachments_stays_the_empty_case() {
        assert!(decode_attachments(&[]).expect("none is valid").is_empty());
    }

    #[test]
    fn a_hostile_filename_cannot_escape_the_markdown_link_or_the_directory() {
        let png = ATTACHMENT_TYPES[0];
        // Path traversal: only the base name survives, and it holds no dot.
        assert_eq!(safe_filename("../../etc/passwd", png, 0), "passwd.png");
        assert_eq!(safe_filename(r"C:\Users\x\shot.png", png, 0), "shot.png");
        // Markdown metacharacters would otherwise break out of `[label](url)`.
        let label = safe_filename("a[b](c)!.png", png, 0);
        assert_eq!(label, "a-b-c.png");
        assert!(!label.contains(['[', ']', '(', ')']));
        // Control characters and quotes never reach the post.
        let messy = safe_filename("bad\nname\"'`.png", png, 0);
        assert!(
            messy
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
        );
        // Nothing usable left: a generated name keyed by position.
        assert_eq!(safe_filename("", png, 0), "capture-1.png");
        assert_eq!(safe_filename("...", png, 1), "capture-2.png");
        // The extension follows the BYTES, never the name.
        assert_eq!(safe_filename("invoice.pdf", png, 0), "invoice.png");
        // Long names are clamped, extension included.
        let long = safe_filename(&"a".repeat(200), png, 0);
        assert_eq!(long, format!("{}.png", "a".repeat(MAX_FILENAME_STEM)));
    }

    #[test]
    fn attachment_links_use_the_frozen_discourse_shapes() {
        let linked = vec![
            LinkedAttachment {
                filename: "shot.png".to_owned(),
                short_url: "upload://abc.png".to_owned(),
                is_image: true,
            },
            LinkedAttachment {
                filename: "rapport.pdf".to_owned(),
                short_url: "upload://def.pdf".to_owned(),
                is_image: false,
            },
        ];
        let raw = topic_raw(
            IntakeKind::Install,
            "Installer fails at step 2.",
            None,
            &linked,
        );
        assert_eq!(
            raw,
            "> Installer fails at step 2\\.\n\n\
             kind: install\n\n\
             ![shot.png](upload://abc.png)\n\
             [rapport.pdf|attachment](upload://def.pdf)"
        );
    }

    #[test]
    fn a_body_without_attachments_is_byte_identical_to_before_the_feature() {
        // Clients predating the feature send no `attachments` key at all;
        // their topics must not gain a stray blank line.
        let raw = topic_raw(
            IntakeKind::Payment,
            "Card declined at checkout.",
            Some("macOS"),
            &[],
        );
        assert_eq!(
            raw,
            "> Card declined at checkout\\.\n\nkind: payment\nplatform: macOS"
        );
    }
}
