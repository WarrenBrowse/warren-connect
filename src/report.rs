//! In-app bug report: a wallet-signed topic in the bug-reports category, with
//! the redacted logs delivered to the staff the way attach-logs delivers
//! them, for a user who cannot complete the browser sign-in.
//!
//! The body mirrors the forum's "Report a bug" form template field for field
//! (area, device, version, what happened, steps, frequency), so staff read one
//! kind of report whether it was filed from the composer or from the app.
//! Every free-text value is markdown-defanged before it reaches a post the
//! reporter's own account authors: a hostile report must not be able to ping
//! members, plant a link, or reorder its own text.

use serde::Deserialize;

use crate::error::AuthError;
use crate::forum_api::escape_md_inline;
use crate::intake::{MAX_MESSAGE_CHARS, MIN_MESSAGE_CHARS, defang_mentions, quote_block};

/// Longest optional title the reporter may set; the server derives one
/// otherwise.
pub const MAX_TITLE_CHARS: usize = 100;
/// Shortest title accepted when one is given.
pub const MIN_TITLE_CHARS: usize = 5;
/// Cap on the client-declared version and OS facts (same bound as the facts
/// parsed out of the report itself).
pub const MAX_FACT_CHARS: usize = crate::attach::MAX_FACT_CHARS;
/// Cap on the locale tag handed to Discourse at account creation.
pub const MAX_LOCALE_CHARS: usize = 10;
/// Characters of the reporter's text kept in a derived title.
const TITLE_EXCERPT_CHARS: usize = 60;

/// The platform the report is filed from; doubles as the topic's tag, which
/// is why the values are exactly the forum's `Platform` tag group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Android app.
    Android,
    /// iOS app.
    Ios,
    /// Linux desktop app.
    Linux,
    /// macOS desktop app.
    Macos,
    /// Windows desktop app.
    Windows,
}

impl Platform {
    /// The forum tag, and the value the form's device field would carry.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Platform::Android => "android",
            Platform::Ios => "ios",
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Windows => "windows",
        }
    }

    /// Capitalized form for the title prefix.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Platform::Android => "Android",
            Platform::Ios => "iOS",
            Platform::Linux => "Linux",
            Platform::Macos => "macOS",
            Platform::Windows => "Windows",
        }
    }
}

/// Where the problem happens; the form's first dropdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Area {
    /// Pages not loading, slow, broken sites.
    Browsing,
    /// Cannot connect, drops, no internet.
    Connection,
    /// Wallet, payment or subscription.
    Wallet,
    /// Installing or updating Warren.
    Install,
    /// Anything else, including the forum sign-in itself.
    Other,
}

impl Area {
    /// The form's choice string, byte for byte, so the section reads like a
    /// composer-filed report.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Area::Browsing => "Browsing (pages not loading, slow, broken sites)",
            Area::Connection => "Connection (cannot connect, drops, no internet)",
            Area::Wallet => "Wallet, payment or subscription",
            Area::Install => "Installing or updating Warren",
            Area::Other => "Something else",
        }
    }

    /// Short form for the derived title.
    #[must_use]
    pub fn short(self) -> &'static str {
        match self {
            Area::Browsing => "Browsing",
            Area::Connection => "Connection",
            Area::Wallet => "Wallet",
            Area::Install => "Install",
            Area::Other => "Other",
        }
    }
}

/// How often it happens; the form's last dropdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    /// Every time.
    Always,
    /// Sometimes.
    Sometimes,
    /// It happened once.
    Once,
}

impl Frequency {
    /// The form's choice string, byte for byte.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Frequency::Always => "Every time",
            Frequency::Sometimes => "Sometimes",
            Frequency::Once => "It happened once",
        }
    }
}

/// The signed request body. Unknown fields are ignored so an older server
/// tolerates a newer client, the property the intake already relies on.
#[derive(Debug, Deserialize)]
pub struct ReportRequest {
    /// Platform, also the topic tag.
    pub platform: Platform,
    /// Where the problem happens.
    pub area: Area,
    /// How often it happens.
    pub frequency: Frequency,
    /// The reporter's description.
    pub what_happened: String,
    /// Steps to reproduce.
    #[serde(default)]
    pub steps: Option<String>,
    /// Optional title; derived from the description otherwise.
    #[serde(default)]
    pub title: Option<String>,
    /// The app's own version string, the fallback when the log carries none.
    #[serde(default)]
    pub app_version: Option<String>,
    /// The device's OS string, same fallback rule.
    #[serde(default)]
    pub os_version: Option<String>,
    /// The device locale, applied by Discourse at account creation only.
    #[serde(default)]
    pub locale: Option<String>,
    /// The gzipped redacted problem report, base64 (standard alphabet).
    #[serde(default)]
    pub log_gz_b64: Option<String>,
}

/// Validates the caps. Lengths count chars, as the intake does.
///
/// # Errors
/// [`AuthError::InvalidReport`] on any violation.
pub fn validate(req: &ReportRequest) -> Result<(), AuthError> {
    let chars = |s: &str| s.chars().count();
    if !(MIN_MESSAGE_CHARS..=MAX_MESSAGE_CHARS).contains(&chars(&req.what_happened)) {
        return Err(AuthError::InvalidReport);
    }
    if req
        .steps
        .as_deref()
        .is_some_and(|s| chars(s) > MAX_MESSAGE_CHARS)
    {
        return Err(AuthError::InvalidReport);
    }
    if req
        .title
        .as_deref()
        .is_some_and(|t| !(MIN_TITLE_CHARS..=MAX_TITLE_CHARS).contains(&chars(t.trim())))
    {
        return Err(AuthError::InvalidReport);
    }
    for fact in [req.app_version.as_deref(), req.os_version.as_deref()]
        .into_iter()
        .flatten()
    {
        if chars(fact) > MAX_FACT_CHARS {
            return Err(AuthError::InvalidReport);
        }
    }
    if let Some(locale) = req.locale.as_deref() {
        let shape_ok = (2..=MAX_LOCALE_CHARS).contains(&chars(locale))
            && locale.chars().all(|c| c.is_ascii_alphabetic() || c == '-');
        if !shape_ok {
            return Err(AuthError::InvalidReport);
        }
    }
    if req
        .log_gz_b64
        .as_deref()
        .is_some_and(|b| b.len() > crate::attach::MAX_LOG_GZ_B64_CHARS)
    {
        return Err(AuthError::PayloadTooLarge);
    }
    Ok(())
}

/// One line of user text for a title: whitespace collapsed, control and
/// bidi characters dropped, clamped. A title is plain text to Discourse (no
/// markdown, no mention parsing), so it is NOT backslash-escaped: the
/// escapes showed as literal backslashes in the topic list (topic 168).
fn title_excerpt(text: &str) -> String {
    let collapsed: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .take(TITLE_EXCERPT_CHARS)
        .collect();
    collapsed.trim().to_owned()
}

/// Unicode bidirectional formatting characters (the same set the markdown
/// escaper drops): none belongs in a title, every one can reorder it.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Topic title: `[Android] Connection: cannot connect after update #a1b2c3`.
/// The random suffix is what makes two reports with the same text distinct,
/// since the forum refuses duplicate titles.
#[must_use]
pub fn topic_title(req: &ReportRequest, shortid: &str) -> String {
    let excerpt = req
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map_or_else(|| title_excerpt(&req.what_happened), title_excerpt);
    format!(
        "[{}] {}: {excerpt} #{shortid}",
        req.platform.label(),
        req.area.short()
    )
}

/// Topic body: the form template's sections, in its order and wording, with
/// every free-text value quoted and defanged, then the sentence that replaces
/// the form's upload field.
#[must_use]
pub fn topic_raw(req: &ReportRequest) -> String {
    let mut raw = String::new();
    raw.push_str("### Where does the problem happen?\n");
    raw.push_str(req.area.label());
    raw.push_str("\n\n### Your device\n");
    raw.push_str(req.platform.tag());
    raw.push_str("\n\n### Warren version (optional)\n");
    match req
        .app_version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(version) => raw.push_str(&defang_mentions(&escape_md_inline(version))),
        None => raw.push_str("not provided"),
    }
    raw.push_str("\n\n### What happened?\n");
    raw.push_str(&quote_block(&req.what_happened));
    if let Some(steps) = req
        .steps
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        raw.push_str("\n\n### How can we make it happen too? (optional)\n");
        raw.push_str(&quote_block(steps));
    }
    raw.push_str("\n\n### How often does it happen?\n");
    raw.push_str(req.frequency.label());
    if let Some(os) = req
        .os_version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        raw.push_str("\n\n### System\n");
        raw.push_str(&defang_mentions(&escape_md_inline(os)));
    }
    raw.push_str(
        "\n\nFiled from the Warren app. Technical logs, when included, are visible to the \
         support team only.",
    );
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ReportRequest {
        ReportRequest {
            platform: Platform::Android,
            area: Area::Connection,
            frequency: Frequency::Always,
            what_happened: "I tap Connect, the rabbit spins, then nothing happens.".into(),
            steps: None,
            title: None,
            app_version: None,
            os_version: None,
            locale: None,
            log_gz_b64: None,
        }
    }

    #[test]
    fn accepts_a_minimal_report() {
        validate(&base()).expect("minimal report is valid");
    }

    #[test]
    fn refuses_a_description_outside_the_message_caps() {
        let mut short = base();
        short.what_happened = "too short".into();
        assert!(matches!(validate(&short), Err(AuthError::InvalidReport)));
        let mut long = base();
        long.what_happened = "x".repeat(MAX_MESSAGE_CHARS + 1);
        assert!(matches!(validate(&long), Err(AuthError::InvalidReport)));
        let mut edge = base();
        edge.what_happened = "\u{e9}".repeat(MAX_MESSAGE_CHARS);
        validate(&edge).expect("the cap counts chars, not bytes");
    }

    #[test]
    fn refuses_oversized_steps_title_facts_and_a_malformed_locale() {
        let mut steps = base();
        steps.steps = Some("s".repeat(MAX_MESSAGE_CHARS + 1));
        assert!(matches!(validate(&steps), Err(AuthError::InvalidReport)));
        let mut title = base();
        title.title = Some("abc".into());
        assert!(matches!(validate(&title), Err(AuthError::InvalidReport)));
        title.title = Some("t".repeat(MAX_TITLE_CHARS + 1));
        assert!(matches!(validate(&title), Err(AuthError::InvalidReport)));
        title.title = Some("A fine title".into());
        validate(&title).expect("a title inside the caps is valid");
        let mut fact = base();
        fact.app_version = Some("v".repeat(MAX_FACT_CHARS + 1));
        assert!(matches!(validate(&fact), Err(AuthError::InvalidReport)));
        let mut locale = base();
        locale.locale = Some("fr_FR;q=1".into());
        assert!(matches!(validate(&locale), Err(AuthError::InvalidReport)));
        locale.locale = Some("pt-BR".into());
        validate(&locale).expect("a BCP47-shaped tag is valid");
    }

    #[test]
    fn an_oversized_log_field_is_too_large_not_invalid() {
        // The client distinguishes 413 (send a smaller report) from 422 (fix
        // the form), so the log cap must not collapse into the form error.
        let mut req = base();
        req.log_gz_b64 = Some("A".repeat(crate::attach::MAX_LOG_GZ_B64_CHARS + 1));
        assert!(matches!(validate(&req), Err(AuthError::PayloadTooLarge)));
    }

    #[test]
    fn enum_labels_are_the_form_templates_choice_strings() {
        // Pinned against the live form template "Report a bug" (form id 1):
        // a report filed from the app must read exactly like one filed from
        // the composer.
        assert_eq!(
            Area::Browsing.label(),
            "Browsing (pages not loading, slow, broken sites)"
        );
        assert_eq!(
            Area::Connection.label(),
            "Connection (cannot connect, drops, no internet)"
        );
        assert_eq!(Area::Wallet.label(), "Wallet, payment or subscription");
        assert_eq!(Area::Install.label(), "Installing or updating Warren");
        assert_eq!(Area::Other.label(), "Something else");
        assert_eq!(Frequency::Always.label(), "Every time");
        assert_eq!(Frequency::Sometimes.label(), "Sometimes");
        assert_eq!(Frequency::Once.label(), "It happened once");
        for (p, tag) in [
            (Platform::Android, "android"),
            (Platform::Ios, "ios"),
            (Platform::Linux, "linux"),
            (Platform::Macos, "macos"),
            (Platform::Windows, "windows"),
        ] {
            assert_eq!(
                p.tag(),
                tag,
                "the tag is a member of the Platform tag group"
            );
        }
    }

    #[test]
    fn enums_deserialize_from_lowercase_tokens_only() {
        let req: ReportRequest = serde_json::from_str(
            r#"{"platform":"macos","area":"install","frequency":"once",
                "what_happened":"The installer stops at the service step every time.",
                "unknown_future_field": 1}"#,
        )
        .expect("lowercase tokens parse, unknown fields are ignored");
        assert_eq!(req.platform, Platform::Macos);
        assert_eq!(req.area, Area::Install);
        assert_eq!(req.frequency, Frequency::Once);
        assert!(
            serde_json::from_str::<ReportRequest>(
                r#"{"platform":"Android","area":"install","frequency":"once","what_happened":"long enough description here"}"#
            )
            .is_err(),
            "capitalized tokens are not accepted"
        );
    }

    #[test]
    fn title_is_prefixed_suffixed_bounded_and_plain() {
        // A Discourse title is plain text: no markdown to defang, so no
        // backslashes either (they rendered literally on the live forum,
        // topic 168), but a bidi override or a control character still goes.
        let mut req = base();
        req.what_happened =
            "Cannot connect: the app\u{202E} says no-exit\n".to_owned() + &"x".repeat(200);
        let title = topic_title(&req, "a1b2c3");
        assert!(
            title.starts_with("[Android] Connection: Cannot connect: the app says no-exit"),
            "{title}"
        );
        assert!(title.ends_with(" #a1b2c3"));
        assert!(title.chars().count() < 120);
        assert!(
            !title.contains('\\'),
            "no escape survives into a title: {title}"
        );
        assert!(!title.contains('\u{202E}'));
        assert!(!title.contains('\n'));
    }

    #[test]
    fn an_explicit_title_replaces_the_excerpt() {
        let mut req = base();
        req.title = Some("  Cannot connect after the update  ".into());
        assert_eq!(
            topic_title(&req, "ffffff"),
            "[Android] Connection: Cannot connect after the update #ffffff"
        );
    }

    #[test]
    fn body_mirrors_the_form_sections_and_quotes_the_text() {
        let mut req = base();
        req.steps = Some("Open the app\nTap Connect".into());
        req.app_version = Some("1.1.20".into());
        req.os_version = Some("Android 15 (API 35)".into());
        let raw = topic_raw(&req);
        let expected = "### Where does the problem happen?\n\
Connection (cannot connect, drops, no internet)\n\n\
### Your device\n\
android\n\n\
### Warren version (optional)\n\
1\\.1\\.20\n\n\
### What happened?\n\
> I tap Connect\\, the rabbit spins\\, then nothing happens\\.\n\n\
### How can we make it happen too? (optional)\n\
> Open the app\n\
> Tap Connect\n\n\
### How often does it happen?\n\
Every time\n\n\
### System\n\
Android 15 \\(API 35\\)\n\n\
Filed from the Warren app. Technical logs, when included, are visible to the support team only.";
        assert_eq!(raw, expected);
    }

    #[test]
    fn body_of_a_minimal_report_omits_the_empty_sections() {
        let raw = topic_raw(&base());
        assert!(raw.contains("### Warren version (optional)\nnot provided"));
        assert!(!raw.contains("### How can we make it happen too?"));
        assert!(!raw.contains("### System"));
    }

    #[test]
    fn hostile_text_cannot_ping_link_or_reorder() {
        let mut req = base();
        req.what_happened =
            "@admin look [here](https://evil) \u{202E}reversed\u{2028}next and more words".into();
        let raw = topic_raw(&req);
        assert!(raw.contains("\\@\u{200B}admin"));
        assert!(!raw.contains("](https://evil)"));
        assert!(!raw.contains('\u{202E}'));
        assert!(!raw.contains('\u{2028}'));
    }
}
