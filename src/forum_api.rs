//! Discourse admin API client for the attach-logs flow.
//!
//! Three writes per attach: upload the decompressed log, open a private
//! message to the staff group with the file attached, then leave a staff-only
//! whisper on the public topic pointing at that PM. The public topic never
//! carries the log itself.
//!
//! No-log discipline: errors expose a coarse operation name and an HTTP
//! status only, never a response body (Discourse echoes post content and
//! usernames in error bodies).

use serde::Deserialize;

use crate::error::AuthError;

/// Public base of the forum, used in the PM/whisper cross-links (the API
/// itself is reached through [`ForumApi::base_url`], typically the internal
/// docker alias).
pub(crate) const FORUM_PUBLIC_URL: &str = "https://forum.warrenbrowse.com";

/// A Discourse API failure, redacted by construction.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ForumApiError {
    /// The HTTP request itself failed (network, timeout).
    #[error("discourse request failed: {op}")]
    Request {
        /// Coarse operation name.
        op: &'static str,
        /// Transport-level cause (carries no response body).
        #[source]
        source: reqwest::Error,
    },
    /// Discourse answered with a non-success status.
    #[error("discourse returned status {status} for {op}")]
    Status {
        /// Coarse operation name.
        op: &'static str,
        /// HTTP status code.
        status: u16,
    },
    /// The response body did not have the expected shape.
    #[error("discourse response malformed for {op}")]
    Malformed {
        /// Coarse operation name.
        op: &'static str,
    },
}

impl From<ForumApiError> for AuthError {
    fn from(err: ForumApiError) -> Self {
        // The coarse Display (op + status only) is safe to log; the caller
        // gets an opaque 502.
        tracing::error!(error = %err, "discourse api call failed");
        AuthError::Forum
    }
}

/// Tag put on a topic once its logs were delivered. It is the only durable,
/// publicly readable signal that the attach flow succeeded: the staff PM is
/// private and the whisper is invisible to the reporter, so without this the
/// theme cannot tell an author who still has to send logs from one who
/// already did. Also gives staff a way to filter reports that carry logs.
pub const LOGS_ATTACHED_TAG: &str = "logs-attached";

/// A forum topic's identity-relevant fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicInfo {
    /// Topic title, echoed in the staff PM.
    pub title: String,
    /// Username of the topic author (first poster).
    pub author_username: String,
    /// Current tags, needed because Discourse's topic update REPLACES the
    /// whole tag list rather than appending to it.
    pub tags: Vec<String>,
}

/// A completed upload (an attach-flow log, or a guest intake screenshot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedFile {
    /// Discourse `upload://` short url, used in the markdown attachment link.
    pub short_url: String,
}

/// Discourse admin API client (system user).
#[derive(Debug)]
pub struct ForumApi {
    base_url: String,
    api_key: String,
    api_username: String,
    staff_group: String,
    client: reqwest::Client,
}

/// Longest a report-derived fact (version, os) may be once published, so a
/// forged report cannot flood the public topic.
const MAX_FACT_LEN: usize = 80;

/// Neutralizes Discourse markdown in an untrusted string that will be
/// interpolated into a post authored by the system/staff account: strips
/// control characters (no forged extra lines) and backslash-escapes every
/// ASCII punctuation char, so links, images, code spans and `@`-mentions
/// render as literal text instead of firing. Non-ASCII text is preserved.
#[must_use]
pub(crate) fn escape_md_inline(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_control() {
            out.push(' ');
        } else {
            if ch.is_ascii_punctuation() {
                out.push('\\');
            }
            out.push(ch);
        }
    }
    out
}

/// `escape_md_inline` plus a length clamp, for the attacker-controlled report
/// facts (version, os). Clamps on the raw value before escaping so the cap is
/// on visible characters, not on the escapes.
#[must_use]
fn safe_fact(input: &str) -> String {
    let clamped: String = input.chars().take(MAX_FACT_LEN).collect();
    escape_md_inline(&clamped)
}

/// Title of the staff PM carrying the uploaded log.
#[must_use]
pub fn pm_title(topic_id: u64, topic_title: &str) -> String {
    format!(
        "Journaux Warren pour le sujet #{topic_id} : {}",
        escape_md_inline(topic_title)
    )
}

/// Body of the staff PM: author, topic, attachment link, public-topic link.
#[must_use]
pub fn pm_raw(
    topic_id: u64,
    topic_title: &str,
    author_username: &str,
    filename: &str,
    short_url: &str,
) -> String {
    // author_username is our server-derived handle (safe), so the mention is
    // intentional; topic_title is user-chosen and must be defanged.
    let title = escape_md_inline(topic_title);
    format!(
        "L'utilisateur @{author_username} a transmis les journaux de son application Warren \
         (rapport de probl\u{e8}me expurg\u{e9}) pour le sujet #{topic_id} \
         \u{ab}\u{a0}{title}\u{a0}\u{bb}.\n\n\
         [{filename}|attachment]({short_url})\n\n\
         Sujet public : {FORUM_PUBLIC_URL}/t/{topic_id}"
    )
}

/// Title of the receipt PM sent to the reporter.
#[must_use]
pub fn author_pm_title(topic_id: u64) -> String {
    format!("Vos journaux sont bien arriv\u{e9}s (sujet #{topic_id})")
}

/// Body of the receipt PM: what was received, who can read it, and how to
/// send a newer one. Says plainly that the logs are NOT public, because the
/// public topic shows no trace of them and a reporter cannot tell otherwise.
#[must_use]
pub fn author_pm_raw(topic_id: u64, topic_title: &str) -> String {
    let title = escape_md_inline(topic_title);
    format!(
        "Merci, les journaux de votre application Warren ont bien \u{e9}t\u{e9} re\u{e7}us pour le sujet \
         \u{ab}\u{a0}{title}\u{a0}\u{bb}.\n\n\
         Ils sont visibles uniquement par l'\u{e9}quipe support, jamais publiquement, et \
         n'apparaissent pas dans votre sujet.\n\n\
         Si vous reproduisez le probl\u{e8}me plus tard, vous pouvez envoyer une version plus \
         r\u{e9}cente depuis le bouton en bas du sujet, autant de fois que n\u{e9}cessaire.\n\n\
         Votre sujet : {FORUM_PUBLIC_URL}/t/{topic_id}"
    )
}

/// Body of the staff-only whisper on the public topic, linking to the PM.
#[must_use]
pub fn whisper_raw(pm_topic_id: u64) -> String {
    format!(
        "L'auteur du sujet a transmis ses journaux depuis l'application Warren. \
         Message priv\u{e9} au staff : {FORUM_PUBLIC_URL}/t/{pm_topic_id}"
    )
}

/// Body of the PUBLIC note posted on the topic when the report carried
/// parseable metadata: only values that are safe to publish (app version,
/// OS), plus the staff-only visibility statement. `None` when the report
/// exposed neither, so nothing public gets posted.
#[must_use]
pub fn public_note_raw(version: Option<&str>, os: Option<&str>) -> Option<String> {
    let mut facts = Vec::new();
    if let Some(v) = version {
        facts.push(format!("version de l'app : {}", safe_fact(v)));
    }
    if let Some(o) = os {
        facts.push(format!("syst\u{e8}me : {}", safe_fact(o)));
    }
    if facts.is_empty() {
        return None;
    }
    Some(format!(
        "Donn\u{e9}es techniques jointes automatiquement depuis l'application Warren ({}). \
         Les journaux complets ne sont visibles que par l'\u{e9}quipe support, jamais publiquement.",
        facts.join(", ")
    ))
}

impl ForumApi {
    /// Builds a client for a Discourse instance.
    #[must_use]
    pub fn new(base_url: &str, api_key: String, api_username: String, staff_group: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            api_username,
            staff_group,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client builds from static config"),
        }
    }

    /// The Discourse user this client acts as. The guest follow-up flow
    /// checks a topic against it: only a topic this bot opened is one a guest
    /// code may post into.
    #[must_use]
    pub fn api_username(&self) -> &str {
        &self.api_username
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.base_url, path))
            .header("Api-Key", &self.api_key)
            .header("Api-Username", &self.api_username)
    }

    /// Fetches a topic's title and author username.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure, non-success status, or a body
    /// without a resolvable author.
    pub async fn topic(&self, topic_id: u64) -> Result<TopicInfo, ForumApiError> {
        const OP: &str = "topic_fetch";
        #[derive(Deserialize)]
        struct CreatedBy {
            username: String,
        }
        #[derive(Deserialize)]
        struct Details {
            created_by: Option<CreatedBy>,
        }
        #[derive(Deserialize)]
        struct PostJson {
            username: Option<String>,
        }
        #[derive(Deserialize)]
        struct PostStream {
            posts: Vec<PostJson>,
        }
        #[derive(Deserialize)]
        struct TopicJson {
            title: String,
            details: Option<Details>,
            post_stream: Option<PostStream>,
            #[serde(default)]
            tags: Vec<String>,
        }

        let body: TopicJson = self
            .send(
                OP,
                self.request(reqwest::Method::GET, &format!("/t/{topic_id}.json")),
            )
            .await?;
        // `details.created_by` is the canonical author; the first post of the
        // stream is the fallback for API shapes that omit `details`.
        let author = body
            .details
            .and_then(|d| d.created_by)
            .map(|c| c.username)
            .or_else(|| {
                body.post_stream
                    .and_then(|p| p.posts.into_iter().next())
                    .and_then(|p| p.username)
            })
            .ok_or(ForumApiError::Malformed { op: OP })?;
        Ok(TopicInfo {
            title: body.title,
            author_username: author,
            tags: body.tags,
        })
    }

    /// Adds [`LOGS_ATTACHED_TAG`] to a topic, preserving the tags it already
    /// carries. No-op when the tag is already there, so re-attaching a second
    /// log version does not rewrite the topic.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure or non-success status. Callers
    /// treat this as non-fatal: the logs are already delivered by then, and a
    /// missing tag costs a louder button, not a lost report.
    pub async fn tag_logs_attached(
        &self,
        topic_id: u64,
        existing_tags: &[String],
    ) -> Result<(), ForumApiError> {
        const OP: &str = "tag_topic";
        if existing_tags
            .iter()
            .any(|t| t.eq_ignore_ascii_case(LOGS_ATTACHED_TAG))
        {
            return Ok(());
        }
        let mut tags: Vec<&str> = existing_tags.iter().map(String::as_str).collect();
        tags.push(LOGS_ATTACHED_TAG);
        let _: serde::de::IgnoredAny = self
            .send(
                OP,
                self.request(reqwest::Method::PUT, &format!("/t/-/{topic_id}.json"))
                    .json(&serde_json::json!({ "tags": tags })),
            )
            .await?;
        Ok(())
    }

    /// Uploads arbitrary bytes as a composer attachment. `mime` must be a
    /// type the caller has already validated: Discourse enforces its own
    /// `authorized_extensions` and size settings on top, and a rejection
    /// surfaces here as a non-success status.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure, non-success status, or a body
    /// without a `short_url`.
    pub async fn upload_file(
        &self,
        filename: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<UploadedFile, ForumApiError> {
        const OP: &str = "upload";
        #[derive(Deserialize)]
        struct UploadJson {
            short_url: String,
        }

        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_owned())
            .mime_str(mime)
            .map_err(|_| ForumApiError::Malformed { op: OP })?;
        let form = reqwest::multipart::Form::new()
            .text("type", "composer")
            .text("synchronous", "true")
            .part("files[]", part);
        let body: UploadJson = self
            .send(
                OP,
                self.request(reqwest::Method::POST, "/uploads.json")
                    .multipart(form),
            )
            .await?;
        Ok(UploadedFile {
            short_url: body.short_url,
        })
    }

    /// Creates the staff private message; returns the PM's topic id.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure, non-success status, or a body
    /// without a `topic_id`.
    pub async fn create_staff_pm(&self, title: &str, raw: &str) -> Result<u64, ForumApiError> {
        self.create_pm("staff_pm", &self.staff_group.clone(), title, raw)
            .await
    }

    /// Creates the receipt private message to the reporter. Discourse has no
    /// post visible to one member of a public topic, so the only way to tell
    /// an author their logs arrived, without telling everyone, is a PM.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure, non-success status, or a body
    /// without a `topic_id`.
    pub async fn create_author_pm(
        &self,
        username: &str,
        title: &str,
        raw: &str,
    ) -> Result<u64, ForumApiError> {
        self.create_pm("author_pm", username, title, raw).await
    }

    async fn create_pm(
        &self,
        op: &'static str,
        recipients: &str,
        title: &str,
        raw: &str,
    ) -> Result<u64, ForumApiError> {
        #[derive(Deserialize)]
        struct PostJson {
            topic_id: u64,
        }

        let body: PostJson = self
            .send(
                op,
                self.request(reqwest::Method::POST, "/posts.json")
                    .json(&serde_json::json!({
                        "title": title,
                        "raw": raw,
                        "archetype": "private_message",
                        "target_recipients": recipients,
                    })),
            )
            .await?;
        Ok(body.topic_id)
    }

    /// Posts the staff-only whisper on the public topic.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure or non-success status.
    pub async fn post_whisper(&self, topic_id: u64, raw: &str) -> Result<(), ForumApiError> {
        const OP: &str = "whisper";
        let _: serde::de::IgnoredAny = self
            .send(
                OP,
                self.request(reqwest::Method::POST, "/posts.json")
                    .json(&serde_json::json!({
                        "topic_id": topic_id,
                        "raw": raw,
                        "whisper": "true",
                    })),
            )
            .await?;
        Ok(())
    }

    /// Posts a plain public reply on a topic (the safe-to-publish technical
    /// facts note, and a guest follow-up).
    ///
    /// Returns the post number when Discourse reports one, which is what makes
    /// a reply linkable. Optional rather than required: a caller that only
    /// wants the post published must not lose it because the response shape
    /// drifted, and the one caller that wants the anchor can do without it.
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure or a non-success status.
    pub async fn post_reply(&self, topic_id: u64, raw: &str) -> Result<Option<u64>, ForumApiError> {
        const OP: &str = "reply";
        #[derive(Deserialize)]
        struct PostJson {
            #[serde(default)]
            post_number: Option<u64>,
        }

        let body: PostJson = self
            .send(
                OP,
                self.request(reqwest::Method::POST, "/posts.json")
                    .json(&serde_json::json!({
                        "topic_id": topic_id,
                        "raw": raw,
                    })),
            )
            .await?;
        Ok(body.post_number)
    }

    /// Creates a public topic in `category_id`; returns the topic id. Used by
    /// the guest intake flow (this client is then built with the dedicated
    /// low-privilege intake bot as `api_username`, not the system user).
    ///
    /// # Errors
    /// [`ForumApiError`] on transport failure, non-success status, or a body
    /// without a `topic_id`.
    pub async fn create_topic(
        &self,
        title: &str,
        raw: &str,
        category_id: u64,
    ) -> Result<u64, ForumApiError> {
        const OP: &str = "intake_topic";
        #[derive(Deserialize)]
        struct PostJson {
            topic_id: u64,
        }

        let body: PostJson = self
            .send(
                OP,
                self.request(reqwest::Method::POST, "/posts.json")
                    .json(&serde_json::json!({
                        "title": title,
                        "raw": raw,
                        "category": category_id,
                    })),
            )
            .await?;
        Ok(body.topic_id)
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        op: &'static str,
        req: reqwest::RequestBuilder,
    ) -> Result<T, ForumApiError> {
        let resp = req
            .send()
            .await
            .map_err(|source| ForumApiError::Request { op, source })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ForumApiError::Status {
                op,
                status: status.as_u16(),
            });
        }
        resp.json::<T>()
            .await
            .map_err(|_| ForumApiError::Malformed { op })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pm_title_names_the_topic() {
        let t = pm_title(42, "Connexion impossible");
        assert!(t.contains("42"));
        assert!(t.contains("Connexion impossible"));
    }

    #[test]
    fn pm_raw_links_attachment_author_and_public_topic() {
        let raw = pm_raw(
            42,
            "Connexion impossible",
            "lusab-babad-dovok",
            "warren-report-topic42-1700000000.log",
            "upload://abc.log",
        );
        assert!(raw.contains("@lusab-babad-dovok"));
        assert!(raw.contains("Connexion impossible"));
        assert!(
            raw.contains("[warren-report-topic42-1700000000.log|attachment](upload://abc.log)"),
            "markdown attachment link is the Discourse-frozen shape"
        );
        assert!(raw.contains("https://forum.warrenbrowse.com/t/42"));
    }

    #[test]
    fn whisper_raw_links_the_pm() {
        let raw = whisper_raw(987);
        assert!(raw.contains("https://forum.warrenbrowse.com/t/987"));
    }

    #[test]
    fn public_note_neutralizes_markdown_from_report_metadata() {
        // version and os come from the client-signed report body, so a forged
        // report must not inject a link, image, mention or code span into the
        // system-authored public reply.
        let raw = public_note_raw(Some("[pay](https://evil)"), Some("@admin `x`"))
            .expect("some fact present");
        assert!(
            !raw.contains("[pay](https://evil)"),
            "no live markdown link"
        );
        assert!(!raw.contains("](http"), "no link syntax survives");
        assert!(
            raw.contains("\\@admin"),
            "the mention is backslash-defanged"
        );
        assert!(raw.contains("evil"), "the text is preserved, only defanged");
    }

    #[test]
    fn public_note_clamps_an_oversized_field() {
        let huge = "a".repeat(500);
        let raw = public_note_raw(Some(&huge), None).expect("some fact");
        assert!(raw.len() < 300, "an attacker cannot flood the public topic");
    }

    #[test]
    fn public_note_strips_control_characters() {
        // A newline could forge an extra "staff-only" style line in the note.
        let raw = public_note_raw(Some("1.0\n\nFAKE LINE"), None).expect("some fact");
        assert!(!raw.contains('\n'), "no injected newline from metadata");
    }

    #[test]
    fn pm_raw_defangs_a_hostile_topic_title() {
        let raw = pm_raw(
            42,
            "@everyone [x](https://evil)",
            "lusab-babad-dovok",
            "f.log",
            "upload://a.log",
        );
        assert!(
            raw.contains("@lusab-babad-dovok"),
            "the real author mention stays"
        );
        assert!(
            raw.contains("\\@everyone"),
            "a title mention is backslash-defanged"
        );
        assert!(!raw.contains("](https://evil)"), "a title link is defanged");
    }
}
