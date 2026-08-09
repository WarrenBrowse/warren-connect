//! Shaping a Discourse notification row into what the app's panel renders.
//!
//! The broadcast digest says only THAT an account has activity. This is the
//! other half: when the user opens the panel, the app asks for the content
//! once, over a wallet-signed request. That request is user-initiated and
//! infrequent, so it creates no periodic presence signal, and it can only
//! ever return the caller's own notifications because the username is
//! derived from the signing wallet rather than taken from the request.

/// Longest excerpt a row carries. A panel row shows a couple of lines, and
/// a whole post would only make the response bigger for nothing.
const MAX_EXCERPT_CHARS: usize = 240;

/// Most notifications one response carries. The panel is a recent-activity
/// view, and Discourse itself is one click away for the rest.
pub const MAX_NOTIFICATIONS: i64 = 50;

/// Discourse notification types the panel never shows.
///
/// Dropped from the unread COUNT in the same breath, or the badge would offer
/// a number the list cannot account for.
///
/// - 12 `granted_badge`: the most numerous thing this forum emits and the only
///   one caused by nobody. The panel is about what people did.
/// - 38 `admin_problems`: the site-health warning Discourse raises for admins.
///   It carries no title, no actor and nothing to open, so it can only render
///   as a dead row, and it is actionable on the admin dashboard rather than in
///   a reader's panel.
pub const HIDDEN_NOTIFICATION_TYPES: [i32; 2] = [12, 38];

/// Stable label for a Discourse `notification_type`.
///
/// The integers are Discourse's own `Notification.types` enum. Only the
/// kinds a Warren user actually meets on a support forum are named; anything
/// else degrades to `other`, which the panel still renders as a row rather
/// than dropping, so a Discourse upgrade adding a type cannot make a
/// notification silently vanish.
#[must_use]
pub fn kind_for(notification_type: i32) -> &'static str {
    match notification_type {
        1 => "mentioned",
        2 => "replied",
        3 => "quoted",
        // 5 is a like, 25 a plugin reaction, 19 the consolidated form of
        // either. A reader tells none of them apart.
        5 | 19 | 25 => "liked",
        // 6 and 7 are a message and an invitation to one, 16 the daily
        // summary of a group inbox.
        6 | 7 | 16 => "private_message",
        9 => "posted",
        11 | 39 => "linked",
        12 => "granted_badge",
        // 17 is the first post of a watched topic, 36 a new topic in a
        // watched category or tag. Both mean a topic just opened.
        17 | 36 => "watching_first_post",
        // Discourse announcing its own new features, which only staff
        // receive. It counts in their bell, so it counts here.
        37 => "announcement",
        _ => "other",
    }
}

/// Forum path of the post a notification points at, `None` when it points at
/// no post (a badge, a group invitation).
#[must_use]
pub fn topic_path(topic_id: Option<i64>, post_number: Option<i32>) -> Option<String> {
    let topic_id = topic_id?;
    Some(match post_number {
        Some(n) if n > 1 => format!("/t/{topic_id}/{n}"),
        _ => format!("/t/{topic_id}"),
    })
}

/// Discourse `notification_type` of a group inbox summary, the one kind that
/// opens something while carrying no topic.
const GROUP_MESSAGE_SUMMARY: i32 = 16;

/// Where a notification row opens, or `None` when it opens nothing.
///
/// One entry point rather than a branch at the call site, so a type that needs
/// its own destination is added here and nowhere else.
#[must_use]
pub fn path_for(
    notification_type: i32,
    topic_id: Option<i64>,
    post_number: Option<i32>,
    recipient: &str,
    group_name: Option<&str>,
) -> Option<String> {
    if let Some(path) = topic_path(topic_id, post_number) {
        return Some(path);
    }
    // A summary says "your group inbox moved" and names no post, so the inbox
    // is the only thing there is to open. Path shape taken from Discourse's own
    // `group-message-summary` notification type.
    if notification_type == GROUP_MESSAGE_SUMMARY {
        return group_name.map(|group| format!("/u/{recipient}/messages/group/{group}"));
    }
    None
}

/// One-line excerpt of a post body: whitespace collapsed so a row stays a
/// row, then truncated on a character boundary.
#[must_use]
pub fn excerpt(raw: Option<&str>) -> Option<String> {
    let collapsed = raw?.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    let truncated: String = collapsed.chars().take(MAX_EXCERPT_CHARS).collect();
    Some(if truncated.chars().count() < collapsed.chars().count() {
        format!("{truncated}...")
    } else {
        truncated
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kinds_a_support_forum_actually_produces_are_named() {
        assert_eq!(kind_for(2), "replied");
        assert_eq!(kind_for(5), "liked");
        assert_eq!(
            kind_for(19),
            "liked",
            "consolidated likes are still likes to a reader"
        );
    }

    #[test]
    fn every_type_this_forum_actually_emits_is_named() {
        // Measured against the live forum on 2026-08-08: these four were
        // landing in the panel as "New forum activity", which says nothing
        // to the reader about what happened.
        assert_eq!(
            kind_for(25),
            "liked",
            "a plugin reaction is a like as far as the reader is concerned"
        );
        assert_eq!(
            kind_for(16),
            "private_message",
            "a group inbox summary belongs with the messages"
        );
        assert_eq!(
            kind_for(36),
            "watching_first_post",
            "a new topic in a watched category is a new topic"
        );
        assert_eq!(kind_for(39), "linked", "consolidated links are still links");
        assert_eq!(
            kind_for(37),
            "announcement",
            "a forum-software release note is not community activity"
        );
    }

    #[test]
    fn an_unknown_type_still_becomes_a_row() {
        assert_eq!(
            kind_for(9999),
            "other",
            "a Discourse upgrade must not make a notification vanish from the panel"
        );
    }

    #[test]
    fn a_reply_links_to_the_post_not_just_the_topic() {
        assert_eq!(topic_path(Some(86), Some(4)).as_deref(), Some("/t/86/4"));
    }

    #[test]
    fn the_first_post_links_to_the_topic_itself() {
        assert_eq!(
            topic_path(Some(86), Some(1)).as_deref(),
            Some("/t/86"),
            "post 1 is the topic, and the bare path is the one users recognise"
        );
    }

    #[test]
    fn the_site_health_warning_never_reaches_a_reader() {
        // Discourse raises `admin_problems` (38) for admins when the site has
        // maintenance items. It carries no title, no actor and no link, so the
        // panel could only ever render it as a dead row.
        assert!(HIDDEN_NOTIFICATION_TYPES.contains(&38));
        assert!(
            HIDDEN_NOTIFICATION_TYPES.contains(&12),
            "badge awards stay hidden too"
        );
    }

    #[test]
    fn a_group_inbox_summary_opens_that_inbox() {
        // The one kind with no topic that is still worth opening: it points at
        // the group's message list rather than at a post.
        assert_eq!(
            path_for(16, None, None, "gunak-sibuf-havon", Some("staff")).as_deref(),
            Some("/u/gunak-sibuf-havon/messages/group/staff")
        );
    }

    #[test]
    fn a_group_summary_missing_its_group_has_no_link() {
        assert_eq!(path_for(16, None, None, "someone", None), None);
    }

    #[test]
    fn a_reply_still_links_to_its_own_post() {
        assert_eq!(
            path_for(2, Some(86), Some(4), "someone", None).as_deref(),
            Some("/t/86/4"),
            "adding the group case must not disturb the ordinary one"
        );
    }

    #[test]
    fn a_direct_message_links_to_the_message_itself() {
        // Types 6 and 7 carry a topic, so they take the ordinary path even
        // though they share the `private_message` kind with the summary.
        assert_eq!(
            path_for(6, Some(120), Some(1), "someone", Some("staff")).as_deref(),
            Some("/t/120"),
            "a real message opens itself, not the group inbox"
        );
    }

    #[test]
    fn a_notification_about_no_post_has_no_link() {
        assert_eq!(
            topic_path(None, Some(3)),
            None,
            "a badge award has no post to open"
        );
    }

    #[test]
    fn an_excerpt_is_one_line_and_bounded() {
        let raw = format!("first line\n\n   second   line\n{}", "x".repeat(400));

        let excerpt = excerpt(Some(&raw)).expect("non-empty");

        assert!(
            excerpt.starts_with("first line second line"),
            "newlines and runs of spaces must collapse: {excerpt}"
        );
        assert_eq!(
            excerpt.chars().count(),
            MAX_EXCERPT_CHARS + 3,
            "a long post is truncated to the cap plus the ellipsis"
        );
    }

    #[test]
    fn a_short_excerpt_is_not_marked_as_truncated() {
        assert_eq!(excerpt(Some("hello")).as_deref(), Some("hello"));
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // A multi-byte body: truncating on bytes would panic or emit
        // invalid UTF-8 on the wire.
        let raw = "é".repeat(400);

        let excerpt = excerpt(Some(&raw)).expect("non-empty");

        assert_eq!(excerpt.chars().count(), MAX_EXCERPT_CHARS + 3);
    }

    #[test]
    fn a_body_of_only_whitespace_yields_no_excerpt() {
        assert_eq!(excerpt(Some("  \n\t ")), None);
    }
}
