//! Postgres access: the `forum_links` linkage table (own database) and the
//! read-only active-subscription check against the Warren API database.
//!
//! ## No cleartext wallet at rest
//!
//! `forum_links` used to store the cleartext `pubkey_ss58`, the only
//! reversible wallet identity in this service and one that was never purged.
//! It is gone: the row is keyed by `external_id`, which is already
//! `HMAC-SHA256(handle_secret, pubkey)` (see [`crate::handle`]), a keyed,
//! one-way, per-wallet identifier. The uniqueness gate and the
//! pubkey -> handle lookup both work off `external_id` (re-derived from the
//! wallet presented at login), so nothing needs the cleartext pubkey. The
//! reverse handle -> pubkey lookup is intentionally no longer possible: a DB
//! seizure yields keyed hashes and public handles, not wallets.

use sqlx::PgPool;
use sqlx::Row as _;

/// A coarse, value-free category for an sqlx error, safe to log under the
/// no-log policy.
///
/// The full `Display`/`Debug` of an `sqlx::Error` embeds the Postgres error
/// DETAIL, which echoes the offending row values: a unique-constraint
/// violation on `forum_links` would put a handle or a keyed `external_id` in
/// the line. Every call site that logs an sqlx failure goes through this,
/// which `tests/log_privacy.rs` enforces.
#[must_use]
pub fn error_kind(err: &sqlx::Error) -> &'static str {
    match err {
        sqlx::Error::Database(_) => "database",
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::PoolTimedOut => "pool_timed_out",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        _ => "other",
    }
}

/// Runs the embedded migrations for the `forum_auth` database.
///
/// # Errors
/// Propagates sqlx migration failures.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Records (or refreshes) the pubkey <-> handle link at login time.
///
/// # Errors
/// Propagates sqlx errors (logged upstream, redacted).
pub async fn upsert_link(
    pool: &PgPool,
    external_id: &str,
    username: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO forum_links (external_id, username, created_at, last_login_at)
         VALUES ($1, $2, now(), now())
         ON CONFLICT (external_id) DO UPDATE SET last_login_at = now()",
    )
    .bind(external_id)
    .bind(username)
    .execute(pool)
    .await?;
    Ok(())
}

/// How many random slots to try before widening the published range. A
/// collision only happens when two logins race onto the same free slot, so
/// a handful of attempts covers everything except a genuinely full range.
const SLOT_ATTEMPTS: usize = 4;

/// Number of registered forum accounts, which sizes the published digest.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn link_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM forum_links")
        .fetch_one(pool)
        .await
}

/// The digest slot a wallet already holds, if it has one.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn notify_slot_for_external_id(
    pool: &PgPool,
    external_id: &str,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar("SELECT notify_slot FROM forum_links WHERE external_id = $1")
        .bind(external_id)
        .fetch_optional(pool)
        .await
        .map(Option::flatten)
}

/// Assigns the wallet a digest slot, or returns the one it already holds.
///
/// The slot is drawn uniformly from the free positions of the published
/// range, never from a retired one: a slot handed to a second account would
/// give it the previous holder's badge. `None` means the range was full at
/// every attempt, which leaves the account without a badge until its next
/// login rather than failing that login.
///
/// # Errors
/// Propagates sqlx errors other than the unique-violation retry.
pub async fn assign_notify_slot(
    pool: &PgPool,
    external_id: &str,
) -> Result<Option<i32>, sqlx::Error> {
    if let Some(slot) = notify_slot_for_external_id(pool, external_id).await? {
        return Ok(Some(slot));
    }
    let links = link_count(pool).await?;
    let range = crate::digest::published_slots(usize::try_from(links).unwrap_or(usize::MAX));
    let range = i32::try_from(range).unwrap_or(i32::MAX);

    for _ in 0..SLOT_ATTEMPTS {
        // One statement: pick a free slot at random and claim it. MATERIALIZED
        // pins the draw so both references see the same row, and the UNIQUE
        // constraint is what makes the claim safe against a racing login.
        let claimed: Result<Option<i32>, sqlx::Error> = sqlx::query_scalar(
            "WITH free AS MATERIALIZED (
                 SELECT g AS slot
                   FROM generate_series(0, $1 - 1) g
                  WHERE NOT EXISTS (SELECT 1 FROM forum_links WHERE notify_slot = g)
                    AND NOT EXISTS (SELECT 1 FROM forum_slots_retired WHERE notify_slot = g)
                  ORDER BY random()
                  LIMIT 1
             )
             UPDATE forum_links
                SET notify_slot = (SELECT slot FROM free)
              WHERE external_id = $2
                AND notify_slot IS NULL
                AND EXISTS (SELECT 1 FROM free)
             RETURNING notify_slot",
        )
        .bind(range)
        .bind(external_id)
        .fetch_optional(pool)
        .await
        .map(Option::flatten);

        match claimed {
            Ok(Some(slot)) => return Ok(Some(slot)),
            // No row updated: either the range is full or a racing login just
            // took the last free slot. Both are answered by trying again.
            Ok(None) => continue,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Every account's public handle and the digest slot it holds. The join key
/// between what Discourse reports as unread and where it lands in the
/// broadcast document.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn slots_by_username(pool: &PgPool) -> Result<Vec<(String, i32)>, sqlx::Error> {
    let rows =
        sqlx::query("SELECT username, notify_slot FROM forum_links WHERE notify_slot IS NOT NULL")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<String, _>("username"),
                r.get::<i32, _>("notify_slot"),
            )
        })
        .collect())
}

/// Unread notification count per forum username, read from Discourse's own
/// database on the same host through a SELECT-only role.
///
/// Badge awards (`notification_type` 12) are dropped, from the count and
/// from the panel list alike, so the two can never disagree. They are the
/// most numerous notification this forum produces and the only one caused by
/// nobody: the panel is about what people did. The cost is stated plainly:
/// while an unread badge sits on the forum, its bell reads higher than the
/// app's. Every other kind still matches it exactly, and marking the list
/// seen clears the badges on the forum too, so the gap closes by itself.
///
/// **This is Discourse's own `all_unread_notifications_count`, verbatim.**
/// Unread there means not read AND not yet seen AND its topic still exists,
/// with no high-priority exception: `read` only turns true when the reader
/// opens that one notification, while `users.seen_notification_id` advances
/// as soon as they look at the list. Counting `read = false` alone made the
/// app claim unread activity the forum showed as none.
///
/// Reusing the forum's own predicate rather than an approximation of it is
/// what lets the app's single bell carry a number the user can check against
/// the forum and find equal. Discourse splits private messages onto a second
/// indicator; the app has one bell, so it follows the one number.
///
/// This is also what makes reading on the web clear the app: opening the
/// forum bell moves `seen_notification_id`, and the next digest carries a
/// zero for that slot.
///
/// Bounded by `max_age_days` because an unread notification old enough stops
/// being worth a badge, and because that bound is what keeps the scan
/// proportional to recent activity rather than to the whole table. Discourse
/// gives its built-in accounts non-positive ids, so `id > 0` drops them.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn unread_by_username(
    discourse_pool: &PgPool,
    max_age_days: i32,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT u.username AS username, count(*) AS unread
           FROM notifications n
           JOIN users u ON u.id = n.user_id
           LEFT JOIN topics t ON t.id = n.topic_id
          WHERE u.id > 0
            AND n.created_at > now() - make_interval(days => $1)
            AND n.read = false
            AND n.id > COALESCE(u.seen_notification_id, 0)
            AND (t.id IS NULL OR t.deleted_at IS NULL)
            AND NOT (n.notification_type = ANY($2))
          GROUP BY u.username",
    )
    .bind(max_age_days)
    .bind(crate::notifications::HIDDEN_NOTIFICATION_TYPES.as_slice())
    .fetch_all(discourse_pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get::<String, _>("username"), r.get::<i64, _>("unread")))
        .collect())
}

/// One of the caller's own Discourse notifications, as read from Discourse's
/// database. Shaped for the app panel by [`crate::notifications`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRow {
    /// Discourse notification id.
    pub id: i64,
    /// Discourse `notification_type` enum value.
    pub notification_type: i32,
    /// Whether it still counts as unread, by the same rule as the badge, so
    /// a row the panel marks unread is one the badge counted.
    pub unread: bool,
    /// Unix epoch seconds it was created.
    pub created_unix: i64,
    /// Topic it points at, when it points at one.
    pub topic_id: Option<i64>,
    /// Post number within that topic.
    pub post_number: Option<i32>,
    /// Topic title, as Discourse denormalised it onto the notification.
    pub title: Option<String>,
    /// Username that caused the notification.
    pub actor: Option<String>,
    /// Group whose inbox a summary points at. Only a group message summary
    /// carries one, and it is the only thing that row has to open.
    pub group_name: Option<String>,
    /// Body of the post it points at, still untrimmed.
    pub raw: Option<String>,
}

/// The caller's own recent notifications, newest first.
///
/// `username` is derived from the signing wallet by the caller, never taken
/// from a request field, so this cannot be pointed at somebody else's
/// account. Read-only, and no write path exists: Discourse marks a
/// notification read when the reader opens the post, which is what drains
/// the badge.
///
/// Every column is cast explicitly, so a Discourse migration widening an id
/// cannot turn into a silent decode failure here.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn notifications_for_username(
    discourse_pool: &PgPool,
    username: &str,
    max_age_days: i32,
    limit: i64,
) -> Result<Vec<NotificationRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT n.id::bigint               AS id,
                n.notification_type::int   AS notification_type,
                (n.read = false
                 AND n.id > COALESCE(u.seen_notification_id, 0)
                 AND (t.id IS NULL OR t.deleted_at IS NULL))
                                           AS unread,
                EXTRACT(EPOCH FROM n.created_at)::bigint AS created_unix,
                n.topic_id::bigint         AS topic_id,
                n.post_number::int         AS post_number,
                (n.data::jsonb)->>'topic_title' AS title,
                COALESCE((n.data::jsonb)->>'display_username',
                         (n.data::jsonb)->>'original_username') AS actor,
                (n.data::jsonb)->>'group_name'  AS group_name,
                left(p.raw, 400)           AS raw
           FROM notifications n
           JOIN users u ON u.id = n.user_id
           LEFT JOIN topics t ON t.id = n.topic_id
           LEFT JOIN posts p
                  ON p.topic_id = n.topic_id
                 AND p.post_number = n.post_number
                 AND p.deleted_at IS NULL
          WHERE u.username = $1
            AND n.created_at > now() - make_interval(days => $2)
            AND NOT (n.notification_type = ANY($4))
          ORDER BY n.created_at DESC
          LIMIT $3",
    )
    .bind(username)
    .bind(max_age_days)
    .bind(limit)
    .bind(crate::notifications::HIDDEN_NOTIFICATION_TYPES.as_slice())
    .fetch_all(discourse_pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| NotificationRow {
            id: r.get::<i64, _>("id"),
            notification_type: r.get::<i32, _>("notification_type"),
            unread: r.get::<bool, _>("unread"),
            created_unix: r.get::<i64, _>("created_unix"),
            topic_id: r.get::<Option<i64>, _>("topic_id"),
            post_number: r.get::<Option<i32>, _>("post_number"),
            title: r.get::<Option<String>, _>("title"),
            actor: r.get::<Option<String>, _>("actor"),
            group_name: r.get::<Option<String>, _>("group_name"),
            raw: r.get::<Option<String>, _>("raw"),
        })
        .collect())
}

/// Advances the caller's read bookmark to their newest notification, which
/// is exactly what Discourse does when a reader opens their own forum bell
/// (`User#bump_last_seen_notification!`). Returns the bookmark afterwards.
///
/// This is the only write this service makes into Discourse, and it is
/// deliberately the narrowest one that exists. It moves a single integer
/// column and touches no row that carries content, so the worst a bug, a
/// replay or a compromised caller can do is mark somebody's list as seen.
/// Nothing can be lost, edited or published. The grant backing it is
/// `UPDATE (seen_notification_id) ON users` and nothing else, so that bound
/// is enforced by the database rather than by this code being correct.
///
/// **Monotonic.** `GREATEST` keeps a bookmark that is already further along,
/// so a stale client, a retry or two racing devices can only ever fail to
/// advance it, never resurrect notifications the reader has dealt with.
///
/// `username` is derived from the signing wallet by the caller, never taken
/// from a request field, so this cannot be pointed at somebody else.
///
/// The returned bookmark is cast explicitly, like every column the panel
/// reads: Discourse widened it to BIGINT, and decoding it narrower failed
/// AFTER the update had committed, so the route reported a landed write as
/// a failure.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn mark_seen_for_username(
    discourse_pool: &PgPool,
    username: &str,
) -> Result<i64, sqlx::Error> {
    // Same visibility rule as the count: a bookmark must not land on a
    // notification the reader can never be shown.
    let seen: Option<i64> = sqlx::query_scalar(
        "UPDATE users u
            SET seen_notification_id = GREATEST(
                  COALESCE(u.seen_notification_id, 0),
                  COALESCE((SELECT max(n.id)
                              FROM notifications n
                              LEFT JOIN topics t ON t.id = n.topic_id
                             WHERE n.user_id = u.id
                               AND (t.id IS NULL OR t.deleted_at IS NULL)), 0))
          WHERE u.username = $1
      RETURNING u.seen_notification_id::bigint",
    )
    .bind(username)
    .fetch_optional(discourse_pool)
    .await?;
    Ok(seen.unwrap_or(0))
}

/// A wallet's subscription standing, derived from the single `subscriptions`
/// row (created only on payment, never purged on expiry by `retention.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscriptionStatus {
    /// A `subscriptions` row exists: the wallet has paid at least once, ever
    /// (even if the subscription has since lapsed). Forum access requires this.
    pub ever_paid: bool,
    /// `expires_at > now()`: the subscription is active right now.
    pub active: bool,
    /// `expires_at` as unix seconds, if a row exists (for admin display).
    pub expires_at_unix: Option<i64>,
}

/// Reads a wallet's subscription standing. Read-only query on the Warren API
/// database (`SELECT`-only role). A missing row means never paid.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn subscription_status(
    warren_pool: &PgPool,
    pubkey_ss58: &str,
) -> Result<SubscriptionStatus, sqlx::Error> {
    // COALESCE guards a NULL `expires_at` from panicking under `panic = "abort"`.
    let row = sqlx::query(
        "SELECT COALESCE(expires_at > now(), false) AS active, \
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_unix \
         FROM subscriptions WHERE pubkey_ss58 = $1",
    )
    .bind(pubkey_ss58)
    .fetch_optional(warren_pool)
    .await?;
    Ok(match row {
        Some(r) => SubscriptionStatus {
            ever_paid: true,
            active: r.get::<bool, _>("active"),
            expires_at_unix: r.get::<Option<i64>, _>("expires_unix"),
        },
        None => SubscriptionStatus::default(),
    })
}

/// Support lookup: has this handle (public username) ever logged in? The
/// reverse handle -> pubkey is intentionally gone (no cleartext wallet is
/// stored); support can only confirm the handle exists.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn username_exists(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM forum_links WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Support lookup: has the wallet behind `external_id` (the keyed hash of the
/// pubkey, [`crate::handle::derive`]) ever logged in, and under which handle?
/// Replaces the old cleartext `pubkey -> username` lookup: the caller derives
/// `external_id` from the presented/known wallet, so no cleartext pubkey is
/// stored or queried.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn username_for_external_id(
    pool: &PgPool,
    external_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT username FROM forum_links WHERE external_id = $1")
        .bind(external_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("username")))
}

/// GDPR unlink: remove the forum link for a wallet, keyed by its `external_id`
/// (the caller derives it from the wallet, [`crate::handle::derive`]). Returns
/// the number of rows removed. Not yet exposed by any route: the
/// account-deletion endpoint (auth model, proof of wallet control) remains
/// TODO, and this is the storage primitive it will call.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn delete_link_for_external_id(
    pool: &PgPool,
    external_id: &str,
) -> Result<u64, sqlx::Error> {
    let removed: i64 = sqlx::query_scalar(
        "WITH gone AS (
             DELETE FROM forum_links WHERE external_id = $1 RETURNING notify_slot
         ), retired AS (
             INSERT INTO forum_slots_retired (notify_slot)
             SELECT notify_slot FROM gone WHERE notify_slot IS NOT NULL
             ON CONFLICT DO NOTHING
         )
         SELECT count(*) FROM gone",
    )
    .bind(external_id)
    .fetch_one(pool)
    .await?;
    Ok(u64::try_from(removed).unwrap_or(0))
}

/// Retention: delete links not logged into since `cutoff_unix`. Bounds how
/// long an inactive forum link (keyed hash + public handle) lingers, so the
/// table stops being the one identity artifact that survives forever. Returns
/// the number of rows purged.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn purge_inactive_links(pool: &PgPool, cutoff_unix: i64) -> Result<u64, sqlx::Error> {
    // The purged rows' slots are retired rather than freed: a device that
    // never logs in again still holds the slot it was told, so reissuing it
    // would show that device another account's badge.
    let purged: i64 = sqlx::query_scalar(
        "WITH gone AS (
             DELETE FROM forum_links WHERE last_login_at < to_timestamp($1) RETURNING notify_slot
         ), retired AS (
             INSERT INTO forum_slots_retired (notify_slot)
             SELECT notify_slot FROM gone WHERE notify_slot IS NOT NULL
             ON CONFLICT DO NOTHING
         )
         SELECT count(*) FROM gone",
    )
    .bind(cutoff_unix)
    .fetch_one(pool)
    .await?;
    Ok(u64::try_from(purged).unwrap_or(0))
}

/// The three identity reads and writes a wallet-signed admission needs, behind
/// one seam so the login and the in-app report share a single admission path
/// and the integration suite can drive it without a database.
///
/// Every deployment builds the Postgres form; the in-memory form exists for
/// the stub harness in `tests/`, where the pools never dial.
#[derive(Debug)]
pub enum IdentityStore {
    /// The real thing: `forum_auth` for the links, the Warren API database
    /// (read-only role) for the subscription standing.
    Postgres {
        /// `forum_auth` database.
        forum: PgPool,
        /// Warren API database, read-only role.
        warren: PgPool,
    },
    /// Test double: in-memory maps with the same semantics.
    Memory(MemoryIdentity),
}

/// In-memory identity state for tests: subscriptions keyed by SS58 address,
/// links keyed by `external_id` holding the username and the slot, if drawn.
#[derive(Debug, Default)]
pub struct MemoryIdentity {
    /// Subscription standing per wallet address.
    pub subscriptions: std::sync::Mutex<std::collections::HashMap<String, SubscriptionStatus>>,
    /// Registered links: `external_id` to `(username, notify_slot)`.
    pub links: std::sync::Mutex<std::collections::HashMap<String, (String, Option<i32>)>>,
}

impl IdentityStore {
    /// A wallet's subscription standing; a missing row means never paid.
    ///
    /// # Errors
    /// Propagates sqlx errors from the Postgres form.
    pub async fn subscription_status(
        &self,
        pubkey_ss58: &str,
    ) -> Result<SubscriptionStatus, sqlx::Error> {
        match self {
            IdentityStore::Postgres { warren, .. } => {
                subscription_status(warren, pubkey_ss58).await
            }
            IdentityStore::Memory(m) => Ok(m
                .subscriptions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(pubkey_ss58)
                .copied()
                .unwrap_or_default()),
        }
    }

    /// Records (or refreshes) the link at admission time.
    ///
    /// # Errors
    /// Propagates sqlx errors from the Postgres form.
    pub async fn upsert_link(&self, external_id: &str, username: &str) -> Result<(), sqlx::Error> {
        match self {
            IdentityStore::Postgres { forum, .. } => {
                upsert_link(forum, external_id, username).await
            }
            IdentityStore::Memory(m) => {
                m.links
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .entry(external_id.to_owned())
                    .or_insert_with(|| (username.to_owned(), None));
                Ok(())
            }
        }
    }

    /// The wallet's digest slot, drawn on first admission.
    ///
    /// # Errors
    /// Propagates sqlx errors from the Postgres form.
    pub async fn assign_notify_slot(&self, external_id: &str) -> Result<Option<i32>, sqlx::Error> {
        match self {
            IdentityStore::Postgres { forum, .. } => assign_notify_slot(forum, external_id).await,
            IdentityStore::Memory(m) => {
                let mut links = m
                    .links
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let next = i32::try_from(links.len()).unwrap_or(i32::MAX);
                Ok(links
                    .get_mut(external_id)
                    .map(|(_, slot)| *slot.get_or_insert(next)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // external_id stands in for HMAC-SHA256(handle_secret, pubkey): an opaque
    // keyed hash. The tests only need it to be a stable per-wallet string.
    #[sqlx::test(migrations = "./migrations")]
    async fn upsert_is_idempotent_and_forward_lookup_works_without_cleartext(pool: PgPool) {
        upsert_link(&pool, "ext_alice", "lusab-babad-dovok")
            .await
            .expect("first upsert");
        // A second login for the same wallet must not create a duplicate row.
        upsert_link(&pool, "ext_alice", "lusab-babad-dovok")
            .await
            .expect("second upsert");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM forum_links")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 1, "upsert on external_id must be idempotent");

        let handle = username_for_external_id(&pool, "ext_alice")
            .await
            .expect("lookup");
        assert_eq!(
            handle.as_deref(),
            Some("lusab-babad-dovok"),
            "the pubkey -> handle lookup resolves via the keyed external_id"
        );
        assert!(
            username_for_external_id(&pool, "ext_unknown")
                .await
                .expect("lookup")
                .is_none(),
            "an unregistered wallet resolves to nothing"
        );
        assert!(
            username_exists(&pool, "lusab-babad-dovok")
                .await
                .expect("exists"),
            "support can confirm a handle exists"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_slot_is_stable_for_a_wallet_and_never_shared(pool: PgPool) {
        upsert_link(&pool, "ext_alice", "lusab-babad-dovok")
            .await
            .expect("alice");
        upsert_link(&pool, "ext_bob", "rudop-tijub-sozom")
            .await
            .expect("bob");

        let alice = assign_notify_slot(&pool, "ext_alice")
            .await
            .expect("assign alice")
            .expect("a fresh forum has room");
        let bob = assign_notify_slot(&pool, "ext_bob")
            .await
            .expect("assign bob")
            .expect("a fresh forum has room");

        assert_ne!(
            alice, bob,
            "two accounts sharing a slot would show each other's badge"
        );
        assert!(
            (0..1024).contains(&alice),
            "the slot must land inside the published range, got {alice}"
        );
        assert_eq!(
            assign_notify_slot(&pool, "ext_alice")
                .await
                .expect("re-assign"),
            Some(alice),
            "a second login must return the same slot, or the device loses its badge"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_purged_accounts_slot_is_retired_not_reissued(pool: PgPool) {
        sqlx::query(
            "INSERT INTO forum_links (external_id, username, created_at, last_login_at) \
             VALUES ('ext_stale', 'aaaaa-bbbbb-ccccc', now() - interval '400 days', now() - interval '400 days')",
        )
        .execute(&pool)
        .await
        .expect("seed");
        let stale_slot = assign_notify_slot(&pool, "ext_stale")
            .await
            .expect("assign")
            .expect("slot");

        let cutoff = (chrono::Utc::now() - chrono::Duration::days(365)).timestamp();
        purge_inactive_links(&pool, cutoff).await.expect("purge");

        let retired: Vec<i32> =
            sqlx::query_scalar("SELECT notify_slot FROM forum_slots_retired ORDER BY notify_slot")
                .fetch_all(&pool)
                .await
                .expect("retired");
        assert_eq!(
            retired,
            vec![stale_slot],
            "the purged account's slot must be retired: its device still holds it"
        );

        // Fill every other slot so the allocator can only pick the retired one
        // if it is willing to reuse it at all.
        for i in 0..1024 {
            if i == stale_slot {
                continue;
            }
            sqlx::query(
                "INSERT INTO forum_links (external_id, username, notify_slot) VALUES ($1, $2, $3)",
            )
            .bind(format!("ext_filler_{i}"))
            .bind(format!("filler-{i:05}"))
            .bind(i)
            .execute(&pool)
            .await
            .expect("filler");
        }
        upsert_link(&pool, "ext_new", "nnnnn-nnnnn-nnnnn")
            .await
            .expect("new");

        let reissued = assign_notify_slot(&pool, "ext_new").await.expect("assign");

        assert_ne!(
            reissued,
            Some(stale_slot),
            "a retired slot must never come back: it would hand a stranger's badge to an old device"
        );
    }

    // Reproduces the two Discourse columns the digest reads. Their own
    // database is remote in production; this pins the SQL against a real
    // Postgres so a rename or a bad aggregate fails here, not on the box.
    async fn seed_fake_discourse(pool: &PgPool) {
        // One statement per call: a prepared statement cannot carry several.
        sqlx::query(
            // The bookmark and the notification id are BIGINT on the live
            // forum (schema_migrations 20260728071552, read on 2026-09-03):
            // Discourse widened both. Narrower fixture columns hid a decode
            // that failed only in production, after the write had landed.
            "CREATE TABLE users (
                 id INTEGER PRIMARY KEY,
                 username TEXT NOT NULL,
                 seen_notification_id BIGINT NOT NULL DEFAULT 0
             )",
        )
        .execute(pool)
        .await
        .expect("fake users table");
        sqlx::query(
            "CREATE TABLE notifications (
                 id BIGSERIAL PRIMARY KEY,
                 user_id INTEGER NOT NULL,
                 notification_type INTEGER NOT NULL,
                 read BOOLEAN NOT NULL,
                 high_priority BOOLEAN NOT NULL DEFAULT false,
                 created_at TIMESTAMPTZ NOT NULL,
                 topic_id INTEGER,
                 post_number INTEGER,
                 data VARCHAR
             )",
        )
        .execute(pool)
        .await
        .expect("fake notifications table");
        sqlx::query(
            "CREATE TABLE posts (
                 id SERIAL PRIMARY KEY,
                 topic_id INTEGER NOT NULL,
                 post_number INTEGER NOT NULL,
                 raw TEXT NOT NULL,
                 deleted_at TIMESTAMPTZ
             )",
        )
        .execute(pool)
        .await
        .expect("fake posts table");
        // Discourse's own count joins this to drop notifications whose topic
        // is gone, so the fixture needs it to exercise the same SQL.
        sqlx::query(
            "CREATE TABLE topics (
                 id INTEGER PRIMARY KEY,
                 deleted_at TIMESTAMPTZ
             )",
        )
        .execute(pool)
        .await
        .expect("fake topics table");
        sqlx::query(
            "INSERT INTO topics (id, deleted_at) VALUES
                 (86, NULL), (90, NULL), (12, NULL), (13, NULL), (99, NULL)",
        )
        .execute(pool)
        .await
        .expect("fake topics");
        sqlx::query(
            // seen_notification_id 0: nobody has glanced at their list yet,
            // so every unread row still counts.
            "INSERT INTO users (id, username, seen_notification_id) VALUES
                 (1, 'lusab-babad-dovok', 0), (2, 'rudop-tijub-sozom', 0), (-1, 'system', 0)",
        )
        .execute(pool)
        .await
        .expect("fake users");
        sqlx::query(
            "INSERT INTO notifications
                 (user_id, notification_type, read, created_at, topic_id, post_number, data) VALUES
                 (1, 2, false, now(),                    86, 4, '{\"topic_title\":\"Port forwarding\",\"display_username\":\"rudop-tijub-sozom\"}'),
                 (1, 5, false, now() - interval '1 hour', 86, 1, '{\"topic_title\":\"Port forwarding\",\"display_username\":\"nomar-kubad-fidor\"}'),
                 (1, 2, true,  now(),                    90, 2, '{\"topic_title\":\"Already read\"}'),
                 (2, 2, false, now() - interval '400 days', 12, 1, '{\"topic_title\":\"Ancient\"}'),
                 (-1, 2, false, now(),                    13, 1, '{\"topic_title\":\"System\"}')",
        )
        .execute(pool)
        .await
        .expect("fake notifications");
        sqlx::query(
            "INSERT INTO posts (topic_id, post_number, raw, deleted_at) VALUES
                 (86, 4, 'As-tu vérifié   que le pare-feu
laisse passer ?', NULL),
                 (86, 1, 'Le port forwarding ne s''ouvre pas', NULL)",
        )
        .execute(pool)
        .await
        .expect("fake posts");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn unread_counts_exclude_read_stale_and_system_rows(pool: PgPool) {
        seed_fake_discourse(&pool).await;

        let mut counts = unread_by_username(&pool, 90).await.expect("query");
        counts.sort();

        assert_eq!(
            counts,
            vec![("lusab-babad-dovok".to_owned(), 2)],
            "only unread, recent notifications of a real account may raise a badge"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn glancing_at_the_forum_bell_clears_the_badge(pool: PgPool) {
        // Reported 2026-08-08: the app claimed 3 unread while the forum bell
        // showed none. Discourse only sets `read` when the reader opens that
        // one notification, and advances `seen_notification_id` as soon as
        // they look at the list, so counting `read = false` counts what the
        // reader has already dealt with.
        seed_fake_discourse(&pool).await;
        let before = unread_by_username(&pool, 90).await.expect("query");
        assert_eq!(
            before,
            vec![("lusab-babad-dovok".to_owned(), 2)],
            "arrivals nobody has looked at still count"
        );

        // The reader opens their forum bell on the web: Discourse marks every
        // existing notification as seen, and nothing else.
        sqlx::query(
            "UPDATE users SET seen_notification_id = (SELECT max(id) FROM notifications) \
             WHERE username = 'lusab-babad-dovok'",
        )
        .execute(&pool)
        .await
        .expect("seen");

        let after = unread_by_username(&pool, 90).await.expect("query");

        assert!(
            after.is_empty(),
            "reading on the web must clear the app's badge, got {after:?}"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_glance_clears_a_private_message_too_because_the_bell_does(pool: PgPool) {
        // Read off Discourse's own `all_unread_notifications_count` on the
        // live forum: its bell counts unread-and-unseen with no high-priority
        // exception. Private messages get a separate indicator there, but the
        // app has one bell, so it follows the one number the forum paints.
        seed_fake_discourse(&pool).await;
        sqlx::query(
            "INSERT INTO notifications (user_id, notification_type, read, high_priority, \
             created_at, topic_id, post_number, data) \
             VALUES (1, 6, false, true, now(), 99, 1, '{\"topic_title\":\"Private\"}')",
        )
        .execute(&pool)
        .await
        .expect("pm");
        sqlx::query(
            "UPDATE users SET seen_notification_id = (SELECT max(id) FROM notifications) \
             WHERE username = 'lusab-babad-dovok'",
        )
        .execute(&pool)
        .await
        .expect("seen");

        let counts = unread_by_username(&pool, 90).await.expect("query");

        assert!(
            counts.is_empty(),
            "the app's count must be the number the forum bell shows, got {counts:?}"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_badge_award_reaches_neither_the_count_nor_the_list(pool: PgPool) {
        // Both queries drop them, and that is the point: a badge counted but
        // not listed would put a number on the bell with nothing behind it.
        seed_fake_discourse(&pool).await;
        sqlx::query(
            "INSERT INTO notifications (user_id, notification_type, read, created_at, data) \
             VALUES (1, 12, false, now(), '{\"badge_name\":\"Nice Post\"}')",
        )
        .execute(&pool)
        .await
        .expect("badge");

        let counts = unread_by_username(&pool, 90).await.expect("count");
        let rows = notifications_for_username(&pool, "lusab-babad-dovok", 90, 50)
            .await
            .expect("list");

        assert_eq!(
            counts,
            vec![("lusab-babad-dovok".to_owned(), 2)],
            "a badge must not raise the badge"
        );
        assert!(
            rows.iter().all(|r| r.notification_type != 12),
            "and it must not appear in the panel either"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_site_health_warning_reaches_neither_the_count_nor_the_list(pool: PgPool) {
        // `admin_problems` (38) is Discourse telling an ADMIN that the site has
        // maintenance items. It has no title, no actor and nothing to open, so
        // in the panel it was a row that said "New forum activity" and did
        // nothing when clicked.
        seed_fake_discourse(&pool).await;
        sqlx::query(
            "INSERT INTO notifications (user_id, notification_type, read, created_at, data) \
             VALUES (1, 38, false, now(), '{}')",
        )
        .execute(&pool)
        .await
        .expect("admin problem");

        let counts = unread_by_username(&pool, 90).await.expect("count");
        let rows = notifications_for_username(&pool, "lusab-babad-dovok", 90, 50)
            .await
            .expect("list");

        assert_eq!(
            counts,
            vec![("lusab-babad-dovok".to_owned(), 2)],
            "a maintenance warning must not raise the badge"
        );
        assert!(
            rows.iter().all(|r| r.notification_type != 38),
            "and it must not appear in the panel either"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_group_inbox_summary_carries_its_group(pool: PgPool) {
        // It has no topic, so the group name is the only thing that can point
        // the row at anything openable.
        seed_fake_discourse(&pool).await;
        sqlx::query(
            "INSERT INTO notifications (user_id, notification_type, read, created_at, data) \
             VALUES (1, 16, false, now(), \
             '{\"group_name\":\"staff\",\"inbox_count\":15,\"username\":\"lusab-babad-dovok\"}')",
        )
        .execute(&pool)
        .await
        .expect("group summary");

        let rows = notifications_for_username(&pool, "lusab-babad-dovok", 90, 50)
            .await
            .expect("list");
        let summary = rows
            .iter()
            .find(|r| r.notification_type == 16)
            .expect("the summary is listed");

        assert_eq!(summary.group_name.as_deref(), Some("staff"));
        assert_eq!(summary.topic_id, None, "a summary points at no topic");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_notification_whose_topic_was_deleted_stops_counting(pool: PgPool) {
        // Discourse's count joins `topics` and drops the deleted ones, so a
        // badge that kept counting them would outlive the thing it points at.
        seed_fake_discourse(&pool).await;
        sqlx::query("UPDATE topics SET deleted_at = now() WHERE id = 86")
            .execute(&pool)
            .await
            .expect("delete topic");

        let counts = unread_by_username(&pool, 90).await.expect("query");

        assert!(
            counts.is_empty(),
            "a deleted topic's notifications must stop counting, got {counts:?}"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn marking_seen_clears_the_count_without_touching_anything_else(pool: PgPool) {
        seed_fake_discourse(&pool).await;
        assert_eq!(
            unread_by_username(&pool, 90).await.expect("before"),
            vec![("lusab-babad-dovok".to_owned(), 2)]
        );

        let seen = mark_seen_for_username(&pool, "lusab-babad-dovok")
            .await
            .expect("mark seen");

        assert!(seen > 0, "the bookmark must land on a real notification id");
        assert!(
            unread_by_username(&pool, 90)
                .await
                .expect("after")
                .is_empty(),
            "marking the list seen is what the forum bell does, and it clears the count"
        );
        // The one authority this holds is a bookmark. Nothing that carries
        // content may move, so a bug here can never lose a notification.
        let still_unread: i64 =
            sqlx::query_scalar("SELECT count(*) FROM notifications WHERE read = false")
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(
            still_unread, 4,
            "no notification row may be rewritten by marking the list seen"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn marking_seen_reports_the_bookmark_discourse_stores_as_bigint(pool: PgPool) {
        // Seen live on 2026-09-03 against connect v0.15.3: the UPDATE landed
        // (the forum's bookmark advanced, the next digest read 0) and the
        // route still answered 404, because the returned bookmark was decoded
        // as a 32-bit integer while Discourse now stores it as BIGINT. A
        // landed write that reports failure is the worst shape of bug: the
        // client retries, or shows an error, over a state that is correct.
        seed_fake_discourse(&pool).await;
        let newest: i64 = sqlx::query_scalar("SELECT max(id) FROM notifications WHERE user_id = 1")
            .fetch_one(&pool)
            .await
            .expect("newest");

        let reported = mark_seen_for_username(&pool, "lusab-babad-dovok").await;

        let stored: i64 = sqlx::query_scalar(
            "SELECT seen_notification_id FROM users WHERE username = 'lusab-babad-dovok'",
        )
        .fetch_one(&pool)
        .await
        .expect("stored");
        assert_eq!(
            stored, newest,
            "the write itself must land on the newest notification"
        );
        assert_eq!(
            reported.map_err(|e| e.to_string()),
            Ok(stored),
            "a write that landed must be reported as such, with the bookmark it left"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn the_seen_bookmark_only_ever_moves_forward(pool: PgPool) {
        // It is the one guarantee that makes this write safe to expose: a
        // replay, a race or a stale client can only ever fail to advance it,
        // never resurrect notifications the reader has already dealt with.
        seed_fake_discourse(&pool).await;
        let first = mark_seen_for_username(&pool, "lusab-babad-dovok")
            .await
            .expect("first");
        sqlx::query("UPDATE users SET seen_notification_id = $1 WHERE username = $2")
            .bind(first + 100)
            .bind("lusab-babad-dovok")
            .execute(&pool)
            .await
            .expect("jump ahead");

        let second = mark_seen_for_username(&pool, "lusab-babad-dovok")
            .await
            .expect("second");

        assert_eq!(
            second,
            first + 100,
            "a later bookmark must not be dragged backwards"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn marking_seen_reaches_only_the_named_account(pool: PgPool) {
        seed_fake_discourse(&pool).await;
        sqlx::query("UPDATE users SET seen_notification_id = 0")
            .execute(&pool)
            .await
            .expect("reset");

        mark_seen_for_username(&pool, "lusab-babad-dovok")
            .await
            .expect("mark seen");

        let other: i64 = sqlx::query_scalar(
            "SELECT seen_notification_id FROM users WHERE username = 'rudop-tijub-sozom'",
        )
        .fetch_one(&pool)
        .await
        .expect("other");
        assert_eq!(other, 0, "one account's read must not touch another's");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn marking_seen_for_an_unknown_account_changes_nothing(pool: PgPool) {
        seed_fake_discourse(&pool).await;

        let seen = mark_seen_for_username(&pool, "nobod-yhere-atall")
            .await
            .expect("no error");

        assert_eq!(seen, 0, "an account with no rows has nothing to bookmark");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn the_panel_reads_only_the_callers_own_recent_notifications(pool: PgPool) {
        seed_fake_discourse(&pool).await;

        let rows = notifications_for_username(&pool, "lusab-babad-dovok", 90, 50)
            .await
            .expect("query");

        assert_eq!(
            rows.len(),
            3,
            "read ones still belong in the panel; another account's do not"
        );
        let newest = &rows[0];
        assert_eq!(newest.notification_type, 2);
        assert_eq!(newest.topic_id, Some(86));
        assert_eq!(newest.post_number, Some(4));
        assert_eq!(newest.title.as_deref(), Some("Port forwarding"));
        assert_eq!(
            newest.actor.as_deref(),
            Some("rudop-tijub-sozom"),
            "the actor comes out of Discourse's denormalised data blob"
        );
        assert!(
            newest
                .raw
                .as_deref()
                .is_some_and(|r| r.starts_with("As-tu vérifié")),
            "the row carries the post body the panel excerpts"
        );
        assert!(
            rows.iter().all(|r| r.title.as_deref() != Some("Ancient")),
            "another account's notification must never reach this caller"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_notification_whose_post_is_gone_still_lists(pool: PgPool) {
        seed_fake_discourse(&pool).await;
        sqlx::query("UPDATE posts SET deleted_at = now() WHERE topic_id = 86 AND post_number = 4")
            .execute(&pool)
            .await
            .expect("delete post");

        let rows = notifications_for_username(&pool, "lusab-babad-dovok", 90, 50)
            .await
            .expect("query");

        assert_eq!(
            rows[0].raw, None,
            "a deleted post yields no excerpt, and the row stays: dropping it would hide history"
        );
        assert_eq!(rows[0].title.as_deref(), Some("Port forwarding"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gdpr_unlink_removes_the_row(pool: PgPool) {
        upsert_link(&pool, "ext_bob", "rudop-tijub-sozom")
            .await
            .expect("upsert");
        let removed = delete_link_for_external_id(&pool, "ext_bob")
            .await
            .expect("delete");
        assert_eq!(
            removed, 1,
            "the GDPR unlink removes exactly the wallet's row"
        );
        assert!(
            username_for_external_id(&pool, "ext_bob")
                .await
                .expect("lookup")
                .is_none(),
            "after unlink the wallet has no forum link"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_purges_only_inactive_links(pool: PgPool) {
        // A stale link (last login 400 days ago) and a fresh one; only the
        // stale one is purged past a 365-day cutoff.
        sqlx::query(
            "INSERT INTO forum_links (external_id, username, created_at, last_login_at) VALUES \
             ('ext_stale', 'aaaaa-bbbbb-ccccc', now() - interval '400 days', now() - interval '400 days'), \
             ('ext_fresh', 'ddddd-eeeee-fffff', now() - interval '2 days', now() - interval '2 days')",
        )
        .execute(&pool)
        .await
        .expect("seed links");

        let cutoff = (chrono::Utc::now() - chrono::Duration::days(365)).timestamp();
        let purged = purge_inactive_links(&pool, cutoff).await.expect("purge");
        assert_eq!(
            purged, 1,
            "only the link inactive past the cutoff is purged"
        );

        let survivors: Vec<String> =
            sqlx::query_scalar("SELECT external_id FROM forum_links ORDER BY external_id")
                .fetch_all(&pool)
                .await
                .expect("survivors");
        assert_eq!(survivors, vec!["ext_fresh".to_owned()]);
    }
}
