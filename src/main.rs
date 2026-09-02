//! Service entry point. Configuration is environment-only (12-factor, no
//! config file): see `required` calls below for the exhaustive list.

use std::sync::Arc;

use anyhow::Context as _;
use sqlx::postgres::PgPoolOptions;

use warren_connect::attach::AttachStore;
use warren_connect::forum_api::ForumApi;
use warren_connect::nonces::NonceStore;
use warren_connect::routes::{AppState, router};
use warren_connect::sessions::SessionStore;
use warren_connect::store;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var {name}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8095".into());
    let connect_secret = required("DISCOURSE_CONNECT_SECRET")?.into_bytes();
    let handle_secret = required("FORUM_HANDLE_SECRET")?.into_bytes();
    let public_host =
        std::env::var("PUBLIC_HOST").unwrap_or_else(|_| "connect.warrenbrowse.com".into());
    let internal_token = std::env::var("INTERNAL_TOKEN").unwrap_or_default();
    anyhow::ensure!(
        connect_secret.len() >= 32,
        "DISCOURSE_CONNECT_SECRET too short"
    );
    anyhow::ensure!(handle_secret.len() >= 32, "FORUM_HANDLE_SECRET too short");
    // Empty disables the internal support endpoints; a non-empty token gates
    // pubkey<->handle lookups, so it must be a strong secret.
    anyhow::ensure!(
        internal_token.is_empty() || internal_token.len() >= 32,
        "INTERNAL_TOKEN too short (>= 32 bytes, or empty to disable)"
    );

    // Forum staff. Discourse re-applies the SSO admin field on every login, so
    // an unset roster demotes every operator on their next one: warn loudly
    // rather than start silently ungoverned.
    let admins = warren_connect::admins::Allowlist::parse(
        &std::env::var("WARREN_ADMIN_PUBKEYS").unwrap_or_default(),
    )
    .context("WARREN_ADMIN_PUBKEYS")?;
    if admins.is_empty() {
        tracing::warn!("WARREN_ADMIN_PUBKEYS empty: the forum has no staff wallet");
    } else {
        tracing::info!(count = admins.len(), "forum staff allowlist loaded");
    }

    // Attach-logs feature: reaches Discourse over the shared docker network
    // (plain HTTP container alias, bypassing the edge basic_auth). An empty
    // API key disables the whole feature (503 on its endpoints).
    let discourse_url =
        std::env::var("DISCOURSE_URL").unwrap_or_else(|_| "http://discourse".into());
    let discourse_api_key = std::env::var("DISCOURSE_API_KEY").unwrap_or_default();
    let discourse_api_username =
        std::env::var("DISCOURSE_API_USERNAME").unwrap_or_else(|_| "system".into());
    let staff_group = std::env::var("WARREN_STAFF_GROUP").unwrap_or_else(|_| "staff".into());
    let forum_api = if discourse_api_key.is_empty() {
        tracing::warn!("DISCOURSE_API_KEY not set: attach-logs feature disabled");
        None
    } else {
        Some(ForumApi::new(
            &discourse_url,
            discourse_api_key.clone(),
            discourse_api_username,
            staff_group.clone(),
        ))
    };

    // Guest help intake: enabled only when both the Discourse API key and the
    // target category are configured; otherwise the endpoint answers 503 and
    // the rest of the service is unaffected. The topics are created as a
    // dedicated LOW-PRIVILEGE bot user (not system), so Discourse's own
    // per-user rate limits act as a server-side circuit breaker.
    let intake_category = std::env::var("DISCOURSE_INTAKE_CATEGORY_ID").ok();
    let intake_username =
        std::env::var("DISCOURSE_INTAKE_USERNAME").unwrap_or_else(|_| "warren-intake".into());
    // The attach-logs DISCOURSE_API_KEY is tied to the system user, and a
    // user-scoped key cannot impersonate another Api-Username. The intake
    // therefore uses its own key minted for the bot user; the shared key
    // only works as a fallback when it is a global ("all users") key.
    let intake_api_key =
        std::env::var("DISCOURSE_INTAKE_API_KEY").unwrap_or_else(|_| discourse_api_key.clone());
    let intake = match intake_category {
        None => {
            tracing::warn!("DISCOURSE_INTAKE_CATEGORY_ID not set: guest intake disabled");
            None
        }
        Some(_) if intake_api_key.is_empty() => {
            tracing::warn!("no Discourse API key available: guest intake disabled");
            None
        }
        Some(raw) => {
            let category_id: u64 = raw
                .parse()
                .context("DISCOURSE_INTAKE_CATEGORY_ID must be a u64")?;
            Some(warren_connect::routes::IntakeState {
                api: ForumApi::new(
                    &discourse_url,
                    intake_api_key,
                    intake_username,
                    staff_group.clone(),
                ),
                category_id,
                // Abuse budgets, env-tunable so a spam wave can be answered
                // with a config change instead of a rebuild. The global cap
                // is a deliberate circuit breaker: full = everyone 429s,
                // which we prefer over unbounded spam in a public category.
                limiter: warren_connect::intake::RateLimiter::new(
                    env_usize("INTAKE_MAX_PER_IP", 3),
                    env_usize("INTAKE_MAX_GLOBAL", 30),
                    3_600,
                ),
                // Looser than opening a report, and on its own budget: a
                // follow-up is a conversation (several in an hour is normal,
                // and a mistyped code costs a slot), while it only ever adds
                // a post to a topic the sender already proved they own.
                reply_limiter: warren_connect::intake::RateLimiter::new(
                    env_usize("HELP_REPLY_MAX_PER_IP", 10),
                    env_usize("HELP_REPLY_MAX_GLOBAL", 60),
                    3_600,
                ),
                // Derived, so the follow-up codes need no key of their own in
                // the deployment (and survive every redeploy unchanged).
                ticket: warren_connect::ticket::TicketKey::derive(&handle_secret),
            })
        }
    };

    let forum_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&required("FORUM_DATABASE_URL")?)
        .await
        .context("connect forum_auth database")?;
    let warren_pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&required("WARREN_DATABASE_URL_RO")?)
        .await
        .context("connect warren database (read-only)")?;

    // Discourse's own database, SELECT-only role on the same host. Unset
    // disables the broadcast activity digest and nothing else: the forum,
    // the SSO and the attach flow do not depend on it.
    let discourse_pool = match std::env::var("DISCOURSE_DATABASE_URL_RO") {
        Ok(url) if !url.is_empty() => Some(
            PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .context("connect discourse database (read-only)")?,
        ),
        _ => {
            tracing::warn!("DISCOURSE_DATABASE_URL_RO not set: forum activity digest disabled");
            None
        }
    };

    // The one write path into Discourse, through its own role: marking the
    // caller's own notification list seen, which is what the forum bell does
    // by itself. Kept off the pool above so that one stays unable to write.
    let seen_pool = match std::env::var("DISCOURSE_DATABASE_URL_SEEN") {
        Ok(url) if !url.is_empty() => Some(
            PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .context("connect discourse database (seen bookmark)")?,
        ),
        _ => {
            tracing::warn!("DISCOURSE_DATABASE_URL_SEEN not set: marking the list seen disabled");
            None
        }
    };

    store::migrate(&forum_pool).await.context("migrations")?;

    // In-app bug reports: enabled only with an all-users Discourse key scoped
    // to topic writes (the system key is user-bound and cannot act as the
    // reporter) and the target category; otherwise the endpoint answers 503
    // and nothing else changes. The log delivery reuses the system client.
    let report = match (
        std::env::var("DISCOURSE_REPORT_API_KEY")
            .ok()
            .filter(|k| !k.is_empty()),
        std::env::var("DISCOURSE_REPORT_CATEGORY_ID").ok(),
    ) {
        (None, _) => {
            tracing::warn!("DISCOURSE_REPORT_API_KEY not set: in-app reports disabled");
            None
        }
        (Some(_), None) => {
            tracing::warn!("DISCOURSE_REPORT_CATEGORY_ID not set: in-app reports disabled");
            None
        }
        (Some(key), Some(raw)) => {
            let category_id: u64 = raw
                .parse()
                .context("DISCOURSE_REPORT_CATEGORY_ID must be a u64")?;
            Some(warren_connect::routes::ReportState {
                // The username is replaced per request (`as_user`); "system"
                // here is only what a misrouted call would act as.
                topic_api: ForumApi::new(&discourse_url, key, "system".into(), staff_group.clone()),
                category_id,
                // Per wallet, then global: a member files a few reports a
                // day at most, and the global cap is the circuit breaker a
                // spam wave from many paid wallets would trip.
                limiter: warren_connect::intake::RateLimiter::new(
                    env_usize("REPORT_MAX_PER_WALLET", 3),
                    env_usize("REPORT_MAX_GLOBAL", 20),
                    3_600,
                ),
                // A refused decode gives its topic slot back, so this is the
                // budget that bounds the gunzip a wallet can make the server
                // do without ever filing anything.
                decode_failures: warren_connect::intake::RateLimiter::new(
                    env_usize("REPORT_MAX_DECODE_FAILURES", 3),
                    env_usize("REPORT_MAX_GLOBAL", 20),
                    3_600,
                ),
            })
        }
    };

    let identity = warren_connect::store::IdentityStore::Postgres {
        forum: forum_pool.clone(),
        warren: warren_pool.clone(),
    };
    let state = Arc::new(AppState {
        connect_secret,
        handle_secret,
        public_host,
        internal_token,
        admins,
        forum_pool,
        warren_pool,
        identity,
        discourse_pool,
        seen_pool,
        digest_generation: warren_connect::digest::GenerationStamp::default(),
        sessions: SessionStore::default(),
        nonces: NonceStore::default(),
        attach: AttachStore::default(),
        forum_api,
        intake,
        report,
    });

    // Retention: bound how long an inactive forum link (keyed hash + public
    // handle) lingers, so the linkage table stops being the one identity
    // artifact that survives forever. Daily sweep, best-effort.
    {
        let pool = state.forum_pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let cutoff = (chrono::Utc::now()
                    - chrono::Duration::days(warren_connect::FORUM_LINK_RETENTION_DAYS))
                .timestamp();
                match store::purge_inactive_links(&pool, cutoff).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(purged = n, "forum_links retention sweep applied");
                    }
                    Ok(_) => {}
                    // The KIND only: an sqlx error's Debug carries the Postgres
                    // error detail, which echoes the row values (a handle, a
                    // keyed external_id).
                    Err(err) => tracing::error!(
                        kind = store::error_kind(&err),
                        "forum_links retention sweep failed"
                    ),
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    tracing::info!(%listen, "warren-connect listening");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("server")
}
