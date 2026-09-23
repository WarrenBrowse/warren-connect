//! Bounds on the reads a route makes before it knows whether to act on a
//! wallet-signed request: its gate reads (the subscription standing, the
//! forum link, the topic's author).
//!
//! A wallet costs nothing to mint and this service never sees a client IP, so
//! a gate read is work anybody can order for the price of a signature. Two
//! things bound it: a bulkhead per kind of read, which caps how many run at
//! once and refuses at once past a short queue, and a short memory of the
//! "no" answers, so a wallet that repeats itself costs one read per
//! [`NEGATIVE_TTL_SECS`]. Only the "no" is remembered: a "yes" held in memory
//! could outlive a revoked subscription.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Semaphore, SemaphorePermit};

use crate::intake::RateLimiter;
use crate::store::{FORUM_POOL_CONNECTIONS, WARREN_POOL_CONNECTIONS};

/// How long a "no" is answered from memory. Short, because the one wallet it
/// can wrong is one whose answer changed: a wallet that pays, then files an
/// in-app report within this window, is refused once more. The forum link's
/// "no" is also forgotten the moment an admission records the link.
pub const NEGATIVE_TTL_SECS: u64 = 30;

/// Answers each negative cache holds. A flood of fresh wallets only churns
/// it; the bulkheads are what bound that flood.
const NEGATIVE_MAX_ENTRIES: usize = 4_096;

/// Topic fetches a signer may spend, per hour, on uploads to topics it did not
/// write. The per-session count bounds one page, and a fresh page opens a
/// fresh session; this bounds the signer, which the forum-link gate has
/// already made a wallet that paid at least once.
const AUTHOR_MISSES_PER_HOUR: usize = 10;

const LOGIN_PERMITS: usize = 2;
const OPEN_PERMITS: usize = 1;
const TOPIC_PERMITS: usize = 2;
const MAX_QUEUED: usize = 8;
const MAX_WAIT: Duration = Duration::from_secs(2);

// The two bulkheads that read the subscription standing never hold more
// connections between them than the pool has, so a flood of the open routes
// never leaves a login waiting for a connection.
const _: () = assert!(LOGIN_PERMITS + OPEN_PERMITS <= WARREN_POOL_CONNECTIONS as usize);
// The forum link reads leave `forum_auth` connections for the link and slot
// writes of an admission.
const _: () = assert!(LOGIN_PERMITS + OPEN_PERMITS < FORUM_POOL_CONNECTIONS as usize);

/// The bulkheads and negative caches of the gate reads.
#[derive(Debug)]
pub struct Gates {
    /// The login's reads: its paywall, and the staff status of the legacy
    /// form. A login read needs a session still waiting for its approval,
    /// which ends at the first "never paid", and one DiscourseConnect payload
    /// from the forum opens three at most, so it is the costly read to flood
    /// and it has a bulkhead of its own that no flood of the open routes can
    /// fill.
    pub login: GateLimiter,
    /// The reads any signature can order with nothing else: the in-app
    /// report's paywall, and the forum link the notification routes and the
    /// attach uploads check.
    pub open: GateLimiter,
    /// The Discourse topic fetch an attach upload makes before its author
    /// check.
    pub topic: GateLimiter,
    /// Wallets the in-app report found never paid. The login never reads it:
    /// the login is where a wallet that just paid comes back, and a login
    /// read already costs a session.
    pub never_paid: NegativeCache,
    /// Wallets found with no forum link.
    pub unlinked: NegativeCache,
    /// Topic fetches that ended in a failed author check, per signer's
    /// keyed forum id. An author's own uploads are given back.
    pub author_misses: RateLimiter<String>,
}

impl Default for Gates {
    fn default() -> Self {
        Self {
            login: GateLimiter::new(LOGIN_PERMITS, MAX_QUEUED, MAX_WAIT),
            open: GateLimiter::new(OPEN_PERMITS, MAX_QUEUED, MAX_WAIT),
            topic: GateLimiter::new(TOPIC_PERMITS, MAX_QUEUED, MAX_WAIT),
            never_paid: NegativeCache::new(NEGATIVE_TTL_SECS, NEGATIVE_MAX_ENTRIES),
            unlinked: NegativeCache::new(NEGATIVE_TTL_SECS, NEGATIVE_MAX_ENTRIES),
            author_misses: RateLimiter::new(AUTHOR_MISSES_PER_HOUR, usize::MAX, 3_600),
        }
    }
}

/// Bulkhead over one kind of gate read.
#[derive(Debug)]
pub struct GateLimiter {
    permits: Semaphore,
    queued: AtomicUsize,
    max_queued: usize,
    max_wait: Duration,
}

/// The gate is saturated: the read was refused without running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("gate saturated")]
pub struct GateBusy;

impl GateLimiter {
    /// Runs at most `permits` reads at once. A read that finds none free
    /// waits for one behind at most `max_queued` others, for at most
    /// `max_wait`.
    #[must_use]
    pub fn new(permits: usize, max_queued: usize, max_wait: Duration) -> Self {
        Self {
            permits: Semaphore::new(permits),
            queued: AtomicUsize::new(0),
            max_queued,
            max_wait,
        }
    }

    /// Runs `read` under a permit.
    ///
    /// # Errors
    /// [`GateBusy`] when the queue is full, or when no permit freed within
    /// the longest wait. `read` has not run.
    pub async fn run<F: Future>(&self, read: F) -> Result<F::Output, GateBusy> {
        let _permit = self.enter().await?;
        Ok(read.await)
    }

    /// Reads waiting for a permit right now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }

    async fn enter(&self) -> Result<SemaphorePermit<'_>, GateBusy> {
        // The semaphore hands a released permit to the oldest waiter, so this
        // never overtakes the queue.
        if let Ok(permit) = self.permits.try_acquire() {
            return Ok(permit);
        }
        let _place = QueuePlace::take(&self.queued, self.max_queued).ok_or(GateBusy)?;
        match tokio::time::timeout(self.max_wait, self.permits.acquire()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(GateBusy),
        }
    }
}

/// A place in a gate's queue, given back when dropped, whether the wait ended
/// with a permit, a timeout or the caller going away.
struct QueuePlace<'a>(&'a AtomicUsize);

impl<'a> QueuePlace<'a> {
    fn take(queued: &'a AtomicUsize, max_queued: usize) -> Option<Self> {
        queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max_queued).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(queued))
    }
}

impl Drop for QueuePlace<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Short-lived memory of the "no" a gate read answered for a wallet, keyed by
/// its public key.
#[derive(Debug)]
pub struct NegativeCache {
    state: Mutex<Negatives>,
    ttl_secs: u64,
    max_entries: usize,
}

#[derive(Debug, Default)]
struct Negatives {
    /// Per key, the first second the answer is no longer trusted.
    until: HashMap<[u8; 32], u64>,
    /// Moves on every [`NegativeCache::forget`].
    generation: u64,
}

/// When a read started, as [`NegativeCache::record`] needs to know.
#[derive(Debug, Clone, Copy)]
pub struct ReadStart(u64);

impl NegativeCache {
    /// A cache that holds each answer `ttl_secs` and at most `max_entries`
    /// answers.
    #[must_use]
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            state: Mutex::default(),
            ttl_secs,
            max_entries,
        }
    }

    /// Whether a "no" for `key` is still held at `now_unix`.
    #[must_use]
    pub fn holds(&self, key: &[u8; 32], now_unix: u64) -> bool {
        self.lock()
            .until
            .get(key)
            .is_some_and(|until| now_unix < *until)
    }

    /// Marks the start of a read whose "no" may be recorded.
    #[must_use]
    pub fn start_read(&self) -> ReadStart {
        ReadStart(self.lock().generation)
    }

    /// Records the "no" a read started at `started` answered for `key`,
    /// unless a [`Self::forget`] came in between.
    ///
    /// At capacity the expired answers go first, then all of them: dropping
    /// an answer only costs one more read, so the size bound needs no order.
    pub fn record(&self, key: [u8; 32], started: ReadStart, now_unix: u64) {
        let mut negatives = self.lock();
        if negatives.generation != started.0 {
            return;
        }
        if negatives.until.len() >= self.max_entries && !negatives.until.contains_key(&key) {
            negatives.until.retain(|_, until| now_unix < *until);
            if negatives.until.len() >= self.max_entries {
                negatives.until.clear();
            }
        }
        negatives
            .until
            .insert(key, now_unix.saturating_add(self.ttl_secs));
    }

    /// Drops the "no" held for `key`: the answer just changed. A read already
    /// in flight may still return the old answer, so none that started before
    /// this call is recorded.
    pub fn forget(&self, key: &[u8; 32]) {
        let mut negatives = self.lock();
        negatives.until.remove(key);
        negatives.generation = negatives.generation.wrapping_add(1);
    }

    /// Answers held, live or expired.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().until.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Negatives> {
        // A map of hints: after a panic under the lock the worst it holds is
        // a stale "no" that expires on its own.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    /// A read that holds its permit until the test lets it go.
    fn held_read(release: &Arc<tokio::sync::Notify>) -> impl Future<Output = ()> + use<> {
        let release = release.clone();
        async move { release.notified().await }
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_gate_refuses_at_once() {
        let gate = Arc::new(GateLimiter::new(1, 1, Duration::from_secs(30)));
        let release = Arc::new(tokio::sync::Notify::new());
        let running = tokio::spawn({
            let gate = gate.clone();
            let read = held_read(&release);
            async move { gate.run(read).await }
        });
        let queued = tokio::spawn({
            let gate = gate.clone();
            async move { gate.run(async {}).await }
        });
        tokio::task::yield_now().await;
        let before = tokio::time::Instant::now();

        let refused = gate.run(async { "ran" }).await;

        assert_eq!(refused, Err(GateBusy), "one running and one queued fill it");
        assert_eq!(
            tokio::time::Instant::now(),
            before,
            "the refusal waits for nothing"
        );
        release.notify_one();
        assert_eq!(running.await.expect("task"), Ok(()));
        assert_eq!(queued.await.expect("task"), Ok(()), "the queued read runs");
    }

    #[tokio::test(start_paused = true)]
    async fn a_queued_read_gives_up_after_the_longest_wait() {
        let gate = Arc::new(GateLimiter::new(1, 4, Duration::from_secs(2)));
        let release = Arc::new(tokio::sync::Notify::new());
        let running = tokio::spawn({
            let gate = gate.clone();
            let read = held_read(&release);
            async move { gate.run(read).await }
        });
        tokio::task::yield_now().await;
        let before = tokio::time::Instant::now();

        let waited = gate.run(async { "ran" }).await;

        assert_eq!(waited, Err(GateBusy));
        assert_eq!(
            tokio::time::Instant::now() - before,
            Duration::from_secs(2),
            "it waited exactly the longest wait"
        );
        release.notify_one();
        assert_eq!(running.await.expect("task"), Ok(()));
        assert_eq!(
            gate.run(async { "ran" }).await,
            Ok("ran"),
            "and the queue it left is empty again"
        );
    }

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn a_recorded_no_is_held_until_its_ttl_runs_out() {
        let cache = NegativeCache::new(30, 16);
        let started = cache.start_read();
        cache.record(KEY, started, 1_000);

        assert!(cache.holds(&KEY, 1_000));
        assert!(cache.holds(&KEY, 1_029));
        assert!(!cache.holds(&KEY, 1_030), "thirty seconds and no more");
        assert!(!cache.holds(&[8; 32], 1_000), "another wallet is not held");
    }

    #[test]
    fn a_forgotten_no_is_not_held_and_a_read_that_started_before_records_nothing() {
        // A read that started before the change can still come back with the
        // old "no": recording it would undo the forget.
        let cache = NegativeCache::new(30, 16);
        cache.record(KEY, cache.start_read(), 1_000);
        let stale = cache.start_read();

        cache.forget(&KEY);
        cache.record(KEY, stale, 1_001);

        assert!(!cache.holds(&KEY, 1_001));
        cache.record(KEY, cache.start_read(), 1_002);
        assert!(
            cache.holds(&KEY, 1_002),
            "a read that started after the change is recorded"
        );
    }

    #[test]
    fn the_cache_never_holds_more_than_its_size() {
        let cache = NegativeCache::new(30, 4);
        for seed in 0..10u8 {
            cache.record([seed; 32], cache.start_read(), 1_000);
            assert!(cache.held() <= 4, "after {seed}: {}", cache.held());
        }
        assert!(
            cache.holds(&[9; 32], 1_000),
            "the latest answer is always kept"
        );
    }
}
