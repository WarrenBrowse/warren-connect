//! DiscourseConnect SSO provider for the Warren community forum.
//!
//! Users authenticate by proving control of their Warren wallet key
//! (Ed25519, frozen `X-Warren-*` canonical request format from
//! `warren-contract`); Discourse receives a pairwise opaque handle, a
//! synthetic `.invalid` email, and never a password, a real email, or an IP.
//! Design record: warren-core `docs/55-FORUM-DISCOURSE-SUPPORT.md`.
//!
//! warren-core, referenced throughout this crate, is Warren's private backend
//! repo; its design docs are internal records and are not publicly readable.

/// Public origin of the forum this broker authenticates for.
///
/// One constant for the four things that must agree: the cross-links written
/// into Discourse posts, the success redirect of the attach page, the CORS
/// grant of the attach session API, and the origin an incoming
/// DiscourseConnect payload is allowed to send the user back to. They were
/// three separate literals, which is one edit away from a broker that trusts
/// a return URL it will never link to.
pub const FORUM_PUBLIC_URL: &str = "https://forum.warrenbrowse.com";

/// Days of inactivity after which a `forum_links` row (keyed hash + public
/// handle, no cleartext wallet) is purged by the retention sweep. Two years
/// is generous for a long-lived forum account while still bounding how long a
/// dormant link survives, so the table is no longer the one identity artifact
/// kept forever.
pub const FORUM_LINK_RETENTION_DAYS: i64 = 730;

pub mod admins;
pub mod attach;
pub mod digest;
pub mod discourse;
pub mod error;
pub mod forum_api;
pub mod handle;
pub mod i18n;
pub mod intake;
pub mod nonces;
pub mod notifications;
pub mod pages;
pub mod routes;
pub mod sessions;
pub mod store;
pub mod ticket;
pub mod verify;
