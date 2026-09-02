//! Privacy invariants on what warren-connect may log.
//!
//! Mirror of the `log_privacy.rs` guards carried by every other Warren
//! service (warren-api, warren-exit, warren-client): no `tracing::*` call
//! site may interpolate a full wallet pubkey, a client IP, a request nonce
//! or signature, the pairwise forum identifiers, or any of the shared
//! secrets this broker holds (the DiscourseConnect secret, the forum handle
//! HMAC key, the Discourse API key).
//!
//! This broker is the one Warren service that sees a wallet pubkey and a
//! forum identity in the same process, so a single unredacted log line here
//! would rebuild exactly the link the pairwise handle exists to break. The
//! canonical safe wrapper is `warren_contract::redact`.
//!
//! The check runs at source level with a walkdir over `src/` so a newly
//! added module cannot slip past it.

/// Substrings forbidden in code (post `code_only` filter).
///
/// Every entry matches the tracing-specific interpolation syntax
/// (`name = %value` for Display, `name = ?value` for Debug, or the bare
/// `, name,` field shorthand). Matching that syntax rather than the bare
/// identifier is what keeps SQL literals (`WHERE username = $1`) and route
/// templates out of the scan.
const FORBIDDEN_LITERAL_SUBSTRINGS: &[&str] = &[
    // Full wallet pubkey, in either encoding. The redacted form
    // `pubkey = %redact(&identity.pubkey_ss58)` is the only accepted one:
    // the full value is a stable correlation key across every request of
    // the same user.
    "= %identity.pubkey",
    "= ?identity.pubkey",
    "= %pubkey_ss58",
    "= ?pubkey_ss58",
    "= %pubkey_hex",
    "= ?pubkey_hex",
    ", pubkey_ss58,",
    // Pairwise forum identity. Non-invertible, but still a stable per-user
    // identifier: logging it correlates a user's forum activity across lines.
    "external_id = %",
    "external_id = ?",
    "username = %",
    "username = ?",
    // Synthetic Discourse email. Derived from the handle, so logging it
    // leaks the handle.
    "email = %",
    "email = ?",
    // Client IP: never identify a user by source address. Caddy already
    // pins the forwarded header to a null value; the service must not
    // recover one from its own socket either.
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "remote_address()",
    "ConnectInfo",
    // Request authenticator material: a logged nonce or signature turns a
    // read-only log into a replay kit.
    "nonce = %",
    "nonce = ?",
    ", nonce,",
    "signature = %",
    "signature = ?",
    "signature_hex = %",
    "signature_hex = ?",
    // Shared secrets held by this broker.
    "connect_secret = %",
    "connect_secret = ?",
    ", connect_secret,",
    "handle_secret = %",
    "handle_secret = ?",
    ", handle_secret,",
    "api_key = %",
    "api_key = ?",
    ", api_key,",
    // The signed DiscourseConnect payload carries the nonce and the return
    // URL: logging it defeats the nonce guard.
    "sso = %",
    "sso = ?",
    "payload = %",
    "payload = ?",
    // A bare `e` binding at a tracing call site is an unmapped error, in
    // practice an `sqlx::Error` whose Debug carries the Postgres error DETAIL,
    // which echoes the offending row values (a handle, a keyed external_id).
    // Every sqlx call site goes through `store::error_kind` instead, which
    // yields a coarse `&'static str`. The closing character is part of the
    // pattern so a properly named error (`error = %err`) is not caught.
    "= ?e,",
    "= ?e)",
    "= %e,",
    "= %e)",
];

fn read_module(path: &str) -> String {
    std::fs::read_to_string(format!("src/{path}"))
        .unwrap_or_else(|e| panic!("read src/{path}: {e}"))
}

/// Lines starting with `//` (incl. `///` and `//!`) are exempt: doc comments
/// legitimately name these fields while describing why they are never logged.
fn code_only(body: &str) -> String {
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_no_forbidden_in(file: &str) {
    let body = code_only(&read_module(file));
    for substr in FORBIDDEN_LITERAL_SUBSTRINGS {
        assert!(
            !body.contains(substr),
            "source file `src/{file}` contains forbidden log-leakage substring {substr:?}. \
             warren-connect must never log a full wallet pubkey, a pairwise forum \
             identifier, a client IP, a nonce or signature, or a shared secret. \
             Wrap the identifier in `warren_contract::redact` at the call site."
        );
    }
}

fn collect_rs_files(dir: &std::path::Path, prefix: &str, acc: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).expect("read_dir src/");
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_dir() {
            collect_rs_files(&path, &rel, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            acc.push(rel);
        }
    }
}

#[test]
fn every_warren_connect_module_passes_log_privacy_scan() {
    let mut files = Vec::new();
    collect_rs_files(std::path::Path::new("src"), "", &mut files);
    assert!(
        !files.is_empty(),
        "walkdir must find at least one .rs file in src/"
    );
    for file in files {
        assert_no_forbidden_in(&file);
    }
}

/// The scan is only worth its runtime if it actually rejects a leak, so pin
/// that: a synthetic line in the shape the service would really write must
/// trip every identifier class the guard claims to cover.
#[test]
fn the_scan_rejects_a_leaking_log_line() {
    let leaks = [
        r#"tracing::info!(pubkey = %identity.pubkey_ss58, "forum login approved");"#,
        r#"tracing::info!(external_id = %forum.external_id, "link upserted");"#,
        r#"tracing::warn!(nonce = %nonce, "replayed nonce");"#,
        r#"tracing::error!(handle_secret = ?state.handle_secret, "hmac failed");"#,
    ];
    for leak in leaks {
        let body = code_only(leak);
        assert!(
            FORBIDDEN_LITERAL_SUBSTRINGS
                .iter()
                .any(|s| body.contains(s)),
            "the guard must reject this leaking line: {leak}"
        );
    }
}

/// Every `tracing::<level>!(...)` call site in a source body, as the text
/// between the macro's parentheses. String literals are skipped when
/// balancing the parentheses, so a message like `"(API 35)"` cannot cut a
/// block short.
fn tracing_call_sites(body: &str) -> Vec<String> {
    let mut sites = Vec::new();
    for level in ["error", "warn", "info", "debug", "trace"] {
        let opener = format!("tracing::{level}!(");
        let mut from = 0;
        while let Some(at) = body[from..].find(&opener) {
            let start = from + at + opener.len();
            let mut depth = 1usize;
            let mut in_string = false;
            let mut escaped = false;
            let mut end = None;
            for (offset, ch) in body[start..].char_indices() {
                if in_string {
                    match ch {
                        '\\' if !escaped => escaped = true,
                        '"' if !escaped => in_string = false,
                        _ => escaped = false,
                    }
                    continue;
                }
                match ch {
                    '"' => in_string = true,
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(start + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end.expect("unbalanced tracing call site");
            sites.push(body[start..end].to_owned());
            from = end;
        }
    }
    sites
}

/// A line that names both the wallet and a topic is the wallet-to-forum link
/// the pairwise handle exists to break, and `docker logs` is retained. Even
/// redacted, an 8-character prefix over a user base of tens of wallets is
/// identifying. Refusals are no exception: on the attach-logs path the
/// topic is public and the author check has already tied the signer to it,
/// so a refusal naming both is the same link. A line carries the topic or
/// the wallet, never both: a topic-mode line keeps the topic (the author is
/// recoverable from the topic itself), a pre-topic line keeps the wallet.
fn wallet_to_topic_links(body: &str) -> Vec<String> {
    tracing_call_sites(&code_only(body))
        .into_iter()
        .filter(|site| site.contains("pubkey") && site.contains("topic_id"))
        .collect()
}

#[test]
fn no_line_links_a_wallet_to_a_topic() {
    let mut files = Vec::new();
    collect_rs_files(std::path::Path::new("src"), "", &mut files);
    for file in files {
        let links = wallet_to_topic_links(&read_module(&file));
        assert!(
            links.is_empty(),
            "src/{file} logs a wallet next to a topic: {links:?}. \
             Drop the pubkey field; the topic id alone is what the operator needs."
        );
    }
}

#[test]
fn the_link_scan_rejects_any_line_carrying_both_and_keeps_a_one_sided_one() {
    let success = r#"
        tracing::info!(
            pubkey = %redact(&identity.pubkey_ss58),
            topic_id,
            "in-app report topic created (API 35)"
        );
    "#;
    assert_eq!(wallet_to_topic_links(success).len(), 1);
    let refusal_with_both = r#"
        tracing::info!(
            pubkey = %redact(&identity.pubkey_ss58),
            topic_id = req.topic_id,
            "attach-logs refused: signer is not the topic author"
        );
    "#;
    assert_eq!(wallet_to_topic_links(refusal_with_both).len(), 1);
    let topic_only_refusal = r#"
        tracing::info!(
            topic_id = req.topic_id,
            "attach-logs refused: signer is not the topic author"
        );
    "#;
    assert!(wallet_to_topic_links(topic_only_refusal).is_empty());
    let no_topic =
        r#"tracing::info!(pubkey = %redact(&identity.pubkey_ss58), "forum login approved");"#;
    assert!(wallet_to_topic_links(no_topic).is_empty());
}
