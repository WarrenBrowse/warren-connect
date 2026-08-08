//! E2E signing helper: prints the four `X-Warren-*` header values for a
//! signed `POST /v1/forum/login`, so a shell script can drive the full SSO
//! flow with curl. Uses an ephemeral key by default (any valid Ed25519 key
//! is accepted; subscription simply resolves to inactive) or a 32-byte seed
//! from `SEED_HEX`.
//!
//! Args: <sid> [timestamp]. Env: SEED_HEX (optional).

use ed25519_dalek::SigningKey;
use warren_contract::auth::sign_request;

fn main() {
    let mut args = std::env::args().skip(1);
    let sid = args.next().expect("usage: e2e_sign <sid> [timestamp]");
    let timestamp: u64 = args.next().map_or_else(
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_secs()
        },
        |s| s.parse().expect("timestamp must be a u64"),
    );

    let seed: [u8; 32] = std::env::var("SEED_HEX").map_or([42u8; 32], |h| {
        let bytes = hex::decode(h).expect("SEED_HEX must be hex");
        bytes.try_into().expect("SEED_HEX must be 32 bytes")
    });
    let key = SigningKey::from_bytes(&seed);

    // The caller shares the exact body bytes via env so the signed preimage
    // and the bytes sent by curl cannot drift (shell quote-stripping bit us).
    let body = std::env::var("WFA_BODY").unwrap_or_else(|_| format!("{{\"sid\":\"{sid}\"}}"));
    // Same drift rationale as WFA_BODY: the attach flow signs a different
    // path, so the caller can override it without a second binary.
    let path = std::env::var("WFA_PATH").unwrap_or_else(|_| "/v1/forum/login".to_owned());
    // A fixed nonce is fine per run (single-use within the process).
    let nonce = {
        let mut n = [0u8; 16];
        n[..8].copy_from_slice(&timestamp.to_le_bytes());
        n
    };
    let sig = sign_request(&key, "POST", &path, body.as_bytes(), timestamp, nonce);

    // Shell-eval friendly: KEY=VALUE lines.
    println!("PUBKEY={}", sig.pubkey_ss58);
    println!("SIG={}", sig.signature_hex);
    println!("TS={}", sig.timestamp);
    println!("NONCE={}", sig.nonce_hex);
}
