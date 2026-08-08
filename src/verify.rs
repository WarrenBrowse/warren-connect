//! Verification of a wallet-signed login request.
//!
//! Same frozen wire contract as the Warren API: the four `X-Warren-*` headers
//! over the canonical message from `warren_contract::auth`. Semantics mirror
//! the production `WarrenAuthVerifier` (warren-core): clock window, then
//! Ed25519 verification, then nonce consumption. The nonce is consumed only
//! AFTER the signature verifies so an attacker cannot burn a victim's nonce
//! with a garbage signature.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use warren_contract::auth::canonical_message;

use crate::error::AuthError;
use crate::nonces::NonceStore;

/// Accepted clock skew between client and server, seconds. Mirrors the
/// production API window.
pub const TIMESTAMP_WINDOW_SECS: u64 = 60;

/// The four raw header values of a signed request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// `X-Warren-PubKey`: SS58 `wb…` address.
    pub pubkey_ss58: String,
    /// `X-Warren-Sig`: 128 hex chars.
    pub signature_hex: String,
    /// `X-Warren-Timestamp`: unix epoch seconds.
    pub timestamp: u64,
    /// `X-Warren-Nonce`: 32 hex chars (16 bytes).
    pub nonce_hex: String,
}

/// A successfully proven wallet identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Raw Ed25519 public key.
    pub pubkey: [u8; 32],
    /// The same key as its SS58 `wb…` address.
    pub pubkey_ss58: String,
}

/// Verifies a signed request end to end.
///
/// # Errors
/// [`AuthError::Pubkey`] on SS58/point decode failure, [`AuthError::Clock`]
/// outside the timestamp window, [`AuthError::Signature`] on Ed25519
/// mismatch, [`AuthError::Nonce`] on malformed or replayed nonce.
pub fn verify_signed_request(
    headers: &SignedHeaders,
    method: &str,
    path: &str,
    body: &[u8],
    now_unix: u64,
    nonces: &NonceStore,
) -> Result<VerifiedIdentity, AuthError> {
    let pubkey =
        warren_contract::ss58::decode(&headers.pubkey_ss58).map_err(|_| AuthError::Pubkey)?;
    let verifying = VerifyingKey::from_bytes(&pubkey).map_err(|_| AuthError::Pubkey)?;
    // A small-order key accepts signatures nobody had to produce, so it is not
    // a proof of anything. No wallet ever derives one, so refusing it costs no
    // legitimate user a login.
    if verifying.is_weak() {
        return Err(AuthError::Pubkey);
    }

    if now_unix.abs_diff(headers.timestamp) > TIMESTAMP_WINDOW_SECS {
        return Err(AuthError::Clock);
    }

    let nonce_bytes = hex::decode(&headers.nonce_hex).map_err(|_| AuthError::Nonce)?;
    if nonce_bytes.len() != 16 {
        return Err(AuthError::Nonce);
    }

    let sig_bytes = hex::decode(&headers.signature_hex).map_err(|_| AuthError::Signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| AuthError::Signature)?;

    let body_hash_hex = hex::encode(Sha256::digest(body));
    let canonical = canonical_message(
        method,
        path,
        headers.timestamp,
        &headers.nonce_hex,
        &body_hash_hex,
    );
    // `verify_strict`: it rejects non-canonical encodings and mixed-order
    // points, which the permissive `verify` accepts. Every signature a real
    // wallet produces passes both, so this only narrows what an adversarially
    // chosen key can claim, and the wire contract is unchanged for clients.
    verifying
        .verify_strict(canonical.as_bytes(), &signature)
        .map_err(|_| AuthError::Signature)?;

    // Authorization decisions (admin allowlist, subscription lookup) and the
    // forum_links key must use ONE canonical address, re-encoded from the
    // proven key bytes rather than the raw client string.
    let pubkey_ss58 = warren_contract::ss58::encode(&pubkey);

    // Signature proven: only now is the nonce consumed (DoS ordering).
    if !nonces.check_and_store(&pubkey_ss58, &headers.nonce_hex, now_unix) {
        return Err(AuthError::Nonce);
    }

    Ok(VerifiedIdentity {
        pubkey,
        pubkey_ss58,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use warren_contract::auth::sign_request;

    fn signed(
        key: &SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
        ts: u64,
        nonce: [u8; 16],
    ) -> SignedHeaders {
        let s = sign_request(key, method, path, body, ts, nonce);
        SignedHeaders {
            pubkey_ss58: s.pubkey_ss58,
            signature_hex: s.signature_hex,
            timestamp: s.timestamp,
            nonce_hex: s.nonce_hex,
        }
    }

    #[test]
    fn accepts_a_valid_signed_request() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/v1/forum/login", b"{}", 1_000, [1; 16]);
        let nonces = NonceStore::default();

        let id = verify_signed_request(&h, "POST", "/v1/forum/login", b"{}", 1_000, &nonces)
            .expect("valid request must verify");
        assert_eq!(id.pubkey, key.verifying_key().to_bytes());
        assert_eq!(id.pubkey_ss58, h.pubkey_ss58);
    }

    #[test]
    fn rejects_a_tampered_body() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"{\"sid\":\"a\"}", 1_000, [1; 16]);
        let nonces = NonceStore::default();

        let err = verify_signed_request(&h, "POST", "/p", b"{\"sid\":\"EVIL\"}", 1_000, &nonces)
            .expect_err("body swap must break the signature");
        assert!(matches!(err, AuthError::Signature));
    }

    #[test]
    fn rejects_a_stale_timestamp() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        let nonces = NonceStore::default();

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000 + 61, &nonces)
            .expect_err("61 s of skew is outside the window");
        assert!(matches!(err, AuthError::Clock));
    }

    #[test]
    fn rejects_a_replayed_nonce() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        let nonces = NonceStore::default();

        verify_signed_request(&h, "POST", "/p", b"", 1_000, &nonces).expect("first use passes");
        let err = verify_signed_request(&h, "POST", "/p", b"", 1_001, &nonces)
            .expect_err("identical request replayed must be rejected");
        assert!(matches!(err, AuthError::Nonce));
    }

    #[test]
    fn a_bad_signature_does_not_burn_the_nonce() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        let good_sig = h.signature_hex.clone();
        h.signature_hex = "00".repeat(64);
        let nonces = NonceStore::default();

        verify_signed_request(&h, "POST", "/p", b"", 1_000, &nonces)
            .expect_err("garbage signature rejected");
        h.signature_hex = good_sig;
        verify_signed_request(&h, "POST", "/p", b"", 1_000, &nonces)
            .expect("the legitimate request must still pass afterwards");
    }

    #[test]
    fn rejects_a_small_order_pubkey_before_looking_at_the_signature() {
        // The identity point is a well-formed encoding whose "signatures" are
        // satisfiable without any private key, so it proves no key control.
        // It must be refused as a KEY, not left to fail as a signature: the
        // distinction is what stops a forged one from ever being verified.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        h.pubkey_ss58 = warren_contract::ss58::encode(&identity);
        let nonces = NonceStore::default();

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000, &nonces)
            .expect_err("a small-order key must be refused");
        assert!(matches!(err, AuthError::Pubkey), "got {err:?}");
    }

    #[test]
    fn rejects_an_invalid_ss58_pubkey() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        h.pubkey_ss58 = "not-an-address".into();
        let nonces = NonceStore::default();

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000, &nonces)
            .expect_err("bad address must be rejected");
        assert!(matches!(err, AuthError::Pubkey));
    }
}
