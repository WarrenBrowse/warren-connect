//! Verification of a wallet-signed request.
//!
//! Same frozen wire contract as the Warren API: the four `X-Warren-*` headers
//! over the canonical message from `warren_contract::auth`. The clock window
//! and the Ed25519 check mirror the production `WarrenAuthVerifier`
//! (warren-core). The nonce is spent in a step of its own,
//! [`VerifiedRequest::admit`], which only a proven signature can reach, so a
//! garbage signature cannot burn a victim's nonce.

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

/// A request whose signature is proven and whose nonce is not spent yet.
#[derive(Debug)]
pub struct VerifiedRequest {
    /// The wallet that signed it.
    pub identity: VerifiedIdentity,
    nonce_hex: String,
}

impl VerifiedRequest {
    /// Spends the request's nonce.
    ///
    /// # Errors
    /// [`AuthError::Nonce`] on a replay, when the wallet is over its budget,
    /// or when the store is full.
    pub fn admit(&self, nonces: &NonceStore, now_unix: u64) -> Result<(), AuthError> {
        if nonces.check_and_store(&self.identity.pubkey_ss58, &self.nonce_hex, now_unix) {
            Ok(())
        } else {
            Err(AuthError::Nonce)
        }
    }
}

/// Verifies the signature of a request: key, clock window, nonce shape and
/// Ed25519 signature. Spends no nonce: see [`VerifiedRequest::admit`].
///
/// # Errors
/// [`AuthError::Pubkey`] on SS58/point decode failure, [`AuthError::Clock`]
/// outside the timestamp window, [`AuthError::Nonce`] on a malformed nonce,
/// [`AuthError::Signature`] on Ed25519 mismatch.
pub fn verify_signed_request(
    headers: &SignedHeaders,
    method: &str,
    path: &str,
    body: &[u8],
    now_unix: u64,
) -> Result<VerifiedRequest, AuthError> {
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

    Ok(VerifiedRequest {
        identity: VerifiedIdentity {
            pubkey,
            pubkey_ss58,
        },
        nonce_hex: headers.nonce_hex.clone(),
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

        let id = verify_signed_request(&h, "POST", "/v1/forum/login", b"{}", 1_000)
            .expect("valid request must verify")
            .identity;
        assert_eq!(id.pubkey, key.verifying_key().to_bytes());
        assert_eq!(id.pubkey_ss58, h.pubkey_ss58);
    }

    #[test]
    fn rejects_a_tampered_body() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"{\"sid\":\"a\"}", 1_000, [1; 16]);

        let err = verify_signed_request(&h, "POST", "/p", b"{\"sid\":\"EVIL\"}", 1_000)
            .expect_err("body swap must break the signature");
        assert!(matches!(err, AuthError::Signature));
    }

    #[test]
    fn rejects_a_stale_timestamp() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000 + 61)
            .expect_err("61 s of skew is outside the window");
        assert!(matches!(err, AuthError::Clock));
    }

    #[test]
    fn rejects_a_replayed_nonce() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        let nonces = NonceStore::default();

        verify_signed_request(&h, "POST", "/p", b"", 1_000)
            .expect("first use verifies")
            .admit(&nonces, 1_000)
            .expect("and is admitted");
        let err = verify_signed_request(&h, "POST", "/p", b"", 1_001)
            .expect("the replay carries a valid signature")
            .admit(&nonces, 1_001)
            .expect_err("identical request replayed must be rejected");
        assert!(matches!(err, AuthError::Nonce));
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

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000)
            .expect_err("a small-order key must be refused");
        assert!(matches!(err, AuthError::Pubkey), "got {err:?}");
    }

    #[test]
    fn rejects_an_invalid_ss58_pubkey() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        h.pubkey_ss58 = "not-an-address".into();

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000)
            .expect_err("bad address must be rejected");
        assert!(matches!(err, AuthError::Pubkey));
    }
}
