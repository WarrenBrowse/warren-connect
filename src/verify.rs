//! Verification of a wallet-signed request.
//!
//! Same frozen wire contract as the Warren API: the four `X-Warren-*` headers
//! over the canonical message from `warren_contract::auth`. The clock window
//! and the Ed25519 check mirror the production `WarrenAuthVerifier`
//! (warren-core). The nonce is spent in a step of its own,
//! [`VerifiedRequest::admit`], which only a proven signature can reach, so a
//! garbage signature cannot burn a victim's nonce, and which each route takes
//! only once it has decided to act on the request. It hands back the
//! [`Admitted`] witness every store call a signed route acts through asks
//! for, so a route that skips it does not compile.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use warren_contract::auth::canonical_message;

use crate::error::AuthError;
use crate::nonces::NonceStore;

/// Accepted clock skew between client and server, seconds. Mirrors the
/// production API window.
pub const TIMESTAMP_WINDOW_SECS: u64 = 60;

/// How long after its signed timestamp a request may still be admitted, and
/// so how long its nonce is remembered.
///
/// A route admits a request after its gate, which reads the database or the
/// forum, so admission can come well after the verification the clock window
/// bounds. Its twin has to be remembered until then, or a replay verified at
/// the end of the window would find it forgotten. Twice the window on top of
/// it covers the slowest gate at its timeouts: three database pool waits in a
/// row on a legacy login (30 s each), or one forum fetch on an attach (60 s).
/// A request whose gate took longer is refused.
pub const ADMISSION_HORIZON_SECS: u64 = 3 * TIMESTAMP_WINDOW_SECS;

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
pub struct VerifiedRequest {
    /// The wallet that signed it.
    pub identity: VerifiedIdentity,
    nonce_hex: String,
    timestamp: u64,
}

impl VerifiedRequest {
    /// Spends the request's nonce and hands back the [`Admitted`] witness. A
    /// route calls it once it has decided to act on the request, past its own
    /// gate (paywall, forum link, topic author) and before its first side
    /// effect, so each signed request is acted on at most once. A request the gate refuses spends nothing, and the wallets no
    /// gate admits, which cost nothing to mint, never reach the store. A
    /// refusal whose cause changes while the signature is still valid (a read
    /// that failed recovers, the wallet pays or gains its forum link) leaves
    /// that request admissible once after the change.
    ///
    /// `now_unix` is the time of admission, read after the gate.
    ///
    /// # Errors
    /// [`AuthError::Nonce`] on a replay, past [`ADMISSION_HORIZON_SECS`], when
    /// the wallet is over its budget, or when the store is full.
    pub fn admit(&self, nonces: &NonceStore, now_unix: u64) -> Result<Admitted, AuthError> {
        if nonces.check_and_store(
            &self.identity.pubkey_ss58,
            &self.nonce_hex,
            self.timestamp,
            now_unix,
        ) {
            Ok(Admitted {
                identity: self.identity.clone(),
            })
        } else {
            Err(AuthError::Nonce)
        }
    }
}

/// Proof that a wallet-signed request passed its route's gate and spent its
/// nonce. Only [`VerifiedRequest::admit`] makes one, and the store calls a
/// signed route acts through (a login approval, a forum link write, a parked
/// or delivered report, a notification read or write) each take one: a
/// route that forgets its admission does not compile, where a forgotten call
/// would otherwise leave that route replayable and open to wallets its gate
/// was meant to refuse.
pub struct Admitted {
    identity: VerifiedIdentity,
}

impl Admitted {
    /// The wallet the admitted request was signed by.
    #[must_use]
    pub fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }

    /// A witness for the unit tests of the stores, which exercise the calls
    /// that take one without a signed request.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        let pubkey = [0x42; 32];
        Self {
            identity: VerifiedIdentity {
                pubkey,
                pubkey_ss58: warren_contract::ss58::encode(&pubkey),
            },
        }
    }
}

/// The signer redacted, as [`VerifiedRequest`] renders it.
impl std::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field(
                "signer",
                &warren_contract::redact(&self.identity.pubkey_ss58),
            )
            .finish()
    }
}

/// Renders the signer redacted and leaves the nonce out: request
/// authenticator material stays out of every log line, as `tests/log_privacy.rs`
/// requires of the source.
impl std::fmt::Debug for VerifiedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRequest")
            .field(
                "signer",
                &warren_contract::redact(&self.identity.pubkey_ss58),
            )
            .finish_non_exhaustive()
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
        timestamp: headers.timestamp,
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
    fn the_clock_window_is_sixty_seconds_either_way() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);

        for now in [1_000 - 60, 1_000 + 60] {
            verify_signed_request(&h, "POST", "/p", b"", now)
                .unwrap_or_else(|err| panic!("{now}: 60 s of skew is inside the window: {err}"));
        }
        for now in [1_000 - 61, 1_000 + 61] {
            let err = verify_signed_request(&h, "POST", "/p", b"", now)
                .expect_err("61 s of skew is outside the window");
            assert!(matches!(err, AuthError::Clock), "{now}: {err:?}");
        }
    }

    #[test]
    fn a_nonce_is_remembered_for_as_long_as_its_request_can_be_admitted() {
        // The twin reaches the server at the first second its timestamp is
        // valid and is admitted at once. The replay reaches it at the last
        // second, and its route reads the database and the forum for two
        // minutes before admitting it.
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        let nonces = NonceStore::default();
        let earliest = 1_000 - TIMESTAMP_WINDOW_SECS;
        verify_signed_request(&h, "POST", "/p", b"", earliest)
            .expect("the twin verifies")
            .admit(&nonces, earliest)
            .expect("and is admitted");

        let err = verify_signed_request(&h, "POST", "/p", b"", 1_000 + TIMESTAMP_WINDOW_SECS)
            .expect("the replay verifies at the last second of the window")
            .admit(&nonces, 1_000 + ADMISSION_HORIZON_SECS)
            .expect_err("its twin must still be remembered when it reaches admission");
        assert!(matches!(err, AuthError::Nonce));
    }

    #[test]
    fn a_request_is_admitted_up_to_two_minutes_after_its_window_and_not_after() {
        // Between verification and admission the slowest gate waits on the
        // database pool three times (30 s each) or on the forum once (60 s),
        // so a request verified at the last second of its window is still
        // admitted two minutes later. Past that its twin may already be
        // forgotten, and admitting it could admit a replay.
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let nonces = NonceStore::default();
        let on_time = signed(&key, "POST", "/p", b"", 1_000, [1; 16]);
        verify_signed_request(&on_time, "POST", "/p", b"", 1_060)
            .expect("verifies at the last second of the window")
            .admit(&nonces, 1_180)
            .expect("admitted two minutes later");

        let too_late = signed(&key, "POST", "/p", b"", 1_000, [2; 16]);
        let err = verify_signed_request(&too_late, "POST", "/p", b"", 1_060)
            .expect("verifies")
            .admit(&nonces, 1_181)
            .expect_err("one second later it is refused");
        assert!(matches!(err, AuthError::Nonce));
        assert_eq!(nonces.held(), 1, "and stores nothing for it");
    }

    #[test]
    fn a_verified_request_renders_neither_its_nonce_nor_its_full_signer() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [0xab; 16]);

        let rendered = format!(
            "{:?}",
            verify_signed_request(&h, "POST", "/p", b"", 1_000).expect("verifies")
        );

        assert!(!rendered.contains(&h.nonce_hex), "{rendered}");
        assert!(!rendered.contains(&h.pubkey_ss58), "{rendered}");
        assert!(
            rendered.contains(&warren_contract::redact(&h.pubkey_ss58)),
            "the redacted signer is what an incident needs: {rendered}"
        );
    }

    #[test]
    fn an_admission_names_its_signer_and_renders_it_redacted() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed(&key, "POST", "/p", b"", 1_000, [0xcd; 16]);
        let request = verify_signed_request(&h, "POST", "/p", b"", 1_000).expect("verifies");

        let admitted = request
            .admit(&NonceStore::default(), 1_000)
            .expect("admitted");

        assert_eq!(admitted.identity(), &request.identity);
        let rendered = format!("{admitted:?}");
        assert!(!rendered.contains(&h.pubkey_ss58), "{rendered}");
        assert!(
            rendered.contains(&warren_contract::redact(&h.pubkey_ss58)),
            "{rendered}"
        );
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
