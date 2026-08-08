//! Pairwise public identity: the forum handle.
//!
//! The public forum username must not be correlatable with the user's Warren
//! account handle (the `wb…` SS58 address), while staying deterministic so
//! support can recompute it from a known pubkey. A keyed HMAC gives exactly
//! that directed-identifier property: without `FORUM_HANDLE_SECRET` nobody can
//! map pubkey -> handle, and the handle alone can never be reversed.
//!
//! Format is FROZEN (golden-vector-tested below): changing it orphans every
//! existing forum account.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;

/// Proquint consonants (4 bits) and vowels (2 bits): the pronounceable,
/// language-neutral bit-encoding of Daniel Wilkerson's "Proquint" scheme
/// (2009). A 16-bit word maps to a `cvcvc` quintet, e.g. `lusab`.
const PROQUINT_CONSONANTS: &[u8; 16] = b"bdfghjklmnprstvz";
const PROQUINT_VOWELS: &[u8; 4] = b"aiou";

/// Number of 16-bit quints in a username = 48 bits of the keyed HMAC. Three
/// hyphen-separated quints (17 chars) read cleanly and fit Discourse's 20-char
/// username limit; 48 bits keeps collisions negligible at any realistic user
/// count (the unique constraint on `forum_links.username` catches the rest).
const USERNAME_QUINTS: usize = 3;

/// Encodes one 16-bit word as a proquint quintet (`cvcvc`).
fn proquint(word: u16) -> [u8; 5] {
    [
        PROQUINT_CONSONANTS[usize::from((word >> 12) & 0xF)],
        PROQUINT_VOWELS[usize::from((word >> 10) & 0x3)],
        PROQUINT_CONSONANTS[usize::from((word >> 6) & 0xF)],
        PROQUINT_VOWELS[usize::from((word >> 4) & 0x3)],
        PROQUINT_CONSONANTS[usize::from(word & 0xF)],
    ]
}

/// A user's derived forum identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForumHandle {
    /// Discourse `external_id` (private, admin-only): full HMAC, 64 hex chars.
    pub external_id: String,
    /// Discourse username (public): pronounceable proquint, e.g.
    /// `lusab-babad-dovok`. Language-neutral, deterministic, non-invertible.
    pub username: String,
    /// Synthetic address satisfying Discourse's not-null email constraint.
    /// `.invalid` (RFC 2606) never routes; mail sending is disabled site-wide.
    pub email: String,
}

/// Derives the pairwise forum identity for a wallet public key.
#[must_use]
pub fn derive(handle_secret: &[u8], pubkey: &[u8; 32]) -> ForumHandle {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(handle_secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(pubkey);
    let tag = mac.finalize().into_bytes();

    let external_id = hex::encode(tag);

    let mut username = String::with_capacity(USERNAME_QUINTS * 6);
    for i in 0..USERNAME_QUINTS {
        if i > 0 {
            username.push('-');
        }
        let word = (u16::from(tag[2 * i]) << 8) | u16::from(tag[2 * i + 1]);
        // proquint bytes are ASCII by construction.
        username.push_str(std::str::from_utf8(&proquint(word)).expect("proquint is ASCII"));
    }

    let email = format!("{username}@users.warrenbrowse.invalid");
    ForumHandle {
        external_id,
        username,
        email,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vector_is_frozen() {
        // Changing the derivation orphans every forum account; this vector is
        // the tripwire. secret="test-secret", pubkey=[0xab; 32].
        let h = derive(b"test-secret", &[0xab; 32]);
        assert_eq!(
            h.external_id,
            hex::encode({
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(b"test-secret").expect("any key length");
                mac.update(&[0xab; 32]);
                mac.finalize().into_bytes()
            }),
            "external_id must be the hex HMAC"
        );
        // Independently pinned exact strings (computed once with a reference
        // HMAC implementation, frozen).
        assert_eq!(
            h.external_id,
            "d570cbe8bc6adfc240d6e7da47f5856e83789a36600820ee92eb1167c7aa1356"
        );
        assert_eq!(h.username, "tijub-sozom-rudop");
        assert_eq!(h.email, "tijub-sozom-rudop@users.warrenbrowse.invalid");
    }

    #[test]
    fn distinct_pubkeys_get_unlinkable_handles() {
        let a = derive(b"s", &[1u8; 32]);
        let b = derive(b"s", &[2u8; 32]);
        assert_ne!(a.username, b.username);
        assert_ne!(a.external_id, b.external_id);
    }

    #[test]
    fn distinct_secrets_change_the_handle() {
        let a = derive(b"secret-a", &[9u8; 32]);
        let b = derive(b"secret-b", &[9u8; 32]);
        assert_ne!(
            a.username, b.username,
            "the mapping must be keyed, not a plain hash of the pubkey"
        );
    }

    #[test]
    fn username_shape_is_valid_for_discourse() {
        let h = derive(b"k", &[0u8; 32]);
        // 3 quints of 5 chars + 2 separators = 17, within Discourse's 20 max
        // and above the 3 min; starts and ends with a letter.
        assert_eq!(
            h.username.len(),
            USERNAME_QUINTS * 5 + (USERNAME_QUINTS - 1)
        );
        assert_eq!(h.username.matches('-').count(), USERNAME_QUINTS - 1);
        assert!(h.username.starts_with(|c: char| c.is_ascii_lowercase()));
        assert!(h.username.ends_with(|c: char| c.is_ascii_lowercase()));
        assert!(
            h.username
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-'),
            "proquint lowercase letters + hyphens keep usernames within Discourse's charset"
        );
    }

    #[test]
    fn username_is_pronounceable_proquint() {
        // Every non-separator char is a valid proquint consonant or vowel.
        let h = derive(b"k", &[7u8; 32]);
        let valid = |c: u8| PROQUINT_CONSONANTS.contains(&c) || PROQUINT_VOWELS.contains(&c);
        assert!(h.username.bytes().all(|b| b == b'-' || valid(b)));
    }
}
