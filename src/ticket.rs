//! Follow-up codes for the guest help flow.
//!
//! A guest has no forum account, so nothing about a later message proves it
//! belongs to an existing report. The code issued with a report is that proof:
//! a keyed MAC over the topic id, which the service can verify while storing
//! nothing. No ticket table, no retention question, and a restart or a
//! redeploy can never orphan a code.
//!
//! The code is a CREDENTIAL: whoever holds it can post into that topic as the
//! reporter. It is therefore returned to the guest once, over the intake
//! response, and never written into the public topic, a log line or a metric.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::error::AuthError;

/// Domain separator: the ticket key is derived from `FORUM_HANDLE_SECRET`, so
/// it must be a PRF output independent from the forum-handle derivation that
/// uses the same secret directly.
const DERIVATION_LABEL: &[u8] = b"warren-connect/help-ticket/v1";

/// Bytes of MAC kept in a code. 48 bits: forging one takes 2^48 tries against
/// an endpoint that admits a few per hour and per IP, while keeping the code
/// short enough to read out loud.
const TAG_BYTES: usize = 6;

/// Bytes encoded in a code: the topic id (u32) followed by the tag.
const RAW_BYTES: usize = 4 + TAG_BYTES;

/// Characters of the encoded body. 10 bytes = 80 bits = exactly 16 base32
/// characters, so no padding bit is ever carried.
const CODE_CHARS: usize = RAW_BYTES * 8 / 5;

/// Group size of the displayed form.
const GROUP: usize = 4;

/// Displayed prefix. Accepted but not required on input.
const PREFIX: &str = "WRN";

/// Crockford base32: no `I`, `L`, `O` or `U`, so the glyph pairs a human
/// confuses (1/I/l, 0/O) are unambiguous and no code can spell an obscenity.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Key that issues and verifies follow-up codes.
pub struct TicketKey([u8; 32]);

impl std::fmt::Debug for TicketKey {
    /// Never renders the key: it is the only thing standing between a stranger
    /// and posting as any guest reporter.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketKey(redacted)")
    }
}

impl TicketKey {
    /// Derives the ticket key from the forum handle secret.
    ///
    /// Deriving rather than taking a key of its own keeps the feature free of
    /// an operator step: the secret already exists, is already required to be
    /// long, and is already never rotated (rotating it would rename every
    /// forum account). The label makes this an independent PRF output.
    #[must_use]
    pub fn derive(handle_secret: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(handle_secret)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(DERIVATION_LABEL);
        Self(mac.finalize().into_bytes().into())
    }

    fn mac(&self, domain: u8, input: &[u8]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC-SHA256 accepts any key length");
        mac.update(&[domain]);
        mac.update(input);
        mac.finalize().into_bytes().into()
    }

    fn tag(&self, topic_id: u32) -> [u8; TAG_BYTES] {
        let full = self.mac(b't', &topic_id.to_be_bytes());
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&full[..TAG_BYTES]);
        tag
    }

    /// Keystream hiding the topic id inside the code. Without it every code
    /// issued the same week would share its first characters (the id sits in
    /// the high bytes and the forum's ids are small), which reads as a broken
    /// generator and hands a reader the neighbouring topic ids for free.
    /// Keyed on the tag, so it costs the verifier nothing to recover.
    fn mask(&self, tag: &[u8; TAG_BYTES]) -> [u8; 4] {
        let full = self.mac(b'm', tag);
        let mut mask = [0u8; 4];
        mask.copy_from_slice(&full[..4]);
        mask
    }

    /// Issues the follow-up code for a topic, in its displayed form.
    ///
    /// # Errors
    /// [`AuthError::Forum`] if the topic id does not fit in 32 bits. Discourse
    /// stores topic ids in a PostgreSQL `integer`, so this means the forum
    /// answered outside its own schema, not that the guest did anything.
    pub fn issue(&self, topic_id: u64) -> Result<String, AuthError> {
        let id = u32::try_from(topic_id).map_err(|_| AuthError::Forum)?;
        let tag = self.tag(id);
        let mask = self.mask(&tag);
        let mut raw = [0u8; RAW_BYTES];
        for (i, byte) in id.to_be_bytes().iter().enumerate() {
            raw[i] = byte ^ mask[i];
        }
        raw[4..].copy_from_slice(&tag);
        Ok(group(&encode(&raw)))
    }

    /// Recovers the topic a code was issued for.
    ///
    /// # Errors
    /// [`AuthError::InvalidTicket`] when the code is malformed, carries a
    /// character outside the alphabet, or does not verify under this key.
    pub fn verify(&self, code: &str) -> Result<u64, AuthError> {
        let raw = decode(code)?;
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&raw[4..]);
        let mask = self.mask(&tag);
        let mut id = [0u8; 4];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = raw[i] ^ mask[i];
        }
        let id = u32::from_be_bytes(id);
        // Constant time: a wrong code must not leak how many leading tag bytes
        // were right, which would turn 2^48 guesses into 6 x 2^8.
        if bool::from(self.tag(id).ct_eq(&raw[4..])) {
            Ok(u64::from(id))
        } else {
            Err(AuthError::InvalidTicket)
        }
    }
}

/// 10 bytes -> 16 base32 characters (80 bits, exact fit).
fn encode(raw: &[u8; RAW_BYTES]) -> String {
    let mut acc: u128 = 0;
    for &b in raw {
        acc = (acc << 8) | u128::from(b);
    }
    let mut out = String::with_capacity(CODE_CHARS);
    for i in (0..CODE_CHARS).rev() {
        let index = ((acc >> (i * 5)) & 0x1F) as usize;
        out.push(char::from(ALPHABET[index]));
    }
    out
}

/// Displayed form: `WRN-XXXX-XXXX-XXXX-XXXX`.
fn group(body: &str) -> String {
    let mut out = String::from(PREFIX);
    for (i, ch) in body.chars().enumerate() {
        if i % GROUP == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Maps one input character to its 5-bit value, absorbing the Crockford
/// confusions (`O` is a zero, `I` and `L` are ones) so a code read off a
/// screen and retyped still lands.
fn value(ch: u8) -> Result<u8, AuthError> {
    match ch {
        b'O' => Ok(0),
        b'I' | b'L' => Ok(1),
        _ => ALPHABET
            .iter()
            .position(|&a| a == ch)
            .map(|p| p as u8)
            .ok_or(AuthError::InvalidTicket),
    }
}

/// Parses any human form of a code (with or without the prefix, dashes,
/// spaces, in any case) back to its 10 raw bytes.
fn decode(code: &str) -> Result<[u8; RAW_BYTES], AuthError> {
    let mut chars = Vec::with_capacity(PREFIX.len() + CODE_CHARS);
    for ch in code.chars() {
        if ch.is_ascii_alphanumeric() {
            // Bounded before pushing: a megabyte of digits must not allocate.
            if chars.len() > PREFIX.len() + CODE_CHARS {
                return Err(AuthError::InvalidTicket);
            }
            chars.push(ch.to_ascii_uppercase() as u8);
        } else if !matches!(ch, '-' | ' ' | '_' | '\t') {
            return Err(AuthError::InvalidTicket);
        }
    }
    let body = if chars.len() == PREFIX.len() + CODE_CHARS && chars.starts_with(PREFIX.as_bytes()) {
        &chars[PREFIX.len()..]
    } else {
        &chars[..]
    };
    if body.len() != CODE_CHARS {
        return Err(AuthError::InvalidTicket);
    }
    let mut acc: u128 = 0;
    for &ch in body {
        acc = (acc << 5) | u128::from(value(ch)?);
    }
    let wide = acc.to_be_bytes();
    let mut raw = [0u8; RAW_BYTES];
    raw.copy_from_slice(&wide[wide.len() - RAW_BYTES..]);
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TicketKey {
        TicketKey::derive(b"a-test-handle-secret-32-bytes!!!")
    }

    #[test]
    fn a_code_round_trips_to_its_topic() {
        let k = key();
        for topic_id in [1u64, 42, 4_242, 999_999, u64::from(u32::MAX)] {
            let code = k.issue(topic_id).expect("issued");
            assert_eq!(k.verify(&code).expect("verifies"), topic_id);
        }
    }

    #[test]
    fn the_displayed_shape_is_pinned() {
        // Frozen: a code already handed to a guest must keep working, so
        // neither the derivation nor the encoding may drift silently.
        let code = key().issue(4_242).expect("issued");
        assert_eq!(code, "WRN-SC0X-Y8GE-JG7J-2EG7");
        assert!(code.starts_with("WRN-"));
        let body: String = code.chars().filter(char::is_ascii_alphanumeric).collect();
        assert_eq!(body.len(), PREFIX.len() + CODE_CHARS);
        assert!(
            body[PREFIX.len()..]
                .bytes()
                .all(|b| ALPHABET.contains(&b) && !b"ILOU".contains(&b)),
            "the body stays inside the confusion-free alphabet"
        );
    }

    #[test]
    fn a_code_issued_under_another_key_is_refused() {
        let code = TicketKey::derive(b"another-secret-of-32-bytes-here!")
            .issue(4_242)
            .expect("issued");
        assert!(matches!(
            key().verify(&code).expect_err("wrong key"),
            AuthError::InvalidTicket
        ));
    }

    #[test]
    fn altering_a_single_character_breaks_the_code() {
        let k = key();
        let code = k.issue(4_242).expect("issued");
        for i in 0..code.len() {
            let (head, tail) = code.split_at(i);
            let Some(ch) = tail.chars().next() else {
                continue;
            };
            if !ch.is_ascii_alphanumeric() {
                continue;
            }
            // Swap for a different character of the alphabet.
            let replacement = if ch == '2' { '3' } else { '2' };
            let mutated = format!("{head}{replacement}{}", &tail[ch.len_utf8()..]);
            assert!(
                k.verify(&mutated).is_err(),
                "a one-character typo must never verify: {mutated}"
            );
        }
    }

    #[test]
    fn a_code_is_accepted_however_a_human_retypes_it() {
        let k = key();
        let code = k.issue(4_242).expect("issued");
        let body: String = code
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .skip(PREFIX.len())
            .collect();
        for form in [
            code.clone(),
            code.to_lowercase(),
            body.clone(),
            body.to_lowercase(),
            format!("  {code}  "),
            body.chars()
                .collect::<Vec<_>>()
                .chunks(2)
                .fold(String::new(), |mut acc, chunk| {
                    if !acc.is_empty() {
                        acc.push(' ');
                    }
                    acc.extend(chunk);
                    acc
                }),
        ] {
            assert_eq!(
                k.verify(&form).unwrap_or_else(|_| panic!("form {form}")),
                4_242
            );
        }
    }

    #[test]
    fn the_crockford_confusions_are_absorbed() {
        // A code whose body holds a 0 and a 1 must still verify when the
        // reader typed the letters they look like.
        let k = key();
        let mut id = 0u64;
        let code = loop {
            let candidate = k.issue(id).expect("issued");
            if candidate.contains('0') && candidate.contains('1') {
                break candidate;
            }
            id += 1;
            assert!(id < 10_000, "a code with both glyphs exists early");
        };
        let confused = code.replace('0', "O").replace('1', "I");
        assert_eq!(k.verify(&confused).expect("confusions absorbed"), id);
        let confused = code.replace('1', "l");
        assert_eq!(k.verify(&confused).expect("lowercase L is a one"), id);
    }

    #[test]
    fn malformed_input_is_refused_without_panicking() {
        let k = key();
        for bad in [
            "",
            "WRN-",
            "WRN-4TVP-N3XY-2QGM",              // one group short
            "WRN-4TVP-N3XY-2QGM-J2XK-J2XK",    // one group long
            "WRN-4TVP-N3XY-2QGM-J2XU",         // U is outside the alphabet
            "WRN-4TVP-N3XY-2QGM-J2X<",         // punctuation
            "https://forum.warrenbrowse.com/", // a pasted URL
            &"9".repeat(100_000),              // a flood
        ] {
            assert!(matches!(
                k.verify(bad).expect_err("refused"),
                AuthError::InvalidTicket
            ));
        }
    }

    #[test]
    fn distinct_topics_get_distinct_codes() {
        let k = key();
        let a = k.issue(4_242).expect("issued");
        let b = k.issue(4_243).expect("issued");
        assert_ne!(a, b);
        assert_eq!(k.verify(&a).expect("a"), 4_242);
        assert_eq!(k.verify(&b).expect("b"), 4_243);
    }

    #[test]
    fn a_topic_id_outside_the_discourse_range_cannot_be_issued() {
        // Discourse stores topic ids in a PostgreSQL integer; anything wider
        // is the forum contradicting its own schema, never guest input.
        assert!(matches!(
            key()
                .issue(u64::from(u32::MAX) + 1)
                .expect_err("out of range"),
            AuthError::Forum
        ));
    }

    #[test]
    fn the_key_never_renders_itself() {
        assert_eq!(format!("{:?}", key()), "TicketKey(redacted)");
    }
}
