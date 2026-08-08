//! Forum staff bootstrap allowlist, supplied by configuration.
//!
//! Keyed by Warren app public key (SS58 `wb…`). This list only ever PROMOTES.
//! It exists because a fresh forum has no admin and no local login with which
//! to make one, so at least one wallet must be able to arrive as staff.
//!
//! **The forum owns staff.** Discourse applies
//! `user.admin = admin unless admin.nil?`, so a login by a wallet outside this
//! list omits both fields and leaves the forum's own state untouched: an
//! operator grants admin or moderator from the Discourse admin UI and the grant
//! survives every later login. Revoking works from the same UI. A wallet listed
//! here is re-promoted on each of its logins, which is what makes it a floor
//! rather than a roster, and means it cannot be demoted from the UI.
//!
//! The list lives in `WARREN_ADMIN_PUBKEYS`, never in this source file, so a
//! public repository carries the mechanism without naming any operator.

use std::collections::BTreeSet;

/// Rejects an allowlist whose entries are not Warren addresses.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowlistError {
    /// An entry does not decode as a Warren SS58 address. Identified by
    /// position: the no-log rule forbids echoing the material itself.
    #[error("admin allowlist entry at position {index} is not a valid Warren SS58 address")]
    InvalidEntry {
        /// Zero-based index of the offending entry in the configured list.
        index: usize,
    },
}

/// The forum staff allowlist, parsed once at startup.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    pubkeys: BTreeSet<String>,
}

impl Allowlist {
    /// Parses a comma-separated list of Warren SS58 addresses. Blank entries and
    /// surrounding whitespace are ignored, so an empty or unset variable yields
    /// an empty allowlist (nobody is staff) rather than an error.
    ///
    /// # Errors
    ///
    /// [`AllowlistError::InvalidEntry`] when an entry does not decode: a typo in
    /// a staff address would otherwise silently demote that operator.
    pub fn parse(raw: &str) -> Result<Self, AllowlistError> {
        let mut pubkeys = BTreeSet::new();
        for (index, entry) in raw
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .enumerate()
        {
            warren_contract::ss58::decode(entry)
                .map_err(|_| AllowlistError::InvalidEntry { index })?;
            pubkeys.insert(entry.to_owned());
        }
        Ok(Self { pubkeys })
    }

    /// Whether a wallet is forum staff.
    #[must_use]
    pub fn is_admin(&self, pubkey_ss58: &str) -> bool {
        self.pubkeys.contains(pubkey_ss58)
    }

    /// Number of configured staff wallets. Safe to log: a count carries no
    /// identity material, and an operator needs to see that the roster loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pubkeys.len()
    }

    /// Whether no wallet is staff at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pubkeys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Addresses are derived from fixed dummy keys rather than written out, so
    /// no real operator wallet appears in this repository.
    fn address(seed: u8) -> String {
        warren_contract::ss58::encode(&[seed; 32])
    }

    #[test]
    fn configured_pubkey_is_admin() {
        let a = address(1);
        let list = Allowlist::parse(&a).expect("valid address parses");
        assert!(list.is_admin(&a));
    }

    #[test]
    fn unlisted_pubkey_is_not_admin() {
        let list = Allowlist::parse(&address(1)).expect("valid address parses");
        assert!(!list.is_admin(&address(2)));
    }

    #[test]
    fn several_entries_are_all_admitted() {
        let (a, b) = (address(1), address(2));
        let list = Allowlist::parse(&format!("{a},{b}")).expect("valid addresses parse");
        assert!(list.is_admin(&a));
        assert!(list.is_admin(&b));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn whitespace_and_blank_entries_are_ignored() {
        let (a, b) = (address(1), address(2));
        let list = Allowlist::parse(&format!("  {a} , , {b}  ,")).expect("valid addresses parse");
        assert_eq!(list.len(), 2);
        assert!(list.is_admin(&a));
        assert!(list.is_admin(&b));
    }

    #[test]
    fn an_unset_or_empty_variable_yields_no_admin() {
        let list = Allowlist::parse("").expect("an empty roster is valid");
        assert!(list.is_empty());
        assert!(!list.is_admin(&address(1)));
    }

    #[test]
    fn a_typo_is_rejected_by_position() {
        // A typo would otherwise silently demote that operator on next login.
        let err = Allowlist::parse(&format!("{},not-an-address", address(1)))
            .expect_err("a malformed entry must be refused");
        assert_eq!(err, AllowlistError::InvalidEntry { index: 1 });
    }

    #[test]
    fn the_rejection_never_echoes_the_offending_material() {
        // No-log discipline: an error must not carry identity material, not even
        // a value that failed to decode.
        let bogus = "wbTOTALLYBOGUSADDRESSVALUE";
        let err = Allowlist::parse(bogus).expect_err("a malformed entry must be refused");
        assert!(!err.to_string().contains(bogus));
    }
}
