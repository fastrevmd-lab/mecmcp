//! In-memory token store and per-request caller context.

use crate::entry::{EntryError, TokenEntry};
use crate::grant::{Grant, NoGrant};
use crate::scope::ScopeSet;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

/// Maximum entries, keeping the linear authenticate scan bounded.
pub const MAX_TOKENS: usize = 1024;

/// Rejection reason for a malformed token store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Two entries share a name.
    #[error("duplicate token name: {0}")]
    Duplicate(String),
    /// The store exceeds [`MAX_TOKENS`].
    #[error("token store contains {0} entries, maximum is {MAX_TOKENS}")]
    TooMany(usize),
    /// An entry failed validation.
    #[error(transparent)]
    Entry(#[from] EntryError),
}

/// Immutable token store, swapped atomically on reload.
#[derive(Debug, Clone)]
pub struct TokenStore<G: Grant = NoGrant> {
    entries: Vec<TokenEntry<G>>,
}

impl<G: Grant> TokenStore<G> {
    /// Validate bounds, uniqueness, and every entry.
    ///
    /// # Errors
    /// Returns [`StoreError`] describing the first failing check.
    pub fn try_new(entries: Vec<TokenEntry<G>>) -> Result<Self, StoreError> {
        // Deliberately NOT rejected here: an entry whose device and tool scopes
        // are both empty. Such a token authenticates but authorizes nothing,
        // which reads like a configuration mistake — but rejecting it would fail
        // the whole call, and this call validates the entire file. One useless
        // entry would then stop every other token in `tokens.json` from loading
        // and take authentication offline server-wide. An entry that authorizes
        // nothing is already fail-closed and harmless; a fleet-wide outage is
        // not. Surface it in `token list` output instead, never here.
        if entries.len() > MAX_TOKENS {
            return Err(StoreError::TooMany(entries.len()));
        }
        let mut seen = BTreeSet::new();
        for entry in &entries {
            entry.validate()?;
            if !seen.insert(entry.name.as_str()) {
                return Err(StoreError::Duplicate(entry.name.clone()));
            }
        }
        Ok(Self { entries })
    }

    /// Authenticate a candidate secret against the current wall clock.
    #[must_use]
    pub fn authenticate(&self, candidate: &str) -> Option<&TokenEntry<G>> {
        self.authenticate_at(candidate, Utc::now())
    }

    /// Authenticate a candidate secret at an explicit instant.
    ///
    /// Every entry is compared even after a match, so lookup time does not
    /// depend on an entry's position in the store.
    #[must_use]
    pub fn authenticate_at(&self, candidate: &str, now: DateTime<Utc>) -> Option<&TokenEntry<G>> {
        let mut found = None;
        for entry in &self.entries {
            if entry.digest.verify(candidate) && !entry.is_expired_at(now) {
                found = Some(entry);
            }
        }
        found
    }

    /// All entries, for `token list` and load-time linting.
    #[must_use]
    pub fn entries(&self) -> &[TokenEntry<G>] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<G: Grant> Default for TokenStore<G> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

/// Authenticated identity copied into per-request state.
#[derive(Debug, Clone)]
pub struct CallerCtx<G: Grant = NoGrant> {
    /// Non-secret token name, used for audit attribution and rate limiting.
    pub token_name: String,
    /// Devices this caller may address.
    pub devices: ScopeSet,
    /// Tools this caller may call.
    pub tools: ScopeSet,
    /// Vendor-specific write authority, if any.
    pub grant: Option<G>,
    /// Server-verified provider name, when the token declares one.
    pub provider: Option<String>,
    /// Server-verified provider tier, when the token declares one.
    pub provider_tier: Option<crate::Tier>,
    /// Server-verified human identity, when the token declares one.
    pub on_behalf_of: Option<String>,
    /// Server-verified actor type from the token entry.
    pub actor_type: crate::ActorType,
}

impl<G: Grant> From<&TokenEntry<G>> for CallerCtx<G> {
    fn from(entry: &TokenEntry<G>) -> Self {
        Self {
            token_name: entry.name.clone(),
            devices: entry.devices.clone(),
            tools: entry.tools.clone(),
            grant: entry.grant.clone(),
            provider: entry.provider.clone(),
            provider_tier: entry.provider_tier,
            on_behalf_of: entry.on_behalf_of.clone(),
            actor_type: entry.actor_type,
        }
    }
}

/// Filter inventory device names down to what this caller may see.
///
/// Filtering starts from the inventory names, never from the scope entries, so
/// a stale token naming a retired device can neither disclose nor synthesize
/// it. An absent caller context is the stdio / explicit-no-auth case and
/// preserves the full list.
#[must_use]
pub fn filter_device_names<G: Grant>(
    ctx: Option<&CallerCtx<G>>,
    names: Vec<String>,
) -> Vec<String> {
    match ctx {
        Some(ctx) => names
            .into_iter()
            .filter(|name| ctx.devices.allows(name))
            .collect(),
        None => names,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenSecret;

    fn entry_named(name: &str) -> (String, TokenEntry) {
        let (secret, digest) = TokenSecret::mint().expect("mint");
        let plaintext = secret.expose_secret().to_owned();
        let entry = TokenEntry {
            name: name.to_owned(),
            digest,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: DateTime::from_timestamp(1_783_850_400, 0).expect("timestamp"),
            expires_at: None,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
        };
        (plaintext, entry)
    }

    #[test]
    fn authenticates_a_known_secret() {
        let (secret, entry) = entry_named("lab");
        let store = TokenStore::try_new(vec![entry]).expect("store");
        assert_eq!(
            store.authenticate(&secret).map(|e| e.name.as_str()),
            Some("lab")
        );
    }

    #[test]
    fn rejects_an_unknown_secret() {
        let (_secret, entry) = entry_named("lab");
        let store = TokenStore::try_new(vec![entry]).expect("store");
        assert!(store.authenticate("not-a-real-token").is_none());
    }

    #[test]
    fn rejects_an_expired_secret() {
        let (secret, mut entry) = entry_named("lab");
        entry.expires_at = Some(DateTime::from_timestamp(1_783_936_800, 0).expect("timestamp"));
        let store = TokenStore::try_new(vec![entry]).expect("store");
        let after = DateTime::from_timestamp(1_784_100_000, 0).expect("timestamp");
        let before = DateTime::from_timestamp(1_783_900_000, 0).expect("timestamp");
        assert!(store.authenticate_at(&secret, before).is_some());
        assert!(store.authenticate_at(&secret, after).is_none());
    }

    #[test]
    fn duplicate_names_are_rejected_at_construction() {
        let (_a, first) = entry_named("lab");
        let (_b, second) = entry_named("lab");
        assert!(matches!(
            TokenStore::try_new(vec![first, second]),
            Err(StoreError::Duplicate(_))
        ));
    }

    #[test]
    fn an_invalid_entry_is_rejected_at_construction() {
        let (_secret, mut entry) = entry_named("lab");
        entry.devices = ScopeSet::Allowlist(vec!["a".to_owned(), "a".to_owned()]);
        assert!(matches!(
            TokenStore::try_new(vec![entry]),
            Err(StoreError::Entry(_))
        ));
    }

    #[test]
    fn more_than_max_tokens_is_rejected() {
        let entries = (0..=MAX_TOKENS)
            .map(|i| entry_named(&format!("t{i}")).1)
            .collect();
        assert!(matches!(
            TokenStore::try_new(entries),
            Err(StoreError::TooMany(_))
        ));
    }

    #[test]
    fn caller_ctx_filters_device_names_to_its_scope() {
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
        };
        let visible =
            filter_device_names(Some(&ctx), vec!["edge-fw".to_owned(), "core-fw".to_owned()]);
        assert_eq!(visible, vec!["edge-fw".to_owned()]);
    }

    #[test]
    fn absent_caller_ctx_sees_everything() {
        let names = vec!["edge-fw".to_owned(), "core-fw".to_owned()];
        let visible = filter_device_names(None::<&CallerCtx>, names.clone());
        assert_eq!(visible, names);
    }

    #[test]
    fn filtering_starts_from_inventory_not_scope() {
        // A stale token naming a device that no longer exists must not
        // synthesize it into the visible list.
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Allowlist(vec!["retired-fw".to_owned()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
        };
        let visible = filter_device_names(Some(&ctx), vec!["edge-fw".to_owned()]);
        assert!(visible.is_empty());
    }

    #[test]
    fn wildcard_scope_sees_the_whole_inventory() {
        // The most common shape for a real token, and the one case the other
        // filter tests do not reach.
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
        };
        let names = vec!["edge-fw".to_owned(), "core-fw".to_owned()];
        let visible = filter_device_names(Some(&ctx), names.clone());
        assert_eq!(visible, names, "a wildcard device scope must not filter");
    }
}
