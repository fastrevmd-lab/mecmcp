# mecmcp-auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract one vendor-neutral bearer-token authentication crate that both `rustjunosmcp` and `rustpanosmcp` consume, without breaking either server's deployed `tokens.json`.

**Architecture:** `mecmcp-auth` takes `rustpanosmcp`'s bounded, validated, `zeroize`-based token/store design and `rustjunosmcp`'s superior file-permission diagnostics. Vendor-specific write authority is abstracted behind a `Grant` trait so the crate names neither XPath nor Junos config paths. On-disk compatibility with both existing `tokens.json` formats is preserved with serde aliases and proven by fixture tests before either server is migrated.

**Tech Stack:** Rust edition 2024 (MSRV 1.88), `serde`, `serde_json`, `sha2`, `subtle`, `zeroize`, `getrandom`, `thiserror`, `chrono`, `arc-swap`, `tempfile`, `rustix` (unix only).

## Global Constraints

Copied verbatim from [`PLAN.md`](../../../PLAN.md). Every task's requirements implicitly include this section.

- Edition 2024, MSRV 1.88.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"` (priority -1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`.
- No breaking change to on-disk `tokens.json`. Live deployments exist (LXC 609, `/etc/jmcp/tokens.json`). Field renames ship as serde aliases; the old spelling keeps working and stays tested.
- No breaking change to the MCP tool surface of either server.
- The deployed systemd override on LXC 609 must keep working unchanged: `0.0.0.0:30031`, `--allow-insecure-bind`, `--allowed-host 192.168.1.194`, no `--inventory-readonly`.
- Licence: MIT, single. `license = "MIT"` on every crate.
- `mecmcp-auth` must compile with **neither** vendor server as a dependency, and must not contain the strings `xpath`, `XPath`, `junos`, `panos`, or `routers` outside of serde aliases and doc comments.
- Consumed as a git dependency pinned by tag: `tag = "auth-v0.1.0"`.

---

## File Structure

```
Cargo.toml                          workspace root: members, lints, shared deps
crates/mecmcp-auth/Cargo.toml       crate manifest
crates/mecmcp-auth/src/lib.rs       module wiring + public re-exports
crates/mecmcp-auth/src/token.rs     TokenSecret, TokenDigest, TokenError
crates/mecmcp-auth/src/scope.rs     ScopeSet + validation
crates/mecmcp-auth/src/grant.rs     Grant trait, NoGrant, GrantError
crates/mecmcp-auth/src/entry.rs     TokenEntry<G> with serde aliases
crates/mecmcp-auth/src/store.rs     TokenStore<G>, CallerCtx<G>, StoreError
crates/mecmcp-auth/src/file.rs      TokenStoreFile: load, perms, atomic write, reload
crates/mecmcp-auth/tests/compat.rs  fixture tests against both servers' real formats
crates/mecmcp-auth/tests/fixtures/junos-tokens.json
crates/mecmcp-auth/tests/fixtures/panos-tokens.json
```

One responsibility per file. `token.rs` knows secrets and nothing about scopes; `scope.rs` knows names and nothing about tokens; `grant.rs` defines the vendor seam; `entry.rs` is the only file that knows the on-disk shape; `file.rs` is the only file that does I/O.

---

### Task 1: Workspace scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `crates/mecmcp-auth/Cargo.toml`
- Create: `crates/mecmcp-auth/src/lib.rs`
- Create: `rust-toolchain.toml`

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace where `cargo clippy --workspace --all-targets -- -D warnings` runs clean and `unsafe_code` is forbidden.

- [ ] **Step 1: Write the workspace manifest**

```toml
# Cargo.toml
[workspace]
members  = ["crates/mecmcp-auth"]
resolver = "2"

[workspace.package]
version      = "0.1.0"
edition      = "2024"
rust-version = "1.88"
license      = "MIT"
repository   = "https://github.com/fastrevmd-lab/mecmcp"
authors      = ["fastrevmd-lab"]

[workspace.dependencies]
arc-swap   = "1"
chrono     = { version = "0.4", default-features = false, features = ["serde", "clock"] }
getrandom  = "0.4"
rustix     = { version = "1", features = ["fs", "process"] }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
sha2       = "0.11"
subtle     = "2"
tempfile   = "3"
thiserror  = "2"
zeroize    = { version = "1", features = ["derive"] }

[workspace.lints.rust]
missing_docs = "warn"
unsafe_code  = "forbid"

[workspace.lints.clippy]
all         = { level = "warn", priority = -1 }
dbg_macro   = "deny"
todo        = "deny"
unwrap_used = "warn"
```

- [ ] **Step 2: Write the crate manifest**

```toml
# crates/mecmcp-auth/Cargo.toml
[package]
name        = "mecmcp-auth"
description = "Vendor-neutral bearer-token authentication and scopes for mechub MCP servers."
version.workspace      = true
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
authors.workspace      = true

[lints]
workspace = true

[dependencies]
arc-swap   = { workspace = true }
chrono     = { workspace = true }
getrandom  = { workspace = true }
serde      = { workspace = true }
serde_json = { workspace = true }
sha2       = { workspace = true }
subtle     = { workspace = true }
tempfile   = { workspace = true }
thiserror  = { workspace = true }
zeroize    = { workspace = true }

[target.'cfg(unix)'.dependencies]
rustix = { workspace = true }
```

`rustix` rather than `libc`, because `libc::getuid()` is an `unsafe extern` call
that `unsafe_code = "forbid"` rejects. `rustpanosmcp` already depends on `rustix`
for the same reason.

- [ ] **Step 3: Write the toolchain pin and a placeholder lib**

```toml
# rust-toolchain.toml
# Pin the toolchain both consumers already use. MSRV 1.88 is the compatibility
# floor declared in Cargo.toml, not the toolchain we build with.
[toolchain]
channel    = "1.97.0"
profile    = "minimal"
components = ["rustfmt", "clippy"]
```

```rust
// crates/mecmcp-auth/src/lib.rs
//! Vendor-neutral bearer-token authentication, scopes, and grants.
//!
//! This crate is deliberately free of vendor concepts. It knows about tokens,
//! names, and opaque authorization subjects; it does not know what a subject
//! means to any particular device family.
```

- [ ] **Step 4: Verify the workspace builds clean**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml crates/mecmcp-auth/Cargo.toml crates/mecmcp-auth/src/lib.rs
git commit -m "chore: scaffold mecmcp workspace and mecmcp-auth crate"
```

---

### Task 2: Token mint, digest, and constant-time verify

**Files:**
- Create: `crates/mecmcp-auth/src/token.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `TokenSecret` with `TokenSecret::mint() -> Result<(TokenSecret, TokenDigest), TokenError>` and `expose_secret(&self) -> &str`
  - `TokenDigest` with `from_secret(&str) -> TokenDigest`, `verify(&self, candidate: &str) -> bool`, `as_str(&self) -> &str`
  - `TokenError::{Random, InvalidDigest(String)}`

This replaces `rustjunosmcp`'s `unsafe { write_volatile }` zeroing with `zeroize`, which is what allows `unsafe_code = "forbid"`.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mecmcp-auth/src/token.rs  (append at the bottom)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_secret_verifies_against_its_own_digest() {
        let (secret, digest) = TokenSecret::mint().expect("mint");
        assert!(digest.verify(secret.expose_secret()));
    }

    #[test]
    fn digest_rejects_a_different_secret() {
        let (_secret, digest) = TokenSecret::mint().expect("mint");
        let (other, _) = TokenSecret::mint().expect("mint");
        assert!(!digest.verify(other.expose_secret()));
    }

    #[test]
    fn minted_secret_is_43_chars_of_base64url_no_pad() {
        let (secret, _) = TokenSecret::mint().expect("mint");
        assert_eq!(secret.expose_secret().len(), ENCODED_SECRET_BYTES);
        assert!(!secret.expose_secret().contains('='));
    }

    #[test]
    fn digest_is_prefixed_and_round_trips_through_serde() {
        let (_secret, digest) = TokenSecret::mint().expect("mint");
        assert!(digest.as_str().starts_with(DIGEST_PREFIX));
        let json = serde_json::to_string(&digest).expect("serialize");
        let back: TokenDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(digest, back);
    }

    #[test]
    fn digest_without_prefix_is_rejected() {
        let err = serde_json::from_str::<TokenDigest>("\"deadbeef\"");
        assert!(err.is_err());
    }

    #[test]
    fn two_mints_differ() {
        let (a, _) = TokenSecret::mint().expect("mint");
        let (b, _) = TokenSecret::mint().expect("mint");
        assert_ne!(a.expose_secret(), b.expose_secret());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mecmcp-auth token::`
Expected: FAIL — `cannot find type TokenSecret in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
// crates/mecmcp-auth/src/token.rs  (top of file, above the tests module)
//! Token minting, versioned digests, and constant-time verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Raw random bytes behind one token secret.
const SECRET_BYTES: usize = 32;
/// Length of 32 random bytes encoded as unpadded base64url.
const ENCODED_SECRET_BYTES: usize = 43;
/// Prefix identifying the digest algorithm on disk.
const DIGEST_PREFIX: &str = "sha256:";

/// Error while minting or decoding token material.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The operating-system CSPRNG failed.
    #[error("operating-system random source failed")]
    Random,
    /// A stored token digest is malformed.
    #[error("invalid token digest: {0}")]
    InvalidDigest(String),
}

/// A freshly minted bearer secret.
///
/// Implements neither `Clone`, `Debug`, `Display`, nor `Serialize`, so it
/// cannot be logged or persisted by accident. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TokenSecret(String);

impl TokenSecret {
    /// Mint 256 random bits and return the plaintext with its stored digest.
    ///
    /// The plaintext is expected to leave the process exactly once, printed by
    /// a `token add` or `token rotate` command.
    pub fn mint() -> Result<(Self, TokenDigest), TokenError> {
        let mut random = [0_u8; SECRET_BYTES];
        getrandom::fill(&mut random).map_err(|_| TokenError::Random)?;
        let encoded = base64url_no_pad(&random);
        random.zeroize();
        let digest = TokenDigest::from_secret(&encoded);
        Ok((Self(encoded), digest))
    }

    /// Expose the plaintext for the single write that prints it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

/// Versioned SHA-256 digest of a token secret, as stored in `tokens.json`.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenDigest(String);

impl TokenDigest {
    /// Compute the stored digest for a secret.
    #[must_use]
    pub fn from_secret(secret: &str) -> Self {
        let hashed = Sha256::digest(secret.as_bytes());
        Self(format!("{DIGEST_PREFIX}{}", base64url_no_pad(&hashed)))
    }

    /// Constant-time comparison of a candidate secret against this digest.
    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        let computed = Self::from_secret(candidate);
        computed.0.as_bytes().ct_eq(self.0.as_bytes()).into()
    }

    /// The `sha256:`-prefixed digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Digests are not secrets, but they are not useful in logs either.
        f.write_str("TokenDigest(sha256:…)")
    }
}

impl Serialize for TokenDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TokenDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if !raw.starts_with(DIGEST_PREFIX) {
            return Err(serde::de::Error::custom(format!(
                "token digest must start with '{DIGEST_PREFIX}'"
            )));
        }
        Ok(Self(raw))
    }
}

/// Encode bytes as unpadded base64url without pulling in a base64 crate.
fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let indices = [
            (triple >> 18) & 0x3F,
            (triple >> 12) & 0x3F,
            (triple >> 6) & 0x3F,
            triple & 0x3F,
        ];
        let emit = chunk.len() + 1;
        for index in indices.iter().take(emit) {
            out.push(ALPHABET[*index as usize] as char);
        }
    }
    out
}
```

- [ ] **Step 4: Wire the module and run the tests**

```rust
// crates/mecmcp-auth/src/lib.rs  (append)
pub mod token;

pub use token::{TokenDigest, TokenError, TokenSecret};
```

Run: `cargo test -p mecmcp-auth token::`
Expected: PASS, 6 tests.

- [ ] **Step 5: Verify the digest matches both existing servers byte for byte**

This is the compatibility check that makes migration safe. Both servers already
store `sha256:` + unpadded-base64url of the SHA-256 of the secret.

```rust
// crates/mecmcp-auth/src/token.rs  (add to the tests module)
#[test]
fn digest_matches_the_format_both_existing_servers_write() {
    // Known-answer: SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015
    //                                a3bf4f1b2b0b822cd15d6c15b0f00a08
    // base64url-unpadded of those 32 bytes:
    let digest = TokenDigest::from_secret("test");
    assert_eq!(
        digest.as_str(),
        "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
    );
}
```

Run: `cargo test -p mecmcp-auth token::digest_matches`
Expected: PASS. If it fails, `base64url_no_pad` is wrong — fix it before continuing, because every deployed token depends on this exact encoding.

- [ ] **Step 6: Commit**

```bash
git add crates/mecmcp-auth/src/token.rs crates/mecmcp-auth/src/lib.rs
git commit -m "feat(auth): token mint, versioned digest, constant-time verify"
```

---

### Task 3: ScopeSet

**Files:**
- Create: `crates/mecmcp-auth/src/scope.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ScopeSet::{Wildcard, Allowlist(Vec<String>)}`
  - `allows(&self, name: &str) -> bool`
  - `allows_tool(&self, name: &str, write_tools: &[&str]) -> bool`
  - `is_empty(&self) -> bool`, `summary(&self) -> String`
  - `validate(&self, field: &'static str) -> Result<(), ScopeError>`
  - `ScopeError::Invalid(String)`
  - `MAX_SCOPE_NAMES: usize = 256`

The write-tool registry is a parameter rather than a crate constant, because
`rustpanosmcp` hardcodes its own `MUTATION_TOOLS` list and `rustjunosmcp` has a
different tool surface. The crate must not know either.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mecmcp-auth/src/scope.rs  (append at the bottom)
#[cfg(test)]
mod tests {
    use super::*;

    const WRITE_TOOLS: &[&str] = &["load_and_commit_config", "commit_panos_candidate"];

    #[test]
    fn wildcard_allows_any_device_name() {
        assert!(ScopeSet::Wildcard.allows("edge-fw"));
    }

    #[test]
    fn allowlist_allows_only_exact_names() {
        let scope = ScopeSet::Allowlist(vec!["edge-fw".to_owned()]);
        assert!(scope.allows("edge-fw"));
        assert!(!scope.allows("edge-fw-2"));
        assert!(!scope.allows("edge"));
    }

    #[test]
    fn wildcard_tool_scope_excludes_write_tools() {
        let scope = ScopeSet::Wildcard;
        assert!(scope.allows_tool("get_junos_config", WRITE_TOOLS));
        assert!(!scope.allows_tool("load_and_commit_config", WRITE_TOOLS));
    }

    #[test]
    fn explicit_allowlist_may_name_a_write_tool() {
        let scope = ScopeSet::Allowlist(vec!["load_and_commit_config".to_owned()]);
        assert!(scope.allows_tool("load_and_commit_config", WRITE_TOOLS));
    }

    #[test]
    fn empty_allowlist_permits_nothing() {
        let scope = ScopeSet::Allowlist(vec![]);
        assert!(scope.is_empty());
        assert!(!scope.allows("anything"));
    }

    #[test]
    fn wildcard_round_trips_as_a_single_star_entry() {
        let json = serde_json::to_string(&ScopeSet::Wildcard).expect("serialize");
        assert_eq!(json, "[\"*\"]");
        let back: ScopeSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ScopeSet::Wildcard);
    }

    #[test]
    fn star_inside_a_longer_list_fails_validation() {
        let scope = ScopeSet::Allowlist(vec!["a".to_owned(), "*".to_owned()]);
        assert!(scope.validate("devices").is_err());
    }

    #[test]
    fn duplicate_names_fail_validation() {
        let scope = ScopeSet::Allowlist(vec!["a".to_owned(), "a".to_owned()]);
        assert!(scope.validate("devices").is_err());
    }

    #[test]
    fn oversized_allowlist_fails_validation() {
        let names = (0..=MAX_SCOPE_NAMES).map(|i| format!("d{i}")).collect();
        assert!(ScopeSet::Allowlist(names).validate("devices").is_err());
    }

    #[test]
    fn summary_is_stable_for_audit_metadata() {
        assert_eq!(ScopeSet::Wildcard.summary(), "*");
        assert_eq!(
            ScopeSet::Allowlist(vec!["a".to_owned(), "b".to_owned()]).summary(),
            "a,b"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mecmcp-auth scope::`
Expected: FAIL — `cannot find type ScopeSet in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
// crates/mecmcp-auth/src/scope.rs  (top of file)
//! Wildcard-or-allowlist authorization scopes over opaque names.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum names in one explicit scope, keeping linear lookup bounded.
pub const MAX_SCOPE_NAMES: usize = 256;

/// Rejection reason for a malformed scope.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    /// The scope failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// Wildcard or literal allowlist for device and tool names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSet {
    /// Permit every name known to the server.
    Wildcard,
    /// Permit only the exact listed names. May be empty, which permits nothing.
    Allowlist(Vec<String>),
}

impl ScopeSet {
    /// Whether an exact name is allowed.
    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        }
    }

    /// Whether a tool is allowed, with write tools excluded from the wildcard.
    ///
    /// A wildcard tool scope is a convenience for read-only automation; granting
    /// write authority must always be an explicit, named decision. The caller
    /// supplies its own write-tool registry so this crate stays vendor-neutral.
    #[must_use]
    pub fn allows_tool(&self, name: &str, write_tools: &[&str]) -> bool {
        match self {
            Self::Wildcard => !write_tools.contains(&name),
            Self::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        }
    }

    /// Whether this scope permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Allowlist(names) if names.is_empty())
    }

    /// Stable comma-separated representation for audit metadata.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Wildcard => "*".to_owned(),
            Self::Allowlist(names) => names.join(","),
        }
    }

    /// Validate count, duplicates, and wildcard spelling.
    pub fn validate(&self, field: &'static str) -> Result<(), ScopeError> {
        let Self::Allowlist(names) = self else {
            return Ok(());
        };
        if names.len() > MAX_SCOPE_NAMES {
            return Err(ScopeError::Invalid(format!(
                "{field} scope contains more than {MAX_SCOPE_NAMES} names"
            )));
        }
        let mut seen = BTreeSet::new();
        for name in names {
            if name == "*" {
                return Err(ScopeError::Invalid(format!(
                    "{field} scope may use '*' only as the sole list entry"
                )));
            }
            if name.is_empty() || name.len() > 128 || name.contains('\0') {
                return Err(ScopeError::Invalid(format!(
                    "{field} scope contains an out-of-range name"
                )));
            }
            if !seen.insert(name) {
                return Err(ScopeError::Invalid(format!(
                    "duplicate name '{name}' in {field} scope"
                )));
            }
        }
        Ok(())
    }
}

impl Serialize for ScopeSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let names: Vec<&str> = match self {
            Self::Wildcard => vec!["*"],
            Self::Allowlist(names) => names.iter().map(String::as_str).collect(),
        };
        names.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let names = Vec::<String>::deserialize(deserializer)?;
        if names.len() == 1 && names[0] == "*" {
            Ok(Self::Wildcard)
        } else {
            Ok(Self::Allowlist(names))
        }
    }
}
```

- [ ] **Step 4: Wire the module and run the tests**

```rust
// crates/mecmcp-auth/src/lib.rs  (append)
pub mod scope;

pub use scope::{MAX_SCOPE_NAMES, ScopeError, ScopeSet};
```

Run: `cargo test -p mecmcp-auth scope::`
Expected: PASS, 10 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-auth/src/scope.rs crates/mecmcp-auth/src/lib.rs
git commit -m "feat(auth): ScopeSet with bounded validation and write-tool exclusion"
```

---

### Task 4: The Grant trait — the vendor seam

**Files:**
- Create: `crates/mecmcp-auth/src/grant.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `trait Grant` with associated `Action`, methods `allows_action`, `allows_subject`, `validate`
  - `NoGrant` — the default for servers with no write-grant model
  - `GrantError::Invalid(String)`

`allows_subject` is deliberately named for an opaque string. `rustpanosmcp`
implements it over XPath roots; a future Junos grant implements it over
configuration paths. The crate never learns which.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mecmcp-auth/src/grant.rs  (append at the bottom)
#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in for a vendor grant: prefix-matched subjects, enumerated actions.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PrefixGrant {
        roots: Vec<String>,
        actions: Vec<TestAction>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestAction {
        Set,
        Delete,
    }

    impl Grant for PrefixGrant {
        type Action = TestAction;

        fn allows_action(&self, action: Self::Action) -> bool {
            self.actions.contains(&action)
        }

        fn allows_subject(&self, subject: &str) -> bool {
            self.roots.iter().any(|root| {
                subject == root
                    || subject
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
        }

        fn validate(&self) -> Result<(), GrantError> {
            if self.roots.is_empty() {
                return Err(GrantError::Invalid("grant needs at least one root".into()));
            }
            Ok(())
        }
    }

    fn grant() -> PrefixGrant {
        PrefixGrant {
            roots: vec!["/a/b".to_owned()],
            actions: vec![TestAction::Set],
        }
    }

    #[test]
    fn grant_permits_only_enumerated_actions() {
        assert!(grant().allows_action(TestAction::Set));
        assert!(!grant().allows_action(TestAction::Delete));
    }

    #[test]
    fn grant_permits_a_root_and_its_descendants() {
        assert!(grant().allows_subject("/a/b"));
        assert!(grant().allows_subject("/a/b/c"));
    }

    #[test]
    fn grant_rejects_a_sibling_that_merely_shares_a_prefix() {
        assert!(!grant().allows_subject("/a/bc"));
        assert!(!grant().allows_subject("/a"));
    }

    #[test]
    fn no_grant_permits_nothing() {
        assert!(!NoGrant.allows_subject("/a/b"));
        assert!(NoGrant.validate().is_ok());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mecmcp-auth grant::`
Expected: FAIL — `cannot find trait Grant in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
// crates/mecmcp-auth/src/grant.rs  (top of file)
//! The vendor seam: per-token write authority over opaque subjects.

use serde::{Deserialize, Serialize};

/// Rejection reason for a malformed grant.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// The grant failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// Per-token write authority.
///
/// A "subject" is an opaque, vendor-defined address of a configuration region —
/// an XPath subtree, a configuration path, a policy container. This crate never
/// interprets it; it only asks the implementing type whether a given subject and
/// action are permitted.
pub trait Grant: Clone + std::fmt::Debug + Send + Sync + 'static {
    /// The set of mutating actions this vendor distinguishes.
    type Action: Copy + Eq + std::fmt::Debug;

    /// Whether this grant permits an action.
    fn allows_action(&self, action: Self::Action) -> bool;

    /// Whether this grant permits mutating a subject.
    fn allows_subject(&self, subject: &str) -> bool;

    /// Structural validation, run at token-store load time.
    ///
    /// # Errors
    /// Returns [`GrantError::Invalid`] when the grant is malformed.
    fn validate(&self) -> Result<(), GrantError>;
}

/// The grant type for servers that do not yet model write authority.
///
/// Permits no action and no subject, so a token carrying it can never be
/// mistaken for one with write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoGrant;

/// The uninhabited action set of [`NoGrant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoAction {}

impl Grant for NoGrant {
    type Action = NoAction;

    fn allows_action(&self, _action: Self::Action) -> bool {
        false
    }

    fn allows_subject(&self, _subject: &str) -> bool {
        false
    }

    fn validate(&self) -> Result<(), GrantError> {
        Ok(())
    }
}
```

- [ ] **Step 4: Wire the module and run the tests**

```rust
// crates/mecmcp-auth/src/lib.rs  (append)
pub mod grant;

pub use grant::{Grant, GrantError, NoAction, NoGrant};
```

Run: `cargo test -p mecmcp-auth grant::`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-auth/src/grant.rs crates/mecmcp-auth/src/lib.rs
git commit -m "feat(auth): Grant trait as the vendor seam for write authority"
```

---

### Task 5: TokenEntry with backward-compatible serde

**Files:**
- Create: `crates/mecmcp-auth/src/entry.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs`

**Interfaces:**
- Consumes: `TokenDigest` (Task 2), `ScopeSet` (Task 3), `Grant`/`NoGrant` (Task 4).
- Produces:
  - `TokenEntry<G: Grant = NoGrant>` with fields `name: String`, `digest: TokenDigest`, `devices: ScopeSet`, `tools: ScopeSet`, `created_at: DateTime<Utc>`, `expires_at: Option<DateTime<Utc>>`, `grant: Option<G>`
  - `TokenEntry::is_expired_at(&self, now: DateTime<Utc>) -> bool`
  - `TokenEntry::validate(&self) -> Result<(), EntryError>`
  - `EntryError::{Scope { name, source }, Grant { name, source }, Invalid(String)}`

This is the compatibility-critical task. `rustjunosmcp` writes `hash`,
`routers`, and RFC 3339 `created_at`; `rustpanosmcp` writes `digest`, `devices`,
and `created_at_unix`. Both must load unchanged.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mecmcp-auth/src/entry.rs  (append at the bottom)
#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly the shape rustjunosmcp 0.9.1 writes today.
    const JUNOS_SHAPE: &str = r#"{
        "name": "lab",
        "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "routers": ["edge-fw", "core-fw"],
        "tools": ["*"],
        "created_at": "2026-07-12T10:00:00Z"
    }"#;

    /// Exactly the shape rustpanosmcp 0.2.2 writes today.
    const PANOS_SHAPE: &str = r#"{
        "name": "lab",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "devices": ["panosvm"],
        "tools": ["get_panos_config"],
        "created_at_unix": 1783850400
    }"#;

    #[test]
    fn loads_the_junos_on_disk_shape() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse junos shape");
        assert_eq!(entry.name, "lab");
        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["edge-fw".to_owned(), "core-fw".to_owned()])
        );
        assert_eq!(entry.tools, ScopeSet::Wildcard);
        assert!(entry.digest.verify("test"));
        assert!(entry.expires_at.is_none());
    }

    #[test]
    fn loads_the_panos_on_disk_shape() {
        let entry: TokenEntry = serde_json::from_str(PANOS_SHAPE).expect("parse panos shape");
        assert_eq!(entry.name, "lab");
        assert_eq!(entry.devices, ScopeSet::Allowlist(vec!["panosvm".to_owned()]));
        assert!(entry.digest.verify("test"));
    }

    #[test]
    fn both_shapes_produce_an_identical_entry() {
        let junos: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("junos");
        let panos: TokenEntry = serde_json::from_str(PANOS_SHAPE).expect("panos");
        assert_eq!(junos.created_at, panos.created_at);
        assert_eq!(junos.digest, panos.digest);
    }

    #[test]
    fn a_token_without_expiry_never_expires() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        let far_future = DateTime::from_timestamp(4_102_444_800, 0).expect("timestamp");
        assert!(!entry.is_expired_at(far_future));
    }

    #[test]
    fn a_token_past_its_expiry_is_expired() {
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "expires_at_unix": 1783936800
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        let before = DateTime::from_timestamp(1_783_900_000, 0).expect("timestamp");
        let after = DateTime::from_timestamp(1_784_100_000, 0).expect("timestamp");
        assert!(!entry.is_expired_at(before));
        assert!(entry.is_expired_at(after));
    }

    #[test]
    fn an_entry_with_an_invalid_scope_fails_validation() {
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["a", "a"],
            "tools": ["*"],
            "created_at_unix": 1783850400
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        assert!(entry.validate().is_err());
    }

    #[test]
    fn an_entry_with_an_out_of_range_name_fails_validation() {
        let raw = format!(
            r#"{{
                "name": "{}",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["*"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            }}"#,
            "x".repeat(200)
        );
        let entry: TokenEntry = serde_json::from_str(&raw).expect("parse");
        assert!(entry.validate().is_err());
    }

    #[test]
    fn serializing_writes_the_canonical_field_names() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"digest\""));
        assert!(json.contains("\"devices\""));
        assert!(!json.contains("\"hash\""));
        assert!(!json.contains("\"routers\""));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mecmcp-auth entry::`
Expected: FAIL — `cannot find type TokenEntry in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
// crates/mecmcp-auth/src/entry.rs  (top of file)
//! One token as persisted on disk, in a shape both existing servers can load.

use crate::grant::{Grant, GrantError, NoGrant};
use crate::scope::{ScopeError, ScopeSet};
use crate::token::TokenDigest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum length of an operator-facing token name.
pub const MAX_TOKEN_NAME: usize = 128;

/// Rejection reason for a malformed token entry.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// A scope failed validation.
    #[error("token '{name}': {source}")]
    Scope {
        /// The offending token's name.
        name: String,
        /// The underlying scope error.
        #[source]
        source: ScopeError,
    },
    /// A grant failed validation.
    #[error("token '{name}': {source}")]
    Grant {
        /// The offending token's name.
        name: String,
        /// The underlying grant error.
        #[source]
        source: GrantError,
    },
    /// The entry failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// One digest-only token entry.
///
/// Field names are canonical (`digest`, `devices`); the aliases accept the
/// spellings `rustjunosmcp` wrote before extraction so deployed `tokens.json`
/// files load unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry<G: Grant = NoGrant> {
    /// Operator-facing, non-secret token name. Used for audit attribution.
    pub name: String,

    /// Versioned token digest. Never plaintext.
    #[serde(alias = "hash")]
    pub digest: TokenDigest,

    /// Devices this token may address.
    #[serde(alias = "routers", default = "wildcard")]
    pub devices: ScopeSet,

    /// MCP tools this token may call.
    #[serde(default = "wildcard")]
    pub tools: ScopeSet,

    /// Creation or last-rotation time.
    ///
    /// Accepts RFC 3339 under `created_at` (the `rustjunosmcp` spelling) or a
    /// Unix timestamp under `created_at_unix` (the `rustpanosmcp` spelling).
    #[serde(alias = "created_at_unix", with = "timestamp")]
    pub created_at: DateTime<Utc>,

    /// Optional absolute expiry. An expired token never authenticates.
    #[serde(
        default,
        alias = "expires_at_unix",
        with = "optional_timestamp",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<DateTime<Utc>>,

    /// Optional vendor-specific write authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<G>,
}

fn wildcard() -> ScopeSet {
    ScopeSet::Wildcard
}

impl<G: Grant> TokenEntry<G> {
    /// Whether this token is expired at the given instant.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }

    /// Validate name, scopes, and grant.
    ///
    /// # Errors
    /// Returns [`EntryError`] describing the first failing check.
    pub fn validate(&self) -> Result<(), EntryError> {
        if self.name.is_empty() || self.name.len() > MAX_TOKEN_NAME {
            return Err(EntryError::Invalid(format!(
                "token name must be 1-{MAX_TOKEN_NAME} characters"
            )));
        }
        if self.name.contains('\0') || self.name.contains(char::is_whitespace) {
            return Err(EntryError::Invalid(format!(
                "token name '{}' contains whitespace or a null byte",
                self.name
            )));
        }
        self.devices
            .validate("devices")
            .map_err(|source| EntryError::Scope {
                name: self.name.clone(),
                source,
            })?;
        self.tools
            .validate("tools")
            .map_err(|source| EntryError::Scope {
                name: self.name.clone(),
                source,
            })?;
        if let Some(grant) = &self.grant {
            grant.validate().map_err(|source| EntryError::Grant {
                name: self.name.clone(),
                source,
            })?;
        }
        Ok(())
    }
}

/// Accept a timestamp as either RFC 3339 (`rustjunosmcp`) or Unix seconds
/// (`rustpanosmcp`); always write RFC 3339.
mod timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Either on-disk spelling of an instant.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Rfc3339(DateTime<Utc>),
        Unix(i64),
    }

    impl Raw {
        fn into_datetime<E: serde::de::Error>(self) -> Result<DateTime<Utc>, E> {
            match self {
                Self::Rfc3339(value) => Ok(value),
                Self::Unix(seconds) => DateTime::from_timestamp(seconds, 0)
                    .ok_or_else(|| E::custom(format!("timestamp {seconds} is out of range"))),
            }
        }
    }

    pub(super) fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_rfc3339())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        Raw::deserialize(deserializer)?.into_datetime()
    }

    /// The `Option` form, for fields that may be absent entirely.
    pub(super) mod optional {
        use super::Raw;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub(in super::super) fn serialize<S: Serializer>(
            value: &Option<DateTime<Utc>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_str(&value.to_rfc3339()),
                None => serializer.serialize_none(),
            }
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            match Option::<Raw>::deserialize(deserializer)? {
                Some(raw) => raw.into_datetime().map(Some),
                None => Ok(None),
            }
        }
    }
}

use timestamp::optional as optional_timestamp;
```

> **Implementer note:** `#[serde(with = "…")]` names a module, so the
> `optional_timestamp` alias above is what makes
> `with = "optional_timestamp"` on the `expires_at` field resolve. Do not
> replace the `with` attribute with `#[serde(flatten)]` on an `Option` — a
> flattened `Option` does not reliably deserialize to `None` when its keys are
> absent, which would make every token without an expiry fail to load.

- [ ] **Step 4: Wire the module and run the tests**

```rust
// crates/mecmcp-auth/src/lib.rs  (append)
pub mod entry;

pub use entry::{EntryError, MAX_TOKEN_NAME, TokenEntry};
```

Run: `cargo test -p mecmcp-auth entry::`
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-auth/src/entry.rs crates/mecmcp-auth/src/lib.rs
git commit -m "feat(auth): TokenEntry loading both servers' on-disk shapes"
```

---

### Task 6: TokenStore and CallerCtx

**Files:**
- Create: `crates/mecmcp-auth/src/store.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs`

**Interfaces:**
- Consumes: `TokenEntry<G>` (Task 5), `ScopeSet` (Task 3), `Grant` (Task 4).
- Produces:
  - `TokenStore<G>` with `try_new(Vec<TokenEntry<G>>) -> Result<Self, StoreError>`, `authenticate(&self, candidate: &str) -> Option<&TokenEntry<G>>`, `authenticate_at(&self, candidate: &str, now: DateTime<Utc>) -> Option<&TokenEntry<G>>`, `entries()`, `len()`, `is_empty()`
  - `CallerCtx<G>` with `token_name`, `devices`, `tools`, `grant`, and `From<&TokenEntry<G>>`
  - `filter_device_names(ctx: Option<&CallerCtx<G>>, names: Vec<String>) -> Vec<String>`
  - `StoreError::{Duplicate(String), TooMany(usize), Entry(EntryError)}`
  - `MAX_TOKENS: usize = 1024`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mecmcp-auth/src/store.rs  (append at the bottom)
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
        };
        (plaintext, entry)
    }

    #[test]
    fn authenticates_a_known_secret() {
        let (secret, entry) = entry_named("lab");
        let store = TokenStore::try_new(vec![entry]).expect("store");
        assert_eq!(store.authenticate(&secret).map(|e| e.name.as_str()), Some("lab"));
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
        let entries = (0..=MAX_TOKENS).map(|i| entry_named(&format!("t{i}")).1).collect();
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
        };
        let visible = filter_device_names(
            Some(&ctx),
            vec!["edge-fw".to_owned(), "core-fw".to_owned()],
        );
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
        };
        let visible = filter_device_names(Some(&ctx), vec!["edge-fw".to_owned()]);
        assert!(visible.is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mecmcp-auth store::`
Expected: FAIL — `cannot find type TokenStore in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
// crates/mecmcp-auth/src/store.rs  (top of file)
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
    pub fn authenticate_at(
        &self,
        candidate: &str,
        now: DateTime<Utc>,
    ) -> Option<&TokenEntry<G>> {
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
}

impl<G: Grant> From<&TokenEntry<G>> for CallerCtx<G> {
    fn from(entry: &TokenEntry<G>) -> Self {
        Self {
            token_name: entry.name.clone(),
            devices: entry.devices.clone(),
            tools: entry.tools.clone(),
            grant: entry.grant.clone(),
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
```

- [ ] **Step 4: Wire the module and run the tests**

```rust
// crates/mecmcp-auth/src/lib.rs  (append)
pub mod store;

pub use store::{CallerCtx, MAX_TOKENS, StoreError, TokenStore, filter_device_names};
```

Run: `cargo test -p mecmcp-auth store::`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-auth/src/store.rs crates/mecmcp-auth/src/lib.rs
git commit -m "feat(auth): TokenStore with expiry and CallerCtx device filtering"
```

---

### Task 7: TokenStoreFile — load, permissions, atomic write, reload

**Files:**
- Create: `crates/mecmcp-auth/src/file.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs`

**Interfaces:**
- Consumes: `TokenStore<G>` (Task 6), `TokenEntry<G>` (Task 5).
- Produces:
  - `TokenStoreFile<G>` with `load(path: &Path) -> Result<Self, FileError>`, `store(&self) -> Arc<TokenStore<G>>`, `reload(&self) -> Result<(), FileError>`, `path(&self) -> &Path`
  - `write_atomic(path: &Path, entries: &[TokenEntry<G>]) -> Result<(), FileError>`
  - `FileError::{Io, Parse, Store, Permissions, NotAFile}`

Carries `rustjunosmcp`'s operator diagnostics: on `EACCES`, report the file's
owner uid and mode alongside the calling process's uid.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mecmcp-auth/src/file.rs  (append at the bottom)
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TWO_TOKENS: &str = r#"{
        "tokens": [
            {
                "name": "reader",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["edge-fw"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            },
            {
                "name": "writer",
                "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "routers": ["*"],
                "tools": ["load_and_commit_config"],
                "created_at": "2026-07-12T10:00:00Z"
            }
        ]
    }"#;

    fn write_file(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("tokens.json");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        path
    }

    #[test]
    fn loads_a_file_mixing_both_on_disk_shapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 2);
    }

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.json");
        let err = TokenStoreFile::<NoGrant>::load(&path).expect_err("should fail");
        assert!(err.to_string().contains("absent.json"));
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "{ not json");
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Parse { .. })
        ));
    }

    #[test]
    fn duplicate_names_surface_as_a_store_error() {
        let body = TWO_TOKENS.replace("\"writer\"", "\"reader\"");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, &body);
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Store { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Permissions { .. })
        ));
    }

    #[test]
    fn reload_picks_up_a_changed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 2);

        let single = TWO_TOKENS
            .split_once("        {\n                \"name\": \"writer\"")
            .map(|(head, _)| format!("{}]\n}}", head.trim_end().trim_end_matches(',')))
            .expect("split");
        write_file(&dir, &single);

        file.reload().expect("reload");
        assert_eq!(file.store().len(), 1);
    }

    #[test]
    fn a_failed_reload_leaves_the_previous_store_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        write_file(&dir, "{ not json");
        assert!(file.reload().is_err());
        assert_eq!(file.store().len(), 2, "previous store must survive");
    }

    #[test]
    fn atomic_write_round_trips_through_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let file: TokenStoreFile = {
            let source = write_file(&dir, TWO_TOKENS);
            TokenStoreFile::load(&source).expect("load")
        };
        write_atomic(&path, file.store().entries()).expect("write");
        let reloaded: TokenStoreFile = TokenStoreFile::load(&path).expect("reload");
        assert_eq!(reloaded.store().len(), 2);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mecmcp-auth file::`
Expected: FAIL — `cannot find type TokenStoreFile in this scope`.

- [ ] **Step 3: Write the implementation**

```rust
// crates/mecmcp-auth/src/file.rs  (top of file)
//! Reading, validating, hot-reloading, and atomically writing `tokens.json`.

use crate::entry::TokenEntry;
use crate::grant::{Grant, NoGrant};
use crate::store::{StoreError, TokenStore};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Failure while reading or writing a token file.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// The file could not be read or written.
    #[error("token file {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid JSON in the expected shape.
    #[error("token file {path} is not valid JSON: {source}")]
    Parse {
        /// The path involved.
        path: PathBuf,
        /// The underlying deserialization error.
        #[source]
        source: serde_json::Error,
    },
    /// The parsed entries did not form a valid store.
    #[error("token file {path}: {source}")]
    Store {
        /// The path involved.
        path: PathBuf,
        /// The underlying store error.
        #[source]
        source: StoreError,
    },
    /// The file's permissions are too permissive, or unreadable by this process.
    #[error("token file {path}: {detail}")]
    Permissions {
        /// The path involved.
        path: PathBuf,
        /// Operator-facing explanation including uid and mode where known.
        detail: String,
    },
}

/// On-disk document shape. Both existing servers use a `tokens` array.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "G: Grant + Serialize",
    deserialize = "G: Grant + Deserialize<'de>"
))]
struct TokenDocument<G: Grant> {
    tokens: Vec<TokenEntry<G>>,
}

/// A token file plus the store parsed from it, swappable on reload.
#[derive(Debug)]
pub struct TokenStoreFile<G: Grant = NoGrant> {
    path: PathBuf,
    store: ArcSwap<TokenStore<G>>,
}

impl<G: Grant + serde::Serialize + serde::de::DeserializeOwned> TokenStoreFile<G> {
    /// Read, validate, and parse a token file.
    ///
    /// # Errors
    /// Returns [`FileError`] on I/O failure, malformed JSON, unsafe
    /// permissions, or an invalid store.
    pub fn load(path: &Path) -> Result<Self, FileError> {
        let store = Self::read_store(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            store: ArcSwap::from_pointee(store),
        })
    }

    /// The current store. Cheap to clone; safe to hold across a reload.
    #[must_use]
    pub fn store(&self) -> Arc<TokenStore<G>> {
        self.store.load_full()
    }

    /// The path this file was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the file and swap the store in on success.
    ///
    /// On failure the previous store stays in place, so a bad edit delivered by
    /// `SIGHUP` cannot take the server's authentication offline.
    ///
    /// # Errors
    /// Returns [`FileError`] if the new contents are unusable.
    pub fn reload(&self) -> Result<(), FileError> {
        let store = Self::read_store(&self.path)?;
        self.store.store(Arc::new(store));
        Ok(())
    }

    fn read_store(path: &Path) -> Result<TokenStore<G>, FileError> {
        check_permissions(path)?;
        let body = std::fs::read_to_string(path).map_err(|source| FileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let document: TokenDocument<G> =
            serde_json::from_str(&body).map_err(|source| FileError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        TokenStore::try_new(document.tokens).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Write entries to `path` atomically, via a same-directory temporary file.
///
/// # Errors
/// Returns [`FileError`] on serialization or I/O failure.
pub fn write_atomic<G: Grant + serde::Serialize>(
    path: &Path,
    entries: &[TokenEntry<G>],
) -> Result<(), FileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let document = TokenDocument {
        tokens: entries.to_vec(),
    };
    let body = serde_json::to_vec_pretty(&document).map_err(|source| FileError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let mut temp = tempfile::Builder::new()
        .prefix(".tokens-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|source| FileError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o600)).map_err(
            |source| FileError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    use std::io::Write as _;
    temp.write_all(&body).map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    temp.as_file().sync_all().map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    temp.persist(path).map_err(|error| FileError::Io {
        path: path.to_path_buf(),
        source: error.error,
    })?;
    Ok(())
}

/// Reject group- or world-accessible token files, with an operator-facing
/// explanation naming the file's owner and mode and the calling process's uid.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), FileError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(FileError::Permissions {
                path: path.to_path_buf(),
                detail: format!(
                    "permission denied reading metadata; this process runs as uid {}",
                    // SAFETY-free: getuid is infallible and takes no arguments.
                    nix_getuid()
                ),
            });
        }
        Err(source) => {
            return Err(FileError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    if !metadata.is_file() {
        return Err(FileError::Permissions {
            path: path.to_path_buf(),
            detail: "not a regular file".to_owned(),
        });
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(FileError::Permissions {
            path: path.to_path_buf(),
            detail: format!(
                "mode {mode:04o} is group- or world-accessible (owner uid {}, this process uid {}); \
                 run: chmod 600 {}",
                metadata.uid(),
                nix_getuid(),
                path.display()
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(path: &Path) -> Result<(), FileError> {
    if !path.is_file() {
        return Err(FileError::Permissions {
            path: path.to_path_buf(),
            detail: "not a regular file".to_owned(),
        });
    }
    Ok(())
}

/// The calling process's real uid.
///
/// `rustix` rather than `libc::getuid`, which is an `unsafe extern` call that
/// `unsafe_code = "forbid"` rejects.
#[cfg(unix)]
fn nix_getuid() -> u32 {
    rustix::process::getuid().as_raw()
}
```

- [ ] **Step 4: Wire the module and run the tests**

```rust
// crates/mecmcp-auth/src/lib.rs  (append)
pub mod file;

pub use file::{FileError, TokenStoreFile, write_atomic};
```

Run: `cargo test -p mecmcp-auth file::`
Expected: PASS, 8 tests (7 on non-unix).

- [ ] **Step 5: Verify the whole crate is clean**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo test -p mecmcp-auth`
Expected: PASS, no warnings, 37 tests.

- [ ] **Step 6: Commit**

```bash
git add crates/mecmcp-auth/src/file.rs crates/mecmcp-auth/src/lib.rs crates/mecmcp-auth/Cargo.toml Cargo.toml
git commit -m "feat(auth): token file load, permission checks, hot reload, atomic write"
```

---

### Task 8: Compatibility fixtures from the real deployments

**Files:**
- Create: `crates/mecmcp-auth/tests/compat.rs`
- Create: `crates/mecmcp-auth/tests/fixtures/junos-tokens.json`
- Create: `crates/mecmcp-auth/tests/fixtures/panos-tokens.json`

**Interfaces:**
- Consumes: `TokenStoreFile` (Task 7), `Grant` (Task 4).
- Produces: a regression gate proving neither deployment breaks. No new API.

**Before writing the fixtures:** capture the *shape* of the live files without
their digests. On LXC 609:

```bash
ssh root@pve3.mechub.org "pct exec 609 -- jq '.tokens[0] | keys' /etc/jmcp/tokens.json"
```

Reproduce every key that appears, with fabricated digests. **Never copy a real
digest into the repository** — digests are not plaintext but they are
authentication material, and this repo is a different trust boundary.

- [ ] **Step 1: Write the fixtures**

```json
// crates/mecmcp-auth/tests/fixtures/junos-tokens.json
{
  "tokens": [
    {
      "name": "claude-desktop",
      "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
      "routers": ["*"],
      "tools": ["*"],
      "created_at": "2026-07-12T10:00:00Z"
    },
    {
      "name": "readonly-observer",
      "hash": "sha256:LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
      "routers": ["edge-fw", "core-fw", "dc-fw"],
      "tools": ["get_junos_config", "execute_junos_command", "get_router_list"],
      "created_at": "2026-07-12T10:05:00Z"
    }
  ]
}
```

```json
// crates/mecmcp-auth/tests/fixtures/panos-tokens.json
{
  "tokens": [
    {
      "name": "panos-operator",
      "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
      "devices": ["panosvm"],
      "tools": ["get_panos_config", "list_devices", "stage_panos_config"],
      "created_at_unix": 1783850400,
      "mutation": {
        "allowed_xpath_roots": ["/config/devices/entry/vsys/entry/rulebase"],
        "actions": ["set", "delete"]
      }
    }
  ]
}
```

- [ ] **Step 2: Write the failing compatibility tests**

```rust
// crates/mecmcp-auth/tests/compat.rs
//! Regression gate: both deployed `tokens.json` shapes must keep loading.

use mecmcp_auth::{Grant, GrantError, ScopeSet, TokenStoreFile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The PAN-OS write grant, defined here exactly as `rustpanosmcp` defines it,
/// to prove a vendor grant round-trips through the generic entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MutationGrant {
    allowed_xpath_roots: Vec<String>,
    actions: Vec<MutationAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MutationAction {
    Set,
    Delete,
}

impl Grant for MutationGrant {
    type Action = MutationAction;

    fn allows_action(&self, action: Self::Action) -> bool {
        self.actions.contains(&action)
    }

    fn allows_subject(&self, subject: &str) -> bool {
        self.allowed_xpath_roots.iter().any(|root| {
            subject == root
                || subject
                    .strip_prefix(root.as_str())
                    .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('['))
        })
    }

    fn validate(&self) -> Result<(), GrantError> {
        if self.allowed_xpath_roots.is_empty() {
            return Err(GrantError::Invalid("grant needs at least one root".into()));
        }
        Ok(())
    }
}

/// Copy a fixture to a temp dir with 0600 so permission checks pass.
fn staged(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let target = dir.path().join("tokens.json");
    std::fs::copy(&source, &target).expect("copy fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
    }
    (dir, target)
}

#[test]
fn the_deployed_junos_token_file_still_loads() {
    let (_dir, path) = staged("junos-tokens.json");
    let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load junos tokens");
    let store = file.store();
    assert_eq!(store.len(), 2);

    let wildcard = store
        .entries()
        .iter()
        .find(|e| e.name == "claude-desktop")
        .expect("claude-desktop entry");
    assert_eq!(wildcard.devices, ScopeSet::Wildcard);

    let observer = store
        .entries()
        .iter()
        .find(|e| e.name == "readonly-observer")
        .expect("readonly-observer entry");
    assert!(observer.devices.allows("edge-fw"));
    assert!(!observer.devices.allows("br1-fw"));
}

#[test]
fn the_deployed_panos_token_file_still_loads_with_its_grant() {
    let (_dir, path) = staged("panos-tokens.json");
    let file: TokenStoreFile<MutationGrant> =
        TokenStoreFile::load(&path).expect("load panos tokens");
    let store = file.store();
    assert_eq!(store.len(), 1);

    let entry = &store.entries()[0];
    let grant = entry.grant.as_ref().expect("mutation grant present");
    assert!(grant.allows_action(MutationAction::Set));
    assert!(grant.allows_subject("/config/devices/entry/vsys/entry/rulebase/security"));
    assert!(!grant.allows_subject("/config/devices/entry/network"));
}

#[test]
fn a_junos_wildcard_tool_scope_still_excludes_write_tools() {
    const JUNOS_WRITE_TOOLS: &[&str] = &[
        "load_and_commit_config",
        "render_and_apply_j2_template",
        "rollback_config",
        "add_device",
    ];
    let (_dir, path) = staged("junos-tokens.json");
    let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
    let store = file.store();
    let wildcard = store
        .entries()
        .iter()
        .find(|e| e.name == "claude-desktop")
        .expect("entry");

    assert!(wildcard.tools.allows_tool("get_junos_config", JUNOS_WRITE_TOOLS));
    assert!(!wildcard.tools.allows_tool("load_and_commit_config", JUNOS_WRITE_TOOLS));
}
```

> **Behaviour-change note for the migration:** that last test encodes a
> *deliberate* tightening. `rustjunosmcp` today grants write tools to a `["*"]`
> tool scope; after migration it does not. Every deployed token that relies on a
> wildcard scope to call `load_and_commit_config` must be re-minted with an
> explicit tool list **before** Task 10 is deployed. Enumerate affected tokens
> with `rust-junosmcp token list` on LXC 609 and record them in the migration
> note required by Task 10, Step 4.

- [ ] **Step 3: Run the tests to verify they fail, then pass**

Run: `cargo test -p mecmcp-auth --test compat`
Expected: FAIL first if `mutation` is not aliased to the `grant` field — the
PAN-OS fixture spells it `mutation`. Fix by adding the alias in `entry.rs`:

```rust
    /// Optional vendor-specific write authority.
    #[serde(default, alias = "mutation", skip_serializing_if = "Option::is_none")]
    pub grant: Option<G>,
```

Re-run: `cargo test -p mecmcp-auth --test compat`
Expected: PASS, 3 tests.

- [ ] **Step 4: Commit**

```bash
git add crates/mecmcp-auth/tests crates/mecmcp-auth/src/entry.rs
git commit -m "test(auth): compatibility fixtures for both deployed token formats"
```

---

### Task 9: Migrate rustpanosmcp

**Files:**
- Modify: `~/Projects/rust-panosmcp/Cargo.toml` (workspace deps)
- Modify: `~/Projects/rust-panosmcp/rust-panosmcp-auth/Cargo.toml`
- Modify: `~/Projects/rust-panosmcp/rust-panosmcp-auth/src/lib.rs`
- Delete: `~/Projects/rust-panosmcp/rust-panosmcp-auth/src/{token,store,file}.rs`
- Keep: `~/Projects/rust-panosmcp/rust-panosmcp-auth/src/{bearer,secret}.rs`

**Interfaces:**
- Consumes: everything from Tasks 2–8.
- Produces: `rust-panosmcp-auth` as a thin vendor layer exporting `MutationGrant`, `MutationAction`, `KNOWN_TOOLS`, `MUTATION_TOOLS`, and re-exporting the shared types.

`rustpanosmcp` migrates first: it is the smaller consumer, its design is the one
the crate adopted, and its test suite is the shorter feedback loop.

- [ ] **Step 1: Point the crate at mecmcp-auth**

```toml
# ~/Projects/rust-panosmcp/Cargo.toml, in [workspace.dependencies]
mecmcp-auth = { git = "https://github.com/fastrevmd-lab/mecmcp", tag = "auth-v0.1.0" }
```

```toml
# ~/Projects/rust-panosmcp/rust-panosmcp-auth/Cargo.toml, in [dependencies]
mecmcp-auth = { workspace = true }
```

- [ ] **Step 2: Reduce the vendor auth crate to its vendor parts**

```rust
// ~/Projects/rust-panosmcp/rust-panosmcp-auth/src/lib.rs
//! PAN-OS authorization vocabulary over the shared mecmcp auth core.

pub mod bearer;
pub mod secret;
mod grant;

pub use bearer::{BearerHeaderError, parse_bearer_header};
pub use grant::{MutationAction, MutationGrant};
pub use secret::SecretString;

// Shared core, re-exported so downstream `use rust_panosmcp_auth::…` paths
// keep working unchanged.
pub use mecmcp_auth::{
    CallerCtx as CallerContext, FileError as TokenStoreFileError, Grant, ScopeSet, StoreError,
    TokenDigest, TokenEntry as SharedTokenEntry, TokenError, TokenSecret, TokenStore as SharedStore,
    TokenStoreFile as SharedFile,
};

/// PAN-OS token entry: the shared entry specialised to the PAN-OS grant.
pub type TokenEntry = SharedTokenEntry<MutationGrant>;
/// PAN-OS token store.
pub type TokenStore = SharedStore<MutationGrant>;
/// PAN-OS token file.
pub type TokenStoreFile = SharedFile<MutationGrant>;

/// Exact tool registry used to validate token scopes.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_panos_change_set",
    "approve_panos_change_set",
    "commit_panos_candidate",
    "create_panos_change_set",
    "diff_panos_candidate",
    "discard_panos_candidate",
    "execute_panos_op",
    "gather_device_facts",
    "get_candidate_fingerprint",
    "get_panos_change_set",
    "get_panos_config",
    "get_panos_operation",
    "list_devices",
    "stage_panos_config",
    "validate_panos_candidate",
];

/// Tools that always require an explicit token allowlist entry.
pub const MUTATION_TOOLS: &[&str] = &[
    "commit_panos_candidate",
    "apply_panos_change_set",
    "approve_panos_change_set",
    "create_panos_change_set",
    "diff_panos_candidate",
    "discard_panos_candidate",
    "get_candidate_fingerprint",
    "get_panos_change_set",
    "get_panos_operation",
    "stage_panos_config",
    "validate_panos_candidate",
];
```

Move the `MutationGrant`/`MutationAction` definitions out of the old `store.rs`
into a new `grant.rs`, implementing `mecmcp_auth::Grant` for `MutationGrant`
with the body already written in Task 8's `compat.rs`, plus the full
`validate()` from the original `rust-panosmcp-auth/src/store.rs:42-76`
(bounds on `MAX_MUTATION_ROOTS`, absolute `/config/` roots, duplicate detection).

- [ ] **Step 3: Fix the call sites**

`ScopeSet::allows_tool` now takes the write-tool registry as an argument. Update
every caller — principally `rust-panosmcp/src/http_transport.rs` in
`tool_call_exceeds_scope`:

```rust
// before
if !caller.tools.allows_tool(tool_name) {

// after
if !caller.tools.allows_tool(tool_name, rust_panosmcp_auth::MUTATION_TOOLS) {
```

Run: `cargo build --workspace` in `~/Projects/rust-panosmcp` and fix each
compile error until clean. Expect errors only at `allows_tool` call sites and at
`TokenEntry` field accesses, where the `created_at_unix: u64` field becomes
`created_at: DateTime<Utc>` (use `.timestamp()` where a `u64` is still wanted).

- [ ] **Step 4: Run the existing test suite unmodified**

Run: `cargo test --workspace` in `~/Projects/rust-panosmcp`
Expected: PASS. Any failure is a behaviour change and must be understood before
proceeding — do not edit a test to make it pass without recording why.

- [ ] **Step 5: Verify against the real config**

Run: `cargo run -p rust-panosmcp -- validate-config --tokens <path to a copy of the deployed tokens.json>`
Expected: reports the same token count and scopes as before the migration.

- [ ] **Step 6: Commit in both repos**

```bash
cd ~/Projects/mecmcp && git tag auth-v0.1.0 && git push --tags
cd ~/Projects/rust-panosmcp && git add -A
git commit -m "refactor(auth): consume mecmcp-auth for tokens, scopes, and store"
```

---

### Task 10: Migrate rustjunosmcp and remove the last `unsafe`

**Files:**
- Modify: `~/Projects/RustJunosMCP/Cargo.toml`
- Modify: `~/Projects/RustJunosMCP/rust-junosmcp-auth/Cargo.toml`
- Modify: `~/Projects/RustJunosMCP/rust-junosmcp-auth/src/lib.rs`
- Delete: `~/Projects/RustJunosMCP/rust-junosmcp-auth/src/{token,store,file,caller}.rs`
- Keep: `~/Projects/RustJunosMCP/rust-junosmcp-auth/src/tower.rs`
- Create: `~/Projects/mecmcp/docs/migrations/2026-XX-XX-auth-token-scope-tightening.md`

**Interfaces:**
- Consumes: everything from Tasks 2–8.
- Produces: `rust-junosmcp-auth` as a thin vendor layer; `unsafe` eliminated from the repo; token expiry available on Junos for the first time.

- [ ] **Step 1: Point the crate at mecmcp-auth and reduce it**

```toml
# ~/Projects/RustJunosMCP/Cargo.toml, in [workspace.dependencies]
mecmcp-auth = { git = "https://github.com/fastrevmd-lab/mecmcp", tag = "auth-v0.1.0" }
```

```rust
// ~/Projects/RustJunosMCP/rust-junosmcp-auth/src/lib.rs
//! Junos authorization vocabulary over the shared mecmcp auth core.
//!
//! Pure data plus HTTP glue; no async device work.

pub mod tower;

pub use mecmcp_auth::{
    CallerCtx, FileError as TokenStoreError, NoGrant, ScopeSet, StoreError, TokenDigest,
    TokenEntry as SharedTokenEntry, TokenError, TokenSecret, TokenStore as SharedStore,
    TokenStoreFile as SharedFile, filter_device_names,
};

/// Junos token entry. Write authority is not yet modelled per token.
pub type TokenEntry = SharedTokenEntry<NoGrant>;
/// Junos token store.
pub type TokenStore = SharedStore<NoGrant>;
/// Junos token file.
pub type TokenStoreFile = SharedFile<NoGrant>;

/// Tools that always require an explicit token allowlist entry.
///
/// A wildcard tool scope no longer grants these; see the migration note at
/// `docs/migrations/` in the mecmcp repository.
pub const WRITE_TOOLS: &[&str] = &[
    "add_device",
    "load_and_commit_config",
    "render_and_apply_j2_template",
    "rollback_config",
    "transfer_file",
    "upgrade_junos",
    "manage_idp_security_package",
    "manage_appid_signature_package",
    "discard_candidate",
    "reload_devices",
];

/// Backwards-compatible alias. `filter_router_names` was the pre-extraction
/// name; the shared crate calls devices devices.
pub use mecmcp_auth::filter_device_names as filter_router_names;
```

- [ ] **Step 2: Fix the call sites**

Three categories of compile error, all mechanical:

1. `entry.hash` → `entry.digest`
2. `entry.routers` → `entry.devices`; `ctx.routers` → `ctx.devices`
3. `scope.allows_tool(name)` → `scope.allows_tool(name, WRITE_TOOLS)` — this is
   a *new* call site in `rust-junosmcp/src/server.rs`; before extraction
   `rustjunosmcp` did not distinguish write tools in wildcard scopes at all.
4. `entry.created_at` stays a `DateTime<Utc>` and needs no change in
   `token_cmd.rs`'s list output — `rustjunosmcp` already stored it that way.

Run: `cargo build --workspace` in `~/Projects/RustJunosMCP`, fix until clean.

- [ ] **Step 3: Prove the `unsafe` is gone**

```bash
cd ~/Projects/RustJunosMCP
grep -rn "unsafe" --include='*.rs' rust-junosmcp-auth/ ; echo "exit=$?"
```

Expected: no matches (`exit=1`).

Then add `unsafe_code = "forbid"` to the `rustjunosmcp` workspace lints (the
Phase 0 lint that was documented as failing) and rebuild:

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. This is the concrete deliverable that Phase 0 deferred.

- [ ] **Step 4: Write the migration note**

```markdown
<!-- ~/Projects/mecmcp/docs/migrations/2026-XX-XX-auth-token-scope-tightening.md -->
# Migration — wildcard tool scopes no longer grant write tools

**Affects:** rustjunosmcp, from the release that adopts mecmcp-auth.

Before this change a token with `"tools": ["*"]` could call every tool,
including `load_and_commit_config`. After it, a wildcard tool scope grants only
non-write tools; write tools must be named explicitly.

## Affected tokens

Enumerate before upgrading:

```bash
ssh root@pve3.mechub.org "pct exec 609 -- rust-junosmcp token list"
```

Any token with a `*` tool scope that is used for configuration change must be
re-minted with an explicit list, for example:

```bash
pct exec 609 -- sudo -u jmcp rust-junosmcp token rotate <name> \
  --tools get_junos_config,load_and_commit_config,commit_check_config
```

## Rollback

The previous release remains installed; revert per the LXC rollback procedure in
the rustjunosmcp packaging docs. `tokens.json` is unchanged by this migration and
is readable by both releases.
```

Fill in the actual date and the real affected token names from the `token list`
output at execution time.

- [ ] **Step 5: Run the existing test suite unmodified**

Run: `cargo test --workspace --all-features` in `~/Projects/RustJunosMCP`
Expected: PASS, except tests that assert a wildcard tool scope permits a write
tool. Those assert the *old* behaviour and should be updated to assert the new
behaviour, with the change noted in the commit message.

- [ ] **Step 6: Verify against the deployed config, then deploy**

```bash
# non-destructive: validate a copy of the live file
scp root@pve3.mechub.org:/tmp/tokens-copy.json /tmp/
cargo run -p rust-junosmcp -- validate-config --tokens /tmp/tokens-copy.json
```

Expected: same token count and scopes as `rust-junosmcp token list` on LXC 609.

Then deploy per the standard procedure and confirm the systemd override is
intact:

```bash
ssh root@pve3.mechub.org "pct exec 609 -- systemctl cat rust-junosmcp.service | grep -A5 'override.conf'"
ssh root@pve3.mechub.org "pct exec 609 -- systemctl status rust-junosmcp.service"
```

Expected: `0.0.0.0:30031`, `--allow-insecure-bind`, `--allowed-host 192.168.1.194`,
service active. Then confirm end to end with an MCP call against a lab device.

- [ ] **Step 7: Commit**

```bash
cd ~/Projects/mecmcp && git add docs/migrations && git commit -m "docs: migration note for wildcard tool-scope tightening"
cd ~/Projects/RustJunosMCP && git add -A
git commit -m "refactor(auth): consume mecmcp-auth; forbid unsafe; gain token expiry"
```

---

## Phase exit criteria

Phase 1 is done when all of the following hold:

- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean in all three repos.
- [ ] `unsafe_code = "forbid"` active in all three workspaces, with no `unsafe` in `rustjunosmcp`.
- [ ] Both servers authenticate against their **existing, unmodified** production `tokens.json`.
- [ ] `crates/mecmcp-auth/tests/compat.rs` passes, covering both on-disk shapes and the PAN-OS grant.
- [ ] `rustjunosmcp` has token expiry, scope bounds, and name validation it did not have before.
- [ ] `grep -rniE 'xpath|junos|panos' crates/mecmcp-auth/src/` returns matches only in doc comments and serde aliases.
- [ ] `mecmcp` tagged `auth-v0.1.0`; both consumers pin that tag.
- [ ] LXC 609 running the migrated `rustjunosmcp` with its systemd override intact, verified against a lab vSRX.
- [ ] Migration note published for the wildcard tool-scope tightening, with affected tokens re-minted.
