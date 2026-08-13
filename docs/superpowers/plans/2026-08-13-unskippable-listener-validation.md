# Unskippable Listener Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it impossible for a consumer of `mecmcp-transport` to serve an unauthenticated or unpoliced listener off loopback, by moving the decision from a validation function nobody is required to call into the type system and the one function every consumer must call to obtain a listener.

**Architecture:** Authentication becomes a constructor choice on `HttpTransportConfig`, so "forgot auth" and "chose no auth" stop being the same value. `build_streamable_http_router` returns a `ServePlan` carrying the listener facts, and `serve_router` — the only path to a bound socket — evaluates the address-dependent refusals before it binds.

**Tech Stack:** Rust 2024 edition, MSRV 1.88, axum 0.8, axum-server 0.8, rmcp 3.x, tokio, thiserror, trybuild (new dev-dependency).

**Spec:** `docs/superpowers/specs/2026-08-13-unskippable-listener-validation-design.md`

## Global Constraints

- **Target release: 0.9.0.** This is a breaking change set. All workspace crates bump together; intra-workspace path dependencies pin the exact version.
- **MSRV stays 1.88; edition stays 2024.** CI enforces both.
- **`cargo clippy --workspace --all-targets` must be clean.** The workspace denies `unwrap_used`; test code included. Use `.expect("reason")` in tests.
- **Loopback is exempt from every refusal.** A listener on `127.0.0.1` or `::1` is bounded by the host; requiring flags there would break every local and stdio deployment for no gain.
- **`--allow-no-auth` never permits an off-loopback bind.** The acknowledgement legitimises loopback only.
- **No escape hatch on `ServePlan`.** No `into_router`, no `into_parts`, no `#[doc(hidden)]` accessor that yields the `Router`. If the router can leave the plan, the fix degrades to "documented, not impossible", which is the exact defect being fixed.
- **`ListenerPolicy` is private (`pub(crate)`) in 0.9.0.** It can be made public later without a break; it cannot be closed later.
- **Sabotage before done.** For each refusal, delete the check and confirm the matching test fails. A test that has never failed proves nothing.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/mecmcp-transport/src/consent.rs` (create) | The two acknowledgement types. Nothing else — they are the vocabulary of operator intent and must not accumulate transport logic. |
| `crates/mecmcp-transport/src/listener.rs` (create) | `ListenerPolicy`, `ListenerRefusal`, and the pure `check_listener` function. Separated from `server.rs` so the refusal logic is testable without constructing a router. |
| `crates/mecmcp-transport/src/server.rs` (modify) | `HttpTransportConfig` constructors, `ServePlan`, `build_streamable_http_router` return type, `serve_router` signature and its pre-bind check. |
| `crates/mecmcp-transport/src/lib.rs` (modify) | Exports. |
| `crates/mecmcp-runtime/src/cli_validate.rs` (modify) | Collapse `validate` / `validate_with_origin_policy`; demote to a courtesy pre-check in the docs. |
| `crates/mecmcp-transport/tests/listener_refusal.rs` (create) | Refusal and loopback carve-out tests against the real `serve_router`. |
| `crates/mecmcp-transport/tests/compile_fail.rs` + `tests/ui/*.rs` (create) | trybuild guard that the removed constructors stay removed. |
| `crates/mecmcp-transport/tests/router_integration.rs` (modify) | Migrate off direct `axum_server` serving onto `serve_router`. |
| `README.md`, `docs/PACKAGING.md` (modify) | 0.9.0 upgrade notes and the pre-upgrade fleet step. |

---

### Task 1: Acknowledgement types

**Files:**
- Create: `crates/mecmcp-transport/src/consent.rs`
- Modify: `crates/mecmcp-transport/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `NoAuthAcknowledgement::operator_allowed_no_auth() -> NoAuthAcknowledgement`, `InsecureBindAcknowledgement::operator_allowed_insecure_bind() -> InsecureBindAcknowledgement`. Both are `Copy`, and neither can be constructed any other way (private unit field).

- [ ] **Step 1: Write the failing test**

Create `crates/mecmcp-transport/src/consent.rs` with the test module only:

```rust
//! Operator intent, carried as types the transport cannot infer.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgements_are_constructible_only_by_their_named_constructor() {
        let no_auth = NoAuthAcknowledgement::operator_allowed_no_auth();
        let insecure = InsecureBindAcknowledgement::operator_allowed_insecure_bind();
        // Copy semantics: passing one to a config must not move it away from a caller
        // that wants to log it too.
        let _copy = no_auth;
        let _copy2 = insecure;
        assert_eq!(format!("{no_auth:?}"), "NoAuthAcknowledgement");
        assert_eq!(format!("{insecure:?}"), "InsecureBindAcknowledgement");
    }
}
```

Add `mod consent;` to `crates/mecmcp-transport/src/lib.rs`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mecmcp-transport --lib consent`
Expected: FAIL to compile — `cannot find type NoAuthAcknowledgement in this scope`.

- [ ] **Step 3: Write minimal implementation**

Prepend to `crates/mecmcp-transport/src/consent.rs`:

```rust
/// The operator explicitly chose to serve without authentication.
///
/// Required by [`HttpTransportConfig::unauthenticated`]. The transport cannot
/// infer this: an absent bearer boundary means either a deliberate
/// `--allow-no-auth` or a consumer that forgot, and those were the same value
/// until mecmcp#273 gave them different types.
///
/// **This acknowledgement is loopback-only.** It does not permit an
/// off-loopback bind; `serve_router` refuses that regardless
/// ([`ListenerRefusal::UnauthenticatedOffLoopback`]).
#[derive(Clone, Copy)]
pub struct NoAuthAcknowledgement(());

impl std::fmt::Debug for NoAuthAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoAuthAcknowledgement")
    }
}

impl NoAuthAcknowledgement {
    /// Record that the operator passed `--allow-no-auth`.
    ///
    /// Call this only from a code path that actually read that flag. Calling it
    /// unconditionally reintroduces the defect this type exists to prevent.
    #[must_use]
    pub fn operator_allowed_no_auth() -> Self {
        Self(())
    }
}

/// The operator explicitly accepted a plaintext off-loopback listener.
///
/// Absence is fail-closed: without this, `serve_router` refuses to bind an
/// off-loopback address that has no TLS.
#[derive(Clone, Copy)]
pub struct InsecureBindAcknowledgement(());

impl std::fmt::Debug for InsecureBindAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InsecureBindAcknowledgement")
    }
}

impl InsecureBindAcknowledgement {
    /// Record that the operator passed `--allow-insecure-bind`.
    #[must_use]
    pub fn operator_allowed_insecure_bind() -> Self {
        Self(())
    }
}
```

Export from `crates/mecmcp-transport/src/lib.rs`:

```rust
pub use consent::{InsecureBindAcknowledgement, NoAuthAcknowledgement};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mecmcp-transport --lib consent`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-transport/src/consent.rs crates/mecmcp-transport/src/lib.rs
git commit -m "feat(transport): add operator acknowledgement types (#273)"
```

---

### Task 2: `ListenerPolicy` and the refusal check

**Files:**
- Create: `crates/mecmcp-transport/src/listener.rs`
- Modify: `crates/mecmcp-transport/src/lib.rs`

**Interfaces:**
- Consumes: `InsecureBindAcknowledgement` (Task 1), `HostOriginPolicy` (existing, `server.rs:37`).
- Produces: `pub enum ListenerRefusal` with variants `UnauthenticatedOffLoopback { address }`, `InsecureBindNotAcknowledged { address }`, `AllowedHostRequired { address }`, `AllowedOriginRequired { address }`; `pub(crate) struct ListenerPolicy { authenticated: bool, host_origin: HostOriginPolicy, insecure_bind: Option<InsecureBindAcknowledgement> }`; `pub(crate) fn check_listener(policy: &ListenerPolicy, address: SocketAddr, tls_configured: bool) -> Result<(), ListenerRefusal>`.

- [ ] **Step 1: Write the failing test**

Create `crates/mecmcp-transport/src/listener.rs` with the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::HostOriginPolicy;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("address")
    }

    fn policy(authenticated: bool, hosts: &[&str], origins: &[&str]) -> ListenerPolicy {
        ListenerPolicy {
            authenticated,
            host_origin: HostOriginPolicy::enforced(hosts.to_vec(), origins.to_vec()),
            insecure_bind: None,
        }
    }

    #[test]
    fn unauthenticated_off_loopback_is_refused() {
        let result = check_listener(&policy(false, &["h"], &["o"]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::UnauthenticatedOffLoopback {
                address: addr("192.168.1.5:30031")
            })
        );
    }

    #[test]
    fn unauthenticated_loopback_is_allowed() {
        check_listener(&policy(false, &[], &[]), addr("127.0.0.1:30030"), false)
            .expect("loopback must stay exempt");
        check_listener(&policy(false, &[], &[]), addr("[::1]:30030"), false)
            .expect("ipv6 loopback must stay exempt");
    }

    #[test]
    fn plaintext_off_loopback_needs_acknowledgement() {
        let result = check_listener(&policy(true, &["h"], &["o"]), addr("192.168.1.5:30031"), false);
        assert_eq!(
            result,
            Err(ListenerRefusal::InsecureBindNotAcknowledged {
                address: addr("192.168.1.5:30031")
            })
        );

        let mut acked = policy(true, &["h"], &["o"]);
        acked.insecure_bind = Some(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        check_listener(&acked, addr("192.168.1.5:30031"), false)
            .expect("acknowledged plaintext bind must be allowed");
    }

    #[test]
    fn off_loopback_requires_host_then_origin_allowlists() {
        let result = check_listener(&policy(true, &[], &["o"]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::AllowedHostRequired {
                address: addr("192.168.1.5:30031")
            })
        );

        let result = check_listener(&policy(true, &["h"], &[]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::AllowedOriginRequired {
                address: addr("192.168.1.5:30031")
            })
        );
    }

    #[test]
    fn whitespace_only_allowlist_entries_do_not_count() {
        let result = check_listener(&policy(true, &["   "], &["o"]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::AllowedHostRequired {
                address: addr("192.168.1.5:30031")
            })
        );
    }

    #[test]
    fn authentication_is_refused_before_transport_concerns() {
        // No auth, no TLS, no allowlists: the caller must be told about the
        // most severe problem, not the first one a reordering happens to hit.
        let result = check_listener(&policy(false, &[], &[]), addr("192.168.1.5:30031"), false);
        assert_eq!(
            result,
            Err(ListenerRefusal::UnauthenticatedOffLoopback {
                address: addr("192.168.1.5:30031")
            })
        );
    }
}
```

Add `mod listener;` to `crates/mecmcp-transport/src/lib.rs`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mecmcp-transport --lib listener`
Expected: FAIL to compile — `cannot find function check_listener in this scope`.

- [ ] **Step 3: Write minimal implementation**

Prepend to `crates/mecmcp-transport/src/listener.rs`:

```rust
//! Listener admission: the refusals that need the bind address.
//!
//! These checks live here rather than in `mecmcp_runtime::cli_validate` because
//! the address is not known until `serve_router` is called, and because a check
//! a consumer may decline to invoke is not a control (mecmcp#273).

use crate::consent::InsecureBindAcknowledgement;
use crate::server::HostOriginPolicy;
use std::net::SocketAddr;

/// A listener configuration the transport refuses to bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListenerRefusal {
    /// No bearer boundary was attached and the address is not loopback.
    #[error(
        "refusing to serve {address} without authentication: --allow-no-auth is loopback-only"
    )]
    UnauthenticatedOffLoopback {
        /// The address that would have been bound.
        address: SocketAddr,
    },
    /// Off-loopback plaintext listener with no acknowledgement.
    #[error(
        "refusing to bind {address} without TLS: pass --allow-insecure-bind to accept a \
         plaintext off-loopback listener"
    )]
    InsecureBindNotAcknowledged {
        /// The address that would have been bound.
        address: SocketAddr,
    },
    /// Off-loopback listener with no usable Host allowlist entry.
    #[error("refusing to bind {address}: an off-loopback listener requires --allowed-host")]
    AllowedHostRequired {
        /// The address that would have been bound.
        address: SocketAddr,
    },
    /// Off-loopback listener with no usable Origin allowlist entry.
    #[error("refusing to bind {address}: an off-loopback listener requires --allowed-origin")]
    AllowedOriginRequired {
        /// The address that would have been bound.
        address: SocketAddr,
    },
}

/// What the transport knows about a listener before its address is chosen.
#[derive(Debug, Clone)]
pub(crate) struct ListenerPolicy {
    /// Whether a bearer boundary was attached.
    pub(crate) authenticated: bool,
    /// Host and Origin allowlists.
    pub(crate) host_origin: HostOriginPolicy,
    /// Operator acceptance of a plaintext off-loopback listener.
    pub(crate) insecure_bind: Option<InsecureBindAcknowledgement>,
}

/// An allowlist entry that is only whitespace configures nothing.
fn has_usable_entry(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

/// Decide whether this listener may be bound.
///
/// Ordered most-severe first: a caller with several problems is told about the
/// authentication one, because fixing a lesser refusal first would leave them
/// iterating toward an outcome that is still refused.
pub(crate) fn check_listener(
    policy: &ListenerPolicy,
    address: SocketAddr,
    tls_configured: bool,
) -> Result<(), ListenerRefusal> {
    // Loopback is bounded by the host. Requiring flags here would break every
    // local deployment for no gain — the same carve-out cli_validate made.
    if address.ip().is_loopback() {
        return Ok(());
    }

    if !policy.authenticated {
        return Err(ListenerRefusal::UnauthenticatedOffLoopback { address });
    }

    if !tls_configured && policy.insecure_bind.is_none() {
        return Err(ListenerRefusal::InsecureBindNotAcknowledged { address });
    }

    let HostOriginPolicy::Enforced {
        allowed_hosts,
        allowed_origins,
    } = &policy.host_origin;

    if !has_usable_entry(allowed_hosts) {
        return Err(ListenerRefusal::AllowedHostRequired { address });
    }
    if !has_usable_entry(allowed_origins) {
        return Err(ListenerRefusal::AllowedOriginRequired { address });
    }

    Ok(())
}
```

Export the public error from `crates/mecmcp-transport/src/lib.rs`:

```rust
pub use listener::ListenerRefusal;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mecmcp-transport --lib listener`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-transport/src/listener.rs crates/mecmcp-transport/src/lib.rs
git commit -m "feat(transport): add listener admission checks (#273)"
```

---

### Task 3: Constructor split on `HttpTransportConfig`

**Files:**
- Modify: `crates/mecmcp-transport/src/server.rs:131-240`

**Interfaces:**
- Consumes: `NoAuthAcknowledgement`, `InsecureBindAcknowledgement` (Task 1).
- Produces: `HttpTransportConfig::authenticated(identity, limits, host_origin, shutdown, bearer) -> Self`, `HttpTransportConfig::unauthenticated(identity, limits, host_origin, shutdown, ack) -> Self`, `HttpTransportConfig::with_insecure_bind(self, ack) -> Self`, unchanged `with_metrics`. `new` and `with_bearer` are **removed**.

- [ ] **Step 1: Write the failing test**

Add to the existing `mod tests` in `crates/mecmcp-transport/src/server.rs`:

```rust
#[test]
fn authenticated_and_unauthenticated_configs_record_their_posture() {
    use crate::consent::{InsecureBindAcknowledgement, NoAuthAcknowledgement};
    use mecmcp_auth::{BearerSyntax, NoGrant};

    let identity = || TransportIdentity::new("testmcp", "test", "test", ["device"]);
    let policy = || HostOriginPolicy::enforced(vec!["h".to_owned()], vec!["o".to_owned()]);

    let authenticator =
        crate::BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_| None);
    let boundary =
        crate::BearerBoundary::new(authenticator, crate::BearerResponseProfile::detailed("t"));

    let authed = HttpTransportConfig::authenticated(
        identity(),
        LimitsConfig::default(),
        policy(),
        CancellationToken::new(),
        boundary,
    );
    assert!(authed.bearer.is_some(), "authenticated config must carry the boundary");
    assert!(authed.insecure_bind.is_none(), "insecure bind must default to unacknowledged");

    let open = HttpTransportConfig::<NoGrant>::unauthenticated(
        identity(),
        LimitsConfig::default(),
        policy(),
        CancellationToken::new(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    )
    .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
    assert!(open.bearer.is_none());
    assert!(open.insecure_bind.is_some());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mecmcp-transport --lib authenticated_and_unauthenticated`
Expected: FAIL to compile — `no function or associated item named authenticated found`.

- [ ] **Step 3: Write minimal implementation**

In `crates/mecmcp-transport/src/server.rs`, add the field to the struct (after `bearer`):

```rust
    insecure_bind: Option<crate::consent::InsecureBindAcknowledgement>,
```

Replace `pub fn new` (line 163) and `pub fn with_bearer` (line 211) entirely with:

```rust
    /// Construct transport settings for an authenticated listener.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::{BearerSyntax, NoGrant};
    /// use mecmcp_transport::{
    ///     BearerAuthenticator, BearerBoundary, BearerResponseProfile,
    ///     HttpTransportConfig, HostOriginPolicy, LimitsConfig, TransportIdentity,
    /// };
    /// use tokio_util::sync::CancellationToken;
    ///
    /// let authenticator =
    ///     BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_candidate| None);
    /// let boundary =
    ///     BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"));
    /// let config = HttpTransportConfig::authenticated(
    ///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
    ///     LimitsConfig::default(),
    ///     HostOriginPolicy::enforced(["host"], ["https://origin"]),
    ///     CancellationToken::new(),
    ///     boundary,
    /// );
    /// ```
    #[must_use]
    pub fn authenticated(
        identity: TransportIdentity,
        limits: LimitsConfig,
        host_origin: HostOriginPolicy,
        shutdown: CancellationToken,
        bearer: BearerBoundary<G>,
    ) -> Self {
        Self {
            identity,
            limits,
            host_origin,
            bearer: Some(bearer),
            enable_metrics: false,
            shutdown,
            insecure_bind: None,
        }
    }

    /// Construct transport settings for a listener that serves without
    /// authentication.
    ///
    /// Requires a [`NoAuthAcknowledgement`], which exists so that "the operator
    /// chose this" and "the consumer forgot" are different values. Before
    /// mecmcp#273 they were the same one, and a consumer could serve the LAN
    /// unauthenticated without any code path recording a decision.
    ///
    /// The acknowledgement does **not** permit an off-loopback bind:
    /// `serve_router` refuses that with
    /// [`ListenerRefusal::UnauthenticatedOffLoopback`].
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::NoGrant;
    /// use mecmcp_transport::{
    ///     HttpTransportConfig, HostOriginPolicy, LimitsConfig, NoAuthAcknowledgement,
    ///     TransportIdentity,
    /// };
    /// use tokio_util::sync::CancellationToken;
    ///
    /// let config = HttpTransportConfig::<NoGrant>::unauthenticated(
    ///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
    ///     LimitsConfig::default(),
    ///     HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
    ///     CancellationToken::new(),
    ///     NoAuthAcknowledgement::operator_allowed_no_auth(),
    /// );
    /// ```
    #[must_use]
    pub fn unauthenticated(
        identity: TransportIdentity,
        limits: LimitsConfig,
        host_origin: HostOriginPolicy,
        shutdown: CancellationToken,
        _acknowledgement: crate::consent::NoAuthAcknowledgement,
    ) -> Self {
        Self {
            identity,
            limits,
            host_origin,
            bearer: None,
            enable_metrics: false,
            shutdown,
            insecure_bind: None,
        }
    }

    /// Accept a plaintext listener on a non-loopback address.
    ///
    /// Without this, `serve_router` refuses to bind an off-loopback address
    /// that has no TLS. Absence is the safe default, so this is a builder step
    /// rather than a constructor parameter.
    #[must_use]
    pub fn with_insecure_bind(
        mut self,
        acknowledgement: crate::consent::InsecureBindAcknowledgement,
    ) -> Self {
        self.insecure_bind = Some(acknowledgement);
        self
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mecmcp-transport --lib authenticated_and_unauthenticated`
Expected: PASS. Other tests in the crate will not compile yet — Task 5 migrates them.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-transport/src/server.rs
git commit -m "feat(transport)!: make authentication a constructor choice (#273)"
```

---

### Task 4: `ServePlan` and the pre-bind refusal

**Files:**
- Modify: `crates/mecmcp-transport/src/server.rs:363-467` (builder), `:657-695` (error), `:762-790` (serve)
- Modify: `crates/mecmcp-transport/src/lib.rs`

**Interfaces:**
- Consumes: `ListenerPolicy`, `check_listener`, `ListenerRefusal` (Task 2); `HttpTransportConfig` fields (Task 3).
- Produces: `pub struct ServePlan` with `pub fn shutdown(&self) -> &HttpShutdown`; `build_streamable_http_router(...) -> Result<ServePlan, HttpTransportBuildError>`; `serve_router(plan: ServePlan, address: SocketAddr, tls: Option<Arc<rustls::ServerConfig>>, shutdown_timeout: Duration) -> Result<(), HttpServeError>`; `HttpServeError::Refused(ListenerRefusal)`.

- [ ] **Step 1: Write the failing test**

Create `crates/mecmcp-transport/tests/listener_refusal.rs`:

```rust
//! `serve_router` refuses an inadmissible listener, and refuses it *before*
//! binding (mecmcp#273).
//!
//! The ordering matters as much as the refusal. These tests use 192.0.2.1
//! (TEST-NET-1, RFC 5737), an address the host cannot bind: if the check ran
//! after the bind, the error would be `HttpServeError::Bind`. Asserting
//! `Refused` therefore proves the check runs first, without needing to inspect
//! socket state.

use mecmcp_auth::{BearerSyntax, NoGrant};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpServeError, HttpTransportConfig, LimitsConfig, ListenerRefusal, NoAuthAcknowledgement,
    TransportIdentity, build_streamable_http_router, serve_router,
};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct TestServer;

impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("test-server", "0.1"))
    }
}

fn unbindable() -> SocketAddr {
    "192.0.2.1:30031".parse().expect("address")
}

fn boundary() -> BearerBoundary<NoGrant> {
    let authenticator = BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_| None);
    BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"))
}

fn identity() -> TransportIdentity {
    TransportIdentity::new("testmcp", "test", "test", ["device"])
}

async fn serve_with(config: HttpTransportConfig<NoGrant>, address: SocketAddr) -> HttpServeError {
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
        .expect("router build failed");
    serve_router(plan, address, None, Duration::from_secs(1))
        .await
        .expect_err("this listener must be refused")
}

#[tokio::test]
async fn unauthenticated_off_loopback_is_refused_before_binding() {
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(["host"], ["https://origin"]),
        CancellationToken::new(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );

    match serve_with(config, unbindable()).await {
        HttpServeError::Refused(ListenerRefusal::UnauthenticatedOffLoopback { address }) => {
            assert_eq!(address, unbindable());
        }
        other => panic!("expected a refusal before the bind, got {other:?}"),
    }
}

#[tokio::test]
async fn plaintext_off_loopback_is_refused_before_binding() {
    let config = HttpTransportConfig::authenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(["host"], ["https://origin"]),
        CancellationToken::new(),
        boundary(),
    );

    match serve_with(config, unbindable()).await {
        HttpServeError::Refused(ListenerRefusal::InsecureBindNotAcknowledged { address }) => {
            assert_eq!(address, unbindable());
        }
        other => panic!("expected a refusal before the bind, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_allowlists_are_refused_before_binding() {
    use mecmcp_transport::InsecureBindAcknowledgement;

    let config = HttpTransportConfig::authenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        CancellationToken::new(),
        boundary(),
    )
    .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());

    match serve_with(config, unbindable()).await {
        HttpServeError::Refused(ListenerRefusal::AllowedHostRequired { .. }) => {}
        other => panic!("expected AllowedHostRequired, got {other:?}"),
    }
}

/// The loopback carve-out must survive, or every local deployment breaks.
///
/// Serves for real on an ephemeral loopback port with no auth, no TLS and no
/// allowlists, then shuts down. Reaching the shutdown proves the listener was
/// admitted and bound.
#[tokio::test]
async fn loopback_serves_without_auth_tls_or_allowlists() {
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
        .expect("router build failed");

    let serving = tokio::spawn(serve_router(
        plan,
        "127.0.0.1:0".parse().expect("address"),
        None,
        Duration::from_millis(50),
    ));

    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown.cancel();

    serving
        .await
        .expect("serve task panicked")
        .expect("loopback listener must be admitted and serve");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mecmcp-transport --test listener_refusal`
Expected: FAIL to compile — `ServePlan` not found / `serve_router` takes 5 arguments.

- [ ] **Step 3: Write minimal implementation**

In `crates/mecmcp-transport/src/server.rs`:

(a) Add the plan type near `HttpShutdown`:

```rust
/// Everything needed to serve, including the facts `serve_router` must check.
///
/// There is deliberately no accessor that yields the `Router`. If the router
/// could leave the plan, a consumer could serve it directly and skip the
/// listener admission checks — which is the defect mecmcp#273 exists to close.
/// Customise the router through [`HttpTransportConfig`] before building.
pub struct ServePlan {
    router: Router,
    shutdown: HttpShutdown,
    policy: crate::listener::ListenerPolicy,
}

impl ServePlan {
    /// The shutdown pair, for wiring SIGTERM.
    #[must_use]
    pub fn shutdown(&self) -> &HttpShutdown {
        &self.shutdown
    }
}
```

(b) Change the `build_streamable_http_router` return type to
`Result<ServePlan, HttpTransportBuildError>` and replace its final `Ok((...))`
(line 461) with:

```rust
    Ok(ServePlan {
        router,
        shutdown: HttpShutdown {
            listener: config.shutdown,
            sessions,
        },
        policy: crate::listener::ListenerPolicy {
            authenticated: bearer_was_attached,
            host_origin: config.host_origin,
            insecure_bind: config.insecure_bind,
        },
    })
```

Immediately before the `if let Some(bearer) = config.bearer` block that applies
the boundary (near line 420), capture the fact:

```rust
    let bearer_was_attached = config.bearer.is_some();
```

(c) Add the error variant to `HttpServeError` (line 657):

```rust
    /// The listener configuration was refused before binding.
    #[error(transparent)]
    Refused(#[from] crate::listener::ListenerRefusal),
```

(d) Rewrite the `serve_router` signature and insert the check as its first
statement, **before** the existing `TcpListener::bind`:

```rust
pub async fn serve_router(
    plan: ServePlan,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown_timeout: std::time::Duration,
) -> Result<(), HttpServeError> {
    // Before the socket exists. A refusal must cost nothing and leak nothing,
    // so it happens ahead of the bind (mecmcp#273).
    crate::listener::check_listener(&plan.policy, address, tls.is_some())?;

    let ServePlan {
        router, shutdown, ..
    } = plan;
```

Leave the rest of the body unchanged — it already refers to `router`,
`shutdown` and `tls`.

(e) Export from `crates/mecmcp-transport/src/lib.rs`, adding `ServePlan` to the
existing `pub use server::{...}` list.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mecmcp-transport --test listener_refusal`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-transport/src/server.rs crates/mecmcp-transport/src/lib.rs \
        crates/mecmcp-transport/tests/listener_refusal.rs
git commit -m "feat(transport)!: refuse inadmissible listeners in serve_router (#273)"
```

---

### Task 5: Migrate in-repo call sites

**Files:**
- Modify: `crates/mecmcp-transport/tests/router_integration.rs`
- Modify: any remaining `HttpTransportConfig::new` / `with_bearer` call sites surfaced by the compiler

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces: a green `cargo build --workspace --all-targets`.

- [ ] **Step 1: Find every broken call site**

Run: `cargo build --workspace --all-targets 2>&1 | grep -E "^error" -A 3`
Expected: errors at each `HttpTransportConfig::new`, `with_bearer`, and each
`build_streamable_http_router` destructuring `(router, shutdown)`.

- [ ] **Step 2: Migrate `router_integration.rs` onto `serve_router`**

This file currently serves the router through `axum_server` directly, which the
absent escape hatch forbids. Replace the spawn block in
`router_assembly_mounts_session_management` with:

```rust
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let port = listener.local_addr().expect("no local addr").port();
    drop(listener);

    let shutdown = CancellationToken::new();
    let serving = tokio::spawn(serve_router(
        plan,
        format!("127.0.0.1:{port}").parse().expect("address"),
        None,
        std::time::Duration::from_millis(50),
    ));

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
```

and end the test by cancelling `shutdown` and awaiting `serving`. Build the
config with `HttpTransportConfig::<NoGrant>::unauthenticated(..., NoAuthAcknowledgement::operator_allowed_no_auth())`,
passing `shutdown.clone()` as the config's cancellation token.

- [ ] **Step 3: Run the full suite**

Run: `cargo test --workspace`
Expected: PASS, no failures.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace --all-targets`
Expected: no warnings.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(transport): migrate call sites to ServePlan and serve_router (#273)"
```

---

### Task 6: Compile-fail guard

**Files:**
- Create: `crates/mecmcp-transport/tests/compile_fail.rs`
- Create: `crates/mecmcp-transport/tests/ui/unauthenticated_without_acknowledgement.rs`
- Create: `crates/mecmcp-transport/tests/ui/unauthenticated_without_acknowledgement.stderr`
- Modify: `crates/mecmcp-transport/Cargo.toml`

**Interfaces:**
- Consumes: Task 3's constructors.
- Produces: a test that fails if the removed constructors are reintroduced.

**Why this exists:** Tasks 1–4 make the unauthenticated path require an
acknowledgement. Nothing in a normal test can observe that a *removed* API
stays removed — a future refactor could re-add `HttpTransportConfig::new` and
every other test would still pass. This is the only test that guards §1.

- [ ] **Step 1: Add the dev-dependency**

In `crates/mecmcp-transport/Cargo.toml` under `[dev-dependencies]`:

```toml
# Test-only: guards that the pre-0.9.0 constructors, which allowed an
# unauthenticated config with no recorded decision, stay removed (mecmcp#273).
trybuild = "1"
```

- [ ] **Step 2: Write the failing test**

`crates/mecmcp-transport/tests/compile_fail.rs`:

```rust
//! The removed constructors must stay removed (mecmcp#273).

#[test]
fn unauthenticated_config_requires_an_acknowledgement() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/unauthenticated_without_acknowledgement.rs");
}
```

`crates/mecmcp-transport/tests/ui/unauthenticated_without_acknowledgement.rs`:

```rust
use mecmcp_auth::NoGrant;
use mecmcp_transport::{
    HostOriginPolicy, HttpTransportConfig, LimitsConfig, TransportIdentity,
};
use tokio_util::sync::CancellationToken;

fn main() {
    // Pre-0.9.0 this compiled and produced an unauthenticated listener with
    // nothing recording that anyone chose it.
    let _config = HttpTransportConfig::<NoGrant>::new(
        TransportIdentity::new("testmcp", "test", "test", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        CancellationToken::new(),
    );
}
```

- [ ] **Step 3: Generate the expected stderr**

Run: `TRYBUILD=overwrite cargo test -p mecmcp-transport --test compile_fail`

This writes `unauthenticated_without_acknowledgement.stderr`. **Read it** and
confirm it names `new` as not found — if it reports an unrelated error (a bad
import, say), the test would pass for the wrong reason and guard nothing.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p mecmcp-transport --test compile_fail`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-transport/Cargo.toml crates/mecmcp-transport/tests/compile_fail.rs \
        crates/mecmcp-transport/tests/ui/
git commit -m "test(transport): guard that the pre-0.9.0 constructors stay removed (#273)"
```

---

### Task 7: Collapse and demote `cli_validate`

**Files:**
- Modify: `crates/mecmcp-runtime/src/cli_validate.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks (separate crate, no new edge).
- Produces: a single `validate(cli: &Cli) -> Result<(), CliRefusal>` that always
  requires an Origin allowlist off-loopback. `validate_with_origin_policy` is
  **removed**.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/mecmcp-runtime/src/cli_validate.rs`:

```rust
#[test]
fn validate_requires_an_origin_allowlist_off_loopback() {
    let cli = Cli::try_parse_from([
        "test",
        "--transport",
        "streamable-http",
        "--host",
        "192.168.1.5",
        "--tokens-file",
        "/tmp/tokens.json",
        "--allow-insecure-bind",
        "--allowed-host",
        "192.168.1.5",
    ])
    .expect("parse");

    assert!(
        matches!(validate(&cli), Err(CliRefusal::AllowedOriginRequired { .. })),
        "since 0.7.0 the shared transport applies Origin policy for every \
         consumer, so the weaker check is itself the defect class in mecmcp#273"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mecmcp-runtime validate_requires_an_origin`
Expected: FAIL — `validate` returns `Ok(())`.

- [ ] **Step 3: Fold the Origin check into `validate`**

Move the body of `validate_with_origin_policy`'s Origin check into `validate`,
immediately after the `AllowedHostRequired` check, and delete
`validate_with_origin_policy`. Replace the module docs' description of the split
with:

```rust
//! # This is a courtesy pre-check, not the control
//!
//! Since mecmcp#273 the listener admission checks live in
//! `mecmcp_transport::serve_router`, which every consumer must call to obtain a
//! socket. Calling `validate` first is still worth doing — it fails a bad CLI
//! before anything is constructed, and its messages name the flags rather than
//! the transport concepts — but skipping it now costs a startup refusal instead
//! of an open port. Do not reintroduce the assumption that calling this is what
//! makes a deployment safe.
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p mecmcp-runtime`
Expected: PASS. Existing tests that asserted `validate` accepts an
off-loopback listener with no Origin allowlist must be updated to expect the
refusal — that behaviour change is the point.

- [ ] **Step 5: Commit**

```bash
git add crates/mecmcp-runtime/src/cli_validate.rs
git commit -m "refactor(runtime)!: collapse cli_validate and demote it to a pre-check (#273)"
```

---

### Task 8: Sabotage verification

**Files:** none modified permanently.

**Interfaces:**
- Consumes: Tasks 2, 4, 6.
- Produces: evidence that each test fails when its check is removed.

**Why:** mecmcp#269 found an existing test asserting the defect as the contract,
passing since #32. A test that has never failed proves nothing.

- [ ] **Step 1: Sabotage each refusal in turn**

For each of the four early-returns in `check_listener`, comment it out, run
`cargo test -p mecmcp-transport --test listener_refusal`, and record which
tests fail. Restore before the next one.

Expected, one variant at a time:

| Removed check | Must fail |
|---|---|
| `UnauthenticatedOffLoopback` | `unauthenticated_off_loopback_is_refused_before_binding` |
| `InsecureBindNotAcknowledged` | `plaintext_off_loopback_is_refused_before_binding` |
| `AllowedHostRequired` | `missing_allowlists_are_refused_before_binding` |
| the loopback early-return | `loopback_serves_without_auth_tls_or_allowlists` |

- [ ] **Step 2: Sabotage the ordering**

Move `check_listener` to *after* the `TcpListener::bind` call in `serve_router`.
Run the refusal tests.

Expected: the three refusal tests fail with `HttpServeError::Bind` instead of
`Refused`, proving they observe the ordering and not merely the outcome.
Restore.

- [ ] **Step 3: Record the results**

If any row above does not fail, that test does not guard what it claims. Fix the
test before proceeding — do not weaken the table.

- [ ] **Step 4: Confirm the tree is restored**

Run: `git diff --stat`
Expected: empty.

Run: `cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: green, clean.

- [ ] **Step 5: Commit (documentation only)**

```bash
git commit --allow-empty -m "test(transport): sabotage-verify the listener refusals (#273)

Each refusal was removed in turn and the matching test confirmed failing;
moving the check after the bind fails all three refusal tests with Bind
instead of Refused, proving they observe the ordering."
```

---

### Task 9: Release documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/PACKAGING.md`

**Interfaces:**
- Consumes: the final public API from Tasks 1–7.
- Produces: 0.9.0 upgrade notes.

- [ ] **Step 1: Write the 0.9.0 section**

Add above the 0.8.3 entry in `README.md`'s Status section. It must state:

- the defect: `cli_validate` had no call site anywhere in the repo, and a
  consumer could serve unauthenticated on the LAN with nothing failing
- the fix in one line per element: constructor split, `ServePlan`, pre-bind
  refusal in `serve_router`
- **Breaking**, with the exact migration:
  `HttpTransportConfig::new(..).with_bearer(b)` → `HttpTransportConfig::authenticated(.., b)`;
  `HttpTransportConfig::new(..)` → `HttpTransportConfig::unauthenticated(.., NoAuthAcknowledgement::operator_allowed_no_auth())`;
  `let (router, shutdown) = build_streamable_http_router(..)?` → `let plan = ..?` and `serve_router(plan, addr, tls, timeout)`
- that `--allow-no-auth` remains loopback-only
- the operational step below

- [ ] **Step 2: Write the pre-upgrade fleet step**

In `docs/PACKAGING.md`, record that requiring `--allowed-origin` off-loopback is
a behaviour change, and that the fleet survey of 2026-08-13 found exactly one
affected deployment:

> **LXC 950 (`rust-junosmcp`) binds `0.0.0.0` with `--allowed-host` and no
> `--allowed-origin`, and will be refused at startup on 0.9.0.** Add
> `--allowed-origin` to its drop-in override *before* installing the 0.9.0
> binary. 950 is tagged `protected`: snapshot first. LXC 960 and 601 already
> pass an Origin allowlist; 952, 604, 600 and 606 bind loopback and are exempt.

- [ ] **Step 3: Verify every claim against the source**

Re-read each statement and confirm it against the code as merged. The #274 work
in this repo took three review rounds precisely because upgrade notes drifted
from the assembly they described.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/PACKAGING.md
git commit -m "docs: 0.9.0 upgrade notes for unskippable listener validation (#273)"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §1 Authentication as a constructor choice | 1, 3 |
| §2 `ServePlan`, no escape hatch | 4 |
| §3 Refusal surface (4 variants) | 2, 4 |
| §4 `cli_validate` demoted and collapsed | 7 |
| Consequences: consumers edit `main.rs` | 9 (documented; the consumer repos are out of this repo's scope) |
| Consequences: LXC 950 pre-upgrade step | 9 |
| Consequences: `router_integration.rs` migration | 5 |
| Testing 1 (refusal, no socket opened) | 4, via the TEST-NET-1 ordering proof |
| Testing 2 (loopback carve-out) | 2, 4 |
| Testing 3 (compile-fail) | 6 |
| Testing 4 (sabotage) | 8 |
| Open question: `ListenerPolicy` private | 2 (`pub(crate)`) |

No spec requirement is unassigned.

**Placeholder scan:** none — every code step carries the actual code. Task 9's
steps specify required content rather than prose to copy, because the wording
must match the API as merged; the required elements are enumerated.

**Type consistency:** `ListenerPolicy` fields (`authenticated`, `host_origin`,
`insecure_bind`) are used identically in Tasks 2 and 4. `check_listener`'s third
parameter is `tls_configured: bool` in both its definition (Task 2) and its call
site (Task 4, passing `tls.is_some()`). `ServePlan::shutdown()` returns
`&HttpShutdown`, matching the existing `HttpShutdown` at `server.rs:697`.

**One risk carried forward:** Task 4 step (b) assumes `config.bearer` is read
before it is moved into `apply_bearer_boundary`. If the implementer finds the
move happens earlier, capture `bearer_was_attached` at the top of the function
instead — the fact must be recorded before the field is consumed.
