# Unskippable listener validation

**Issue:** mecmcp#273 · **Date:** 2026-08-13 · **Target release:** 0.9.0 (breaking)

## Problem

`mecmcp_runtime::cli_validate::validate` refuses exactly the two configurations
that matter — Streamable HTTP with neither `--tokens-file` nor `--allow-no-auth`
(`cli_validate.rs:94`), and `--allow-no-auth` on a non-loopback bind
(`cli_validate.rs:97`). Both checks are correct. **Neither runs unless the
consumer remembers to call `validate`, and nothing in the crate makes that call
necessary.**

`cli_validate` has exactly one reference anywhere in this repository:
`crates/mecmcp-runtime/src/lib.rs:10`, the `pub mod` declaration. There is no
call site.

`rustproxmoxmcp` 0.1 was built against v0.8.8 and did not call it. It compiled,
passed its full test suite, and would have served

```
rust-proxmoxmcp --transport streamable-http --host 0.0.0.0
```

with no authentication and no Host allowlist — the deployment shape every server
in this family ships in, a Debian LXC on the LAN. Nothing about the omission was
visible from the consumer's tests, because there is nothing to fail.

This is the third instance of one defect class in this repository:

- **0.8.1** made audit unskippable — "a tool is audited because it went through
  the transport, not because someone remembered."
- **0.8.3** found `client_name` propagation that was correct and unreachable,
  because `build_streamable_http_router` never called `with_session_tracker`.
- **#273** is a correct guard a consumer can silently decline to invoke.

### The gap is real in a shipped consumer

A survey of the five consumers on this foundation found four calling `validate`
(`rustjunosmcp`, `rustpanosmcp`, `rustsdcmcp`, `rustproxmoxmcp` — the last after
review caught it) and one that does not: **`rustmistmcp`**. It has a hand-rolled
`validate_runtime_serve` (`http_transport.rs:33`) that checks only the
Host/Origin allowlist rule, and a `load_http_token_store` (`main.rs:161`) whose
`_ => Ok(None)` arm silently yields no token store when neither
`--tokens-file` nor `--allow-no-auth` is given.

The exposure is **latent, not live**: LXC 952 and 604 both bind `127.0.0.1:30030`
with a tokens file and no drop-in override, verified 2026-08-13. It is worth
fixing because `rustjunosmcp` already carries exactly the kind of drop-in
override (`0.0.0.0:30031`) that would trip it.

## Constraints discovered

Three facts about the codebase rule out the fix the issue proposed first
("`build_streamable_http_router` calls `validate` itself").

1. **The router builder never sees the bind address.**
   `HttpTransportConfig` carries identity, limits, Host/Origin policy, an
   optional bearer boundary, a metrics flag and a shutdown token. No host, no
   port. The address arrives later, at
   `serve_router(router, address, tls, shutdown, timeout)`. Both refusals that
   matter are address-dependent.

2. **`mecmcp-runtime` and `mecmcp-transport` are siblings.** `Cli` and
   `cli_validate` live in `mecmcp-runtime`, which depends only on `mecmcp-auth`.
   `mecmcp-transport` depends on `mecmcp-audit` and `mecmcp-auth`. Neither
   depends on the other, so calling `cli_validate` from the transport requires a
   new dependency edge.

3. **`mecmcp-runtime` has no serve helper.** It is CLI parsing, validation, TLS
   bootstrap, shutdown, signals and token subcommands. The consumer's own
   `main.rs` glues runtime to transport, so runtime offers no chokepoint.

The only path every consumer must take to obtain a listener is
`mecmcp_transport::serve_router`.

## Approach

Enforce at the chokepoint, and split each check to where its facts already live.

### The real problem is consent, not validation

The transport can observe four of the five relevant facts by itself:

| Fact | Where it is known |
|---|---|
| Was a bearer boundary attached? | `HttpTransportConfig.bearer` |
| Host/Origin policy | `HttpTransportConfig.host_origin` |
| Bind address | `serve_router`'s `address` parameter |
| Is TLS configured? | `serve_router`'s `tls` parameter |

It cannot observe two operator *intents*: whether serving without authentication
was chosen, and whether an insecure off-loopback bind was accepted.

Today the absence of a bearer boundary is ambiguous — it means either "a
deliberate `--allow-no-auth` on loopback" or "the consumer forgot." Those are the
same value, which is why forgetting is invisible. **The fix is to give them
different types and default to refusing.**

### §1 Authentication becomes a constructor choice

`HttpTransportConfig::new` currently builds an *unauthenticated* config, with
`.with_bearer(boundary)` as an optional builder step. An unauthenticated
LAN-facing server is therefore one `new()` call away, with nothing in the type
recording that anyone chose it.

Replace with two constructors:

```rust
HttpTransportConfig::authenticated(identity, limits, policy, shutdown, bearer)
HttpTransportConfig::unauthenticated(identity, limits, policy, shutdown, ack)
```

`ack: NoAuthAcknowledgement` is an opaque struct with one constructor,
`NoAuthAcknowledgement::operator_allowed_no_auth()`, documented as loopback-only
and refused off-loopback at serve time. `with_bearer` is removed.

A consumer that forgot authentication can no longer construct a config at all.
This converts `CliRefusal::AuthRequired` from a check someone must remember into
a compile error.

### §2 `ServePlan` carries the facts to the chokepoint

`build_streamable_http_router` returns a `ServePlan` instead of
`(Router, HttpShutdown)`:

```rust
pub struct ServePlan {
    router: Router,
    shutdown: HttpShutdown,
    listener_policy: ListenerPolicy,
}
```

`ListenerPolicy` records the authentication posture (authenticated, or
unauthenticated-with-acknowledgement), the Host/Origin policy, and the
insecure-bind acknowledgement.

`serve_router` becomes:

```rust
pub async fn serve_router(
    plan: ServePlan,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown_timeout: Duration,
) -> Result<(), HttpServeError>
```

The `shutdown` parameter disappears — it travels inside the plan. This makes
0.7.2's stated requirement ("the two tokens must stay paired") true by
construction rather than by documentation.

**There is deliberately no escape hatch.** No `into_router()`, no
`into_parts()`. If the router can leave the plan, the hole reopens and the fix
degrades to "documented, not impossible," which is the exact failure mode #273
is about. A consumer with a legitimate need to customise the router does so
through `HttpTransportConfig` before the plan is built.

### §3 Refusal surface

All evaluated inside `serve_router`, where the address exists, and returned as
`HttpServeError::Refused(ListenerRefusal)`:

| Refusal | Condition |
|---|---|
| `UnauthenticatedOffLoopback` | no bearer boundary, and `address` is not loopback |
| `InsecureBindNotAcknowledged` | not loopback, no TLS, no insecure-bind acknowledgement |
| `AllowedHostRequired` | not loopback, Host allowlist has no usable entry |
| `AllowedOriginRequired` | not loopback, Origin allowlist has no usable entry |

`UnauthenticatedOffLoopback` fires regardless of the acknowledgement:
`--allow-no-auth` is loopback-only by policy, so acknowledging it does not buy an
off-loopback bind.

Loopback is exempt from the Host, Origin and TLS rules, preserving the existing
carve-out in `cli_validate` — a listener on `127.0.0.1` is already bounded by the
host, and requiring the flags there would break every local deployment for no
gain.

### §4 `cli_validate` is demoted, not deleted

It remains as an early courtesy check so a malformed CLI fails before anything is
constructed, and it keeps `TlsPairIncomplete`, which has no transport equivalent
(`serve_router` receives an already-resolved `Option<ServerConfig>`, by which
point a half-configured pair cannot be represented).

It stops being load-bearing. Skipping it now costs a startup refusal instead of
an open port. Its module documentation must say exactly that, so the next reader
does not reintroduce the assumption that calling it is what makes a deployment
safe.

**`validate` and `validate_with_origin_policy` collapse into one function.** The
split existed because a consumer whose transport ignored Origin should not be
refused over a value that changed nothing. Since 0.7.0 the shared transport
applies Origin policy for every consumer, so the weaker `validate` is now itself
an instance of this defect class: a check that exists, is the one everybody
calls, and is not the one that matches the transport. All five consumers call the
weaker one today.

The requirement ships as a refusal in 0.9.0 rather than a staged warning. This
estate has a single operator and exactly one affected host, so a deprecation
window would buy nothing and would leave a fail-open default in place for a
release.

## Consequences

- **All five consumers edit `main.rs`.** This is the 0.9.0 break. It can travel
  with mecmcp#269's `CallerCtx` change in the same release.
- **One deployed host must gain an Origin allowlist before 0.9.0 starts.**
  Requiring `--allowed-origin` off-loopback is a behaviour change: an empty
  Origin allowlist is currently valid and disables Origin checking by design.
  Fleet survey, 2026-08-13:

  | LXC | Service | Bind | `allowed-host` | `allowed-origin` | Under 0.9.0 |
  |---|---|---|---|---|---|
  | **950** | rust-junosmcp | `0.0.0.0` | yes | **no** | **refused to start** |
  | 960 | rust-panosmcp | `0.0.0.0` | yes | yes | starts |
  | 601 | rust-panosmcp | `0.0.0.0` | yes | yes | starts |
  | 952 | rustmistmcp | `127.0.0.1` | — | — | exempt (loopback) |
  | 604 | rustmistmcp | `127.0.0.1` | — | — | exempt (loopback) |
  | 600 | rust-junosmcp | `127.0.0.1` | — | — | exempt (loopback) |
  | 606 | rustsdcmcp | `127.0.0.1` | — | — | exempt (loopback) |

  **Pre-upgrade step:** add `--allowed-origin` to LXC 950's drop-in override
  before the 0.9.0 binary is installed. 950 is tagged `protected`; snapshot
  first, per the standing rollback rule for that host. No other deployed host is
  affected.
- **`rustmistmcp`'s latent gap closes without touching that repository.** It
  cannot construct an unauthenticated config without the acknowledgement, and
  cannot bind off-loopback with one.
- **`router_integration.rs` must move onto `serve_router`.** It currently serves
  the router through `axum_server` directly, which the removal of the escape
  hatch forbids. This is an improvement: that harness will then exercise the
  assembly the way a consumer does.

## Testing

The governing lesson is 0.8.3's: a unit test proves a mechanism works *when
wired* and observes nothing about the wiring. Tests that build the guarded type
by hand cannot see this defect class.

1. **Refusal tests, one per `ListenerRefusal` variant**, driving the real
   `serve_router` against a bound ephemeral port and asserting both the refusal
   and that **no socket was opened**. Asserting the error alone would pass on an
   implementation that binds first and refuses second.
2. **Loopback carve-out tests** — the same four configurations on `127.0.0.1`
   must serve, or the fix breaks every local deployment.
3. **A compile-fail test** (`trybuild`) proving `HttpTransportConfig` cannot be
   built without either a bearer boundary or an acknowledgement. This is the only
   test that observes §1's guarantee; without it, §1 is a convention.
4. **Sabotage verification before the work is called done.** For each refusal,
   remove the check and confirm the corresponding test fails. A test that has
   never failed proves nothing — this is how mecmcp#269's boundary test was shown
   to earn its place, and how its predecessor was found asserting the defect as
   the contract.

## Out of scope

- Changing what `--allow-no-auth` permits. It stays loopback-only.
- The `WaiverRecord` work in mecmcp#275.
- Auditing listener refusals. A refusal happens before the audit sink is
  serving; it belongs in startup logs, which already carry it.

## Open question for implementation

Whether `ListenerPolicy` should be public. Keeping it private makes `ServePlan`
opaque and forces every path through `serve_router`; making it public would let a
consumer inspect the posture for its own status tool, which mecmcp#54 asked for
in a different context. Recommend private in 0.9.0 — it can be opened later
without a break, whereas closing it later cannot.
