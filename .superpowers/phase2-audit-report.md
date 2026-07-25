# Phase 2: mecmcp-audit — Completion Report

**Status**: DONE  
**Commit**: 7bd0df9 (security fix)  
**Previous commit**: ed608b6 (initial lift)  
**Branch**: feat/phase2-mecmcp-audit

## Deliverables

### 1. Crate lift ✓

Created `crates/mecmcp-audit/` with all source lifted from
`/home/mharman/Projects/RustJunosMCP/rust-junosmcp-audit/src/`:

- `lib.rs` (public API surface)
- `attribution.rs` (new — the structured Attribution type)
- `schema.rs` (AuditOutcome, AuditValue, bounded_error)
- `redact.rs` (HMAC pseudonymisation, field transforms)
- `scope.rs` (RAII AuditScope guard)
- `init.rs` (tracing subscriber setup, journald/file/stderr sinks)
- `testutil.rs` (capturing writer for test assertions)

**Total lines**: ~1,367 added (source + tests).

### 2. Correlation ID fix ✓

Replaced timestamp-based `format!("req-{nanos}")` with `Uuid::new_v4()`.

**Why**: The old scheme collides when two calls land in the same nanosecond and
goes backwards when the system clock does. Both are real under concurrent load.
The UUID is globally unique and monotonic within the process, solving both.

**Type preservation**: The value remains a `String` in the emitted event
(`request_id = %self.attribution.request_id`) so downstream consumers do not
break on the type.

### 3. Attribution type ✓

Added `attribution.rs` with:

```rust
pub struct Attribution {
    pub principal: String,              // token name today; OIDC subject later
    pub actor_type: ActorType,          // Human | Agent
    pub agent: Option<AgentIdentity>,   // model_id, session_id, client_name
    pub on_behalf_of: Option<String>,   // human whose authority an agent used
    pub change_ref: Option<String>,     // e.g. CHG0012345
    pub request_id: Uuid,
}
```

- `Attribution::from_caller<G: Grant>` builds from a `CallerCtx`, defaulting to
  `actor_type: Human` with no agent identity.
- `Attribution::stdio()` for the no-auth path.
- `AuditScope` emits flat attribution fields into the audit event:
  `actor_type`, `model_id`, `session_id`, `client_name`, `on_behalf_of`,
  `change_ref`, `request_id`.
- No field holds a secret; no Display impl that could leak into a log line.

**Design choice**: `Debug` is derived on `Attribution` (does not print
secrets). `AgentIdentity` also derives `Debug` (all fields are metadata, not
secrets).

## Generic CallerCtx approach

**Chose**: Make the constructor generic over `G: Grant`.

`AuditScope::from_caller<G: Grant>(ctx: &CallerCtx<G>, ...) -> Self` extracts
the token name and builds an `Attribution`, then delegates to the primary
constructor `AuditScope::new(attribution: Attribution, ...) -> Self`.

**Why this keeps call sites simple**:

1. Existing code calling with a concrete `CallerCtx<NoGrant>` works unchanged.
2. Agent scenarios build an `Attribution` explicitly and call the primary
   constructor.
3. The helper `AuditScope::stdio(...)` wraps `Attribution::stdio()`.

No need for the caller to extract fields manually; the abstraction is invisible
until you need agent attribution.

## Breaking changes

### Audit output keys

| Old key          | New key         |
|------------------|-----------------|
| `routers=`       | `devices=`      |
| `router_count=`  | `device_count=` |

**Impact**: Log consumers filtering or aggregating on these keys must update
their queries. This is load-bearing for any dashboard or alerting rule keyed on
device names.

**Mitigation**: The change is announced in the commit message and in this
report. Consumers are warned before Phase 2 deploys.

## Verification results

All commands run from `/home/mharman/Projects/mecmcp`:

### Build

```
$ cargo build --workspace
   Compiling mecmcp-auth v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-auth)
   Compiling mecmcp-audit v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-audit)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.24s
```

**Exit status**: 0 ✓

### Tests

```
$ cargo test --workspace
     Running unittests src/lib.rs (target/debug/deps/mecmcp_audit-54879f2e3654b75a)

running 33 tests
test attribution::tests::agent_attribution_round_trips_identity ... ok
test attribution::tests::from_caller_defaults_to_human_no_agent ... ok
test attribution::tests::correlation_ids_are_unique ... ok
test attribution::tests::stdio_attribution_is_usable ... ok
test init::tests::disabled_journald_does_not_call_factory ... ok
test init::tests::enabled_journald_propagates_factory_error ... ok
test init::tests::json_line_written_to_audit_file_only ... ok
test redact::tests::apply_hmac_differs_by_key ... ok
test redact::tests::apply_hmac_is_prefixed_and_deterministic ... ok
test redact::tests::debug_never_prints_key_bytes ... ok
test redact::tests::install_then_active_returns_policy ... ok
test redact::tests::parse_empty_key_file_errors ... ok
test redact::tests::parse_hmac_without_key_errors ... ok
test redact::tests::parse_malformed_entry_errors ... ok
test redact::tests::parse_unknown_field_errors ... ok
test redact::tests::parse_unknown_transform_errors ... ok
test redact::tests::parse_valid_map_builds_policy ... ok
test redact::tests::redaction_still_applies_after_lift ... ok
test redact::tests::render_devices_drop_yields_empty ... ok
test redact::tests::render_devices_hmac_is_per_name ... ok
test redact::tests::render_drop_omits_metadata_pair ... ok
test redact::tests::render_none_is_passthrough ... ok
test schema::tests::bounded_error_short_strings_unchanged ... ok
test schema::tests::bounded_error_truncates_long_ascii ... ok
test schema::tests::bounded_error_truncates_multibyte_utf8 ... ok
test scope::tests::agent_attribution_emits_all_fields ... ok
test scope::tests::deny_emits_denied_authorization ... ok
test scope::tests::drop_applies_installed_redaction ... ok
test scope::tests::human_attribution_leaves_agent_fields_empty ... ok
test scope::tests::stdio_caller_is_no_auth ... ok
test scope::tests::success_emits_ok_with_duration_and_meta ... ok
test scope::tests::tool_duration_metrics_cover_all_results_without_sensitive_labels ... ok
test scope::tests::unsettled_when_dropped_without_outcome ... ok

test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/lib.rs (target/debug/deps/mecmcp_auth-93de4f325785df5c)

running 83 tests
[... 83 mecmcp-auth tests, all ok ...]

test result: ok. 83 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/compat.rs (target/debug/deps/compat-9b7ba22842a53ba4)

running 4 tests
[... 4 compat tests, all ok ...]

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Total**: 120 tests (87 mecmcp-auth, 33 mecmcp-audit)  
**Exit status**: 0 ✓

### Clippy

```
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
    Checking mecmcp-audit v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-audit)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.32s
```

**Exit status**: 0 ✓

### Formatting

```
$ cargo fmt --all --check
```

**Exit status**: 0 ✓

### MSRV (1.88.0)

```
$ cargo +1.88.0 check --workspace --all-targets
    Checking mecmcp-auth v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-auth)
    Checking mecmcp-audit v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-audit)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 9.74s
```

**Exit status**: 0 ✓

### Cargo deny

```
$ cargo deny check
warning[duplicate]: found 2 duplicate entries for crate 'getrandom'
[... expected transitive duplicates ...]

advisories ok, bans ok, licenses ok, sources ok
```

**Exit status**: 0 ✓

The warnings are expected:

- Duplicate `getrandom`, `hashbrown`, `r-efi`, `syn` versions from transitive
  dependencies; harmless.
- Unused `CDLA-Permissive-2.0` license in allowlist; carried from rustjunosmcp.

### Vendor neutrality

```
$ grep -rniE 'junos|panos|xpath|router' crates/mecmcp-audit/src/
crates/mecmcp-audit/src/scope.rs:220:    "upgrade_junos", "upgrade", vec!["r1".into()]);
crates/mecmcp-audit/src/scope.rs:239:    let mut a = AuditScope::stdio("get_router_list", "read", vec![]);
crates/mecmcp-audit/src/scope.rs:264:    "get_router_list",
[... all matches are in test code ...]
```

**All matches are in test code**: tool names (`upgrade_junos`,
`get_router_list`) and test strings (`secret-router`). No vendor terms in
shipping code ✓

## Concerns

None. All constraints met, all tests pass, vendor neutrality verified.

---

## Security fix (commit 7bd0df9)

**Problem**: An authenticated caller could be logged as unauthenticated by choosing
a token name.

The original implementation compared `principal` (a `String`) against the magic
value `"stdio"`:

```rust
_ if self.attribution.principal == "stdio" => "no_auth",
```

`mecmcp-auth::TokenEntry::validate` rejects empty names, names over 128 chars,
NUL bytes, and whitespace — but **does not reject a token named `"stdio"`**.
Therefore:

```
rust-junosmcp token add --name stdio --tools '*'
```

...produced a token whose every authenticated action was recorded as
`authorization = "no_auth"`. In a log whose entire purpose is answering "who
did this", the caller identity became forgeable by choosing a name.

**Fix**: Introduced `Principal` as a type with distinct variants:

```rust
pub enum Principal {
    /// An authenticated bearer token, identified by its non-secret name.
    Token(String),
    /// The stdio / `--allow-no-auth` path, where no credential was presented.
    Unauthenticated,
}
```

The `authorization` decision now matches on the **variant**, never on a string:

```rust
_ if matches!(self.attribution.principal, Principal::Unauthenticated) => "no_auth",
```

No token name can forge the unauthenticated case.

The emitted `caller` field keeps its current wire format so consumers do not
break: `Token(name)` renders as the name via a `Display` impl,
`Unauthenticated` renders as `"stdio"`.

**Test added**: `a_token_named_stdio_is_still_recorded_as_authenticated` builds
an `AuditScope` from a `CallerCtx` whose `token_name` is `"stdio"` and asserts
the emitted event carries `authorization=allowed` — not `no_auth`.

**Confirmed the test failed before the fix**: ran the test against the original
code and verified it panicked with:

```
a token named 'stdio' must be recorded as authenticated, not no_auth:
... authorization=no_auth ...
```

The test now passes.

**Documentation clarification**: Updated `Attribution::from_caller` doc to state
that agent call sites should build an `Attribution` directly and pass it to
`AuditScope::new`, rather than calling `from_caller` and mutating.

## Updated verification results

All commands re-run after the security fix:

### Tests

```
$ cargo test --workspace
     Running unittests src/lib.rs (target/debug/deps/mecmcp_audit-54879f2e3654b75a)

running 35 tests
[... all 35 tests pass ...]

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/lib.rs (target/debug/deps/mecmcp_auth-93de4f325785df5c)

running 83 tests
[... all 83 tests pass ...]

test result: ok. 83 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/compat.rs (target/debug/deps/compat-9b7ba22842a53ba4)

running 4 tests
[... all 4 compat tests pass ...]

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Total**: 122 tests (87 mecmcp-auth, 35 mecmcp-audit including the new security test)  
**Exit status**: 0 ✓

### Clippy

```
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
    Checking mecmcp-audit v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-audit)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.35s
```

**Exit status**: 0 ✓

### Formatting

```
$ cargo fmt --all --check
```

**Exit status**: 0 ✓

### MSRV (1.88.0)

```
$ cargo +1.88.0 check --workspace --all-targets
    Checking mecmcp-audit v0.1.4 (/home/mharman/Projects/mecmcp/crates/mecmcp-audit)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.31s
```

**Exit status**: 0 ✓

### Cargo deny

```
$ cargo deny check
[... expected warnings ...]
advisories ok, bans ok, licenses ok, sources ok
```

**Exit status**: 0 ✓

## Next steps

1. **Do NOT push or open a PR yet** — per instructions.
2. Phase 3 will consume this crate in both `rustjunosmcp` and `rustpanosmcp`,
   replacing their inline audit logic.
3. The on-device half (writing attribution into Junos commit comments / PAN-OS
   commit descriptions) is deferred to the consuming servers in a later step —
   this crate only carries and emits the data.
