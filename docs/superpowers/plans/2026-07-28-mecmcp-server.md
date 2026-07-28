# `mecmcp-server` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the vendor-neutral `rmcp` handler adapter shared by Junos, PAN-OS, and the future SDC server.

**Architecture:** Add one leaf crate depending on `mecmcp-auth`, `mecmcp-audit`, `rmcp`, `http`, and serde. Keep consumer policy as parameters and split caller, authorization, advertised-tool filtering, result formatting/bounds, and audit construction into focused modules.

**Tech Stack:** Rust 2024, MSRV 1.88, `rmcp` 2, `mecmcp-auth`, `mecmcp-audit`, serde.

## Global Constraints

- Edition 2024 and MSRV 1.88.
- `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"`, `dbg_macro` and `todo` denied, `unwrap_used = "warn"`.
- No tool names, metric names, target vocabulary, or write-tool registry may be baked into the shared crate.
- Existing on-disk and MCP interfaces remain unchanged.
- Tests precede production code and are observed failing for the intended reason.

---

### Task 1: Crate Contract and Caller Extraction

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/mecmcp-server/Cargo.toml`
- Create: `crates/mecmcp-server/src/lib.rs`
- Create: `crates/mecmcp-server/src/caller.rs`
- Test: `crates/mecmcp-server/tests/caller.rs`

**Interfaces:**
- Produces: `caller_from_extensions<G: Grant>(&rmcp::model::Extensions) -> Option<&CallerCtx<G>>`

- [ ] Add a compile-failing integration test importing `mecmcp_server::caller_from_extensions`.
- [ ] Run `cargo test -p mecmcp-server --test caller` and confirm the missing crate/API failure.
- [ ] Add the workspace member, manifest, module skeleton, and caller implementation.
- [ ] Test stdio/no-parts, HTTP parts without caller, and HTTP parts containing a generic caller.
- [ ] Run the crate tests and commit.

### Task 2: Authorization and Tool Filtering

**Files:**
- Create: `crates/mecmcp-server/src/authorize.rs`
- Create: `crates/mecmcp-server/src/tools.rs`
- Test: `crates/mecmcp-server/tests/authorization.rs`

**Interfaces:**
- Produces: `AuthorizationError::{ToolNotInScope, TargetNotInScope}`
- Produces: `authorize_tool`, `authorize_target`, and `authorize_call`
- Produces: `filter_tools_for_scope`

- [ ] Write tests proving stdio admission, explicit read scope, wildcard read scope, wildcard write denial, explicit write admission, target denial without inventory disclosure, and matching `tools/list` filtering.
- [ ] Run the authorization test and confirm unresolved-import failures.
- [ ] Implement the minimal typed authorization API with the write registry passed as `&[&str]`.
- [ ] Run authorization and full crate tests; commit.

### Task 3: Safe MCP Results and Bounds

**Files:**
- Create: `crates/mecmcp-server/src/result.rs`
- Test: `crates/mecmcp-server/tests/result.rs`

**Interfaces:**
- Produces: `ResultFormat::{PrettyJson, StringOrPrettyJson}`
- Produces: `ResultLimits { max_text_bytes, max_json_bytes }`
- Produces: `tool_result`, `tool_error`, `bounded_text`

- [ ] Write tests for pretty JSON, raw `Value::String`, ordinary errors, serialization failure, exact limits, oversized JSON refusal, ASCII truncation, and multibyte UTF-8 truncation.
- [ ] Run the result test and confirm unresolved-import failures.
- [ ] Implement serialization with pre-return byte checks and UTF-8-safe truncation metadata.
- [ ] Run result and full crate tests; commit.

### Task 4: Audit-Scope Construction

**Files:**
- Create: `crates/mecmcp-server/src/audit.rs`
- Test: `crates/mecmcp-server/tests/audit.rs`

**Interfaces:**
- Produces: `audit_scope<G: Grant>(Option<&CallerCtx<G>>, tool, action, targets) -> AuditScope`

- [ ] Write a capture test proving authenticated and stdio attribution retain their distinct principal variants.
- [ ] Run the audit test and confirm the unresolved-import failure.
- [ ] Implement the branch through `AuditScope::from_caller` and `AuditScope::stdio`.
- [ ] Run audit and full crate tests; commit.

### Task 5: Workspace and Compatibility Verification

**Files:**
- Modify: `README.md`
- Modify: `PLAN.md`

**Interfaces:**
- Consumes all Task 1–4 APIs.
- Produces documented crate ownership and downstream migration instructions.

- [ ] Document the new crate and explicitly list what remains consumer-specific.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Run `cargo test --workspace`.
- [ ] Run `cargo deny check`.
- [ ] Inspect `cargo tree -p mecmcp-server -e normal` for unwanted TLS/runtime backends.
- [ ] Commit documentation and verification fixes.

### Task 6: Consumer Adoption

**Files:**
- Modify the matching adapter modules in `rustpanosmcp`.
- Modify the matching adapter modules in `rustjunosmcp`.

**Interfaces:**
- Consume the exact APIs delivered by Tasks 1–4.
- Preserve each consumer’s write-tool registry and result-format choice.

- [ ] Publish or otherwise pin one exact shared `mecmcp` revision for both consumers.
- [ ] In separate issue worktrees, migrate PAN-OS and run its complete offline suite.
- [ ] Integrate and clean the PAN-OS worktree.
- [ ] In a new worktree, migrate Junos and run its complete offline suite.
- [ ] Integrate and clean the Junos worktree.
- [ ] Confirm the replaced local helpers are deleted and no wrappers remain.

