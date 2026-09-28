## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --features mecmcp-audit/test-util,mecmcp-changeset/test-util` passes
- [ ] `cargo audit` and `cargo deny check licenses bans sources` are clean, or any new advisory/license exception is called out below
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] Fixtures are synthetic — no secrets, credentials, real hostnames, serials, or real device configs in code, tests, fixtures, or this description
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches a path that can act on a device: deterministic code decides, not a model output

## Downstream impact

<!-- mecmcp is a foundation crate consumed by rustjunosmcp, rustpanosmcp, and other vendor MCP servers. Check one. -->

- [ ] Not a breaking change for downstream MCP-server consumers
- [ ] Breaking change — described below: what breaks, what a consumer needs to change, and whether it was verified against a consumer checkout
- [ ] Ran (or had someone run) downstream consumer tests against this branch where feasible; if not feasible, said so above

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
