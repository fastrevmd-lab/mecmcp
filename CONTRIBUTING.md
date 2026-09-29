# Contributing to mecmcp

Thanks for considering a contribution. `mecmcp` is the vendor-neutral Rust foundation shared by mechub's per-vendor network-security MCP servers (today [rustjunosmcp](https://github.com/mechubsec/rustjunosmcp) for Junos/SRX and [rustpanosmcp](https://github.com/mechubsec/rustpanosmcp) for PAN-OS, with more vendors expected to build on it). See [README.md](README.md) for what the crate family does and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) / [docs/CRATE-MAP.md](docs/CRATE-MAP.md) for how it's put together.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code. It saves everyone a rewrite.
- This project follows one hard rule across the whole mechub fleet: **deterministic code decides, a model may explain, a human approves.** Nothing contributed here should let an LLM or other model output directly drive a device action (a commit, a set, a config push, an approval). Models may draft, summarize, or explain; deterministic code — the policy engine, the change-set state machine, the auth boundary — decides.
- `mecmcp` is a *foundation* crate, not a leaf. A change here doesn't just affect this repo — it ripples into every vendor server that depends on it. See "Downstream impact" below before touching public API.

## Workspace layout

This is a Cargo workspace. The members, from `Cargo.toml`, all live under `crates/`: `mecmcp-auth`, `mecmcp-audit`, `mecmcp-changeset`, `mecmcp-scp`, `mecmcp-transport`, `mecmcp-runtime`, `mecmcp-policy`, `mecmcp-inventory`, `mecmcp-device`, `mecmcp-secret`, `mecmcp-http`, `mecmcp-job`, `mecmcp-openapi`, `mecmcp-server`. See [docs/CRATE-MAP.md](docs/CRATE-MAP.md) for what each one does and how they depend on each other.

## Build and test

These match what CI (`.github/workflows/ci.yml`, job `build-test`) runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace
cargo test --workspace --features mecmcp-audit/test-util,mecmcp-changeset/test-util
cargo doc --workspace --no-deps
```

Always pass both `test-util` features. They gate tests that reach state a public API deliberately doesn't expose — seeding a change set into a state only its own lifecycle can produce, and installing a per-thread tracing subscriber. Without them, most of the audit and change-set test suites silently don't run at all.

### MSRV

`Cargo.toml` declares `rust-version = "1.89"`, independent of the toolchain `rust-toolchain.toml` pins for everyday building (currently newer). CI's `msrv` job checks the workspace against 1.89 with the toolchain pin removed and a fresh dependency resolution — `Cargo.lock` is gitignored in this repo, so that job resolves whatever the registry currently offers. If you bump a dependency, check it isn't quietly raising this floor out from under it; the consumer repos depend on it holding.

### Conformance fixtures

CI's `conformance` job (`packaging/conformance/tests/`) exercises the packaging manifest reader and container/image fixtures, and shells out to `docker build`. It isn't expected to be run locally for an ordinary code change — CI covers it — but do run it if you're touching `packaging/`.

## Lint and dependency policy

The workspace forbids `unsafe_code`, warns on `missing_docs`, and in Clippy denies `dbg!`/`todo!` and warns on `.unwrap()` (`[workspace.lints]` in `Cargo.toml`). A new dependency needs to satisfy `deny.toml`: a permissive license on the allow-list, sourced only from crates.io, not yanked. `deny.toml`'s header comment notes it's deliberately kept aligned with `rustjunosmcp` and `rustpanosmcp`'s own `deny.toml` files — if you add a license here, flag it in your PR so the consumer repos can pick up the same allowance.

Before opening a PR, also run what CI's `security.yml` runs:

```sh
cargo generate-lockfile   # Cargo.lock is gitignored; audit/deny need one to scan
cargo audit
cargo deny check licenses bans sources
```

## Downstream impact

Vendor servers (`rustjunosmcp`, `rustpanosmcp`, and others being built on this foundation) depend on this repository directly and pin an exact version — `mecmcp` isn't published to crates.io. A behavior or API change here doesn't show up as a failure in *this* repo's CI; it shows up as a build break, or worse a silent behavior change, in a consumer later. When you change public API on a crate you know is consumed downstream (`mecmcp-auth`, `mecmcp-transport`, `mecmcp-runtime`, and `mecmcp-changeset` especially):

- Say so explicitly in the PR description, and call out whether it's additive or breaking.
- If you have access to a consumer checkout, build and run its tests against your branch before asking for review. If you don't, say so in the PR so a reviewer with that access can verify it instead.
- For a breaking change, match the level of detail README.md's version history uses for past ones (search it for "Upgrading to"): what broke, exactly what a consumer needs to change, and whether a fleet survey found anything actually affected by it.

## Commit and PR conventions

- Keep PRs focused on one change. A bug fix doesn't need a drive-by refactor riding along.
- Fill out the PR template, including the exact commands you ran to verify the change.
- By opening a pull request, you're agreeing your contribution is licensed under this repository's [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an independent test run, before anything merges. Only a maintainer merges — contributors, including anyone with write access, should not merge their own PR. CI (build, test, clippy, fmt, `cargo audit`, `cargo deny`, secret scanning) must be green first. All contributions land as a pull request against `main` for that review.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real device configs, hostnames, serial numbers, credentials, or tokens — synthetic or sanitized fixtures only. If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).
