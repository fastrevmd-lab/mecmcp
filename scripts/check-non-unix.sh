#!/usr/bin/env bash
# Compile-check the `cfg(not(unix))` branches of mecmcp-secret on Linux.
#
# Why this exists: those branches are invisible to `cargo build`, `cargo clippy`
# and CI here, because everything runs on Linux and no non-Unix target std is
# installed. A return-type mismatch in that code shipped once and was caught only
# by review — after an earlier ad-hoc run of this same check had gone stale
# because it was not re-run following a later edit.
#
# The trick: copy the crate, flip every `cfg(unix)` to a never-true cfg and drop
# the `cfg(not(unix))` guards, then compile. What builds is the non-Unix path.
#
# This is a compile check only. It says nothing about behaviour, and the non-Unix
# guarantees remain advisory (see #174).
#
# SCOPE, stated because it has already bitten: this checks mecmcp-secret's LIB
# only. It does not cover other crates, and it does not cover test targets — a
# `cfg(unix)`-less chmod in a mecmcp-auth test slipped past it and was caught by
# review instead. Widening it to the workspace and to --all-targets is worth
# doing; until then, do not read a pass here as "non-Unix is fine".
set -euo pipefail

crate_dir="$(cd "$(dirname "$0")/.." && pwd)/crates/mecmcp-secret"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -r "$crate_dir" "$work/crate"
cd "$work/crate"

python3 - <<'PY'
import pathlib

source = pathlib.Path("src/lib.rs")
text = source.read_text()
# `any()` is never true, so the Unix branch compiles out; removing the
# `not(unix)` guards leaves the fallback as the only definition.
text = text.replace("#[cfg(unix)]", "#[cfg(any())]").replace("#[cfg(not(unix))]", "")
source.write_text(text)

manifest = pathlib.Path("Cargo.toml")
text = manifest.read_text()
for workspace_key, literal in [
    ("version.workspace      = true", 'version = "0.0.0"'),
    ("edition.workspace      = true", 'edition = "2024"'),
    ("rust-version.workspace = true", ""),
    ("license.workspace      = true", ""),
    ("repository.workspace   = true", ""),
    ("authors.workspace      = true", ""),
    ("rustix    = { workspace = true }", 'rustix = { version = "1", features = ["fs", "process"] }'),
    ("thiserror = { workspace = true }", 'thiserror = "2"'),
    ("zeroize   = { workspace = true }", 'zeroize = { version = "1", features = ["derive"] }'),
    ("tempfile = { workspace = true }", 'tempfile = "3"'),
    ("[lints]\nworkspace = true", ""),
]:
    text = text.replace(workspace_key, literal)
manifest.write_text(text)
PY

echo "checking cfg(not(unix)) branches..."
cargo check --offline 2>&1 | tail -25
echo "non-Unix branches compile"
