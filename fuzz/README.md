# Fuzz targets

No-panic targets for the parsers in this workspace that consume bytes chosen
by something other than this server: a caller-presented bearer token, an
IdP's discovery/JWKS response, a device/controller's tool-output body, or a
reverse proxy's `X-Forwarded-For` header.
None of these carry an independent oracle (unlike rustnetconf's
`fragment_embeds_cleanly`, which checks a *property* of the parse) -- they
assert only that the function returns instead of aborting, because a panic
partway through auth or redaction is worse than an error: it can take down
the request that was trying to reject something, or leave a partially
redacted body only some of which reached a model.

Requires nightly and a sanitizer, so this crate is deliberately **not** part
of the workspace -- `cargo test --workspace` and CI do not build it.

```bash
cargo +nightly fuzz run oidc_token_verify_never_panics    -- -max_total_time=120
cargo +nightly fuzz run oidc_jwks_parse_is_total          -- -max_total_time=120
cargo +nightly fuzz run oidc_discovery_parse_is_total     -- -max_total_time=120
cargo +nightly fuzz run redact_text_never_panics          -- -max_total_time=120
cargo +nightly fuzz run redact_json_never_panics          -- -max_total_time=120
cargo +nightly fuzz run redact_xml_never_panics           -- -max_total_time=120
cargo +nightly fuzz run xff_parse                         -- -max_total_time=120
```

`cargo fuzz list` from this directory enumerates all seven.

### Stable fallback: coverage-instrumented build without nightly

`cargo fuzz run` needs nightly for ASan. Coverage instrumentation --
libFuzzer's actual mutation feedback signal -- does not, and is the
difference between a run that explores new code paths and one that
mutates the same seed at random for the full duration (see the
`xff_parse` PR #445 review: an uninstrumented 61s run stayed at
`corp: 1/1b`, i.e. never got past the first seed). `--target` is required
even on the host triple; without it the flags also apply to build scripts,
and `httparse`'s build script fails to link:

```bash
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions" \
  cargo build --release --target x86_64-unknown-linux-gnu --bin xff_parse

./target/x86_64-unknown-linux-gnu/release/xff_parse -max_total_time=60 \
  -dict=fuzz_targets/xff_parse.dict corpus/xff_parse
```

Use this whenever nightly is unavailable; prefer real `cargo +nightly fuzz
run` (with ASan) when it is.

## `oidc_token_verify_never_panics`

`TokenVerifier::verify` is the one function in `mecmcp-oidc` that consumes a
fully caller-controlled bearer token. The target fixes the configured issuer,
audience, and JWKS to one real RSA key generated once per fuzzer process
(`OnceLock`), and hands the fuzz input straight to `verify` as the token
string -- covering `decode_header`, the `alg`/JWK-family agreement check, and
`jsonwebtoken::decode` against inputs that are frequently well-formed enough
to reach deep into that path, not just "not three dot-separated segments".

## `oidc_jwks_parse_is_total` / `oidc_discovery_parse_is_total`

The two documents `fetch::HttpKeySource` pulls from a configured issuer,
fed to the same `serde_json::from_slice` call the production `KeySource`
uses. Both are IdP-controlled, not caller-controlled -- the point is that a
compromised or simply broken IdP cannot crash the resource server that
trusts it, only fail closed.

## `redact_text_never_panics` / `redact_json_never_panics` / `redact_xml_never_panics`

The three denylist-and-shape entry points in `mecmcp-redact` that run, on by
default, on unstructured tool output before it reaches a model. Every vendor
server hands this crate device- or controller-sourced text, JSON, or XML;
these targets are the coarse "does not abort mid-redaction" property. Which
secrets get caught is a unit-test question (see the crate's own denylist and
shape tests), not a fuzz-target one -- a fuzzer has no oracle for "this
redaction was correct", only "this call returned".

## `xff_parse`

`mecmcp-transport::rate_limit::resolve_rate_limit_ip` (mecmcp#410, MEC-49)
splits a trusted proxy's `X-Forwarded-For` header on commas, trims each
entry, and parses it as an `IpAddr` to find the per-IP rate-limit bucket key.
The header value is client-influenced -- deployed proxies append the real
client to whatever the client itself sent -- and does not have to be valid
UTF-8. The first fuzz byte picks whether `peer` is inside `trusted_proxies`
or not (so both the fast path and the split/trim/parse walk are reachable),
the rest is split on `\n` into one or more `X-Forwarded-For` header lines
built straight from the fuzz bytes via `HeaderValue::from_bytes` (the
multi-line HAProxy-style `get_all` path, and the same opaque-byte values a
proxy can put on the wire, unlike a `&str`-typed target).

Unlike the other six targets, this one has an oracle beyond "did not panic":
every run asserts the security property the function's own doc comment
states (an untrusted peer's header is never consulted, the returned address
is never a trusted proxy's own address) and the canonicalization property
from PR #445's F2 fix (the returned address is always `to_canonical()`).
`fuzz_targets/xff_parse.dict` is a small token dictionary (`::ffff:`, `,`,
`::`, `.`, `\n`) that makes IPv4-mapped and multi-line inputs vastly more
likely to be generated; pass it to either `cargo fuzz run` or the manual
binary via `-dict=fuzz_targets/xff_parse.dict`.
