# Fuzz targets

No-panic targets for the parsers in this workspace that consume bytes chosen
by something other than this server: a caller-presented bearer token, an
IdP's discovery/JWKS response, or a device/controller's tool-output body.
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
```

`cargo fuzz list` from this directory enumerates all six.

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
