# mecmcp-redact

Tool-output redaction for mechub MCP servers, applied at the boundary between
a vendor's read API and the tool result handed back to the model.

## Why this exists

Every vendor MCP server eventually returns a device's raw config, a REST
response body, or CLI output as a tool result. That output routinely carries
the device's own secrets — PSKs, API tokens, password hashes, private keys —
because a vendor's read API does not distinguish "safe to show the operator
who already has console access" from "safe to hand to a model with no duty of
confidentiality." This crate is the shared place that distinction gets made,
applied the same way by every server, rather than five ad hoc attempts at it.

This crate builds the mechanism. Wiring redaction into each vendor server's
tool handlers is separate work (tracked as H1b/H1c) — this repo has no vendor
MCP servers in it to wire into. The trust-boundary marking below is wired one
level higher, into `mecmcp-server`'s shared `tool_error`/`tool_result` path
every vendor server already calls — see [Marking untrusted content](#marking-untrusted-content).

## Two strategies

- **Allowlist projection** ([`projection::FieldAllowlist`]) — for the
  resource shapes a server fully controls (UniFi `list`/`get_resource`
  results, SDC certificates). A server declares the fields the model may see;
  everything else is dropped, known field or not. This is the strong
  guarantee, and it only covers what a server bothers to declare.
- **Denylist + value-shape catch-all** ([`redact_json_str`], [`redact_xml_str`],
  [`redact_text`]) — for everything else. A fixed key denylist
  ([`denylist::DENYLISTED_KEYS`]) catches known-sensitive field names under
  common spelling variants; a value-shape catch-all ([`shape`]) catches
  secrets under a field name nobody has denylisted yet — crypt-style hashes
  (`$9$...`), PAN-OS's `-AQ==`-suffixed blobs, `ENC`-prefixed ciphertext, PEM
  blocks, and Junos's `## SECRET-DATA` marker.

## Vendor-specific extensions to the denylist scan

A server occasionally has two kinds of policy the denylist-and-shape scan
cannot infer from a vendor's schema on its own: a field whose value must be
withheld as a whole because it is a rendered body (device config, generated
IPsec config) that can embed a secret in a shape the scan is not guaranteed
to catch, or a field name that collides with the denylist by substring in
that vendor's schema but is not a secret (an opaque paging cursor, a logging
flag — redacting it is a functional or security regression in its own
right). A server declares a [`Profile`] once and calls
[`redact_json_value_with_profile`] instead of [`redact_json_value`]; see the
[`profile`] module docs for the ordering guarantees. This never narrows the
generic scan — it only adds exceptions and extra withholding on top of it.

## On by default

[`policy::active()`] defaults to `Enabled`. The only way to change that is
[`policy::install`], called at most once by a server binary at startup from an
operator CLI flag (e.g. `--no-redact`) — never from a tool argument. Doing so
emits a `WARN`-level, `target: "audit"` tracing event naming the flag; every
mecmcp server's `mecmcp_audit::init_tracing` subscriber both prints that to
the console and, when an audit file or journald sink is configured, records
it there. There is no tool-facing parameter on any redaction entry point that
could reach this state — the only lever is the operator flag.

## Marking untrusted content

Redaction decides *what* a model may see. [`trust::Untrusted`] decides how
what's left is *told apart* once it does — a device's hostname, description,
or error body is no more trustworthy than a tool argument, but until this
type existed nothing marked it as such once it landed in a `String`.

Construct `Untrusted::new(value)` where a vendor response is parsed, and
render it with [`Untrusted::render_tagged`] wherever it reaches a tool result
or any other model-facing string:

```rust
use mecmcp_redact::Untrusted;

let hostname = Untrusted::new(device_response.hostname.clone());
let tagged = hostname.render_tagged("device.hostname");
// tagged: "<untrusted-device-content id=\"a1b2c3d4e5f60789\" source=\"device.hostname\">...\n<hostname>\n</untrusted-device-content id=\"a1b2c3d4e5f60789\">"
```

`mecmcp-server::tool_error_with_untrusted_detail` is the sanctioned entry
point for a tool handler's error path — see `crates/mecmcp-changeset/src/apply.rs`
for a worked example of tagging a vendor transaction error before it becomes
part of a `CoordinatorError` message. `render_tagged` entity-escapes `&`, `<`
and `>` in the content and the `source` label, so no tag-shaped text of any
spelling can appear inside the block, and pairs each rendering with a random
id shared by its open and close tags, so device text cannot forge a matching
closing tag even in escaped form.

This is a visibility mechanism, not a sandbox: a model that ignores the
delimiter entirely is a prompting and policy problem downstream of this
crate, not one tagging text can solve by itself. It exists to support the
house rule, not replace it — deterministic code still decides.

## Fingerprints survive redaction

[`digest::digest_hex`] and [`redact_and_digest`] compute the digest from the
*original* bytes, before redaction runs. A digest taken after redaction would
make two configs that differ only in a rotated secret hash identically once
that field is denylisted, breaking change detection. [`redact_and_digest`] is
the recommended entry point specifically because it makes "digest first" the
only order reachable through the API.

## Command-line use

The `cli` feature builds a `mecmcp-redact` binary: the same engine, stdin to
stdout, for a consumer that cannot link the crate (`mechubbench` is Python).

```sh
cargo run -p mecmcp-redact --features cli --bin mecmcp-redact -- --format json < body.json
```

`--format` is `text` (default), `json`, or `xml`. Invalid JSON/XML exits
non-zero rather than printing the input back unredacted — the same
fail-closed contract [`redact_json_str`]/[`redact_xml_str`] document. There is
deliberately no `--profile` flag yet: see the binary's own doc comment
(`src/bin/mecmcp-redact.rs`) for why.

## Shared test coverage helper

The `test-util` feature exposes [`testing::tools_leaking_secrets`]: given a
tool-name registry, a set of fixture secrets, and a closure that exercises one
tool and returns its rendered output, it returns the names of tools whose
output contained any of those secrets. It generalizes the
plant-a-secret-per-tool-and-assert-none-leak test every server has built by
hand, the same way `mecmcp-audit`'s `test-util` feature generalized
audit-coverage checking.

## Residual risk — read this before assuming zero egress

This crate reduces what reaches the model. It does not guarantee nothing
sensitive does.

- **Free text still leaks topology.** A device description, a syslog message,
  a banner, an interface comment — none of that is secret-shaped, so none of
  it is touched. "uplink to core-fw-02 via AS 64512, backup path through
  branch-office-14" survives redaction intact and describes network topology
  to whatever received the tool result.
- **The denylist will miss new vendor fields.** It is a fixed, maintained list.
  A vendor that ships a new sensitive field under a name nobody has seen yet
  — and that does not happen to match one of the value shapes in [`shape`] —
  passes through unredacted until the denylist is updated. The substring
  matching in [`denylist::is_denylisted_key`] catches variant spellings of a
  *known* term; it cannot catch an unrelated one.
- **The value-shape catch-all is also a fixed list.** A vendor encoding a
  secret in a form not in [`shape`] — a new hash scheme, a new marker
  convention — is not caught by shape alone.
- **Allowlist projections are opt-in per resource.** [`projection::FieldAllowlist`]
  is a strong guarantee, but only where a server has declared one. Everything
  routed through the denylist path instead inherits that path's weaker,
  best-effort guarantee.
- **Text-format matching is line-local and heuristic.** The unstructured text
  redactor ([`text`]) reasons about one line at a time; a secret whose vendor
  format spans a line boundary in a way the PEM/marker handlers don't
  recognize is not guaranteed to be caught.

**Operators who need a hard guarantee of zero secret egress to a model should
not rely on this crate alone — they should run a local model**, so nothing
leaves the operator's own infrastructure regardless of what a denylist missed.
This crate makes remote-model use meaningfully safer; it does not make it
provably safe.
