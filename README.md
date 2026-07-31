<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">mecmcp</h1>

<p align="center"><strong>Vendor-neutral Rust foundation for enterprise network-security MCP servers</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

---

`mecmcp` is the shared crate family underneath mechub's per-vendor MCP servers.
Authentication, attribution, audit, transport hardening, policy, inventory,
change control — everything that is *not* NETCONF or XML-API — lives here once
and is consumed by every vendor server.

Today two servers independently reimplement all of it:

| | [rustjunosmcp](https://github.com/fastrevmd-lab/rustjunosmcp) | [rustpanosmcp](https://github.com/fastrevmd-lab/rustpanosmcp) |
|---|---|---|
| Vendor | Juniper Junos / SRX | Palo Alto PAN-OS |
| Device transport | NETCONF over SSH (`rustnetconf`) | HTTPS XML-API (`reqwest`) |
| Shared-by-accident | token auth, scopes, TLS, CLI, HTTP transport, inventory | same, written separately |

The duplication is not the main cost. The main cost is that **each repo is the
reference implementation for something the other lacks** — rustjunosmcp has the
runtime hardening (concurrency, rate limits, session caps, audit redaction),
rustpanosmcp has the change-control state machine (plan → digest → approve →
apply) and the modern crate hygiene. Neither benefits from the other.

`mecmcp` makes both the union instead of the intersection.

## Status

**0.3.8 — eleven crates, extraction complete.** Both the original extraction and
the cloud-foundations programme (#90) have landed: `mecmcp-secret`,
`mecmcp-http`, `mecmcp-job` and `mecmcp-openapi` are new, and `mecmcp-changeset`
gained multi-target change sets.

Not published to crates.io. Consumers depend on this repository directly and pin
an exact version.

### Upgrading to 0.3.8

This release is **breaking at the source level**, and needs a deliberate upgrade
rather than a version-string change:

| Change | What a consumer must do |
|---|---|
| `ChangeSetRecord` and `OperationLimits` gained public fields | struct-literal construction needs `..OperationLimits::default()` |
| `mecmcp-secret` is now Unix-only | nothing on Linux; the crate refuses to compile elsewhere by design |
| `mecmcp-auth` and `mecmcp-inventory` read their files through the shared hardened loader | `tokens.json` and `devices.json` **must** be mode 0600, a regular file, and owned by the service user — inventory had no such check before |

On-disk state is compatible in both directions: a 0.3.8 deployment using no
multi-target change set still writes version-1 files that the previous binary
reads.

**Verify the deployed files before rolling out.** A `tokens.json` or
`devices.json` that has drifted to 0644 loaded fine under 0.3.7 and will be
refused at startup by 0.3.8.

## Documents

| Document | What it is |
|---|---|
| [`ANALYSIS.md`](ANALYSIS.md) | Side-by-side teardown of both repos — what is duplicated, what is asymmetric, what stays vendor-specific |
| [`PLAN.md`](PLAN.md) | Program-level extraction plan: crate map, phase sequencing, decisions, exit criteria (historical — the plan is delivered) |
| [`ROADMAP.md`](ROADMAP.md) | What "enterprise grade" means at 150 engineers and 4,000 multi-vendor firewalls |
| [`docs/PACKAGING.md`](docs/PACKAGING.md) | How a mechub MCP server is delivered and installed — container base, LXC, README requirements |
| [`docs/superpowers/plans/`](docs/superpowers/plans/) | Executable per-phase implementation plans |

## The crate family

| Crate | Responsibility | Extracted from |
|---|---|---|
| `mecmcp-auth` | Token mint/digest/verify, `tokens.json` load + hot-reload, scopes, grants, caller context | both (union) |
| `mecmcp-audit` | Attribution, audit events, redaction, pluggable sinks | rustjunosmcp |
| `mecmcp-transport` | Streamable-HTTP: host/Origin checks, bearer middleware, rate limits, concurrency + session caps, metrics | rustjunosmcp `limits/` + rustpanosmcp scope preflight |
| `mecmcp-runtime` | CLI skeleton, TLS bootstrap, signals, graceful shutdown | both (union) |
| `mecmcp-policy` | Compiled allow/deny rule engine over command and config subjects | rustjunosmcp `policy.rs` |
| `mecmcp-inventory` | Device registry as a trait — file today, database and NetBox later | both (generalized) |
| `mecmcp-device` | Connection lease/pool, per-device concurrency, cancellation, timeouts | rustjunosmcp |
| `mecmcp-changeset` | Plan → digest → approve → apply → verify, two-principal enforcement, indeterminate recovery | rustpanosmcp `mutation.rs` |
| `mecmcp-secret` | Outbound credential type (zeroizing, unprintable) and hardened env/file loader | new — see #90 |
| `mecmcp-job` | Cancellable job polling: immediate first probe, capped backoff, whole-operation deadline | new — see #90 |
| `mecmcp-http` | Outbound HTTP client: HTTPS-only, no redirects, no proxy, bounded concurrency, whole-request deadline, sensitive headers | new — see #90 |
| `mecmcp-openapi` | Whole-segment path expansion and bounded pagination — rejects, never clamps | new — see #90 |
| `mecmcp-intent` | Vendor-neutral policy/object model with per-vendor rendering | new — see ROADMAP |

### Remote listeners fail closed

A Streamable HTTP listener bound off-loopback must name what it accepts:
`--allowed-host` and `--allowed-origin` are both required, and an allowlist of
blank strings does not count. An empty allowlist is not "accept whatever the
operator forgot to configure" — it is a DNS-rebinding and Host-confusion surface
on Host, and it disables browser-origin policy entirely on Origin.

Loopback binds are exempt. A listener on `127.0.0.1` or `::1` is already bounded
by the host, and requiring the flags there would break every stdio and
local-HTTP deployment for nothing.

Vendor servers keep their protocol adapters, XML parsers, and vendor workflows.
For `mecmcp-http` specifically, that means endpoint catalogs, header names, payload
schemas, terminal job states, and retry policy stay in the product repository —
the shared crate owns only the transport posture.

## License

Licensed under [MIT](LICENSE).
