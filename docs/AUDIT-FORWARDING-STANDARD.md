# Audit forwarding standard

**Status:** emission rules are **normative now**. Transport is **specified but
not yet implemented** — see [#292](https://github.com/fastrevmd-lab/mecmcp/issues/292).

## Why this exists

An audit record that only exists on the machine that produced it is not an audit
trail. It is a log file on a box whose operator is the party the record is about.

The family already emits good records — server-verified `actor_type`, `provider`
and `on_behalf_of`, kept deliberately distinct from client-asserted fields via
`token_verified_fields`. The gap is transport: those records terminate on the MCP
host.

## Part 1 — Emission (normative)

Every server, regardless of how the records are later shipped:

1. **`--audit-format json`.** Always. The `text` format is for reading in a
   terminal; it is not a parse target and must never be forwarded. Five of the
   fifteen deployed servers were emitting `text`.
2. **`--audit-log-file <state-dir>/audit.jsonl`.** journald-only is not
   sufficient — the file is the operator-facing artifact and the natural spool
   source. Eleven of fifteen were journald-only.
3. **Rotate it.** The file grows without bound; the server never truncates it.

These rules are transport-independent and hold under any of the options below.

## Part 2 — Transport

**Decision: direct ClickHouse sink, hash-chained.** SSDF is the schema steward;
the contract is theirs:

- [`audit-evidence-contract-v1.md`](https://github.com/fastrevmd-lab/SSDF/blob/main/docs/audit-evidence-contract-v1.md)
- [`audit-evidence-ingestion.md`](https://github.com/fastrevmd-lab/SSDF/blob/main/docs/audit-evidence-ingestion.md)

Records are written by `mecmcp-audit` directly into `ssdf.audit` over the
ClickHouse HTTP interface, carrying `prev_hash`/`row_hash` so that deletion or
modification of a row is detectable.

Implementation, open questions and design requirements are tracked in
[#292](https://github.com/fastrevmd-lab/mecmcp/issues/292). Two are unresolved
and block coding: the contract's dedup guard requires `SELECT` that its own write
identity is specified not to have, and it is not yet agreed whether the per-call
audit stream ships alongside the change-lifecycle evidence records.

### Why not syslog to the existing collector

A syslog path — `rsyslog` `imfile` tailing the JSON file, forwarding over TCP to
a new Vector source — was designed, staged and rejected. It is worth recording
why, because it is the obvious answer and it is cheaper:

**For it.** No code change in `mecmcp-audit`. Reuses the collector already
ingesting five device sources. `rsyslog`'s disk-assisted queue gives durability
for free — a collector restart or reboot buffers rather than discards.

**Against it, decisively.** The records are unchained. Anyone with write access
to the collector or the events table can edit history undetectably. Every other
link in this chain is tamper-evident by construction: plan digests bind
approvals, approvals name a distinct principal, `token_verified_fields`
separates vouched-for provenance from asserted. Shipping the trail over an
unchained final hop discards that guarantee at exactly the point an auditor
relies on it.

It also lands in `ssdf.events` — the device-telemetry table — rather than
`ssdf.audit`, where SSDF's own MCP servers already write their tool-call trail.
Two tables for one question is a reporting trap.

**What carries over.** If the direct sink ever needs a local spool, `rsyslog`'s
queue semantics are the reference: unlimited retry, disk-assisted, and
`saveOnShutdown` so a reboot does not discard the backlog. Durability was the one
thing the syslog design got right for free, and the direct sink has to build it
deliberately.

## Field mapping

Owned by the SSDF contract, not restated here. Two rules are called out because
getting them wrong produces a record that looks stronger than it is:

- **The observer is the MCP host**, never the managed device. The device is a
  target field. Conflating them collides with that device's own syslog stream,
  which arrives by a different path with different semantics.
- **`token_verified_fields` must survive into the record.** It names which
  provenance fields the *token* vouched for. Everything else in that group —
  `client_name`, `model_id`, `session_id` — is client-asserted and authenticated
  by nothing. An auditor who cannot tell them apart has been misled.

## Correlation

`request_id` is the join key. It appears on both audit records for a call — the
transport preflight event and the handler event — and, for Junos, in the device's
commit comment as `request.id=`. That is what links an MCP action to the change
it made on the device.

## Part 3 — At rest (normative)

Emission and transport are only worth as much as what the events sit in. Applied
to every deployed server 2026-08-20 (rustjunosmcp#299).

### Sealing

journald Forward Secure Sealing is enabled on every server, via a drop-in at
`/etc/systemd/journald.conf.d/10-audit-sealing.conf`:

```ini
[Journal]
Storage=persistent
Seal=yes
```

plus `journalctl --setup-keys --interval=1month`. Sealing proves integrity only
from the moment the keys exist, so it is the first thing to enable and the one
item on this list that cannot be applied retroactively.

**`journalctl --setup-keys` fails on a minimal Debian 13 image** with
`Failed to generate key pair: Operation not supported`, even though
`systemctl --version` reports `+GCRYPT`. systemd 257 *dlopens* libgcrypt, and
the image does not ship it; the real error is one line above, in
`SYSTEMD_LOG_LEVEL=debug` output — `libgcrypt.so.20 is not installed`.
`apt-get install libgcrypt20` is the whole fix. Nothing about the message points
there, so it is recorded here.

The verification key is printed once. It belongs **off** the machine: capture it
to a root-only file and move it, rather than letting it scroll past in a
terminal.

### Sinks

`--audit-journald` and `--audit-log-file` are additive, not alternatives. A
server that needs the standalone JSONL — `mecmcp-verify` and the bench read it
directly — runs **both**, so the same events get FSS coverage without taking the
file away. That is the resolution of the "609 sink question": no server has to
choose.

### Redaction

`--audit-redact <field>=hmac` with `--audit-hmac-key-file`, the key passed **by
path** so it can never appear in `ps` output or a unit file, mode 0600 and owned
by the service user. Pseudonymised values are stable
(`devices=hmac:63206a19…`), so correlation survives export while the inventory
does not leave the box.

Enabling it is a one-way door: events written before it are cleartext and will
not correlate with pseudonymised ones written after. Enable it on a server
before its trail matters, not after.

### Retention

Stated, not inherited, at
`/etc/systemd/journald.conf.d/20-audit-retention.conf`:

```ini
[Journal]
SystemMaxUse=512M
SystemKeepFree=256M
MaxRetentionSec=90day
MaxFileSec=1day
```

Without these, journald sizes itself to 10% of the filesystem and discards
silently — how far back the trail reaches becomes a property of disk pressure
rather than a decision. The tighter of `MaxRetentionSec` and `SystemMaxUse`
wins, so raising one alone silently keeps less than it claims.

JSONL sinks get the equivalent through logrotate: `daily`, `rotate 14`,
`compress`, `copytruncate`, `create 0600 <service> <service>`. The mode matters
— an audit file every account on the box can read is not an audit trail.

## Known gaps

- **No native sink yet.** That is #292. Central forwarding
  (`systemd-journal-upload`/rsyslog) is deliberately **not** configured: the
  destination this family wants is the hash-chained SSDF sink, and standing up
  a second, unchained forwarding path first would be the thing #292 exists to
  avoid.
- **The device-side record omits the approver.** A two-person apply commits
  naming only the applier — see
  [rustjunosmcp#307](https://github.com/fastrevmd-lab/rustjunosmcp/issues/307).
- **Retention and journald sealing** are done — see Part 3
  ([rustjunosmcp#299](https://github.com/fastrevmd-lab/rustjunosmcp/issues/299)).
