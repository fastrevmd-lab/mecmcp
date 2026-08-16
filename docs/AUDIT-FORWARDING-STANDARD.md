# Audit forwarding standard — ECS over TCP syslog

**Status: standard.** Every server in the mecmcp family forwards its audit trail
off the host this way. Consumers are expected to ship the configuration, not
invent their own.

## Why this exists

An audit record that only exists on the machine that produced it is not an audit
trail. It is a log file on a box whose operator is the party the record is about.

The mecmcp family already emits good records — server-verified `actor_type`,
`provider`, `on_behalf_of`, plus the client-asserted fields it deliberately keeps
distinct (see `mecmcp-audit`'s `token_verified_fields`). The gap was transport:
those records terminated on the MCP host.

This standard closes that gap and fixes the field format so a collector can parse
every server the same way.

## The rule

1. **Emit JSON, always.** `--audit-format json`. The `text` format is for humans
   reading a terminal; it is not a parse target and must not be forwarded.
2. **Write to a file.** `--audit-log-file <state-dir>/audit.jsonl`. journald-only
   is not sufficient — see "Why not journald" below.
3. **Forward over TCP**, not UDP, with a disk-assisted queue.
4. **Map to ECS** at the collector, not on the MCP host. The host's job is to
   deliver bytes reliably; schema is the collector's concern.

## Why TCP, when everything else is UDP

Device telemetry — flow logs, screen events — is high-volume and individually
disposable. UDP is the right trade there, and the rest of the fleet uses it.

An audit trail is the opposite. It is low-volume, and every record is load
bearing. UDP fails silently: a dropped datagram is indistinguishable from an
action that never happened, and the failure appears nowhere — not on the sender,
not on the collector. For a record whose purpose is to answer "who did this",
silent loss is the one failure mode that cannot be tolerated.

TCP with `action.resumeRetryCount=-1` and a disk-assisted queue means a collector
restart, a network blip, or a reboot buffers rather than discards.

**Volume makes this cheap.** These servers emit two records per tool call. Even a
busy operational server produces a trickle, so the ordering and retransmit cost
that rules TCP out for flow logs is irrelevant here.

## Why not journald

`systemd-journal-upload` exists and would avoid a second daemon. It is not used
because:

- It ships the *whole* journal, not the audit stream. Filtering happens at the
  receiver, so unrelated unit noise crosses the wire.
- The receiver must speak the journal export format. The collector here is
  Vector, whose `socket` source speaks syslog — adding a journal receiver is a
  larger change than adding a file tail.
- The audit file is the artifact operators already inspect. Forwarding the same
  file keeps what is shipped identical to what is read locally.

## Configuration

### On the MCP server

Both flags, in the unit or its drop-in:

```
--audit-format json \
--audit-log-file /var/lib/<service>/audit.jsonl
```

### Forwarder

Ready-to-substitute templates live in
[`packaging/audit-forwarding/`](../packaging/audit-forwarding/) —
`50-mcp-audit.conf` and `logrotate-mcp-audit`, with `@SERVICE@`, `@AUDIT_LOG@`
and `@COLLECTOR@` placeholders. Consumers should install those rather than
retype the config.

`rsyslog` with `imfile`, installed on the MCP host:

```rsyslog
# /etc/rsyslog.d/50-mcp-audit.conf
module(load="imfile")

input(type="imfile"
      File="/var/lib/<service>/audit.jsonl"
      Tag="mcp-audit"
      Severity="info"
      Facility="local5"
      ruleset="mcp_audit_fwd")

ruleset(name="mcp_audit_fwd") {
    action(type="omfwd"
           Target="<collector>" Port="519" Protocol="tcp"
           action.resumeRetryCount="-1"
           queue.type="LinkedList"
           queue.filename="mcp_audit_fwd"
           queue.saveOnShutdown="on"
           queue.maxDiskSpace="256m")
}
```

`queue.saveOnShutdown="on"` is the half that survives a reboot; without it the
in-memory queue is lost exactly when you most need it.

### Rotation

The audit file grows without bound. Ship logrotate alongside the forwarder:

```
/var/lib/<service>/audit.jsonl {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` matters: `imfile` follows an inode, and a rename-based rotation
makes it silently follow the rotated file forever.

## Port assignment

| Port | Source |
|---|---|
| 514 | SRX flow (`security log`) |
| 515 | PAN-OS |
| 516 | UniFi |
| 517 | Proxmox host syslog |
| 518 | Junos system syslog (`system syslog host`) |
| **519** | **mecmcp audit (TCP)** |

519 is TCP. 514–518 remain UDP.

## Field mapping

The record is a `tracing` JSON envelope: `timestamp`, `level`, `target`, and the
audit fields under `fields`. The collector maps it into the shared events schema:

| Column | Source |
|---|---|
| `timestamp` | envelope `timestamp` |
| `event_provider` | `"mecmcp"` |
| `observer_hostname` | MCP host name (`prod-junosmcp`, …) — **not** the managed device |
| `user_name` | `fields.caller` (token name) |
| `event_action` | `fields.action` (`read`, `approve`, `apply`, `transport`, …) |
| `event_outcome` | `fields.result` |
| `event_category` | `"configuration"` when `fields.change_ref` or a change-set tool; else `"process"` |
| `ext` | `actor_type`, `provider`, `provider_tier`, `on_behalf_of`, `client_name`, `model_id`, `session_id`, `tool`, `devices`, `device_count`, `change_ref`, `request_id`, `token_verified_fields` |
| `raw` | the original line |

### Keep the trust boundary visible

`ext.token_verified_fields` lists which provenance fields the **token** vouched
for. Everything else in that group is client-asserted and must not be treated as
authenticated — `client_name`, `model_id` and `session_id` are supplied by the
caller and nothing checks them.

Do not flatten the two groups into one. An auditor who cannot tell a
server-verified `actor_type` from a self-declared `model_id` has a record that
looks stronger than it is.

### `observer_hostname` is the MCP host

The managed device appears in `ext.devices`. Setting `observer_hostname` to the
device would collide with the device's own syslog stream, which arrives on a
different port with a different schema and a different meaning.

## Correlation

`ext.request_id` is the join key. It appears on both audit records for a call —
the transport preflight event and the handler event — and, for Junos, in the
device's commit comment as `request.id=`. That is what links an MCP action to the
change it made on the device.

## What consumers must do

1. Set both audit flags in the shipped unit.
2. Ship `50-mcp-audit.conf` and the logrotate snippet in the package.
3. Depend on `rsyslog`.
4. Document it in the repo README, pointing here for the rationale.

## Known gaps

- **No native sink.** `mecmcp-audit` has no syslog output; forwarding is external
  by necessity. A native TCP sink would remove the second daemon and is worth
  considering once this is proven in the field.
- **No transport authentication.** Plain TCP on a trusted subnet. TLS with a
  client certificate is the obvious hardening step and is deliberately deferred
  rather than forgotten.
- **The collector is a single destination.** No fan-out, no local spool beyond
  the rsyslog queue.
