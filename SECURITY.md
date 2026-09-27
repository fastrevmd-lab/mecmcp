# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/fastrevmd-lab/mecmcp/security/advisories/new

Include what you'd include in a bug report — affected version, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

`mecmcp` is the shared foundation underneath mechub's vendor-neutral network-security MCP servers: authentication, transport hardening, audit, policy, secrets, and change control that every vendor server (Junos, PAN-OS, and others being built on top of it) depends on. A vulnerability here doesn't stay local to this repo — it's inherited by every consumer. Vulnerability classes we especially want to hear about:

- Bearer-token or scope-preflight authentication/authorization bypass (`mecmcp-auth`, `mecmcp-transport`).
- Host/Origin validation bypass or DNS-rebinding on a Streamable HTTP listener (`mecmcp-transport`).
- A change set, approval, or operator waiver that can be forged, replayed, or applied without the two-principal check it's supposed to enforce (`mecmcp-changeset`).
- Secret handling that leaks a credential into logs, audit output, or process memory beyond its intended lifetime (`mecmcp-secret`).
- A `mecmcp-policy` rule that can be bypassed, or a `mecmcp-inventory` record that can be spoofed to widen access to a device.
- An audit gap — an action that reaches a device without producing a corresponding, correctly attributed audit record.
- Anything that would let a model's output, rather than deterministic code, decide or apply a change to a device.

## Response

This is a community-maintained project. There's no guaranteed SLA, but reports are read and triaged by a human maintainer, not by any automated or model-based process.
