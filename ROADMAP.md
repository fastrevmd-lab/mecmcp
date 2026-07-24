# Roadmap — what "enterprise grade" means here

Target operating environment: **150 engineers managing 4,000 firewalls across
multiple vendors.** Everything below is scoped by that sentence. Features that
matter at 10 devices and 3 engineers are not the same as features that matter at
4,000 and 150, and the difference is mostly about *blast radius, attribution, and
not needing a human in the loop for the 95% that is routine*.

Sequenced after the extraction phases in [`PLAN.md`](PLAN.md), because most of it
is unbuildable until the shared crates exist.

---

## 1. Identity — static bearer tokens do not reach 150 people

Both servers today authenticate with minted bearer tokens in a JSON file. That
is correct for service automation and wrong for humans: no lifecycle, no group
membership, no offboarding story, and one shared secret per team in practice.

**Add OIDC/JWT for humans, keep minted tokens for automation.**

- Humans authenticate through the enterprise IdP; IdP group claims map to roles.
- Service tokens keep working exactly as today for CI, agents, and schedulers.
- A role is `(device selector, tool set, action tier)` — not a flat list. At
  4,000 devices the selector must be an expression (`site=emea-*`,
  `vendor=panos`, `tag=pci`), not an enumeration.
- **Multi-tenant scoping by site/region/business unit**, so a regional team's
  credentials are *structurally incapable* of touching another region. This is
  the control that makes a 150-person org safe, and it has to be in the scope
  model rather than in a policy document.

Builds on `mecmcp-auth`. The `Principal` type in `mecmcp-audit` is already
designed to carry either a token name or an OIDC subject.

## 2. Attribution — the piece that makes AI-driven ops auditable

Covered as Phase 2 in [`PLAN.md`](PLAN.md); restated here because it is the
answer to a question that will be asked in every audit:

> An LLM made a change at 03:00. Which model, whose authority, which ticket?

`Attribution` lands in the audit event, in the change-set record, **and on the
device itself** (Junos `commit comment`, PAN-OS commit description). The third
one is what matters when someone is reading `show system commit` during an
incident and the MCP server is not the thing they trust.

The `Human | Agent` distinction with `on_behalf_of` is not currently modelled by
any vendor tooling. It will be required before agent-initiated change is
allowed in a regulated environment.

## 3. Blast radius — the single highest-value control at 4,000 devices

A change set that touches 12 devices and one that touches 4,000 are different
kinds of event and must not be authorised the same way.

```
tier      devices    approval
─────────────────────────────────────────────────────────
read      any        none
low       ≤ 5        auto, audited
medium    ≤ 50       second principal
high      ≤ 500      second principal + change window
fleet     > 500      second principal + change window + change ticket
```

Thresholds configurable; the *shape* is the point. Cheap to build on
`mecmcp-changeset` because plan-time already knows the exact device set. This is
the control that prevents the career-ending outage, and it is worth building
before anything in §5.

**Change windows and freeze calendars** attach at the same layer: a change set
carries an intended execution window and is refused outside it.

## 4. Change-ticket binding

A change set can require a valid change reference (ServiceNow, Jira) that is
verified live against the ITSM API at apply time — state must be *approved and
in-window*, not merely well-formed. The reference then flows into `Attribution`
and onto the device commit comment.

This is what turns the audit trail from "the server logged it" into "the change
record and the device agree", which is the only version an auditor accepts.

## 5. Staged rollout — one change set, 4,000 devices

Applying to a fleet is a supervised process, not a loop.

- **Waves:** canary (5) → wave (50) → fleet, with post-wave verification.
- **Automatic halt** on error rate or verification failure crossing a threshold.
- **Automatic rollback** of completed waves on halt, using the pre-change
  snapshots from §7.
- Long-running as a **job with poll**, resumable across a server restart —
  `rustpanosmcp`'s operation-polling and `resolve_persisted_operation` model
  generalise directly.

Requires `mecmcp-changeset` (Phase 5) plus a job/queue layer above it.

## 6. Drift detection

Periodic `fingerprint()` of every device compared against intended state, with
drift reported as a first-class finding. The primitive already exists in
`rustpanosmcp` (`get_candidate_fingerprint`); it needs a scheduler and a store.

At 4,000 devices this is the difference between knowing your posture and
believing your posture. It is also the cheapest early-warning system for
out-of-band changes made by people bypassing the platform.

## 7. Config vault and change-addressed rollback

Pre-change snapshot of every affected device, keyed by change-set id, retained
under policy. Rollback becomes "revert change set `cs-1a2b`" rather than
"someone remembers what it looked like".

`rustjunosmcp` has `rollback_config` (`rollback N`) but no change-set identity to
roll back *to*; this closes that gap and makes §5's automatic rollback possible.

## 8. Inventory at scale

A JSON file is not the backing store for 4,000 devices. `mecmcp-inventory`
becomes a trait in Phase 4 specifically so this can land without touching either
server: a database-backed implementation plus **NetBox/Nautobot sync**, so the
source of truth is the CMDB the rest of the organisation already uses rather
than a file maintained by the network team alone.

## 9. Reliability at fleet scale

- **Idempotency keys with at-most-once apply.** A retried apply must not double-apply.
- **Indeterminate-operation recovery** — already correct in `rustpanosmcp`;
  generalised in Phase 5. The operation whose outcome was never observed is the
  hardest state in this domain and the one most systems ignore.
- **Circuit breakers** per device and per vendor management API. One unhealthy
  Panorama must not consume the whole worker pool.
- **Backpressure** — bounded queues with explicit rejection, not unbounded growth.

## 10. Observability

- **OpenTelemetry traces**, one trace per change set spanning plan → approve →
  apply → verify across every affected device. Metrics alone cannot answer "why
  did this change take 40 minutes".
- **SLO metrics:** apply success rate, approval lead time, drift count, tool
  latency, per-vendor API error rate.
- **Append-only audit sink.** Audit events ship to SSDF (already running,
  ClickHouse-backed) and/or an object-lock bucket. The MCP server must not be
  the only copy of its own audit trail.

## 11. The multi-vendor intent layer — the actual differentiator

Everything above makes a *good* per-vendor platform. This is the part that makes
it a multi-vendor one, and the pieces already exist as skills rather than code:

- `parsing-cisco` / `parsing-fortinet` / `parsing-palo` / `parsing-srx` already
  emit a **common intermediate schema**.
- `firewall-config-conversion` already renders that schema back to native config
  with a per-section fidelity report.
- `firewall-config-diff` already compares by meaning across vendors.

Turn that schema into `mecmcp-intent` — a Rust crate with
`render(vendor) -> native config`. Then:

- a change is **authored once in intent** and rendered per vendor;
- the change-set digest binds the **rendered** output, so an approver reviews
  exactly what will hit the device, not an abstraction of it;
- cross-vendor parity checking becomes a test, not an exercise;
- the six compliance skills (PCI, HIPAA, SOC 2, CIS, CMMC/NIST 800-171,
  ISO 27001) become `mecmcp-compliance`, running continuously across all 4,000
  devices instead of per-engagement.

Plenty of vendors have per-vendor automation. Vendor-neutral intent with
digest-bound approval and continuous compliance on top is the thing that does
not exist off the shelf.

## 12. Vendor coverage

Once the extraction is done, each addition is a protocol adapter plus a tool
surface:

| Vendor | Transport | Notes |
|---|---|---|
| Juniper Junos / SRX | NETCONF/SSH | shipping (`rustjunosmcp`) |
| Palo Alto PAN-OS | HTTPS XML-API | shipping (`rustpanosmcp`) |
| Panorama | HTTPS XML-API | deferred in `rustpanosmcp` TODO; mostly a scoping/device-group problem |
| FortiGate / FortiOS | REST | parsing skill already exists |
| Cisco ASA / FTD | REST / FMC API | parsing skill already exists |
| FortiManager | JSON-RPC | fleet-manager shape, like Panorama |

---

## Suggested order

1. `mecmcp` Phases 0–2 — extraction through attribution.
2. **Blast-radius tiers (§3)** — highest safety return per unit of work, and it
   needs only `mecmcp-changeset`'s plan stage.
3. Phases 3–5 — transport, inventory, change control on Junos.
4. Config vault (§7) and drift detection (§6) — both unlock staged rollout.
5. Staged rollout (§5) and database inventory (§8).
6. OIDC (§1) and change-ticket binding (§4) — organisational integration.
7. `mecmcp-intent` (§11) and the third vendor.
