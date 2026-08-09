# Packaging standard for mechub MCP servers

The reference the server repos link to. Covers how a mechub MCP server is
delivered and installed: container image, LXC, and what the README must contain.

It exists because the two shipping servers had drifted apart — each had what the
other lacked — and two more (`rustproxmoxmcp`, `rustunifimcp`) are starting.
Settling it once is cheaper than reconciling four repos later.

Tracked in [#6](https://github.com/fastrevmd-lab/mecmcp/issues/6).

**See also:** [FILESYSTEM-LAYOUT.md](FILESYSTEM-LAYOUT.md) for the standard
directory structure, config vs state split, and service naming (#28).

---

## 1. Container image

| | Requirement |
|---|---|
| Runtime base | `gcr.io/distroless/cc-debian13:nonroot` |
| Builder base | `rust:<MSRV>-slim-<suite>`, version taken from the repo's `rust-toolchain.toml` |
| Both | digest-pinned, `image@sha256:…` |
| User | `USER 65532:65532` |
| Compose example | `read_only: true`, with explicit writable mounts for state |

**Why distroless.** It carries no shell and no package manager. A process whose
job is holding credentials for firewalls should not sit next to `sh`, `curl`, and
`apt` — after an RCE those are the pivot. `debian:12-slim` ships all three.

**`cc` rather than `static`/`scratch`.** These binaries link `ring`/`rustls`, and
the Junos server also links `russh`. A fully static musl build would allow
`distroless/static` or even `scratch`, which is strictly better, but musl's
allocator and DNS resolution differ enough that it must be measured per repo
before being mandated. See §5.

**Pin the digest at adoption time**, by resolving the tag then — not by copying a
digest out of this document, which is stale the moment it is written.

### Check this before adopting distroless: does the server spawn processes?

**Distroless presumes the binary is the whole program.** There is no shell and
there are no utilities, so anything reached through `Command::new` is simply
absent at run time — and it fails when that code path is first exercised, not at
build or start, which is the worst possible time to find out.

Before moving a repo to distroless, run:

```bash
grep -rn "Command::new" --include='*.rs' <crate>/src/
```

and account for every hit in non-test code.

This is not hypothetical. `rustjunosmcp` cannot currently adopt distroless:

| Path | Spawns | Tools that would break |
|---|---|---|
| `tools/transfer_file.rs` | `scp` | `transfer_file`, `fetch_file` |
| `workflows/support_bundle/mod.rs` | `tar` | `collect_jtac_support_bundle` |

Its Dockerfile installs `openssh-client` precisely for this. `rustpanosmcp` has no
such paths, which is why the identical move succeeded there.

A server in this position has two honest options: move the spawned work into the
binary (SFTP over the SSH connection it already holds; a Rust archive crate
instead of `tar`), which is worth doing anyway because it removes process spawns
from a credential-holding server — or stay on a slim distro base at the same
distro generation as its LXC, and revisit. Embedding static copies of the
utilities is not an option: it restores the attack surface distroless exists to
remove.

### The glibc constraint

A glibc binary runs on the same or newer glibc, never older. So:

> **builder distro generation ≤ runtime distro generation**

Building on `slim-bookworm` (glibc 2.36) and running on `cc-debian13`
(glibc 2.41) is fine. Building on a trixie-based image and running on
`cc-debian12` is not, and fails at container start with a `GLIBC_…not found`
symbol error rather than at build time. When moving the runtime forward, the
builder can stay put; when moving the builder forward, the runtime must move
first.

---

## 2. LXC

**Debian 13 (trixie), unprivileged, `nesting=1`.** All three are requirements,
not defaults — see below.

### The change-set CLI is identical on every server

An operator who learns one mecmcp server must not have to relearn the next.
These three flags mean the same thing, are spelled the same way, and behave the
same way on every server — including ones not written yet:

| Flag | Meaning |
|---|---|
| `--lab-mode` | Run without two-person control; change sets are approved on creation |
| `--state-file` | Absolute path to the change-set and operation state file |
| `--approval-timeout-secs` | How long an approval stays valid |

This was not free. The same three concepts previously appeared as
`--changeset-state-file` and `--changeset-approval-timeout-secs` on Junos,
`--state-file` on PAN-OS, and a hardcoded constant with no flag at all for the
approval TTL — three presentations of three concepts across two servers
(mecmcp#94). Renaming carried the old spellings as aliases rather than breaking
deployments.

Adding a vendor server means adopting these names, not inventing better ones.

#### CLI beats product configuration, but only when actually supplied

A server that also stores these values in its own configuration file needs one
rule, or adopting the standard flags silently moves durable state or changes an
approval lifetime (mecmcp#162). The rule is:

1. **An explicitly supplied CLI value wins.** The operator typed it; nothing
   should override it.
2. **Otherwise product configuration wins**, if the server has such a file.
3. **Otherwise the built-in default.**

The trap is step 1. A defaulted flag is indistinguishable from a supplied one by
value alone — clap hands you `900` either way, and
`--approval-timeout-secs 900` is a legitimate thing to type. Comparing against
the default gets this wrong in both directions: it ignores a flag the operator
did type, and it overrides a config value with a default the operator never
chose.

`mecmcp_runtime::cli::parse_with_provenance` reports which arguments came from
the command line. It parses **your** CLI type, not the shared `Cli` — the flags
this rule exists for, `--approval-timeout-secs` among them, are defined by each
server, so flatten the shared type into your own struct and pass that:

```rust
#[derive(Debug, clap::Parser)]
struct ServerCli {
    #[command(flatten)]
    shared: mecmcp_runtime::cli::Cli,
    #[arg(long, default_value_t = 900)]
    approval_timeout_secs: u64,
}

let parsed = mecmcp_runtime::cli::parse_with_provenance::<ServerCli>(
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

let approval_ttl = if parsed.was_supplied("approval_timeout_secs") {
    parsed.cli.approval_timeout_secs       // the operator asked for this
} else {
    product_config.approval_ttl_secs       // fall back to the file
};
```

`was_supplied` answers for top-level arguments only. `tokens_file` names both a
server flag and an argument of `token add`, and a server asking about its own
flag must not be told "yes" because the operator typed the other one. For a
management subcommand use `was_supplied_in(&["token", "add"], "tokens_file")`,
or `supplied_arguments()` for the whole tree with paths attached.

**A flag that is present but ignored is worse than one that is absent**, because
the operator has no way to tell. A server that cannot honour a standard flag
should refuse at startup and say so, not accept it silently.

#### Reporting the binary's own version

The shared CLI carries no version of its own, so parsing it directly makes
`--version` a clap error rather than an answer — which breaks the
package-identity check a deployment wants to run (mecmcp#159). Use
`parse_for(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))` so `--version`
and `--help` name the binary rather than the shared crate.

#### `--lab-mode` never fabricates an approver

A waived change set records `approver: null` alongside
`approval_waiver: "lab-mode"`. Both fields are required: `approver: null` alone
means *both* "nobody has approved this yet" and "approved without review", and
an operator or SIEM has to tell those apart.

Do not encode the waiver as a sentinel string inside `approver`. A token named
that string would then be indistinguishable from a genuine waiver in every log
line — the same defect this project already hit with `"stdio"` as a principal
sentinel, recorded in PLAN.md.

The waiver is applied automatically at creation, not through a separate tool.
Starting the service with the flag is already the deliberate decision to run
without a second reviewer, and the digest confirmation a waive call would carry
is already enforced by apply, which is what touches the device. The operator's
flow stays plan-then-apply, identical to production.

A server started in lab mode must warn at startup: a relaxed security control
should be visible where someone will see it, not inferred from flags typed weeks
ago.

### Runtime dependencies must be declared, not inherited from the template

A server's runtime dependencies are part of its packaging contract. State them
and have the installer ensure them; do not rely on whatever the chosen template
happens to include.

| Server | Needs | Why |
|---|---|---|
| both | `curl`, `ca-certificates` | the documented endpoint verification |
| Junos | `openssh-client`, `tar` | `transfer_file`, `fetch_file` and `collect_jtac_support_bundle` spawn `ssh`, `scp` and `tar` |
| PAN-OS | — | talks HTTPS and spawns nothing |

The Junos row is the cautionary one. `ssh`, `scp` and `tar` are present in
Debian's **standard** LXC template, so those tools worked from the first
install and nobody wrote the requirement down. That was luck of template
choice: on a minimal template they are absent and three tools fail at runtime,
having installed and started cleanly.

`curl` is the same failure with the opposite outcome — the Debian 13 standard
template does *not* ship it, so the README's own first verification step could
not run on a fresh container (mecmcp#33).

### Adding `curl` to an LXC is fine; adding it to an image is not

The asymmetry is deliberate.

An LXC is a full operating system with a shell and a package manager already
present. Adding `curl` changes nothing an attacker could not do anyway, and it
makes the documented verification work.

A container image is minimal on purpose. `curl` is exactly the pivot tool
§1 cites as the reason for distroless: a process holding firewall credentials
should not ship an HTTP client for an attacker to use after an RCE. PAN-OS is
distroless and cannot accept one at all.

So verify an image without adding anything to it:

- `docker run --rm <image> --version` proves the binary runs
- check the endpoint **from the host**, against the published port
- keep a `HEALTHCHECK` that needs no HTTP client — junos's `CMD kill -0 1`
  proves the process is alive, which is the right shape

### `nesting=1` is required on Debian 13, not optional

Earlier guidance here said "only where the repo genuinely needs it". That is
wrong for Debian 13, and the difference was measured on a clean container:

| `features` | `systemctl is-system-running` | failed units |
|---|---|---|
| *(none)* | `degraded` | `dev-mqueue.mount`, `run-lock.mount`, `tmp.mount` |
| `nesting=1` | `running` | none |

Debian 13 ships **systemd 257**, and Proxmox itself warns at creation time:
`WARN: Systemd 257 detected. You may need to enable nesting.`

The failures are not fatal — `/tmp` and `/run/lock` remain writable as plain
directories rather than tmpfs, and `systemd-journald` starts and is readable
either way. But a permanently `degraded` unit state is something monitoring
flags forever and operators learn to ignore, which is the same failure mode as
a CI gate that goes red for unrelated reasons.

Set it at creation. Adding it afterwards needs a container reboot.

### Why Debian 13 specifically

A glibc binary runs on the same or newer glibc, never older, so the LXC's distro
generation sets a floor on where a release can run. Measured on the published
artifacts:

| | glibc | rustjunosmcp 0.11.0 (needs 2.39) | rustpanosmcp 0.4.0 (needs 2.34) |
|---|---|---|---|
| Debian 12 | 2.36 | **fails at start** | ok |
| Ubuntu 24.04 | 2.39 | exact, no headroom | ok |
| **Debian 13** | **2.41** | ok | ok |

`rustjunosmcp`'s README used to say "Debian 12 / Ubuntu 24.04". That container
builds clean, installs clean, and then dies at first start with
`GLIBC_2.39 not found` — the worst place to find out, because everything up to
that point looks successful.

**Read the floor from the artifact, do not assume it:**

```bash
objdump -T <extracted>/usr/local/bin/<binary> \
  | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -Vu | tail -1
```

The two servers differ — 2.34 versus 2.39 — because `rustpanosmcp` builds in CI
against a fixed base while `rustjunosmcp`'s `package-lxc.sh` builds against
whatever host runs it. **A release built on a developer workstation is only as
portable as that workstation.** New repos should build releases in CI against a
pinned base for this reason; it is also a provenance requirement if the project
is heading for NIST SSDF (SP 800-218) attestation.

### Logging: journald stays, and is configured, not trimmed

The smallest possible container is one without journald. That is the wrong trade
for a server holding firewall credentials, and it forecloses the audit story.

**Never trim:** `systemd`, `systemd-journald`, `ca-certificates`.
**Trim freely:** compilers and toolchains (the installers ship prebuilt binaries
— no repo needs `cargo` or `rustc` in the container), docs, man pages, anything
desktop.
**Per-repo additions:** whatever the binary spawns. `rustjunosmcp` needs
`openssh-client` and `tar` because `transfer_file`, `fetch_file`, and
`collect_jtac_support_bundle` shell out; that is also why it cannot use
distroless (§1).

Configure journald deliberately:

```ini
# /etc/systemd/journald.conf.d/mecmcp.conf
[Journal]
Storage=persistent
SystemMaxUse=512M
```

### Forward Secure Sealing does not work here — forward instead

An earlier version of this section prescribed `Seal=yes` plus
`journalctl --setup-keys` for tamper-evident logs. **That is not achievable in
an unprivileged LXC**, which is the container model this document mandates.
Measured on a clean Debian 13 container and its Proxmox host, both on ext4:

| | `journalctl --setup-keys` |
|---|---|
| Privileged host | succeeds — `/var/log/journal/<id>/fss` created |
| **Unprivileged LXC** | **fails: `Failed to generate key pair: Operation not supported`** |

Same filesystem, so it is not an ext4 limitation. FSS needs to set a file
attribute that the user namespace blocks, and `capsh` reporting `cap_sys_admin`
in the bounding set does not change that. Running the container privileged to
regain sealing would be a far worse trade for a process holding firewall
credentials than losing the feature.

**So remote forwarding is the primary integrity control, not a supplement:**

```
systemd-journal-upload  ->  central journald
        or  rsyslog     ->  site SIEM
```

This is arguably the stronger control regardless. Local sealing only makes
tampering *detectable after the fact*, and only while the attacker lacks the
sealing key — but the threat model that matters here is "the MCP server was
compromised", which is exactly when local evidence is least trustworthy. A copy
already written to a collector the compromised host cannot reach is not merely
detectable-if-edited; it cannot be edited at all.

This matters concretely: `rustpanosmcp`'s approve event carries the change-set
id and digest specifically so there is independent evidence that a second
principal reviewed the exact digest applied. `mutation-state.json` was never
sufficient on its own, because the server rewrites it. If that event exists only
in a local journal on the box that was compromised, it is not independent
evidence of anything.

**Configure forwarding at provisioning, before the server handles real traffic.**
An audit trail that only becomes durable in month two has a two-month hole in
exactly the period when a new deployment is least hardened.

### Audit flags: the baseline every server runs

All servers share the `mecmcp-audit` surface. The deployed baseline is:

```
--audit-format json
--audit-journald
--audit-redact <fields>=hmac
--audit-hmac-key-file /etc/<svc>/audit-hmac.key
```

Turn redaction on **at first install, not later.** Once events are leaving the
box, device names crossing that boundary is a disclosure decision; HMAC
pseudonymisation keeps events correlatable without exporting the inventory.
Retrofitting means re-keying and losing correlation across the change.

The key is passed as a **path**, never as a flag value or environment variable,
so it cannot leak into `ps` output, a unit file, or a container inspect. Mode
0600, owned by the service user.

Every repo ships `packaging/lxc/install.sh`. It must:

- be idempotent and safe to re-run over an existing install
- create the service user and directories via `systemd-sysusers` and
  `systemd-tmpfiles`, from files the repo ships
- install the binary and the unit
- create the token file as `{"version":1,"tokens":[]}` if absent
- **`chmod 0600` the token file and any file holding credentials**
- **never overwrite existing state** — see the hazards below
- print the next steps, including that config must be edited before the service
  will start

### The 0600 requirement is load-bearing

`mecmcp-auth` refuses to load a group- or world-readable token file, and the
server exits rather than starting with credentials exposed. An installer that
creates the file with a looser mode produces a service that will not come up. The
error names the file, its mode, both uids, and the remedy — but the installer
should not produce it in the first place.

---

## 3. Hazards these repos have actually hit

Each of these cost real time on a real deploy. They are the reason this document
is longer than "use distroless".

**A deployed unit may be site-customized rather than stock.** `rust-panosmcp`'s
LXC carries its TLS certificate paths, its bind address, and its
`--allowed-host`/`--allowed-origin` **in the unit file itself**, not in a
drop-in. Running the README's install sequence there would have overwritten the
unit and taken the TLS endpoint down. **Before any upgrade, check whether the
installed unit differs from the shipped one, and if it does, install the binary
only.** An installer should prefer a drop-in over rewriting the unit, and should
say loudly when it is about to replace one.

**State files must survive an upgrade.** `rust-panosmcp` keeps change-set
lifecycle state — plan, approval, and apply records — in
`/var/lib/rust-panosmcp/mutation-state.json`. Deleting or resetting it loses the
approval history that two-person change control depends on. Any file under the
state directory is presumed load-bearing unless the repo says otherwise.

**Do not install a config that cannot boot.** `rustjunosmcp`'s installer copies
`devices.json.example` to `devices.json`; the example contains placeholder paths,
so the first `systemctl enable --now` crash-loops under `Restart=on-failure`.
Both the installer and the README say to edit it first, but the instruction is a
comment between two commands, so anyone pasting the block walks into it. Either
ship only the example and fail with an explicit "no devices configured" message,
or write a minimal valid config that starts.

**Ship a config example inside the archive.** *(Fixed in rustpanosmcp#48 — kept
as a rule for new repos.)* `rustjunosmcp` ships `devices.json.example`;
`rust-panosmcp` did not, and its schema differs from the Junos one, so a tarball
user could not discover the shape without leaving the artifact and reading the
repo.

**README commands must match the archive.** `rust-panosmcp`'s README told users
to `cd rust-panosmcp-v<VER>-x86_64-unknown-linux-gnu` and install
`rust-panosmcp` from the archive root; the archive extracts to
`rust-panosmcp-v<VER>/` and puts the binary in `bin/`. Both commands failed
verbatim. *(Fixed in rustpanosmcp#48.)* **Verify the install section against a
real archive before each release**, or generate the paths — this is the rule that
keeps it fixed.

**Minting a token should not require full runtime credentials.** *(Fixed in
rustpanosmcp#48 via a name-only inventory load.)* `token add` resolved the whole
inventory, so every device's API-key environment variable had to be set before a
token could be created — even though minting never contacts a device. That blocks
an operator setting up before credentials are provisioned.

---

## 4. README

Every repo documents both paths end to end, and both must work verbatim:

1. **LXC** — download, checksum, install, configure, mint the first token, start.
2. **Docker** — image reference, required mounts, the read-only invocation.

Version strings in the install block are refreshed at release, and the block is
tested against the artifact that release actually publishes.

---

## 5. Deferred: static musl

A fully static musl build would allow `distroless/static` or `scratch`, removing
libc from the attack surface entirely. Before mandating it, each repo needs a
spike answering: does `ring`/`rustls` behave, does `russh` behave, does DNS
resolution behave under musl, and what happens to throughput. Until then `cc` is
the standard.

---

## 6. Adoption checklist

For a new repo, or one being brought into line:

- [ ] `grep -rn "Command::new" --include='*.rs' <crate>/src/` accounted for —
      distroless has no shell or utilities, so a spawn is a blocker (see §1)
- [ ] Runtime `gcr.io/distroless/cc-debian13:nonroot`, digest-pinned
- [ ] Builder pinned from `rust-toolchain.toml`, digest-pinned, distro generation
      not newer than the runtime
- [ ] `USER 65532:65532`
- [ ] `packaging/container/compose.example.yaml` runs `read_only: true` with
      explicit writable mounts
- [ ] `packaging/lxc/install.sh` — idempotent, 0600 on credential files, does not
      clobber state, does not install a non-bootable config
- [ ] A config example ships **inside** the release archive
- [ ] README has complete LXC and Docker sections, verified against a real archive
- [ ] CI gates the repo — see [#7](https://github.com/fastrevmd-lab/mecmcp/issues/7)
      for the check set

**LXC and observability (§2):**

- [ ] LXC is **Debian 13**, unprivileged, **`nesting=1`**. The README says so
      and says why. Without nesting, systemd 257 runs `degraded` with three
      failed mounts.
- [ ] The release binary's glibc floor is **measured** with `objdump -T`, not
      assumed, and recorded in the README
- [ ] The release is built **in CI against a pinned base**, not on a developer
      workstation — otherwise the artifact is only as portable as whoever built it
- [ ] `journald` configured `Storage=persistent`. **Not** `Seal=yes` — Forward
      Secure Sealing cannot initialise in an unprivileged LXC (measured; see §2)
- [ ] Remote forwarding configured **at provisioning**, since it is the integrity
      control that replaces sealing, not an optional extra
- [ ] Server runs with `--audit-format json --audit-journald`
- [ ] `--audit-redact` enabled **at first install** with an HMAC key file at
      mode 0600, owned by the service user, passed as a **path**
- [ ] Log forwarding configured (`systemd-journal-upload` or rsyslog) or
      explicitly deferred with a note saying so
- [ ] No `cargo`/`rustc` in the container — the installer ships a prebuilt binary
- [ ] Anything the binary spawns (`grep -rn "Command::new"`) is installed in the
      LXC, and listed in the README
