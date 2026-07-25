# Packaging standard for mechub MCP servers

The reference the server repos link to. Covers how a mechub MCP server is
delivered and installed: container image, LXC, and what the README must contain.

It exists because the two shipping servers had drifted apart — each had what the
other lacked — and two more (`rustproxmoxmcp`, `rustunifimcp`) are starting.
Settling it once is cheaper than reconciling four repos later.

Tracked in [#6](https://github.com/fastrevmd-lab/mecmcp/issues/6).

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

Debian 13 stable, unprivileged, `nesting=1` only where the repo genuinely needs
it. Matching the container's distro generation means one CVE surface to track
rather than two.

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
