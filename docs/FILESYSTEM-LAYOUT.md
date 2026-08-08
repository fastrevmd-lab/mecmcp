# Filesystem layout standard for mechub MCP servers

**Part of [#6](https://github.com/fastrevmd-lab/mecmcp/issues/6).**

## Problem

The two shipping servers chose different layouts:

| | rust-junosmcp | rust-panosmcp |
|---|---|---|
| **Config dir** | `/etc/jmcp` | `/etc/rust-panosmcp` |
| **Service user** | `jmcp` | `rust-panosmcp` |
| **State dir** | `/var/lib/jmcp` | `/var/lib/rust-panosmcp` |
| **Inventory** | `/etc/jmcp/devices.json` | `/etc/rust-panosmcp/devices.json` |
| **Tokens (609)** | `/etc/jmcp/tokens.json` | n/a |
| **Tokens (608)** | n/a | `/var/lib/rust-panosmcp/tokens.json` |

Neither is wrong in isolation, but an operator managing both types them differently for no technical reason. Any shared tooling — backup scripts, config management, log shipping, monitoring — needs a per-vendor path table.

The placement of `tokens.json` diverges across servers **and within the same server** between deployments. LXC 608 keeps tokens at `/var/lib/rust-panosmcp/tokens.json`; the shipped installer would create them at `/etc/rust-panosmcp/tokens.json`. LXC 609 keeps them at `/etc/jmcp/tokens.json`.

This has already caused operational friction: upgrading 601 (the old PAN-OS test rig, now retired) required correcting a systemd drop-in that pointed at the wrong path, because production (608) and the installer disagreed on the canonical location.

## The config vs state split

**`tokens.json` is state, not config.** The server rewrites it on `token add`, `token rotate`, and `token revoke`. By FHS and systemd-tmpfiles principles:

- `/etc/<svc>`: files the operator edits and the server only reads
- `/var/lib/<svc>`: files the server writes

The current split puts a server-written file under `/etc`, which is why an atomic write there needs the **directory** writable — a subtlety that surfaced as a confusing `Permission denied ... at path "/etc/jmcp/.tokens-KNnZkm.tmp"` when only the files, not the directory, had been chowned.

## Standard layout

```
/etc/<binary-name>/
    devices.json                          # read-only inventory (operator-edited)
    audit-hmac.key                        # HMAC key for redaction (mode 0600)
    credentials.env                       # API keys, tenant IDs (mode 0600)
    *.crt, *.key                          # TLS if applicable (keys mode 0600)

/var/lib/<binary-name>/
    tokens.json                           # server-written token state (mode 0600)
    changeset-state.json                  # change-set lifecycle state
    mutation-state.json                   # PAN-OS change-set state
    device-leases/                        # Junos device-lease directory
    staging/                              # Junos file-transfer staging
    srx-staging/                          # Junos SRX support-bundle staging
    audit.jsonl                           # local audit log (if not journald-only)
```

**Service name == binary name.** Use the full crate name as the binary, service, and directory name. No abbreviations unless inherited from an already-deployed system.

| Repo | Binary | Service user | Config | State |
|---|---|---|---|
| `RustJunosMCP` | `rust-junosmcp` | `rust-junosmcp` | `/etc/rust-junosmcp` | `/var/lib/rust-junosmcp` |
| `rust-panosmcp` | `rust-panosmcp` | `rust-panosmcp` | `/etc/rust-panosmcp` | `/var/lib/rust-panosmcp` |
| `rustsdcmcp` | `rustsdcmcp` | `rustsdcmcp` | `/etc/rustsdcmcp` | `/var/lib/rustsdcmcp` |
| `rustproxmoxmcp` | `rustproxmoxmcp` | `rustproxmoxmcp` | `/etc/rustproxmoxmcp` | `/var/lib/rustproxmoxmcp` |
| `rustunifimcp` | `rustunifimcp` | `rustunifimcp` | `/etc/rustunifimcp` | `/var/lib/rustunifimcp` |

## The `jmcp` exception

**LXC 609** (the live Junos deployment on pve2) uses `/etc/jmcp`, `/var/lib/jmcp`, and service user `jmcp`. This predates the standard and is **protected from breaking changes** per PLAN.md.

The standard requires `rust-junosmcp` to honour the existing paths **if present**, and use the standard paths on a fresh install:

```rust
// Example path resolution (conceptual — actual implementation in mecmcp-server)
let config_dir = if Path::new("/etc/jmcp/devices.json").exists() {
    "/etc/jmcp"           // legacy deployment
} else {
    "/etc/rust-junosmcp"  // standard layout
};

let state_dir = if Path::new("/var/lib/jmcp").exists() {
    "/var/lib/jmcp"
} else {
    "/var/lib/rust-junosmcp"
};
```

**No new deployments use the abbreviated form.** A fresh install of `RustJunosMCP` deploys as `rust-junosmcp`, not `jmcp`. The exception exists only to prevent breaking 609.

## LXC 608: the tokens.json discrepancy

**LXC 608** (live PAN-OS on pve2) keeps `tokens.json` at `/var/lib/rust-panosmcp/tokens.json`, which is correct under this standard. However, **the shipped installer as of 0.4.0 would create it at `/etc/rust-panosmcp/tokens.json`**, which is wrong.

### Migration for rust-panosmcp

The `rust-panosmcp` installer must:

1. Check `/var/lib/rust-panosmcp/tokens.json` first (production layout)
2. If absent, check `/etc/rust-panosmcp/tokens.json` (old installer layout)
3. If found in `/etc`, **do not move it automatically** — print a warning and exit:

```
WARNING: tokens.json found at /etc/rust-panosmcp/tokens.json (deprecated location).

The standard location is /var/lib/rust-panosmcp/tokens.json. To migrate:

  sudo systemctl stop rust-panosmcp
  sudo mv /etc/rust-panosmcp/tokens.json /var/lib/rust-panosmcp/tokens.json
  sudo chown rust-panosmcp:rust-panosmcp /var/lib/rust-panosmcp/tokens.json
  sudo chmod 0600 /var/lib/rust-panosmcp/tokens.json
  # Update the unit file or drop-in to point to the new path
  sudo systemctl daemon-reload
  sudo systemctl start rust-panosmcp
```

4. On a fresh install, create `tokens.json` at `/var/lib/rust-panosmcp/tokens.json` only.

**The unit file ships with the standard path** (`--tokens-file /var/lib/rust-panosmcp/tokens.json`). A deployment with tokens in `/etc` must use a drop-in to override it until migrated.

## Why tokens must be in /var/lib

1. **FHS compliance:** `/etc` is for static config; `/var/lib` is for variable state that survives reboots. Tokens are minted, rotated, and revoked by the server.

2. **Atomic writes need directory ownership:** The server writes `tokens.json` atomically via a temp file in the same directory. If the directory is `/etc/<svc>` with mode 0750 and group ownership (as is correct for a config dir where the operator may need to read other files), the service user cannot create the temp file:

   ```
   Permission denied (os error 13) at path "/etc/jmcp/.tokens-KNnZkm.tmp"
   ```

   Fixing this means making `/etc/<svc>` mode 0700 owned by the service user, which blocks root's ability to edit `devices.json` and other config without `sudo -u <svc>`, which is wrong.

3. **Separate backup/restore flows:** Config in `/etc` goes into config management (tracked, versioned, immutable deployments). State in `/var/lib` goes into operational backups (frequent, encrypted, retained). Tokens are secrets that belong in the latter, not the former.

## Permissions

| File | Mode | Owner | Group | Reason |
|---|---|---|---|
| `/etc/<svc>/` | 0750 | root | `<svc>` | Config dir readable by service |
| `/etc/<svc>/devices.json` | 0640 | root | `<svc>` | Operator edits, service reads |
| `/etc/<svc>/audit-hmac.key` | 0600 | `<svc>` | `<svc>` | Secret, service rewrites (on rotate) |
| `/etc/<svc>/credentials.env` | 0600 | `<svc>` | `<svc>` | API keys |
| `/var/lib/<svc>/` | 0700 | `<svc>` | `<svc>` | State dir, service writes |
| `/var/lib/<svc>/tokens.json` | 0600 | `<svc>` | `<svc>` | mecmcp-auth enforces this |
| `/var/lib/<svc>/*.json` | 0600 | `<svc>` | `<svc>` | All state files |

**The 0600 requirement on tokens.json is enforced by mecmcp-auth.** If the file is group- or world-readable, the server refuses to start:

```
Error: token file /var/lib/<svc>/tokens.json is readable by group or world (mode: 0640)
```

An installer that creates the file with a looser mode produces a service that will not start. This is deliberate: it is safer to refuse than to start insecurely.

## systemd-sysusers and systemd-tmpfiles

Every repo ships:

- `packaging/systemd/<binary>.sysusers`
- `packaging/systemd/<binary>.tmpfiles`

### Example sysusers file (rust-panosmcp.sysusers)

```
u rust-panosmcp - "PAN-OS MCP service" /var/lib/rust-panosmcp /usr/sbin/nologin
```

### Example tmpfiles file (rust-panosmcp.tmpfiles)

```
d /etc/rust-panosmcp          0750 root           rust-panosmcp -
d /var/lib/rust-panosmcp      0700 rust-panosmcp  rust-panosmcp -
```

The installer calls:

```bash
systemd-sysusers packaging/systemd/<binary>.sysusers
systemd-tmpfiles --create packaging/systemd/<binary>.tmpfiles
```

## Installer requirements

Every `packaging/lxc/install.sh` must:

1. Create the service user via `systemd-sysusers`
2. Create directories via `systemd-tmpfiles`
3. If `tokens.json` does not exist at the standard location, create it:
   ```bash
   printf '%s\n' '{"version":1,"tokens":[]}' > /var/lib/<svc>/tokens.json
   ```
4. `chmod 0600` the token file
5. `chown <svc>:<svc>` the token file
6. If `audit-hmac.key` does not exist, generate it:
   ```bash
   umask 077
   head -c 32 /dev/urandom > /etc/<svc>/audit-hmac.key
   chown <svc>:<svc> /etc/<svc>/audit-hmac.key
   ```
7. Never overwrite existing state files (`tokens.json`, `changeset-state.json`, `mutation-state.json`)
8. Print the next steps, including paths to edit

## Deployed systems: what changes

### LXC 609 (rust-junosmcp on pve2) — NO CHANGE REQUIRED

The existing `/etc/jmcp` and `/var/lib/jmcp` layout is **locked in** and remains supported. The standard requires new code to detect and honour these paths when present.

### LXC 608 (rust-panosmcp on pve2) — tokens.json already correct

`tokens.json` is already at `/var/lib/rust-panosmcp/tokens.json`, which is the standard location. **No migration needed.**

The shipped unit file as of 0.5.0+ must reference `/var/lib/rust-panosmcp/tokens.json` by default. If an older deployment has a drop-in pointing elsewhere, that drop-in will continue to work (it overrides the shipped unit).

### LXC 606 (rustsdcmcp on pve2) — verify and document

Check the actual layout on 606:

```bash
ssh root@pve2.mechub.org "pct exec 606 -- ls -la /etc/rustsdcmcp"
ssh root@pve2.mechub.org "pct exec 606 -- ls -la /var/lib/rustsdcmcp"
```

If it matches the standard (`/etc/rustsdcmcp`, `/var/lib/rustsdcmcp`, tokens in `/var/lib`), document that it is already compliant. If it diverges, apply the same migration rule as rust-panosmcp.

## New deployments

All new MCP servers (`rustproxmoxmcp`, `rustunifimcp`, and any future vendors) adopt the standard from day one:

- Binary name == service name == directory base
- Config in `/etc/<binary-name>`
- State in `/var/lib/<binary-name>`
- `tokens.json` in `/var/lib/<binary-name>/tokens.json`
- Service user `<binary-name>`

No exceptions, no abbreviations.

## Verification

For each repo, the packaging tests must assert:

1. The sysusers file declares the correct user and home directory
2. The tmpfiles file declares the correct directories with correct modes
3. The unit file references the standard paths for `--tokens-file`, `--state-file`, etc.
4. The installer creates `tokens.json` at the standard location with mode 0600
5. The installer does not overwrite existing `tokens.json`

See `rustsdcmcp/scripts/verify-packaging.sh` for a reference implementation of these checks.
