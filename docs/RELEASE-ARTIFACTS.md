# Release artifact standard for mechub MCP servers

**Part of [#6](https://github.com/fastrevmd-lab/mecmcp/issues/6).**

## Problem

The two shipping servers disagree on artifact naming, archive layout, and where/how releases are built:

### Artifact naming

```
rust-junosmcp_0.11.0_amd64.tar.gz                       # deb-style naming
rust-panosmcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz    # rust target triple
```

Different separators, different version prefix (`0.11.0` vs `v0.4.0`), different arch spelling (`amd64` vs `x86_64-unknown-linux-gnu`). Any script fetching "the latest release for this platform" needs a per-repo naming rule.

### Archive layout

```
rust-junosmcp_0.11.0_amd64/
    install.sh                                           # installer at root
    bin/rust-junosmcp
    ...

rust-panosmcp-v0.4.0/
    packaging/lxc/install.sh                             # installer nested
    bin/rust-panosmcp
    ...
```

The documented install command differs structurally, not just in path. This has already caused a defect: `rust-panosmcp`'s README once told users to `cd` into a directory that did not exist and run a binary from the archive root when it was in `bin/` — both commands failed verbatim (fixed in rustpanosmcp#48).

### Reproducible builds — the one with teeth

**PAN-OS builds releases in CI against a fixed base. Junos builds via `package-lxc.sh` on whatever workstation runs it.** Measured on the published binaries:

| | glibc floor |
|---|---|
| rustpanosmcp 0.4.0 | **2.34** |
| rustjunosmcp 0.11.0 | **2.39** |

Same standard, different floors, purely because of where the build happened. Consequences already observed:

- Junos's README said the LXC could be "Debian 12 / Ubuntu 24.04". Debian 12 ships glibc 2.36, so that container builds clean, installs clean, then **dies at first start** with `GLIBC_2.39 not found` (fixed in rustjunosmcp#216).
- The floor can rise silently. Build Junos on a newer workstation and the artifact stops running on containers that worked yesterday, with nothing in the repo changed.

**For SSDF work in #26 this is the blocking item:** an artifact that cannot be reproduced from the repo alone fails the first provenance question anyone asks. Signing it would only prove who built it, not what it was built from.

### Checksums

Junos's `package-lxc.sh` originally emitted no `.sha256`, so it was hand-generated and captured the build machine's **absolute path** — verifying only on that machine (rustjunosmcp#207). The packaging script must emit it, generated from inside the output directory so the filename field is bare.

## Standard

### 1. Artifact naming

```
<binary-name>-v<version>-<target-triple>.tar.gz
```

Examples:
```
rust-panosmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
rust-junosmcp-v0.12.0-x86_64-unknown-linux-gnu.tar.gz
rustsdcmcp-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
```

- `<binary-name>`: from `Cargo.toml` `[package] name` (matches the binary, service, and directory names per FILESYSTEM-LAYOUT.md)
- `v<version>`: `v` prefix + semantic version from `Cargo.toml` `[package] version`
- `<target-triple>`: Rust target triple (`x86_64-unknown-linux-gnu` for AMD64 Linux glibc)
- Extension: `.tar.gz` (gzip-compressed POSIX tar)

**Do not abbreviate the arch.** Use the full Rust target triple, not `amd64`. The triple is unambiguous across ecosystems; `amd64` is Debian-specific and loses information (musl vs glibc, for instance).

**Always include the `v` prefix in the version.** This matches Git tag conventions and GitHub release URL patterns.

### 2. Archive layout

```
<archive-root>/
    bin/<binary-name>                                    # the server binary (mode 0755)
    packaging/lxc/install.sh                             # installer (mode 0755)
    packaging/systemd/<binary-name>.service              # systemd unit
    packaging/systemd/<binary-name>.sysusers             # systemd-sysusers declaration
    packaging/systemd/<binary-name>.tmpfiles             # systemd-tmpfiles declaration
    packaging/journald/mecmcp.conf                       # journald config (shared name)
    config/<product>.json.example                        # config file template
    docs/operations.md                                   # deployment and operations guide
    BUILD-INFO                                           # build provenance (see below)
    SBOM.cdx.json                                        # CycloneDX SBOM
    README.md                                            # package-specific README
    LICENSE                                              # MIT license
    SECURITY.md                                          # security model and contact
```

**`<archive-root>` == `<binary-name>-v<version>`** (no target triple in the directory name, only in the tarball filename).

Example for `rust-panosmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz`:
```
rust-panosmcp-v0.5.0/
    bin/rust-panosmcp
    packaging/lxc/install.sh
    ...
```

### 3. BUILD-INFO format

A key=value file (shell-sourceable, one line per key) recording build provenance:

```
release_status=public
version=0.5.0
git_commit=<40-char-hex-sha>
source_date_epoch=<unix-timestamp>
target=x86_64-unknown-linux-gnu
mecmcp_ref=v0.8.1
glibc_floor=2.34
rustc=rustc <version> (<commit> <date>)
```

| Key | Value | Example | Required |
|---|---|---|---|
| `release_status` | `public` or `lab-only` | `public` | Yes |
| `version` | Semantic version from `Cargo.toml` | `0.5.0` | Yes |
| `git_commit` | Full 40-char Git SHA, lowercase hex | `3eac110fd72...` | Yes |
| `source_date_epoch` | Unix timestamp of HEAD commit | `1723123456` | Yes |
| `target` | Rust target triple | `x86_64-unknown-linux-gnu` | Yes |
| `mecmcp_ref` | Git tag of mecmcp dependency | `v0.8.1` | Yes |
| `glibc_floor` | Highest GLIBC version required | `2.34` | Yes |
| `rustc` | Output of `rustc -vV` on one line | `rustc 1.88.0 (...)` | Yes |

**Why mecmcp_ref is mandatory:** It pins the exact shared-crate version in a form that is verifiable against the SBOM and traceable to a Git commit. A consumer can prove that this release was built from a specific version of the shared foundation, which is critical for provenance and SSDF attestation.

**Derive mecmcp_ref, don't hardcode it.** The builder script extracts it from `Cargo.toml`:

```bash
mapfile -t mecmcp_refs < <(grep -oP 'tag = "\K[^"]+' Cargo.toml | sort -u)
[[ ${#mecmcp_refs[@]} -eq 1 ]] || fail "expected exactly one mecmcp tag, found: ${mecmcp_refs[*]}"
mecmcp_ref=${mecmcp_refs[0]}
```

This is enforced in rustsdcmcp: the builder derives `mecmcp_ref`, the installer validates it, and the CI workflow asserts it matches a pinned value. The coupling is deliberate — a package built from one ref cannot be installed by a script expecting another.

**Why glibc_floor is mandatory:** A glibc binary requires the glibc version it was built against or newer. If the floor is not recorded and communicated, operators install on a too-old host and the binary fails at startup with a cryptic symbol error. Measure it from the binary:

```bash
glibc_floor=$(objdump -T bin/<binary> \
    | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' \
    | sed 's/GLIBC_//' | sort -Vu | tail -1)
```

### 4. SBOM (Software Bill of Materials)

- Format: **CycloneDX JSON**
- Generator: `trivy filesystem --scanners vuln --format cyclonedx` or `cargo-cyclonedx`
- Filename: `SBOM.cdx.json`
- Required metadata:
  - `.bomFormat == "CycloneDX"`
  - `.metadata.component.name == "<binary-name>"`
  - `.components` is a non-empty array
  - All `mecmcp-*` crates are listed with their exact versions

**Pin the Trivy version.** CycloneDX identifiers and timestamps are generated by Trivy, so the SBOM is not claimed to be byte-for-byte reproducible — but the *format* and *component set* must be stable. rustsdcmcp pins Trivy 0.70.0 and fails the build if a different version is found.

**Skip worktree and dist directories.** A nested checkout or worktree under the repo root gets scanned as a second copy of every dependency, producing duplicate components in the SBOM. The assertions below then fail:

```bash
trivy filesystem --scanners vuln --format cyclonedx \
    --skip-dirs target,dist,.git,.worktrees,.claude \
    --output SBOM.cdx.json "$repo_root"
```

**Validate the component set.** The builder and installer both assert the exact mecmcp component set and version:

```jq
# In jq (builder, installer, CI)
(
    [.components[]
     | select(.name? | strings | startswith("mecmcp-"))
     | [.name, .version]]
    | sort
) == [
    ["mecmcp-audit", "0.8.1"],
    ["mecmcp-auth", "0.8.1"],
    ["mecmcp-changeset", "0.8.1"],
    ["mecmcp-runtime", "0.8.1"],
    ["mecmcp-secret", "0.8.1"],
    ["mecmcp-server", "0.8.1"],
    ["mecmcp-transport", "0.8.1"]
]
```

This catches: version drift (mixed 0.8.0 and 0.8.1), stale refs (v0.7.3 still present), and the nested-checkout duplication issue.

**Prohibit absolute paths.** The SBOM must not contain the builder's filesystem layout:

```bash
! grep -Eq '"/(home|workspace|workspaces)/' SBOM.cdx.json \
    || fail 'SBOM contains an absolute repository or worktree path'
```

### 5. Checksum

- Format: `sha256sum` output (`<hash> <filename>`)
- Filename: `<archive>.sha256`
- Generated **from inside the output directory**, so the filename field is bare (not an absolute path)

```bash
(
    cd "$dist_dir"
    sha256sum "$(basename -- "$archive")" > "$(basename -- "$checksum")"
    sha256sum -c "$(basename -- "$checksum")"  # verify immediately
)
```

**Why this matters:** A hand-generated checksum captured one build machine's absolute path and verified only on that machine (rustjunosmcp#207). The packaging script must emit it, and CI must verify it from a different directory to prove the filename is bare.

### 6. Reproducible builds in CI

**All releases are built in CI against a pinned base.** No workstation builds, no "it works on my machine" floors.

```yaml
# .github/workflows/release.yml excerpt
- name: Build release binary
  run: |
    # Pin the builder base to match rust-toolchain.toml
    BUILDER_IMAGE="rust:$(cat rust-toolchain.toml | grep channel | cut -d'"' -f2)-slim-bookworm"
    # Build in a container to ensure reproducibility
    docker run --rm -v "$PWD":/workspace -w /workspace \
      "$BUILDER_IMAGE" \
      cargo build --release --locked
```

**The builder distro generation must not be newer than the runtime.** Building on `slim-trixie` (glibc 2.40+) and shipping an LXC installer that says "Debian 12" (glibc 2.36) produces a binary that cannot run on the documented target.

**Lock the Cargo.lock.** Pass `--locked` to `cargo build` so a stale lock file is an error, not silently resolved to different dependencies than the developer tested.

### 7. Package README

The archive ships a **package-specific README**, not the repository's development README. The repository README documents how to build from source, run tests, and contribute. The package README documents:

- What this artifact is (binary name, version, Git commit, mecmcp ref)
- Prerequisites (Debian version, glibc floor, RAM/CPU/disk, network access)
- How to verify integrity (checksum validation)
- Installation (one command that works verbatim: `sudo packaging/lxc/install.sh`)
- Next steps (where to find the operations guide)
- Security model (briefly — link to SECURITY.md for detail)
- License and disclaimers

**Why this exists:** Copying the repo README shipped every archive with download instructions for the **previous release** — lab.3 told its reader to fetch lab.1. Instructions for obtaining an archive are meaningless inside that archive; what a reader here needs is what this is and where to go next.

**Generate it, don't copy it.** The package README embeds version numbers, Git SHAs, and glibc floors that change on every release. Generate it from a template so the version strings cannot drift.

### 8. Testing the artifact

Every repo ships `packaging/tests/package-smoke.sh <archive>`. It runs without installing, asserting:

1. Checksum verifies against the sibling `.sha256`
2. Archive is POSIX tar, gzip-compressed
3. No unsafe member paths (absolute, `..`, symlinks)
4. Exactly one root directory
5. All required files present (bin, installer, unit, sysusers, tmpfiles, BUILD-INFO, SBOM, README, LICENSE, SECURITY)
6. BUILD-INFO contains all required keys with valid formats
7. `mecmcp_ref` in BUILD-INFO matches the expected pinned value
8. SBOM is valid CycloneDX with all expected mecmcp components at correct versions
9. SBOM contains no absolute paths
10. Installer script is executable and passes `bash -n`

CI runs this on every release build.

### 9. Archive generation

**Reproducible tar creation:**

```bash
find "$package_root" -print0 | LC_ALL=C sort -z \
    | tar --create --gzip --file="$archive" --format=posix --sort=name \
        --owner=0 --group=0 --numeric-owner \
        --mtime="@$source_date_epoch" \
        --pax-option=delete=atime,delete=ctime --no-recursion \
        --null --files-from=-
```

- `--format=posix`: reproducible tar format
- `--sort=name`: deterministic file order (combined with `LC_ALL=C sort -z` on input)
- `--numeric-owner --owner=0 --group=0`: strip host uid/gid/names
- `--mtime="@$source_date_epoch"`: use commit timestamp, not build time
- `--pax-option=delete=atime,delete=ctime`: strip access/change times (only mtime remains)
- `--no-recursion --null --files-from=-`: explicit file list from sorted input

This produces identical tarballs across machines given the same Git commit, modulo SBOM generation (which Trivy timestamps).

## CI workflow: what every repo must run

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq

      - name: Validate rust-toolchain.toml
        run: |
          MSRV=$(grep channel rust-toolchain.toml | cut -d'"' -f2)
          [[ -n "$MSRV" ]] || exit 1

      - name: Build release package
        run: |
          # Run the builder script (produces archive + checksum in dist/)
          ./scripts/build-release.sh

      - name: Smoke test package
        run: |
          ARCHIVE=$(find dist -name '*.tar.gz' -type f | head -1)
          packaging/tests/package-smoke.sh "$ARCHIVE"

      - name: Verify package provenance
        run: |
          ARCHIVE=$(find dist -name '*.tar.gz' -type f | head -1)
          EXTRACTED=$(mktemp -d)
          tar -xzf "$ARCHIVE" -C "$EXTRACTED"
          BUILD_INFO="$EXTRACTED/*/BUILD-INFO"
          
          # Assert mecmcp ref matches expectation
          grep -Fqx 'mecmcp_ref=v0.8.1' "$BUILD_INFO" || exit 1
          
          # Assert glibc floor is documented
          grep -Eq '^glibc_floor=[0-9]+\.[0-9]+' "$BUILD_INFO" || exit 1

      - name: Upload release artifacts
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v4
        with:
          name: release-package
          path: dist/*.tar.gz*
          retention-days: 90
```

**Why the main-push condition on upload matters:** Without it, every branch push uploads artifacts, filling storage and making "the release" ambiguous. rustsdcmcp enforces this: the upload step has `if: github.event_name == 'push' && github.ref == 'refs/heads/main'`, and the packaging verifier asserts the condition is attached to the right step (not a different YAML block).

## Installer contract

Every `packaging/lxc/install.sh` must:

1. **Validate the package before mutating the system.** Run all structural checks (layout, BUILD-INFO, SBOM) before `apt-get`, `systemd-sysusers`, or any write. Fail fast if the package is corrupt or mismatched.

2. **Derive paths from the package root, not hardcoded literals.** The installer runs from `<archive-root>/packaging/lxc/install.sh`, so:
   ```bash
   package_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
   ```

3. **Refuse an unsafe root.** Reject symlinks, non-directories, or paths outside the extraction directory:
   ```bash
   [[ -d "$package_dir" && ! -L "$package_dir" ]] || die 'package root is not a real directory'
   ```

4. **Install runtime dependencies explicitly:**
   ```bash
   DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       curl ca-certificates jq
   ```

5. **Never overwrite state files.** Check for `tokens.json`, `changeset-state.json`, `mutation-state.json` before creating. Preserve them on upgrade.

6. **Set permissions correctly:**
   - Config dir: `0750 root:<service-user>`
   - State dir: `0700 <service-user>:<service-user>`
   - Token file: `0600 <service-user>:<service-user>` (mecmcp-auth enforces this)
   - HMAC key: `0600 <service-user>:<service-user>`

7. **Print next steps.** The installer never enables or starts the service — config and credentials must be in place first. Tell the operator exactly what to do:
   ```
   Installation complete. Next steps:
   1. Edit /etc/<service>/devices.json
   2. Create /etc/<service>/credentials.env with API keys (mode 0600)
   3. Mint a token: <service> token add --name operator --scope ...
   4. systemctl start <service>
   ```

## Verification checklist for each repo

- [ ] Artifact naming: `<binary>-v<version>-<target>.tar.gz`
- [ ] Archive layout matches the standard (installer at `packaging/lxc/install.sh`, binary in `bin/`)
- [ ] `BUILD-INFO` with all required keys, derived (not hardcoded) where applicable
- [ ] `SBOM.cdx.json` with CycloneDX format, exact mecmcp component set validated
- [ ] Checksum generated from inside output dir, verified in CI from a different path
- [ ] Release built in CI against pinned base (no workstation builds)
- [ ] `packaging/tests/package-smoke.sh` exists and is called in CI
- [ ] Package README is generated (embeds version, commit, glibc floor)
- [ ] Installer validates package structure before mutating system
- [ ] Installer sets all file permissions correctly (especially 0600 on tokens)
- [ ] CI asserts artifact upload only on main-branch push

## What each consumer repo must change

### RustJunosMCP

1. **Rename artifacts:** `rust-junosmcp_0.11.0_amd64.tar.gz` → `rust-junosmcp-v0.12.0-x86_64-unknown-linux-gnu.tar.gz`
2. **Move installer:** from archive root to `packaging/lxc/install.sh`
3. **Add BUILD-INFO** with all required keys (especially `mecmcp_ref` and `glibc_floor`)
4. **Add SBOM generation** (Trivy or cargo-cyclonedx)
5. **Build in CI,** not via local `package-lxc.sh` — pin builder image to `rust-toolchain.toml` MSRV
6. **Add `packaging/tests/package-smoke.sh`** (port from rustsdcmcp)
7. **Generate package README** (don't copy repo README)
8. **Installer validation:** assert BUILD-INFO, SBOM, mecmcp_ref before any mutation

### rust-panosmcp

1. **Archive layout already correct** (installer at `packaging/lxc/install.sh`)
2. **Add BUILD-INFO** with all required keys
3. **SBOM validation:** assert exact mecmcp component set in builder, installer, CI
4. **Derive mecmcp_ref** from Cargo.toml (don't hardcode it in multiple places)
5. **Add `packaging/tests/package-smoke.sh`**
6. **Checksum generation:** ensure it's from inside output dir (bare filename)
7. **CI:** add provenance verification step (BUILD-INFO mecmcp_ref, glibc floor)

### rustsdcmcp

**Already compliant.** This is the reference implementation. The standard generalizes from its packaging/ directory and scripts/.

### rustproxmoxmcp, rustunifimcp

Adopt the standard from the start. Use rustsdcmcp's `scripts/build-lab-package.sh`, `scripts/verify-packaging.sh`, and `packaging/tests/package-smoke.sh` as templates.

## See also

- [FILESYSTEM-LAYOUT.md](FILESYSTEM-LAYOUT.md) — directory structure, config vs state split
- [PACKAGING.md](PACKAGING.md) — container images, LXC base, README requirements
- Issue #26 — SSDF observability and provenance baseline (this work enables it)
