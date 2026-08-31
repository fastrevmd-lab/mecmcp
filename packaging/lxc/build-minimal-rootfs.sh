#!/usr/bin/env bash
#
# Build a minimal Debian rootfs for an LXC that runs one mecmcp-family Rust
# service under systemd.
#
# Keeps glibc and systemd deliberately. The guests' entire enforcement posture
# is systemd unit directives -- CapabilityBoundingSet, SystemCallFilter,
# ProtectSystem=strict, RestrictAddressFamilies -- so dropping PID 1 would mean
# reimplementing seccomp and namespace restriction in bespoke code. And glibc is
# what keeps nsswitch resolution, which is how these servers reach devices by
# hostname. See mecmcp#347; the musl route was measured and rejected in #320.
#
# Produces a tarball suitable for `pct create <vmid> local:vztmpl/<file>`.
#
# Requires mmdebstrap and zstd. Neither is installed on the Proxmox hosts and
# neither should be: run this on a workstation, or in a container, and upload
# the result.
#
#   ./build-minimal-rootfs.sh [output.tar.zst]
#
# Then, on the Proxmox host. Unprivileged and nesting=1 are requirements rather
# than defaults -- see docs/PACKAGING.md. Without nesting the guest boots
# `degraded` with failed mounts, which is not the verified configuration:
#
#   pct create <vmid> local:vztmpl/<file> \
#     --ostype debian --unprivileged 1 --features nesting=1 \
#     --hostname <name> --cores 1 --memory 512 --swap 512 \
#     --rootfs <storage>:4 \
#     --net0 name=eth0,bridge=vmbr0,firewall=1,ip=dhcp,type=veth
#
set -euo pipefail

SUITE="${SUITE:-trixie}"
ARCH="${ARCH:-amd64}"
MIRROR="${MIRROR:-http://deb.debian.org/debian}"
SECURITY_MIRROR="${SECURITY_MIRROR:-http://security.debian.org/debian-security}"
OUT="${1:-minimal-${SUITE}-${ARCH}-mcp.tar.zst}"

# All three suites, not just the base one. mmdebstrap writes the mirrors it was
# given into the image's apt sources, so passing only the base suite produces a
# guest that cannot see security fixes -- at build time or ever afterwards.
MIRRORS=(
  "deb ${MIRROR} ${SUITE} main"
  "deb ${MIRROR} ${SUITE}-updates main"
  "deb ${SECURITY_MIRROR} ${SUITE}-security main"
)

# Why each package is here. Everything absent is absent on purpose.
#
#   systemd, systemd-sysv  PID 1 and the unit directives that enforce the posture
#   ca-certificates        TLS trust for outbound HTTPS
#   libgcc-s1              the service binaries link libgcc_s.so.1 (ldd confirms)
#   ifupdown2, iproute2    REQUIRED. Proxmox writes /etc/network/interfaces, and
#                          without ifupdown nothing reads it: the guest boots
#                          with no address, no route and no DNS. Measured.
#   isc-dhcp-client        REQUIRED for a guest created with ip=dhcp. ifupdown2
#                          delegates a dhcp stanza to an external client and only
#                          *suggests* one, so without this a DHCP guest fails the
#                          same way -- no address, no route, no DNS.
#   openssh-server         operator access; `pct exec` works without it, ssh does not
#   curl                   operator debugging and health checks against the
#                          service's own HTTP endpoint
INCLUDE="systemd,systemd-sysv,ca-certificates,libgcc-s1,ifupdown2,iproute2,isc-dhcp-client,openssh-server,curl"

# Units that cannot succeed in an unprivileged LXC. Left unmasked they leave the
# guest permanently `degraded`, which trains operators to ignore that signal --
# the stock Proxmox template masks the first two for the same reason.
#
#   sys-kernel-config.mount / sys-kernel-debug.mount  no access to those trees
#   systemd-modules-load.service                      cannot load kernel modules
#   systemd-networkd-wait-online.service              ifupdown owns the interface,
#                                                     so networkd never configures
#                                                     one and this always times out
MASK="sys-kernel-config.mount sys-kernel-debug.mount systemd-modules-load.service systemd-networkd-wait-online.service"

# Both, before the bootstrap: a missing zstd would otherwise surface only after
# the whole rootfs has been built, leaving no archive to show for it.
for tool in mmdebstrap zstd; do
  command -v "$tool" >/dev/null || { echo "$tool not found; install it first" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --architectures is explicit rather than inherited from the build host: this is
# documented as a workstation build, and an arm64 workstation would otherwise
# produce an arm64 rootfs that silently cannot run an x86-64 service binary.
# The hooks are deliberately not suppressed with `|| true`. A mask that fails
# yields a guest that is permanently `degraded`, and a key-strip that fails
# yields a template carrying private keys -- both are worse than no artifact.
mmdebstrap --variant=minbase \
  --architectures="$ARCH" \
  --include="$INCLUDE" \
  --customize-hook="chroot \$1 systemctl mask $MASK >/dev/null" \
  --customize-hook="rm -f \$1/etc/ssh/ssh_host_*" \
  --customize-hook="rm -f \$1/etc/resolv.conf \$1/etc/hostname" \
  --customize-hook="install -m 0644 /dev/stdin \$1/etc/systemd/system/regenerate-ssh-host-keys.service <<'UNIT'
[Unit]
Description=Regenerate missing SSH host keys
# A template must not ship host keys: every guest built from it would share one
# server identity. They are stripped at build time and made here instead, once,
# before sshd can answer.
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key
Before=ssh.service
Before=sshd.service
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT" \
  --customize-hook="chroot \$1 systemctl enable regenerate-ssh-host-keys.service >/dev/null" \
  --format=tar "$SUITE" "$work/rootfs.tar" "${MIRRORS[@]}"

zstd -q -19 -T0 -f "$work/rootfs.tar" -o "$OUT" 2>/dev/null \
  || zstd -q -f "$work/rootfs.tar" -o "$OUT"

printf 'built %s (%s, %s)\n' "$OUT" "$ARCH" "$(du -h "$OUT" | cut -f1)"
