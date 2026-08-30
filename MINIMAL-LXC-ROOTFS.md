# Minimal LXC rootfs for a mecmcp-family server

Result of the spike in [#347](https://github.com/fastrevmd-lab/mecmcp/issues/347),
which followed [#320](https://github.com/fastrevmd-lab/mecmcp/issues/320) closing
the static-musl route as answered **no**.

Build with [`packaging/lxc/build-minimal-rootfs.sh`](packaging/lxc/build-minimal-rootfs.sh),
then create the guest. **Unprivileged and `nesting=1` are requirements, not
defaults** — see [`docs/PACKAGING.md`](docs/PACKAGING.md). Without nesting the
guest boots `degraded` with failed mounts, which is not the configuration
verified below:

```
pct create <vmid> local:vztmpl/<file> \
  --ostype debian --unprivileged 1 --features nesting=1 \
  --hostname <name> --cores 1 --memory 512 --swap 512 \
  --rootfs <storage>:4 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=dhcp,type=veth
```

The template carries no `/etc/hostname` or `/etc/resolv.conf`: `mmdebstrap`
copies the builder's by default, which would put a workstation hostname and an
internal nameserver into a distributed artifact. `pct create` writes both.

## What it costs and what it saves

Measured on real guests on the mechub cluster, not in a container:

| | packages | rootfs | listening |
|---|---|---|---|
| Stock Proxmox Debian 13 template, as deployed | 257 | 911 MB | `:22`, `:25` (postfix), the service |
| Built by this script, service installed and running | **146** | **260 MB** | `:22`, the service |

**-111 packages, -651 MB, and one fewer listening network service.**

## The service needs almost none of a Debian userland

```
$ ldd /usr/local/bin/rust-junosmcp
    linux-vdso.so.1
    libgcc_s.so.1
    libm.so.6
    libc.so.6
    /lib64/ld-linux-x86-64.so.2
```

Four libraries. TLS and crypto are compiled in. Everything else on a stock guest
is there for the *template*, not for the service.

## A mail server was running on every guest

The stock template installs and starts **postfix**, listening on `:25`. Nothing
uses it. It is also the sole reason `libicu76` — 36.5 MB, the largest single
package on the guest — is installed:

```
$ apt-cache rdepends --installed libicu76
Reverse Depends:  postfix
```

Purge postfix and `libicu76` has zero installed reverse-dependencies. An MTA
listening on a change-control host is attack surface with no benefit, and it is
the single most valuable thing this image removes.

## Why you cannot get here by purging

Trimming a stock guest reaches about 228 packages and then stops:

```
$ apt-cache rdepends --installed perl
Reverse Depends:  debconf, adduser
```

The 48 MB Perl stack is held by `perl`, which is held by `debconf` and
`adduser` — base packages the template wires in. Reaching 145 means *building*
the rootfs, not trimming one. Purging remains a useful incremental step for
guests already deployed; it buys roughly 250 MB and removes postfix.

## What is in the image, and why

`systemd` + `systemd-sysv` — PID 1. The enforcement posture of these guests *is*
systemd unit directives, so replacing the supervisor would mean reimplementing
seccomp and namespace restriction in code we maintain. `ca-certificates` for TLS
trust. `libgcc-s1` because the binaries link it. `openssh-server` and `curl` for
operators. And:

**`ifupdown2` + `iproute2` are required, not optional.** Proxmox writes
`/etc/network/interfaces`, and with no ifupdown nothing reads it: the first build
of this image booted with no address, no route and no DNS. That was measured, not
predicted.

`isc-dhcp-client` is required for the same reason on a guest created with
`ip=dhcp`. `ifupdown2` hands a dhcp stanza to an external client and only
*suggests* one, so a DHCP-configured guest without it fails identically.

The image is built against `trixie`, `trixie-updates` **and** `trixie-security`.
`mmdebstrap` writes the mirrors it was given into the image's apt sources, so
building from the base suite alone yields a guest that cannot see security fixes
— at build time or at any point afterwards. The architecture is pinned rather
than inherited from the build host, and appears in the artifact name, because
this is documented as a workstation build and an arm64 workstation would
otherwise produce a rootfs that silently cannot run an x86-64 service binary.

Four units are masked because they cannot succeed in an unprivileged LXC and
otherwise leave the guest permanently `degraded` — which teaches operators to
ignore that signal. The stock template masks the first two for the same reason:

- `sys-kernel-config.mount`, `sys-kernel-debug.mount`
- `systemd-modules-load.service`
- `systemd-networkd-wait-online.service` — ifupdown owns the interface, so
  networkd never configures one and this always times out

## Verification

Run against a guest built by this script, with `rust-junosmcp` installed and a
real vSRX (Junos 24.4R1.9) reachable. The kill criterion for the spike was any
hardening directive ceasing to be enforced, or any change in hostname resolution.

**Hardening read from the kernel, not from `systemctl show`** — a directive can
be accepted and enforce nothing:

```
CapEff:     0000000000000000     every capability dropped
NoNewPrivs: 1
Seccomp:    2  (32 filters)      SystemCallFilter genuinely loaded
```

`ProtectSystem=strict` tested by entering the service's own mount namespace:

```
$ nsenter -t $MAINPID -m -- touch /etc/probe
touch: cannot touch '/etc/probe': Read-only file system
```

**Resolution** — the check the musl route could not pass:

```
nsswitch hosts: files dns      unchanged; glibc is untouched
external lookups resolve
```

**The service, end to end** — full MCP `initialize` handshake, then
`gather_device_facts` against the device:

```
hostname: vsrx-ci   model: vSRX   version: 24.4R1.9
```

**The operator path** — adding a device is a root edit of `devices.json` plus
`SIGHUP`, with no restart, and it must survive:

```
before HUP: vsrx-ci
after HUP:  vsrx-added-by-operator vsrx-ci
service still: active
```

`systemctl is-system-running` reports `running` with **0 failed units**.

## The template ships no SSH host keys

`openssh-server` generates `/etc/ssh/ssh_host_*_key` during bootstrap, and a
tarball built without care carries all three private keys — so every guest
created from it shares one server identity, and anyone holding a copy of the
template can impersonate them.

They are stripped at build time, and a `regenerate-ssh-host-keys.service` unit
makes them once on first boot, before sshd can answer. `pct create` happens to
generate host keys itself, so the unit's `ConditionPathExists` skips on that path
— but the archive must not carry the keys regardless, and a consumer that does
not go through `pct create` still gets a unique identity.

The build hooks are deliberately not suppressed with `|| true`. A mask that fails
produces a permanently `degraded` guest and a key-strip that fails produces a
template full of private keys; both are worse outcomes than no artifact.

## Also verified

- A guest created with `ip=dhcp` obtains an address, a default route and working
  DNS. That is not incidental: `ifupdown2` only *suggests* a dhcp client, so an
  earlier revision of this image would have left every DHCP-configured guest with
  no network at all.
- `apt-get update` inside the built guest sees the security suite, so the image
  can actually receive fixes.

## Not done here

- Reboot behaviour has not been exercised beyond first boot.
- `IPAddressDeny` is reported by `systemctl show` and is **not** enforced in an
  unprivileged LXC. That is unchanged by this image and predates it, but it is
  worth remembering whenever it appears in a hardening review.
- No deployed guest has been migrated. This spike produces the image and the
  evidence; rolling it out to the fleet is separate work.
