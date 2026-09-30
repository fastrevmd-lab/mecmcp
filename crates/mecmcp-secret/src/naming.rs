//! Canonical config/state/service-user layout, derived once per server.
//!
//! Each mechub MCP server used to pick its own directory and service-user
//! names independently. `rustjunosmcp` (`jmcp`), `rustproxmoxmcp`
//! (`proxmoxmcp`) and `rustunifimcp` (`unifimcp`) already used a short,
//! derived name. The other three -- `rustpanosmcp`, `rustsdcmcp` and
//! `rustmistmcp` -- carry their full crate/repo name into `/etc`,
//! `/var/lib` and the service user in production today. Renaming a live
//! service's config dir, state dir *and* system user (systemd unit edits,
//! sysusers edits, re-chowning directories that hold secrets, coordinated
//! across every deployed LXC) is a bigger, messier operation than the
//! tokens.json config/state split this module's sibling ([`crate::validate`])
//! exists to fix, for a cosmetic naming-consistency win with no
//! operator-facing benefit. Kay's decision (MEC-987, 2026-09-30): **do not
//! rename production.** Those three keep their currently-deployed names.
//! [`known`] therefore encodes `PANOS`, `SDC` and `MIST` as explicit,
//! hand-verified exceptions matching deployed reality, not derivations --
//! the same pattern already used for `JUNOS`'s `jmcp` contraction, just
//! three entries instead of one. No path migration, fallback-path logic, or
//! deploy coordination is needed for these three: nothing on disk changes.
//!
//! [`ServerNaming::derive`] is the single place this triple is computed from
//! now on. It takes a `short_name`, not a crate name: the short name is not a
//! mechanical strip of the crate name (`rust-junosmcp` folds to `jmcp`, not
//! `junosmcp`), so this module does not attempt to derive it automatically.
//! [`known`] is the fixed table for the six servers this module covers today
//! -- `rustfortimcp` and `rustopnsmcp` also exist in the workspace but are
//! not yet in this table; adding them is the same one-constant step as any
//! other new server, not a separate mechanism. A server not yet in `known`
//! picks its own short name by the same rule described there, adds a
//! constant to that table, and calls `ServerNaming::derive` with it --
//! nothing else in this module changes.

use std::path::PathBuf;

/// The canonical filesystem and service-account layout for one mechub MCP
/// server, derived from a single short name.
///
/// - `config_dir` (`/etc/<short_name>`): operator-authored input the server
///   does not rewrite -- device inventories, cluster lists, controller
///   configs, SSH keys, tenant aliases.
/// - `state_dir` (`/var/lib/<short_name>`): anything the server itself
///   writes, foremost `tokens.json`, which is rewritten on `token
///   add`/`rotate`/`revoke` and therefore is not config.
/// - `service_user`: the system account the packaged unit runs as, and the
///   owner every hardened file check in [`crate`] validates against. Same
///   string as `short_name` -- one fewer name to keep in sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerNaming {
    /// The short name this layout was derived from, e.g. `"jmcp"`.
    pub short_name: &'static str,
    /// `/etc/<short_name>` -- operator-authored config, never rewritten by
    /// the server.
    pub config_dir: PathBuf,
    /// `/var/lib/<short_name>` -- state the server rewrites itself.
    pub state_dir: PathBuf,
    /// The service account name. Identical to `short_name`.
    pub service_user: &'static str,
}

impl ServerNaming {
    /// Derive the canonical layout for `short_name`.
    ///
    /// This is the *only* place `/etc/<name>`, `/var/lib/<name>`, and the
    /// service-user string get assembled. A server should call this once
    /// with its entry from [`known`] and pass the resulting paths down,
    /// rather than formatting `/etc/{name}` itself anywhere else.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_secret::naming::{ServerNaming, known};
    ///
    /// let naming = ServerNaming::derive(known::JUNOS);
    /// assert_eq!(naming.config_dir.to_str().unwrap(), "/etc/jmcp");
    /// assert_eq!(naming.state_dir.to_str().unwrap(), "/var/lib/jmcp");
    /// assert_eq!(naming.service_user, "jmcp");
    /// ```
    #[must_use]
    pub fn derive(short_name: &'static str) -> Self {
        Self {
            short_name,
            config_dir: PathBuf::from(format!("/etc/{short_name}")),
            state_dir: PathBuf::from(format!("/var/lib/{short_name}")),
            service_user: short_name,
        }
    }
}

/// The short name for each of the six mechub MCP servers this table covers
/// today. `rustfortimcp` and `rustopnsmcp` also exist in the workspace but
/// have not yet been assigned a short name here.
///
/// Each short name is either derived from the crate name, or an explicit,
/// documented exception matching the server's actual production deployment.
/// `JUNOS`, `PROXMOX` and `UNIFI` are derivations -- the vendor token an
/// operator would actually type, chosen once and fixed here so it cannot
/// drift between packaging, docs, and code. `PANOS`, `SDC` and `MIST` are
/// hand-verified exceptions: Kay decided (MEC-987, 2026-09-30) not to rename
/// those three services in production, so their constant is the name
/// already deployed everywhere (sysusers entry, unit `User=`, `/etc`,
/// `/var/lib`), not a derivation:
///
/// | Repo               | Crate            | Short name (`known`) | Derived or exception        |
/// |---------------------|-------------------|-----------------------|------------------------------|
/// | `rustjunosmcp`      | `rust-junosmcp`   | `jmcp`                | derived                      |
/// | `rustpanosmcp`      | `rust-panosmcp`   | `rust-panosmcp`       | exception -- matches deployed |
/// | `rustsdcmcp`        | `rustsdcmcp`      | `rustsdcmcp`          | exception -- matches deployed |
/// | `rustproxmoxmcp`    | `rust-proxmoxmcp` | `proxmoxmcp`          | derived                      |
/// | `rustmistmcp`       | `rustmistmcp`     | `rustmistmcp`         | exception -- matches deployed |
/// | `rustunifimcp`      | `rustunifimcp`    | `unifimcp`            | derived                      |
///
/// A seventh server adds one constant here, following the same rule: drop
/// the `rust`/`rust-`/`mecmcp` scaffolding, keep the shortest vendor token
/// that is still unambiguous on its own (`junos` folded further, to `j`,
/// because Junos was already the first mechub MCP server and `jmcp` was
/// established in production before this table existed; a new vendor should
/// not assume the same additional contraction applies to it -- keep the
/// full vendor token unless there is already a production deployment using
/// something shorter), *unless* the server is already deployed under a
/// different name, in which case the constant matches deployment as a
/// documented exception, the same as `PANOS`, `SDC` and `MIST` here.
pub mod known {
    /// `rustjunosmcp` / `rust-junosmcp`. Derived.
    pub const JUNOS: &str = "jmcp";
    /// `rustpanosmcp` / `rust-panosmcp`. Hand-verified exception: deployed
    /// everywhere as `rust-panosmcp`, not a derived short name. Do not
    /// change this without a coordinated on-disk migration.
    pub const PANOS: &str = "rust-panosmcp";
    /// `rustsdcmcp`. Hand-verified exception: deployed everywhere as
    /// `rustsdcmcp`, not a derived short name. Do not change this without a
    /// coordinated on-disk migration.
    pub const SDC: &str = "rustsdcmcp";
    /// `rustproxmoxmcp` / `rust-proxmoxmcp`. Derived.
    pub const PROXMOX: &str = "proxmoxmcp";
    /// `rustmistmcp`. Hand-verified exception: deployed everywhere as
    /// `rustmistmcp`, not a derived short name. Do not change this without a
    /// coordinated on-disk migration.
    pub const MIST: &str = "rustmistmcp";
    /// `rustunifimcp`. Derived.
    pub const UNIFI: &str = "unifimcp";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_builds_etc_and_var_lib_from_the_short_name() {
        let naming = ServerNaming::derive("examplemcp");
        assert_eq!(naming.config_dir, PathBuf::from("/etc/examplemcp"));
        assert_eq!(naming.state_dir, PathBuf::from("/var/lib/examplemcp"));
        assert_eq!(naming.service_user, "examplemcp");
        assert_eq!(naming.short_name, "examplemcp");
    }

    #[test]
    fn service_user_matches_short_name_exactly() {
        for short_name in [
            known::JUNOS,
            known::PANOS,
            known::SDC,
            known::PROXMOX,
            known::MIST,
            known::UNIFI,
        ] {
            let naming = ServerNaming::derive(short_name);
            assert_eq!(naming.service_user, short_name);
        }
    }

    #[test]
    fn known_short_names_are_distinct() {
        let names = [
            known::JUNOS,
            known::PANOS,
            known::SDC,
            known::PROXMOX,
            known::MIST,
            known::UNIFI,
        ];
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                assert!(i == j || a != b, "duplicate short name: {a}");
            }
        }
    }

    #[test]
    fn known_table_matches_documented_values() {
        assert_eq!(known::JUNOS, "jmcp");
        assert_eq!(known::PANOS, "rust-panosmcp");
        assert_eq!(known::SDC, "rustsdcmcp");
        assert_eq!(known::PROXMOX, "proxmoxmcp");
        assert_eq!(known::MIST, "rustmistmcp");
        assert_eq!(known::UNIFI, "unifimcp");
    }

    #[test]
    fn panos_sdc_mist_derive_to_their_deployed_paths() {
        // Regression guard for MEC-987: Kay's decision was not to rename
        // production, so these three must resolve to the paths and service
        // user actually deployed today, not a shortened derivation.
        let panos = ServerNaming::derive(known::PANOS);
        assert_eq!(panos.config_dir, PathBuf::from("/etc/rust-panosmcp"));
        assert_eq!(panos.state_dir, PathBuf::from("/var/lib/rust-panosmcp"));
        assert_eq!(panos.service_user, "rust-panosmcp");

        let sdc = ServerNaming::derive(known::SDC);
        assert_eq!(sdc.config_dir, PathBuf::from("/etc/rustsdcmcp"));
        assert_eq!(sdc.state_dir, PathBuf::from("/var/lib/rustsdcmcp"));
        assert_eq!(sdc.service_user, "rustsdcmcp");

        let mist = ServerNaming::derive(known::MIST);
        assert_eq!(mist.config_dir, PathBuf::from("/etc/rustmistmcp"));
        assert_eq!(mist.state_dir, PathBuf::from("/var/lib/rustmistmcp"));
        assert_eq!(mist.service_user, "rustmistmcp");
    }
}
