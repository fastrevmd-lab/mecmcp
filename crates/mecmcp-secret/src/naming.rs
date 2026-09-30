//! Canonical config/state/service-user layout, derived once per server.
//!
//! Each mechub MCP server used to pick its own directory and service-user
//! names independently. Most converged on the same shape by hand (`jmcp`,
//! `sdcmcp`, `proxmoxmcp`, `unifimcp`), but not all: `rust-panosmcp` and
//! `rustmistmcp` still carry their full crate name into `/etc` and
//! `/var/lib` rather than the short vendor name the others use. That
//! divergence is exactly the kind of thing that costs a rebuild two restarts
//! when an operator assumes the sixth server follows the same rule as the
//! first five (MEC-987).
//!
//! [`ServerNaming::derive`] is the single place this triple is computed from
//! now on. It takes a `short_name`, not a crate name: the short name is not a
//! mechanical strip of the crate name (`rust-junosmcp` folds to `jmcp`, not
//! `junosmcp`), so this module does not attempt to derive it automatically.
//! [`known`] is the fixed table for the six servers that exist today. A
//! seventh server picks its own short name by the same rule described there,
//! adds a constant to that table, and calls `ServerNaming::derive` with it --
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

/// The short name for each of the six mechub MCP servers that exist today.
///
/// None of these are a mechanical transform of the crate or repo name --
/// they are the vendor token an operator would actually type, chosen once
/// and fixed here so it cannot drift between packaging, docs, and code:
///
/// | Repo               | Crate            | Short name   |
/// |---------------------|-------------------|--------------|
/// | `rustjunosmcp`      | `rust-junosmcp`   | `jmcp`       |
/// | `rustpanosmcp`      | `rust-panosmcp`   | `panosmcp`   |
/// | `rustsdcmcp`        | `rustsdcmcp`      | `sdcmcp`     |
/// | `rustproxmoxmcp`    | `rust-proxmoxmcp` | `proxmoxmcp` |
/// | `rustmistmcp`       | `rustmistmcp`     | `mistmcp`    |
/// | `rustunifimcp`      | `rustunifimcp`    | `unifimcp`   |
///
/// A seventh server adds one constant here, following the same rule: drop
/// the `rust`/`rust-`/`mecmcp` scaffolding, keep the shortest vendor token
/// that is still unambiguous on its own (`junos` folded further, to `j`,
/// because Junos was already the first mechub MCP server and `jmcp` was
/// established in production before this table existed; a new vendor should
/// not assume the same additional contraction applies to it -- keep the
/// full vendor token unless there is already a production deployment using
/// something shorter).
pub mod known {
    /// `rustjunosmcp` / `rust-junosmcp`.
    pub const JUNOS: &str = "jmcp";
    /// `rustpanosmcp` / `rust-panosmcp`.
    pub const PANOS: &str = "panosmcp";
    /// `rustsdcmcp`.
    pub const SDC: &str = "sdcmcp";
    /// `rustproxmoxmcp` / `rust-proxmoxmcp`.
    pub const PROXMOX: &str = "proxmoxmcp";
    /// `rustmistmcp`.
    pub const MIST: &str = "mistmcp";
    /// `rustunifimcp`.
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
        assert_eq!(known::PANOS, "panosmcp");
        assert_eq!(known::SDC, "sdcmcp");
        assert_eq!(known::PROXMOX, "proxmoxmcp");
        assert_eq!(known::MIST, "mistmcp");
        assert_eq!(known::UNIFI, "unifimcp");
    }
}
