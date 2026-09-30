//! Single-pass startup validation for every credential-adjacent file a
//! server reads.
//!
//! [`read_hardened_file`](crate::read_hardened_file) and
//! [`load_from_file`](crate::load_from_file) each validate and load *one*
//! file, and return on the first thing wrong with it. That is correct for a
//! loader, but wrong for a startup check: a server with five credential
//! files and five wrong modes used to report the first offender, get fixed,
//! restart, report the second, and so on -- which is exactly what cost the
//! 2026-09-07 rebuild two extra restarts across `rustproxmoxmcp` and
//! `rustmistmcp` (MEC-987). [`validate_credential_files`] checks every file
//! in one pass and returns every offender at once.
//!
//! The required mode per file is data owned here
//! ([`CredentialFileRole::required_mode`]), not a single constant and not
//! duplicated in each repo's setup docs. `rustsdcmcp`'s `sdc.json` needs
//! `0640` because it holds no secret (only a tenant alias and endpoint);
//! everything that holds a credential needs `0600`. A caller states which
//! role each file plays; this module owns what mode that role requires.

use std::path::{Path, PathBuf};

use crate::SecretError;

/// What kind of credential-adjacent file a path is, for the purpose of
/// deciding its required mode.
///
/// This is the one place fleet-wide mode requirements live. Adding a third
/// role (or changing what an existing role requires) happens here, once, not
/// in each server's setup doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFileRole {
    /// Holds a secret directly, or is rewritten by the server with secret
    /// material: `tokens.json`, `credentials.env`, an audit HMAC key, a TLS
    /// private key. Must be `0600` -- owner read/write only.
    Secret,
    /// Operator-authored and carries no secret material itself: a device or
    /// cluster inventory, a controller config, `rustsdcmcp`'s `sdc.json`
    /// tenant alias. May be group-readable: `0640`.
    ConfigNoSecret,
}

impl CredentialFileRole {
    /// The mode this role requires. Bits outside this mask must not be set.
    #[must_use]
    pub const fn required_mode(self) -> u32 {
        match self {
            Self::Secret => 0o600,
            Self::ConfigNoSecret => 0o640,
        }
    }
}

/// One file to check as part of a startup validation pass.
#[derive(Debug, Clone, Copy)]
pub struct CredentialFileSpec<'a> {
    /// The path to check.
    pub path: &'a Path,
    /// What kind of file this is, which decides the required mode.
    pub role: CredentialFileRole,
    /// A short, operator-facing name for what this file is, e.g. `"bearer
    /// token store"`. Included in the aggregate error so an operator does
    /// not have to guess what `/etc/panosmcp/audit-hmac.key` is for.
    pub description: &'a str,
    /// Whether this file must exist. A missing optional file (a fresh
    /// install's `tokens.json`, an unused TLS key) is not a failure; a
    /// missing required file is reported like any other offender, so a
    /// caller that passes the canonical path for a file that is still only
    /// present at a legacy fallback path finds out in this same pass rather
    /// than validation silently passing over a file that never gets checked.
    pub required: bool,
}

/// One file that failed validation.
#[derive(Debug)]
pub struct CredentialFileFailure {
    /// The path that failed.
    pub path: PathBuf,
    /// The spec's description, carried through for the aggregate message.
    pub description: String,
    /// What was wrong, and the remedy -- reuses [`SecretError`]'s own
    /// operator-facing message.
    pub detail: String,
}

/// Every credential file that failed validation, collected in one pass.
///
/// Deliberately does not implement [`std::error::Error`] via `#[from]`
/// wrapping of a single `SecretError`: there can be more than one, and the
/// whole point of this type is to say so at once rather than pick one to
/// report.
#[derive(Debug, thiserror::Error)]
#[error("{} credential file(s) failed validation:\n{}", failures.len(), format_failures(failures))]
pub struct CredentialValidationError {
    /// Every file that failed, in the order the specs were given.
    pub failures: Vec<CredentialFileFailure>,
}

fn format_failures(failures: &[CredentialFileFailure]) -> String {
    failures
        .iter()
        .map(|f| format!("  - {} ({}): {}", f.path.display(), f.description, f.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Validate every file in `specs` in a single pass and report every
/// offender together, instead of stopping at the first.
///
/// A missing file is a failure only if its spec sets
/// [`required`](CredentialFileSpec::required): a fresh install has no `tokens.json`
/// yet, and an optional file (a TLS key, say) may legitimately be absent, so
/// those pass. A required file that is missing -- most commonly because the
/// caller passed the canonical path while the file is still only present at
/// a legacy fallback path on an unmigrated install -- is reported here like
/// any other offender, so this pass cannot silently pass over a file that
/// the caller actually depends on.
///
/// # Errors
/// Returns [`CredentialValidationError`] listing every file whose mode,
/// ownership, or type failed the check for its [`CredentialFileRole`].
///
/// # Examples
/// ```no_run
/// use mecmcp_secret::validate::{
///     CredentialFileRole, CredentialFileSpec, validate_credential_files,
/// };
/// use std::path::Path;
///
/// let specs = [
///     CredentialFileSpec {
///         path: Path::new("/var/lib/panosmcp/tokens.json"),
///         role: CredentialFileRole::Secret,
///         description: "bearer token store",
///         required: false,
///     },
///     CredentialFileSpec {
///         path: Path::new("/etc/panosmcp/devices.json"),
///         role: CredentialFileRole::ConfigNoSecret,
///         description: "device inventory",
///         required: true,
///     },
/// ];
///
/// if let Err(error) = validate_credential_files(&specs) {
///     eprintln!("{error}");
///     std::process::exit(1);
/// }
/// ```
pub fn validate_credential_files(
    specs: &[CredentialFileSpec<'_>],
) -> Result<(), CredentialValidationError> {
    let mut failures = Vec::new();

    for spec in specs {
        match check_mode(spec.path, spec.role) {
            Ok(()) => {}
            Err(error) if error_is_not_found(&error) && !spec.required => {}
            Err(error) if error_is_not_found(&error) => failures.push(CredentialFileFailure {
                path: spec.path.to_path_buf(),
                description: spec.description.to_owned(),
                detail: format!(
                    "required file is missing; if this server was upgraded from an older \
                     layout, move it here: {}",
                    spec.path.display()
                ),
            }),
            Err(error) => failures.push(CredentialFileFailure {
                path: spec.path.to_path_buf(),
                description: spec.description.to_owned(),
                detail: error.to_string(),
            }),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(CredentialValidationError { failures })
    }
}

fn error_is_not_found(error: &SecretError) -> bool {
    matches!(
        error,
        SecretError::FileIo { source, .. } if source.kind() == std::io::ErrorKind::NotFound
    )
}

/// Whether `owner` is an acceptable owner of a file for `role`, given the
/// process's effective uid `euid`.
///
/// Root may own (and read) anything. Otherwise the file must be owned by the
/// process itself -- except [`CredentialFileRole::ConfigNoSecret`], which may
/// also be owned by root: that is exactly `rustsdcmcp`'s `sdc.json` layout,
/// `0640 root:<service group>`, where root authors the file and the service
/// group can only read it. A [`CredentialFileRole::Secret`] file never gets
/// that exception -- root ownership of a file the service is supposed to be
/// the sole owner of would defeat the point of `0600`.
fn owner_allowed(role: CredentialFileRole, owner: u32, euid: u32) -> bool {
    euid == 0 || owner == euid || (role == CredentialFileRole::ConfigNoSecret && owner == 0)
}

/// Open with `O_NOFOLLOW`, `fstat`, and check type/owner/mode against `role`
/// -- everything [`crate::read_hardened_file`] checks except size and
/// content, since a validation pass has no reason to read the file into
/// memory. TOCTOU-safe for the same reason: the fd that is stat'd is the fd
/// that would be opened for the real read, immediately dropped afterward
/// without ever reading from it.
fn check_mode(path: &Path, role: CredentialFileRole) -> Result<(), SecretError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    use rustix::io::Errno;

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == Errno::LOOP {
            SecretError::FileIsSymlink {
                path: path.to_path_buf(),
            }
        } else {
            SecretError::FileIo {
                path: path.to_path_buf(),
                source: error.into(),
            }
        }
    })?;

    let stat = fstat(&fd).map_err(|error| SecretError::FileIo {
        path: path.to_path_buf(),
        source: error.into(),
    })?;

    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(SecretError::FileNotRegular {
            path: path.to_path_buf(),
        });
    }

    let required_mode = role.required_mode();
    let mode = stat.st_mode & 0o777;
    if mode & !required_mode != 0 {
        return Err(SecretError::FilePermissions {
            path: path.to_path_buf(),
            detail: format!(
                "mode {mode:04o} exceeds required {required_mode:04o} (owner uid {}, this \
                 process uid {}); run: chmod {required_mode:04o} {}",
                stat.st_uid,
                rustix::process::geteuid().as_raw(),
                path.display()
            ),
        });
    }

    let effective = rustix::process::geteuid().as_raw();
    if !owner_allowed(role, stat.st_uid, effective) {
        let remedy = match role {
            // Root-authored, group-readable config: the valid owners are the
            // service account itself or root, so pointing the operator at
            // `chown <uid>` (which would hand the service ownership of a
            // file it should never write) is the wrong fix here.
            CredentialFileRole::ConfigNoSecret => {
                format!("chown root:<service group> {}", path.display())
            }
            CredentialFileRole::Secret => format!("chown {effective} {}", path.display()),
        };
        return Err(SecretError::FilePermissions {
            path: path.to_path_buf(),
            detail: format!(
                "owner uid {} does not match effective uid {effective}; run: {remedy}",
                stat.st_uid
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(dir: &tempfile::TempDir, name: &str, mode: u32) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"content").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        path
    }

    #[test]
    fn all_valid_files_pass() {
        let dir = tempfile::tempdir().unwrap();
        let secret = write_file(&dir, "tokens.json", 0o600);
        let config = write_file(&dir, "sdc.json", 0o640);

        let specs = [
            CredentialFileSpec {
                path: &secret,
                role: CredentialFileRole::Secret,
                description: "token store",
                required: false,
            },
            CredentialFileSpec {
                path: &config,
                role: CredentialFileRole::ConfigNoSecret,
                description: "tenant alias",
                required: false,
            },
        ];

        validate_credential_files(&specs).unwrap();
    }

    #[test]
    fn a_config_no_secret_file_may_be_group_readable() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(&dir, "sdc.json", 0o640);

        let specs = [CredentialFileSpec {
            path: &config,
            role: CredentialFileRole::ConfigNoSecret,
            description: "tenant alias",
            required: false,
        }];

        validate_credential_files(&specs).unwrap();
    }

    #[test]
    fn a_secret_file_may_not_be_group_readable_even_at_0640() {
        let dir = tempfile::tempdir().unwrap();
        let secret = write_file(&dir, "tokens.json", 0o640);

        let specs = [CredentialFileSpec {
            path: &secret,
            role: CredentialFileRole::Secret,
            description: "token store",
            required: false,
        }];

        let error = validate_credential_files(&specs).unwrap_err();
        assert_eq!(error.failures.len(), 1);
        assert!(error.failures[0].detail.contains("0600"));
    }

    #[test]
    fn every_offender_is_reported_in_one_pass_not_just_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let bad_secret = write_file(&dir, "tokens.json", 0o644);
        let bad_config = write_file(&dir, "sdc.json", 0o646);
        let good = write_file(&dir, "audit-hmac.key", 0o600);

        let specs = [
            CredentialFileSpec {
                path: &bad_secret,
                role: CredentialFileRole::Secret,
                description: "token store",
                required: false,
            },
            CredentialFileSpec {
                path: &bad_config,
                role: CredentialFileRole::ConfigNoSecret,
                description: "tenant alias",
                required: false,
            },
            CredentialFileSpec {
                path: &good,
                role: CredentialFileRole::Secret,
                description: "audit key",
                required: false,
            },
        ];

        let error = validate_credential_files(&specs).unwrap_err();
        assert_eq!(
            error.failures.len(),
            2,
            "both bad files must be reported from a single pass, got {error:?}"
        );
        let paths: Vec<_> = error.failures.iter().map(|f| f.path.clone()).collect();
        assert!(paths.contains(&bad_secret));
        assert!(paths.contains(&bad_config));

        // The aggregate message names both offenders, not just the first.
        let message = error.to_string();
        assert!(message.contains("tokens.json"));
        assert!(message.contains("sdc.json"));
        assert!(!message.contains("audit-hmac.key"));
    }

    #[test]
    fn a_missing_file_is_not_reported_as_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");

        let specs = [CredentialFileSpec {
            path: &missing,
            role: CredentialFileRole::Secret,
            description: "token store",
            required: false,
        }];

        validate_credential_files(&specs).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_reported_as_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_file(&dir, "real.json", 0o600);
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let specs = [CredentialFileSpec {
            path: &link,
            role: CredentialFileRole::Secret,
            description: "token store",
            required: false,
        }];

        let error = validate_credential_files(&specs).unwrap_err();
        assert_eq!(error.failures.len(), 1);
        assert!(error.failures[0].detail.contains("symlink"));
    }

    #[test]
    fn required_mode_matches_documented_roles() {
        assert_eq!(CredentialFileRole::Secret.required_mode(), 0o600);
        assert_eq!(CredentialFileRole::ConfigNoSecret.required_mode(), 0o640);
    }

    // F1 (Percy review of 21a0f70): `ConfigNoSecret` must accept root
    // ownership, since that is rustsdcmcp's actual `sdc.json` layout (`0640
    // root:rustsdcmcp`, root-authored, group-readable by the service). A
    // `Secret` file never gets that exception: root ownership of a file the
    // service is supposed to solely own would defeat `0600`.
    #[test]
    fn owner_allowed_lets_root_own_a_config_no_secret_file() {
        assert!(owner_allowed(CredentialFileRole::ConfigNoSecret, 0, 1000));
    }

    #[test]
    fn owner_allowed_does_not_let_root_own_a_secret_file() {
        assert!(!owner_allowed(CredentialFileRole::Secret, 0, 1000));
    }

    #[test]
    fn owner_allowed_always_permits_the_process_itself() {
        assert!(owner_allowed(CredentialFileRole::Secret, 1000, 1000));
        assert!(owner_allowed(
            CredentialFileRole::ConfigNoSecret,
            1000,
            1000
        ));
    }

    #[test]
    fn owner_allowed_permits_anything_when_effective_uid_is_root() {
        assert!(owner_allowed(CredentialFileRole::Secret, 1000, 0));
        assert!(owner_allowed(CredentialFileRole::ConfigNoSecret, 1000, 0));
    }

    // F3 (Percy review of 21a0f70): on an upgrade install, a file that is
    // still only present at a legacy fallback path is silently skipped if
    // the caller passes the canonical path and the spec has no way to say
    // "this one must exist". `required: true` closes that gap.
    #[test]
    fn a_missing_required_file_is_reported_as_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");

        let specs = [CredentialFileSpec {
            path: &missing,
            role: CredentialFileRole::Secret,
            description: "token store",
            required: true,
        }];

        let error = validate_credential_files(&specs).unwrap_err();
        assert_eq!(error.failures.len(), 1);
        assert!(error.failures[0].detail.contains("missing"));
    }

    #[test]
    fn a_missing_optional_file_still_passes() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");

        let specs = [CredentialFileSpec {
            path: &missing,
            role: CredentialFileRole::Secret,
            description: "token store",
            required: false,
        }];

        validate_credential_files(&specs).unwrap();
    }
}
