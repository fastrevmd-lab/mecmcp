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
/// A file that does not exist is not a failure here: a fresh install has no
/// `tokens.json` yet, and an optional file (a TLS key, say) may legitimately
/// be absent. Whether an absent file is itself a problem is for the caller
/// that actually needs to open it to decide -- this pass only says whether
/// every file that *is* present is safe to trust.
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
///     },
///     CredentialFileSpec {
///         path: Path::new("/etc/panosmcp/devices.json"),
///         role: CredentialFileRole::ConfigNoSecret,
///         description: "device inventory",
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
        match check_mode(spec.path, spec.role.required_mode()) {
            Ok(()) => {}
            Err(SecretError::FileIo { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
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

/// Open with `O_NOFOLLOW`, `fstat`, and check type/owner/mode against
/// `required_mode` -- everything [`crate::read_hardened_file`] checks except
/// size and content, since a validation pass has no reason to read the file
/// into memory. TOCTOU-safe for the same reason: the fd that is stat'd is
/// the fd that would be opened for the real read, immediately dropped
/// afterward without ever reading from it.
fn check_mode(path: &Path, required_mode: u32) -> Result<(), SecretError> {
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
    if effective != 0 && stat.st_uid != effective {
        return Err(SecretError::FileWrongOwner {
            path: path.to_path_buf(),
            owner: stat.st_uid,
            effective,
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
            },
            CredentialFileSpec {
                path: &config,
                role: CredentialFileRole::ConfigNoSecret,
                description: "tenant alias",
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
            },
            CredentialFileSpec {
                path: &bad_config,
                role: CredentialFileRole::ConfigNoSecret,
                description: "tenant alias",
            },
            CredentialFileSpec {
                path: &good,
                role: CredentialFileRole::Secret,
                description: "audit key",
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
}
