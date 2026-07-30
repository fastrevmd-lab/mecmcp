//! Vendor-neutral outbound credential type and hardened loader.
//!
//! Provides a zeroizing secret type for outbound credentials (API keys, bearer
//! tokens) and hardened loaders that validate file permissions and reject
//! symlinks, oversized values, and group/world-accessible files.

use std::env;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An outbound credential. Zeroized on drop.
///
/// Implements neither `Clone`, `Debug`, `Display`, nor `Serialize`, so it
/// cannot be logged or persisted by accident. A consumer needing shared
/// ownership wraps it in `Arc`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OutboundSecret(String);

impl OutboundSecret {
    /// Expose the plaintext for authentication calls.
    ///
    /// Named to be conspicuous at call sites and greppable in review.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// The bytes of a file that may contain credentials. Zeroized on drop.
///
/// Implements neither `Clone`, `Debug`, `Display`, nor `Serialize`, exactly as
/// [`OutboundSecret`] does, so it cannot reach a log by accident.
///
/// A plain `Zeroizing<Vec<u8>>` would not do: it forwards `Vec`'s `Debug`, so a
/// single `tracing::debug!(?bytes)` — or a `#[derive(Debug)]` on any struct
/// holding one — prints the whole file. The documents this reader is for include
/// `devices.json`, which carries device credentials in plaintext.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Expose the bytes for parsing.
    ///
    /// Named to be conspicuous at call sites and greppable in review, matching
    /// [`OutboundSecret::expose`].
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the file was empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Limits applied when loading a secret.
#[derive(Debug, Clone, Copy)]
pub struct SecretLimits {
    /// Maximum number of bytes to accept.
    pub max_bytes: usize,
}

impl Default for SecretLimits {
    fn default() -> Self {
        Self { max_bytes: 8192 }
    }
}

/// Limits applied when reading a hardened **file**, as opposed to a single
/// secret.
///
/// The default is far larger than [`SecretLimits`] because the two describe
/// different things. A credential is a few hundred bytes; a `tokens.json` or
/// `devices.json` is a document that grows with the deployment. Sizing a
/// document against the secret default is a live hazard, not a theoretical one:
/// LXC 609's `tokens.json` measured 7614 bytes against `SecretLimits`' 8192, so
/// a handful more tokens would have taken the server down with what looks like a
/// corruption error.
#[derive(Debug, Clone, Copy)]
pub struct FileLimits {
    /// Maximum number of bytes to accept.
    pub max_bytes: usize,
}

impl Default for FileLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
        }
    }
}

/// Read a file with the full hardening [`load_from_file`] applies, returning the
/// raw bytes.
///
/// This is the single implementation of the symlink / regular-file / mode /
/// owner / size checks in the workspace. Anything reading a
/// credential-adjacent file should come through here rather than growing its
/// own copy — three divergent copies of one check is how
/// [`load_from_file`]'s guarantees quietly stop applying somewhere.
///
/// Unlike [`load_from_file`] this makes no assumptions about the contents: no
/// UTF-8 requirement, no newline stripping, no empty rejection. Callers parsing
/// JSON want the bytes exactly as stored.
///
/// **Unix:** opens once with `O_NOFOLLOW`, validates the descriptor with
/// `fstat`, and reads from that same descriptor. TOCTOU-safe.
///
/// **Non-Unix:** path-based checks that are **advisory only** — see
/// [`load_from_file`].
///
/// Ownership must match the effective uid, except that **root is permitted**:
/// uid 0 can `chown` and read the file anyway, so refusing it would break
/// ordinary `sudo` operator workflows without adding protection.
///
/// The returned buffer zeroizes on drop, since a token file is as sensitive as
/// a token.
///
/// # Errors
/// Returns [`SecretError`] if any check fails or on I/O error.
///
/// # Examples
/// ```no_run
/// use mecmcp_secret::{read_hardened_file, FileLimits};
/// use std::path::Path;
///
/// let bytes = read_hardened_file(Path::new("/etc/example/tokens.json"), FileLimits::default())?;
/// // Parse `bytes.expose()` with whatever the caller uses; nothing was altered.
/// assert!(!bytes.is_empty());
/// # Ok::<(), mecmcp_secret::SecretError>(())
/// ```
pub fn read_hardened_file(path: &Path, limits: FileLimits) -> Result<SecretBytes, SecretError> {
    #[cfg(unix)]
    {
        read_hardened_file_unix(path, limits)
    }
    #[cfg(not(unix))]
    {
        read_hardened_file_fallback(path, limits)
    }
}

/// Error while loading a secret.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The environment variable is not set.
    #[error("environment variable '{var}' is not set")]
    EnvNotSet {
        /// The variable name.
        var: String,
    },
    /// The environment variable contains invalid UTF-8.
    #[error("environment variable '{var}' contains invalid UTF-8")]
    EnvInvalidUtf8 {
        /// The variable name.
        var: String,
    },
    /// The environment variable is empty.
    #[error("environment variable '{var}' is empty")]
    EnvEmpty {
        /// The variable name.
        var: String,
    },
    /// The environment variable exceeds the size limit.
    #[error("environment variable '{var}' is {actual} bytes, limit is {limit}")]
    EnvTooLarge {
        /// The variable name.
        var: String,
        /// The actual size.
        actual: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The file could not be read.
    #[error("file {}: {source}", path.display())]
    FileIo {
        /// The path involved.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is a symlink.
    #[error("file {} is a symlink (symlinks are rejected for security)", path.display())]
    FileIsSymlink {
        /// The path involved.
        path: std::path::PathBuf,
    },
    /// The file is not a regular file (directory, fifo, device, etc.).
    #[error("file {} is not a regular file", path.display())]
    FileNotRegular {
        /// The path involved.
        path: std::path::PathBuf,
    },
    /// The file is group- or world-accessible.
    #[error("file {}: {detail}", path.display())]
    FilePermissions {
        /// The path involved.
        path: std::path::PathBuf,
        /// Operator-facing explanation including uid and mode.
        detail: String,
    },
    /// The file is not owned by the effective uid.
    #[error("file {}: owner uid {owner} does not match effective uid {effective}; run: chown {effective} {}", path.display(), path.display())]
    FileWrongOwner {
        /// The path involved.
        path: std::path::PathBuf,
        /// The file's owner uid.
        owner: u32,
        /// The process's effective uid.
        effective: u32,
    },
    /// The file exceeds the size limit.
    #[error("file {} is {actual} bytes, limit is {limit}", path.display())]
    FileTooLarge {
        /// The path involved.
        path: std::path::PathBuf,
        /// The actual size.
        actual: u64,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The file is empty or contains only whitespace.
    #[error("file {} is empty or whitespace-only", path.display())]
    FileEmpty {
        /// The path involved.
        path: std::path::PathBuf,
    },
    /// The file contains invalid UTF-8.
    #[error("file {} contains invalid UTF-8", path.display())]
    FileInvalidUtf8 {
        /// The path involved.
        path: std::path::PathBuf,
    },
}

/// Validate an already-read environment variable value.
///
/// Pure validation: takes the raw value, applies size/empty checks, and returns
/// the secret. **Does not strip whitespace**: an environment variable has no
/// editor appending newlines, so trimming would silently alter a secret that
/// legitimately ends in whitespace.
fn validate_env_value(
    var: &str,
    raw: String,
    limits: SecretLimits,
) -> Result<OutboundSecret, SecretError> {
    if raw.is_empty() {
        // Empty strings have no secret content, but zeroize for consistency
        let mut raw = raw;
        raw.zeroize();
        return Err(SecretError::EnvEmpty {
            var: var.to_owned(),
        });
    }

    let byte_len = raw.len();
    if byte_len > limits.max_bytes {
        // Zeroize the value before returning the error
        let mut raw = raw;
        raw.zeroize();
        return Err(SecretError::EnvTooLarge {
            var: var.to_owned(),
            actual: byte_len,
            limit: limits.max_bytes,
        });
    }

    Ok(OutboundSecret(raw))
}

/// Load a secret from an environment variable.
///
/// Rejects missing, empty, or oversized values. **Does not strip whitespace**:
/// an environment variable has no editor appending newlines, so trimming would
/// silently alter a secret that legitimately ends in whitespace. This is
/// deliberately asymmetric with [`load_from_file`], which strips at most one
/// trailing newline.
///
/// # Errors
/// Returns [`SecretError`] if the variable is not set, empty, or exceeds
/// `limits.max_bytes`.
///
/// # Examples
/// ```
/// use mecmcp_secret::{load_from_env, SecretLimits};
///
/// // Handle the error case when the variable is not set
/// match load_from_env("MY_API_KEY", SecretLimits::default()) {
///     Ok(secret) => println!("Loaded {} bytes", secret.expose().len()),
///     Err(e) => eprintln!("Failed to load: {}", e),
/// }
/// ```
pub fn load_from_env(var: &str, limits: SecretLimits) -> Result<OutboundSecret, SecretError> {
    // Match VarError variants to handle non-UTF-8 values (which carry the secret)
    // and to avoid misreporting NotUnicode as "not set"
    let value = match env::var(var) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => {
            return Err(SecretError::EnvNotSet {
                var: var.to_owned(),
            });
        }
        Err(env::VarError::NotUnicode(raw)) => {
            // Zeroize the non-UTF-8 secret before returning error
            let mut bytes = raw.into_encoded_bytes();
            bytes.zeroize();
            return Err(SecretError::EnvInvalidUtf8 {
                var: var.to_owned(),
            });
        }
    };
    validate_env_value(var, value, limits)
}

/// Load a secret from a file with hardened validation.
///
/// **Unix platforms:** Opens the file once with `O_NOFOLLOW`, validates the
/// file descriptor (regular file, mode 0600, owned by effective uid, size <=
/// limit), and reads from the same descriptor. TOCTOU-safe.
///
/// **Non-Unix platforms:** Uses path-based checks (`symlink_metadata` then
/// `File::open`), which are **advisory only**. The file may be replaced between
/// validation and open. Mode and ownership are not checked at all. **Callers on
/// non-Unix platforms must not rely on this function as a security boundary.**
///
/// Rejects: symlinks (Unix-only, TOCTOU-safe; non-Unix, advisory), non-regular
/// files (advisory on non-Unix), group- or world-accessible files (Unix-only),
/// files not owned by effective uid (Unix-only), oversized files, empty or
/// whitespace-only files, invalid UTF-8.
///
/// Strips **at most one** trailing `\n` or `\r\n`: credential files routinely
/// end with a newline and a secret with a stray newline fails authentication
/// in a way that is miserable to debug. Does not trim anything else: leading
/// or interior whitespace could be genuine. This is deliberately asymmetric
/// with [`load_from_env`], which does not strip anything.
///
/// # Errors
/// Returns [`SecretError`] if any validation fails or on I/O error.
///
/// # Examples
/// ```no_run
/// use mecmcp_secret::{load_from_file, SecretLimits};
/// use std::path::Path;
///
/// let secret = load_from_file(Path::new("/etc/my-app/token"), SecretLimits::default()).unwrap();
/// println!("Loaded {} bytes", secret.expose().len());
/// ```
pub fn load_from_file(path: &Path, limits: SecretLimits) -> Result<OutboundSecret, SecretError> {
    #[cfg(unix)]
    {
        load_from_file_unix(path, limits)
    }
    #[cfg(not(unix))]
    {
        load_from_file_non_unix(path, limits)
    }
}

/// Unix implementation: open once, validate the fd, read from the same fd.
#[cfg(unix)]
fn load_from_file_unix(path: &Path, limits: SecretLimits) -> Result<OutboundSecret, SecretError> {
    let bytes = read_hardened_file_unix(
        path,
        FileLimits {
            max_bytes: limits.max_bytes,
        },
    )?;

    // Convert to String, zeroizing the bytes on error
    let mut value = match String::from_utf8(bytes.expose().to_vec()) {
        Ok(text) => text,
        Err(error) => {
            // Recover and zeroize the buffer
            let mut recovered = error.into_bytes();
            recovered.zeroize();
            return Err(SecretError::FileInvalidUtf8 {
                path: path.to_path_buf(),
            });
        }
    };

    // Strip at most one trailing newline (either \n or \r\n)
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }

    // Reject empty or whitespace-only secrets
    if value.trim().is_empty() {
        value.zeroize();
        return Err(SecretError::FileEmpty {
            path: path.to_path_buf(),
        });
    }

    Ok(OutboundSecret(value))
}

/// Unix hardened read: open once with `O_NOFOLLOW`, validate the descriptor,
/// read from that same descriptor.
#[cfg(unix)]
fn read_hardened_file_unix(path: &Path, limits: FileLimits) -> Result<SecretBytes, SecretError> {
    use rustix::fs::{Mode, OFlags, fstat, open};
    use rustix::io::Errno;
    use std::io::Read;

    // Open with NOFOLLOW to reject symlinks at open time
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        // ELOOP means the final component is a symlink
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

    // Validate the already-open fd, not the path (TOCTOU-safe)
    let stat = fstat(&fd).map_err(|error| SecretError::FileIo {
        path: path.to_path_buf(),
        source: error.into(),
    })?;

    // Reject non-regular files
    use rustix::fs::FileType;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(SecretError::FileNotRegular {
            path: path.to_path_buf(),
        });
    }

    // Check mode: reject group- or world-accessible
    let mode = stat.st_mode & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretError::FilePermissions {
            path: path.to_path_buf(),
            detail: format!(
                "mode {mode:04o} is group- or world-accessible (owner uid {}, this process uid {}); \
                 run: chmod 600 {}",
                stat.st_uid,
                rustix::process::geteuid().as_raw(),
                path.display()
            ),
        });
    }

    // Ownership must match the effective uid — except for root.
    //
    // Refusing root would buy nothing: uid 0 can `chown` the file and read it
    // regardless. It would, however, break `sudo <server> token list` against a
    // file owned by the service user, which is an ordinary operator action. The
    // exception is deliberate, not an oversight.
    let effective = rustix::process::geteuid().as_raw();
    if effective != 0 && stat.st_uid != effective {
        return Err(SecretError::FileWrongOwner {
            path: path.to_path_buf(),
            owner: stat.st_uid,
            effective,
        });
    }

    // Check size before reading (cheap early reject)
    #[allow(clippy::cast_possible_truncation)]
    if stat.st_size > limits.max_bytes as i64 {
        return Err(SecretError::FileTooLarge {
            path: path.to_path_buf(),
            actual: stat.st_size as u64,
            limit: limits.max_bytes,
        });
    }

    // Read from the SAME fd, bounded by max_bytes + 1. The size check above is
    // only an early reject: the file can grow between fstat and read, so the
    // bound here is the enforcement.
    let file = std::fs::File::from(fd);
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limits.max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| SecretError::FileIo {
            path: path.to_path_buf(),
            source,
        })?;

    // The +1 distinguishes at-limit from over-limit
    if bytes.len() > limits.max_bytes {
        return Err(SecretError::FileTooLarge {
            path: path.to_path_buf(),
            actual: bytes.len() as u64,
            limit: limits.max_bytes,
        });
    }

    Ok(SecretBytes(std::mem::take(&mut bytes)))
}

/// Non-Unix fallback: path-based checks, advisory only.
///
/// Uses `symlink_metadata` followed by `File::open` — two separate operations,
/// so the file may be replaced between validation and open. Mode and ownership
/// are not checked. Callers must not rely on this as a security boundary.
/// Tracked in #174.
#[cfg(not(unix))]
fn load_from_file_non_unix(
    path: &Path,
    limits: SecretLimits,
) -> Result<OutboundSecret, SecretError> {
    let bytes = read_hardened_file_fallback(
        path,
        FileLimits {
            max_bytes: limits.max_bytes,
        },
    )?;

    let mut value = match String::from_utf8(bytes.expose().to_vec()) {
        Ok(text) => text,
        Err(error) => {
            let mut recovered = error.into_bytes();
            recovered.zeroize();
            return Err(SecretError::FileInvalidUtf8 {
                path: path.to_path_buf(),
            });
        }
    };

    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }

    if value.trim().is_empty() {
        value.zeroize();
        return Err(SecretError::FileEmpty {
            path: path.to_path_buf(),
        });
    }

    Ok(OutboundSecret(value))
}

/// Non-Unix hardened read: path-based, **advisory only**. See #174.
#[cfg(not(unix))]
fn read_hardened_file_fallback(
    path: &Path,
    limits: FileLimits,
) -> Result<SecretBytes, SecretError> {
    use std::io::Read;

    let metadata = std::fs::symlink_metadata(path).map_err(|source| SecretError::FileIo {
        path: path.to_path_buf(),
        source,
    })?;

    if !metadata.is_file() {
        return Err(SecretError::FileNotRegular {
            path: path.to_path_buf(),
        });
    }

    let mut file = std::fs::File::open(path).map_err(|source| SecretError::FileIo {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limits.max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| SecretError::FileIo {
            path: path.to_path_buf(),
            source,
        })?;

    if bytes.len() > limits.max_bytes {
        return Err(SecretError::FileTooLarge {
            path: path.to_path_buf(),
            actual: bytes.len() as u64,
            limit: limits.max_bytes,
        });
    }

    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper to write a file with mode 0600.
    fn write_secret_file(dir: &tempfile::TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("secret");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    // Tests for the pure validation function

    #[test]
    fn validate_env_value_accepts_valid_secret() {
        let secret = validate_env_value(
            "TEST_VAR",
            "test-value-valid".to_owned(),
            SecretLimits::default(),
        )
        .unwrap();
        assert_eq!(secret.expose(), "test-value-valid");
    }

    #[test]
    fn validate_env_value_rejects_empty() {
        let result = validate_env_value("TEST_VAR", String::new(), SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::EnvEmpty { .. }));
        assert!(err.to_string().contains("TEST_VAR"));
    }

    #[test]
    fn validate_env_value_rejects_oversized() {
        let large = "x".repeat(100);
        let result = validate_env_value("TEST_VAR", large, SecretLimits { max_bytes: 50 });
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::EnvTooLarge { .. }));
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn validate_env_value_does_not_strip_whitespace() {
        let secret = validate_env_value(
            "TEST_VAR",
            " leading-and-trailing ".to_owned(),
            SecretLimits::default(),
        )
        .unwrap();
        assert_eq!(secret.expose(), " leading-and-trailing ");
    }

    #[test]
    fn oversized_env_error_does_not_contain_value() {
        let canary = "not-a-secret-canary-alpha";
        assert_eq!(canary.len(), 25, "test data assumption");
        let result = validate_env_value(
            "TEST_VAR",
            canary.to_owned(),
            SecretLimits { max_bytes: 10 },
        );
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        // Must be exactly EnvTooLarge, not some other error
        let SecretError::EnvTooLarge { actual, limit, .. } = err else {
            panic!("expected EnvTooLarge, got {err:?}");
        };
        assert_eq!(actual, 25);
        assert_eq!(limit, 10);
        let error_string = err.to_string();
        // Must not contain any distinctive substring from the value
        assert!(!error_string.contains("canary-alpha"));
        assert!(!error_string.contains("not-a-secret"));
    }

    // Test for the actual load_from_env wrapper

    #[test]
    fn load_from_env_rejects_missing_var() {
        // Use a long unlikely name that is not set in the environment
        let result = load_from_env(
            "MECMCP_SECRET_TEST_NONEXISTENT_VAR_12345",
            SecretLimits::default(),
        );
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::EnvNotSet { .. }));
        assert!(
            err.to_string()
                .contains("MECMCP_SECRET_TEST_NONEXISTENT_VAR_12345")
        );
    }

    #[test]
    fn load_from_file_accepts_valid_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "my-file-secret");
        let secret = load_from_file(&path, SecretLimits::default()).unwrap();
        assert_eq!(secret.expose(), "my-file-secret");
    }

    #[test]
    fn load_from_file_strips_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "secret-with-newline\n");
        let secret = load_from_file(&path, SecretLimits::default()).unwrap();
        assert_eq!(secret.expose(), "secret-with-newline");
    }

    #[test]
    fn load_from_file_strips_one_trailing_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "secret-with-crlf\r\n");
        let secret = load_from_file(&path, SecretLimits::default()).unwrap();
        assert_eq!(secret.expose(), "secret-with-crlf");
    }

    #[test]
    fn load_from_file_does_not_strip_leading_or_interior_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, " leading and interior  spaces ");
        let secret = load_from_file(&path, SecretLimits::default()).unwrap();
        assert_eq!(secret.expose(), " leading and interior  spaces ");
    }

    #[test]
    fn load_from_file_does_not_strip_multiple_trailing_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "secret\n\n");
        let secret = load_from_file(&path, SecretLimits::default()).unwrap();
        // Only one newline is stripped
        assert_eq!(secret.expose(), "secret\n");
    }

    #[test]
    fn load_from_file_rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "");
        let result = load_from_file(&path, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FileEmpty { .. }));
    }

    #[test]
    fn load_from_file_rejects_whitespace_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "   \n  \t  \n");
        let result = load_from_file(&path, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FileEmpty { .. }));
    }

    #[test]
    fn load_from_file_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let large = "x".repeat(100);
        let path = write_secret_file(&dir, &large);
        let result = load_from_file(&path, SecretLimits { max_bytes: 50 });
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        // Must be exactly FileTooLarge, not some earlier error
        let SecretError::FileTooLarge { actual, limit, .. } = err else {
            panic!("expected FileTooLarge, got {err:?}");
        };
        assert_eq!(actual, 100);
        assert_eq!(limit, 50);
    }

    #[test]
    fn load_from_file_rejects_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid_utf8");
        std::fs::write(&path, [0xFF, 0xFE, 0x80]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let result = load_from_file(&path, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FileInvalidUtf8 { .. }));
        // Error must not contain the invalid bytes
        assert!(!err.to_string().contains("\u{FFFD}")); // replacement character
    }

    #[test]
    #[cfg(unix)]
    fn load_from_file_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_secret_file(&dir, "target-secret");
        let link = dir.path().join("symlink");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let result = load_from_file(&link, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FileIsSymlink { .. }));
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn load_from_file_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let result = load_from_file(&subdir, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FileNotRegular { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn load_from_file_rejects_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let result = load_from_file(&path, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FilePermissions { .. }));
        assert!(err.to_string().contains("0640"));
    }

    #[test]
    #[cfg(unix)]
    fn load_from_file_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret_file(&dir, "secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();
        let result = load_from_file(&path, SecretLimits::default());
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        assert!(matches!(err, SecretError::FilePermissions { .. }));
        assert!(err.to_string().contains("0604"));
    }

    #[test]
    fn oversized_file_error_does_not_contain_value() {
        let dir = tempfile::tempdir().unwrap();
        let canary = "not-a-secret-canary-bravo-xyz";
        let path = write_secret_file(&dir, canary);
        let result = load_from_file(&path, SecretLimits { max_bytes: 10 });
        let Err(err) = result else {
            panic!("expected error, got Ok");
        };
        // Must be exactly FileTooLarge, not some earlier error
        let SecretError::FileTooLarge { .. } = err else {
            panic!("expected FileTooLarge, got {err:?}");
        };
        let error_string = err.to_string();
        assert!(!error_string.contains("canary-bravo"));
        assert!(!error_string.contains("not-a-secret"));
        assert!(error_string.contains("29")); // length is okay
    }

    // Wrong-owner test: cannot be tested without root privileges to chown.
    // A fabricated test that does not exercise the check would be misleading.
    // To test: run as root, create a file owned by another uid, verify rejection.

    mod hardened_file {
        use super::*;
        use std::io::Write;
        use std::path::PathBuf;

        /// `unwrap_err` will not compile against `SecretBytes` — it has no
        /// `Debug`, which is the whole point of the type.
        fn expect_error(result: Result<SecretBytes, SecretError>) -> SecretError {
            match result {
                Err(error) => error,
                Ok(_) => panic!("expected an error, got a successful read"),
            }
        }

        fn write_file(dir: &tempfile::TempDir, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = dir.path().join(name);
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            }
            path
        }

        /// Bytes come back exactly as stored — no newline stripping, no UTF-8
        /// requirement. A JSON document must not be altered on the way in.
        #[test]
        fn returns_bytes_verbatim() {
            let dir = tempfile::tempdir().unwrap();
            let content = b"{\"a\":1}\n";
            let path = write_file(&dir, "doc.json", content, 0o600);

            let bytes = read_hardened_file(&path, FileLimits::default()).unwrap();
            assert_eq!(bytes.expose(), content, "trailing newline must survive");
        }

        /// Unlike `load_from_file`, arbitrary bytes are allowed.
        #[test]
        fn accepts_non_utf8_content() {
            let dir = tempfile::tempdir().unwrap();
            let content = b"\xC3\x28\xFF binary";
            let path = write_file(&dir, "blob.bin", content, 0o600);

            let bytes = read_hardened_file(&path, FileLimits::default()).unwrap();
            assert_eq!(bytes.expose(), content);
        }

        /// An empty document is not an error here, though it is for a secret.
        #[test]
        fn accepts_empty_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = write_file(&dir, "empty.json", b"", 0o600);
            assert!(
                read_hardened_file(&path, FileLimits::default())
                    .unwrap()
                    .is_empty()
            );
        }

        #[cfg(unix)]
        #[test]
        fn rejects_group_or_world_accessible() {
            let dir = tempfile::tempdir().unwrap();
            for mode in [0o640, 0o604, 0o666] {
                let path = write_file(&dir, &format!("m{mode:o}.json"), b"{}", mode);
                let error = expect_error(read_hardened_file(&path, FileLimits::default()));
                assert!(
                    matches!(error, SecretError::FilePermissions { .. }),
                    "mode {mode:o} should be rejected, got {error:?}"
                );
            }
        }

        #[cfg(unix)]
        #[test]
        fn rejects_symlink() {
            let dir = tempfile::tempdir().unwrap();
            let target = write_file(&dir, "real.json", b"{}", 0o600);
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let error = expect_error(read_hardened_file(&link, FileLimits::default()));
            assert!(
                matches!(error, SecretError::FileIsSymlink { .. }),
                "got {error:?}"
            );
        }

        #[cfg(unix)]
        #[test]
        fn rejects_non_regular_file() {
            let dir = tempfile::tempdir().unwrap();
            let error = expect_error(read_hardened_file(dir.path(), FileLimits::default()));
            assert!(
                matches!(
                    error,
                    SecretError::FileNotRegular { .. } | SecretError::FileIo { .. }
                ),
                "a directory should not read as a file, got {error:?}"
            );
        }

        #[test]
        fn rejects_oversized_and_accepts_at_the_limit() {
            let dir = tempfile::tempdir().unwrap();
            let limits = FileLimits { max_bytes: 64 };

            let at_limit = write_file(&dir, "at.json", &[b'x'; 64], 0o600);
            assert_eq!(read_hardened_file(&at_limit, limits).unwrap().len(), 64);

            let over = write_file(&dir, "over.json", &[b'x'; 65], 0o600);
            let error = expect_error(read_hardened_file(&over, limits));
            assert!(
                matches!(error, SecretError::FileTooLarge { limit: 64, .. }),
                "got {error:?}"
            );
        }

        /// The default is document-sized, not secret-sized.
        ///
        /// LXC 609's real `tokens.json` measured 7614 bytes against
        /// `SecretLimits`' 8192 ceiling, so reusing the secret default here
        /// would have left a running server a few tokens from failing to start.
        #[test]
        fn default_limit_is_document_sized() {
            assert!(
                FileLimits::default().max_bytes >= 1024 * 1024,
                "a token or inventory document grows with the deployment"
            );
            assert!(FileLimits::default().max_bytes > SecretLimits::default().max_bytes * 100);
        }

        /// The returned buffer must not be printable.
        ///
        /// A `Zeroizing<Vec<u8>>` forwards `Vec`'s `Debug`, so one
        /// `tracing::debug!(?bytes)` would have dumped a `devices.json` — device
        /// passwords included — into the logs. This is a compile-time property,
        /// so the test is the commented line: uncommenting it must not compile.
        #[test]
        fn secret_bytes_is_not_printable() {
            let dir = tempfile::tempdir().unwrap();
            let path = write_file(&dir, "doc.json", b"{\"password\":\"hunter2\"}", 0o600);
            let bytes = read_hardened_file(&path, FileLimits::default()).unwrap();

            // println!("{bytes:?}");   // must not compile: no Debug
            // println!("{bytes}");     // must not compile: no Display
            // let copy = bytes.clone(); // must not compile: no Clone

            // Reaching the bytes has to be deliberate and greppable.
            assert!(bytes.expose().starts_with(b"{"));
            assert_eq!(bytes.len(), 22);
        }

        /// `load_from_file` still applies the secret-specific rules on top.
        #[test]
        fn secret_loader_still_trims_and_rejects_empty() {
            let dir = tempfile::tempdir().unwrap();
            let path = write_file(&dir, "secret", b"value\n", 0o600);
            let secret = load_from_file(&path, SecretLimits::default()).unwrap();
            assert_eq!(secret.expose(), "value");

            // `unwrap_err` will not compile here: `OutboundSecret` deliberately
            // implements no `Debug`, which is the point of the type.
            let blank = write_file(&dir, "blank", b"   \n", 0o600);
            match load_from_file(&blank, SecretLimits::default()) {
                Err(SecretError::FileEmpty { .. }) => {}
                Err(other) => panic!("wrong error: {other:?}"),
                Ok(_) => panic!("a whitespace-only secret must be rejected"),
            }
        }
    }
}
