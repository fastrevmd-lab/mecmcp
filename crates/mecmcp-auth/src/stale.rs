//! Stale secret file detection.
//!
//! This module scans for superseded secret files that may have been left behind
//! during migrations or manual operations. It NEVER deletes, moves, or modifies
//! any files — it only reports findings for operator review.
//!
//! ## Why This Matters
//!
//! A fleet sweep found ~25 superseded secret files across five guests:
//! `tokens.json.pre-provenance`, `tokens.json.pre-17`, retired TLS keys,
//! `changeset-state.json` backups. Some are root-owned and bypass the startup
//! permission check entirely.

use std::fs;
use std::path::{Path, PathBuf};

/// Classification of a stale secret file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// Superseded token file (e.g., `tokens.json.pre-17`).
    SupersededToken,
    /// Retired cryptographic key (e.g., `server.key.old`).
    RetiredKey,
    /// Backup file (e.g., `tokens.json.bak`).
    Backup,
}

/// A potentially stale secret file found during scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleSecret {
    /// Path to the potentially stale file.
    pub path: PathBuf,
    /// Reason this file is classified as potentially stale.
    pub reason: StaleReason,
}

/// Scan a directory for potentially stale secret files.
///
/// This function scans `dir` (non-recursively) for files that appear to be
/// superseded or backup copies of secret files. It classifies them as:
///
/// - **SupersededToken**: Files whose name starts with `live_file_name` followed
///   by `.` (e.g., `tokens.json.pre-provenance`, `tokens.json.pre-17`).
/// - **Backup**: Files ending in `.bak`, `.old`, `.prev`, or `.orig`.
/// - **RetiredKey**: Files ending in `.key` or `.pem` that are NOT the live file.
///
/// ## Important: Read-Only Operation
///
/// **This function NEVER deletes, moves, or modifies anything.** Deleting an
/// operator's file is not ours to do. The caller is responsible for deciding
/// how to handle findings (log a warning, require manual cleanup, etc.).
///
/// ## Error Handling
///
/// Returns an empty vector (not an error) if `dir` does not exist or cannot be
/// read — a startup warning must never prevent startup.
///
/// ## Example
///
/// ```no_run
/// use mecmcp_auth::stale::find_stale_secrets;
/// use std::path::Path;
///
/// let secrets_dir = Path::new("/var/lib/rust-junosmcp");
/// let live_file = "tokens.json";
///
/// let stale = find_stale_secrets(secrets_dir, live_file);
/// for secret in &stale {
///     eprintln!("Warning: stale secret file found: {}", secret.path.display());
/// }
/// ```
pub fn find_stale_secrets(dir: &Path, live_file_name: &str) -> Vec<StaleSecret> {
    // Return empty if directory doesn't exist or can't be read
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // Skip unreadable entries
        };

        let path = entry.path();

        // Skip if not a file
        if !path.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        // Skip the live file itself
        if file_name == live_file_name {
            continue;
        }

        // Check for backup files first (highest priority)
        // This must come before the superseded token check because files like
        // `tokens.json.bak` match both patterns but are primarily backups.
        if file_name.ends_with(".bak")
            || file_name.ends_with(".old")
            || file_name.ends_with(".prev")
            || file_name.ends_with(".orig")
        {
            results.push(StaleSecret {
                path: path.clone(),
                reason: StaleReason::Backup,
            });
            continue;
        }

        // Check for superseded token files (e.g., tokens.json.pre-17)
        if file_name.starts_with(live_file_name) && file_name.len() > live_file_name.len() {
            let suffix = &file_name[live_file_name.len()..];
            if suffix.starts_with('.') {
                results.push(StaleSecret {
                    path: path.clone(),
                    reason: StaleReason::SupersededToken,
                });
                continue;
            }
        }

        // Check for retired keys
        if (file_name.ends_with(".key") || file_name.ends_with(".pem"))
            && file_name != live_file_name
        {
            results.push(StaleSecret {
                path: path.clone(),
                reason: StaleReason::RetiredKey,
            });
        }
    }

    // Sort by path for deterministic output
    results.sort_by(|a, b| a.path.cmp(&b.path));

    results
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_find_stale_superseded_tokens() {
        let temp = TempDir::new().unwrap();

        // Create live file
        fs::write(temp.path().join("tokens.json"), "{}").unwrap();

        // Create superseded files
        fs::write(temp.path().join("tokens.json.pre-17"), "{}").unwrap();
        fs::write(temp.path().join("tokens.json.pre-provenance"), "{}").unwrap();

        let stale = find_stale_secrets(temp.path(), "tokens.json");

        assert_eq!(stale.len(), 2);
        assert!(
            stale
                .iter()
                .all(|s| s.reason == StaleReason::SupersededToken)
        );
    }

    #[test]
    fn test_find_stale_backup_files() {
        let temp = TempDir::new().unwrap();

        // Create live file
        fs::write(temp.path().join("tokens.json"), "{}").unwrap();

        // Create backup files
        fs::write(temp.path().join("tokens.json.bak"), "{}").unwrap();
        fs::write(temp.path().join("state.json.old"), "{}").unwrap();
        fs::write(temp.path().join("config.json.prev"), "{}").unwrap();
        fs::write(temp.path().join("data.json.orig"), "{}").unwrap();

        let stale = find_stale_secrets(temp.path(), "tokens.json");

        assert_eq!(stale.len(), 4);
        assert!(stale.iter().all(|s| s.reason == StaleReason::Backup));
    }

    #[test]
    fn test_find_stale_retired_keys() {
        let temp = TempDir::new().unwrap();

        // Create live file
        fs::write(temp.path().join("tokens.json"), "{}").unwrap();

        // Create retired keys
        fs::write(temp.path().join("server.key"), "{}").unwrap();
        fs::write(temp.path().join("old-cert.pem"), "{}").unwrap();

        let stale = find_stale_secrets(temp.path(), "tokens.json");

        assert_eq!(stale.len(), 2);
        assert!(stale.iter().all(|s| s.reason == StaleReason::RetiredKey));
    }

    #[test]
    fn test_live_file_excluded() {
        let temp = TempDir::new().unwrap();

        // Create live file
        fs::write(temp.path().join("tokens.json"), "{}").unwrap();

        let stale = find_stale_secrets(temp.path(), "tokens.json");

        assert_eq!(stale.len(), 0);
    }

    #[test]
    fn test_missing_directory_returns_empty() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("does-not-exist");

        let stale = find_stale_secrets(&missing, "tokens.json");

        assert_eq!(stale.len(), 0);
    }

    #[test]
    fn test_unreadable_directory_returns_empty() {
        let temp = TempDir::new().unwrap();
        let unreadable = temp.path().join("unreadable");
        fs::create_dir(&unreadable).unwrap();

        // Make directory unreadable (mode 0000)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

            let stale = find_stale_secrets(&unreadable, "tokens.json");

            assert_eq!(stale.len(), 0);

            // Restore permissions so temp cleanup works
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn test_nothing_modified() {
        let temp = TempDir::new().unwrap();

        // Create various files
        fs::write(temp.path().join("tokens.json"), "{}").unwrap();
        fs::write(temp.path().join("tokens.json.bak"), "{}").unwrap();
        fs::write(temp.path().join("server.key"), "{}").unwrap();

        // Get initial modification times
        let bak_mtime = fs::metadata(temp.path().join("tokens.json.bak"))
            .unwrap()
            .modified()
            .unwrap();
        let key_mtime = fs::metadata(temp.path().join("server.key"))
            .unwrap()
            .modified()
            .unwrap();

        // Scan
        let _stale = find_stale_secrets(temp.path(), "tokens.json");

        // Verify files not modified
        assert_eq!(
            fs::metadata(temp.path().join("tokens.json.bak"))
                .unwrap()
                .modified()
                .unwrap(),
            bak_mtime
        );
        assert_eq!(
            fs::metadata(temp.path().join("server.key"))
                .unwrap()
                .modified()
                .unwrap(),
            key_mtime
        );
    }

    #[test]
    fn test_output_sorted() {
        let temp = TempDir::new().unwrap();

        // Create files in non-alphabetical order
        fs::write(temp.path().join("z.json.bak"), "{}").unwrap();
        fs::write(temp.path().join("a.json.bak"), "{}").unwrap();
        fs::write(temp.path().join("m.json.bak"), "{}").unwrap();

        let stale = find_stale_secrets(temp.path(), "tokens.json");

        assert_eq!(stale.len(), 3);
        assert!(stale[0].path < stale[1].path);
        assert!(stale[1].path < stale[2].path);
    }

    #[test]
    fn test_mixed_reasons() {
        let temp = TempDir::new().unwrap();

        // Create live file
        fs::write(temp.path().join("tokens.json"), "{}").unwrap();

        // Create files with different reasons
        fs::write(temp.path().join("tokens.json.pre-17"), "{}").unwrap(); // SupersededToken
        fs::write(temp.path().join("state.json.bak"), "{}").unwrap(); // Backup
        fs::write(temp.path().join("server.key"), "{}").unwrap(); // RetiredKey

        let stale = find_stale_secrets(temp.path(), "tokens.json");

        assert_eq!(stale.len(), 3);

        // Verify each reason is present
        assert!(
            stale
                .iter()
                .any(|s| s.reason == StaleReason::SupersededToken)
        );
        assert!(stale.iter().any(|s| s.reason == StaleReason::Backup));
        assert!(stale.iter().any(|s| s.reason == StaleReason::RetiredKey));
    }
}
