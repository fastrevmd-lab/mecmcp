//! Reading, validating, hot-reloading, and atomically writing `tokens.json`.

use crate::entry::TokenEntry;
use crate::grant::{Grant, NoGrant};
use crate::store::{StoreError, TokenStore};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Failure while reading or writing a token file.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// The file could not be read or written.
    #[error("token file {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid JSON in the expected shape.
    #[error("token file {path} is not valid JSON: {source}")]
    Parse {
        /// The path involved.
        path: PathBuf,
        /// The underlying deserialization error.
        #[source]
        source: serde_json::Error,
    },
    /// The parsed entries did not form a valid store.
    #[error("token file {path}: {source}")]
    Store {
        /// The path involved.
        path: PathBuf,
        /// The underlying store error.
        #[source]
        source: StoreError,
    },
    /// The file's permissions are too permissive, or unreadable by this process.
    #[error("token file {path}: {detail}")]
    Permissions {
        /// The path involved.
        path: PathBuf,
        /// Operator-facing explanation including uid and mode where known.
        detail: String,
    },
}

/// On-disk document shape. Both existing servers use a `tokens` array.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "G: Grant + Serialize",
    deserialize = "G: Grant + Deserialize<'de>"
))]
struct TokenDocument<G: Grant> {
    tokens: Vec<TokenEntry<G>>,
}

/// A token file plus the store parsed from it, swappable on reload.
#[derive(Debug)]
pub struct TokenStoreFile<G: Grant = NoGrant> {
    path: PathBuf,
    store: ArcSwap<TokenStore<G>>,
}

impl<G: Grant + serde::Serialize + serde::de::DeserializeOwned> TokenStoreFile<G> {
    /// Read, validate, and parse a token file.
    ///
    /// # Errors
    /// Returns [`FileError`] on I/O failure, malformed JSON, unsafe
    /// permissions, or an invalid store.
    pub fn load(path: &Path) -> Result<Self, FileError> {
        let store = Self::read_store(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            store: ArcSwap::from_pointee(store),
        })
    }

    /// The current store. Cheap to clone; safe to hold across a reload.
    #[must_use]
    pub fn store(&self) -> Arc<TokenStore<G>> {
        self.store.load_full()
    }

    /// The path this file was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the file and swap the store in on success.
    ///
    /// On failure the previous store stays in place, so a bad edit delivered by
    /// `SIGHUP` cannot take the server's authentication offline.
    ///
    /// # Errors
    /// Returns [`FileError`] if the new contents are unusable.
    pub fn reload(&self) -> Result<(), FileError> {
        let store = Self::read_store(&self.path)?;
        self.store.store(Arc::new(store));
        Ok(())
    }

    fn read_store(path: &Path) -> Result<TokenStore<G>, FileError> {
        check_permissions(path)?;
        let body = std::fs::read_to_string(path).map_err(|source| FileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let document: TokenDocument<G> =
            serde_json::from_str(&body).map_err(|source| FileError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        TokenStore::try_new(document.tokens).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Write entries to `path` atomically, via a same-directory temporary file.
///
/// # Errors
/// Returns [`FileError`] on serialization or I/O failure.
pub fn write_atomic<G: Grant + serde::Serialize>(
    path: &Path,
    entries: &[TokenEntry<G>],
) -> Result<(), FileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let document = TokenDocument {
        tokens: entries.to_vec(),
    };
    let body = serde_json::to_vec_pretty(&document).map_err(|source| FileError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let mut temp = tempfile::Builder::new()
        .prefix(".tokens-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|source| FileError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o600)).map_err(
            |source| FileError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    use std::io::Write as _;
    temp.write_all(&body).map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    temp.as_file().sync_all().map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    temp.persist(path).map_err(|error| FileError::Io {
        path: path.to_path_buf(),
        source: error.error,
    })?;
    Ok(())
}

/// Reject group- or world-accessible token files, with an operator-facing
/// explanation naming the file's owner and mode and the calling process's uid.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), FileError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(FileError::Permissions {
                path: path.to_path_buf(),
                detail: format!(
                    "permission denied reading metadata; this process runs as uid {}",
                    rustix_getuid()
                ),
            });
        }
        Err(source) => {
            return Err(FileError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    if !metadata.is_file() {
        return Err(FileError::Permissions {
            path: path.to_path_buf(),
            detail: "not a regular file".to_owned(),
        });
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(FileError::Permissions {
            path: path.to_path_buf(),
            detail: format!(
                "mode {mode:04o} is group- or world-accessible (owner uid {}, this process uid {}); \
                 run: chmod 600 {}",
                metadata.uid(),
                rustix_getuid(),
                path.display()
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(path: &Path) -> Result<(), FileError> {
    if !path.is_file() {
        return Err(FileError::Permissions {
            path: path.to_path_buf(),
            detail: "not a regular file".to_owned(),
        });
    }
    Ok(())
}

/// The calling process's real uid.
///
/// `rustix` rather than `libc::getuid`, which is an `unsafe extern` call that
/// `unsafe_code = "forbid"` rejects.
#[cfg(unix)]
fn rustix_getuid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TWO_TOKENS: &str = r#"{
        "tokens": [
            {
                "name": "reader",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["edge-fw"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            },
            {
                "name": "writer",
                "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "routers": ["*"],
                "tools": ["load_and_commit_config"],
                "created_at": "2026-07-12T10:00:00Z"
            }
        ]
    }"#;

    fn write_file(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("tokens.json");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        path
    }

    #[test]
    fn loads_a_file_mixing_both_on_disk_shapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 2);
    }

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.json");
        let err = TokenStoreFile::<NoGrant>::load(&path).expect_err("should fail");
        assert!(err.to_string().contains("absent.json"));
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "{ not json");
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Parse { .. })
        ));
    }

    #[test]
    fn duplicate_names_surface_as_a_store_error() {
        let body = TWO_TOKENS.replace("\"writer\"", "\"reader\"");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, &body);
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Store { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Permissions { .. })
        ));
    }

    #[test]
    fn reload_picks_up_a_changed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 2);

        // Write a file with only the first token
        let single = r#"{
            "tokens": [
                {
                    "name": "reader",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["edge-fw"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400
                }
            ]
        }"#;
        write_file(&dir, single);

        file.reload().expect("reload");
        assert_eq!(file.store().len(), 1);
    }

    #[test]
    fn a_failed_reload_leaves_the_previous_store_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        write_file(&dir, "{ not json");
        assert!(file.reload().is_err());
        assert_eq!(file.store().len(), 2, "previous store must survive");
    }

    #[test]
    fn atomic_write_round_trips_through_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let file: TokenStoreFile = {
            let source = write_file(&dir, TWO_TOKENS);
            TokenStoreFile::load(&source).expect("load")
        };
        write_atomic(&path, file.store().entries()).expect("write");
        let reloaded: TokenStoreFile = TokenStoreFile::load(&path).expect("reload");
        assert_eq!(reloaded.store().len(), 2);
    }
}
