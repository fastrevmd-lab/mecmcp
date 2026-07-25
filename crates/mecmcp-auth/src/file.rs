//! Reading, validating, hot-reloading, and atomically writing `tokens.json`.

use crate::entry::TokenEntry;
use crate::grant::{Grant, NoGrant};
use crate::scope::ScopeSet;
use crate::store::{StoreError, TokenStore};
use crate::token::TokenSecret;
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
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

/// The names a token's scopes are allowed to reference.
///
/// Both registries are supplied by the caller so this crate stays
/// vendor-neutral: each consuming server has its own device inventory and its
/// own tool surface.
pub struct KnownNames<'a> {
    /// Device names present in the caller's inventory.
    pub devices: &'a [String],
    /// Tool names the caller's server actually implements.
    pub tools: &'a [&'a str],
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

    /// Add one scoped token and return its one-time plaintext.
    ///
    /// # Errors
    /// Returns [`FileError`] if the name already exists, if the scopes reference
    /// unknown devices or tools, or on I/O or validation failure.
    pub fn add(
        path: &Path,
        name: &str,
        devices: ScopeSet,
        tools: ScopeSet,
        known: &KnownNames<'_>,
    ) -> Result<TokenSecret, FileError> {
        Self::add_with_options(path, name, devices, tools, None, None, known)
    }

    /// Add one token with optional expiry and grant.
    ///
    /// # Errors
    /// Returns [`FileError`] if the name already exists, if the scopes reference
    /// unknown devices or tools, or on I/O or validation failure.
    pub fn add_with_options(
        path: &Path,
        name: &str,
        devices: ScopeSet,
        tools: ScopeSet,
        expires_at: Option<DateTime<Utc>>,
        grant: Option<G>,
        known: &KnownNames<'_>,
    ) -> Result<TokenSecret, FileError> {
        use crate::token::TokenSecret;

        let current = if path.exists() {
            Self::read_store(path)?
        } else {
            TokenStore::default()
        };

        if current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Duplicate(format!("token '{name}' already exists")),
            });
        }

        let (secret, digest) = TokenSecret::mint().map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error.to_string())),
        })?;

        let mut entries = current.entries().to_vec();
        entries.push(TokenEntry {
            name: name.to_owned(),
            digest,
            devices,
            tools,
            created_at: Utc::now(),
            expires_at,
            grant,
        });

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        validate_references(&updated, known).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        write_atomic(path, updated.entries())?;
        Ok(secret)
    }

    /// Atomically replace one token digest while preserving its scopes.
    ///
    /// # Errors
    /// Returns [`FileError`] if the named token does not exist, or on I/O or
    /// validation failure.
    pub fn rotate(
        path: &Path,
        name: &str,
        known: &KnownNames<'_>,
    ) -> Result<TokenSecret, FileError> {
        use crate::token::TokenSecret;

        let current = Self::read_store(path)?;

        if !current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                    "token '{name}' does not exist"
                ))),
            });
        }

        let (secret, new_digest) = TokenSecret::mint().map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error.to_string())),
        })?;

        let created_at = Utc::now();
        let entries: Vec<TokenEntry<G>> = current
            .entries()
            .iter()
            .map(|entry| {
                if entry.name == name {
                    TokenEntry {
                        name: entry.name.clone(),
                        digest: new_digest.clone(),
                        devices: entry.devices.clone(),
                        tools: entry.tools.clone(),
                        created_at,
                        expires_at: entry.expires_at,
                        grant: entry.grant.clone(),
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        validate_references(&updated, known).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        write_atomic(path, updated.entries())?;
        Ok(secret)
    }

    /// Narrow or widen an existing token's scopes without touching its secret.
    ///
    /// Pass `None` for a scope to leave it unchanged; `Some(scope)` replaces it.
    /// Both `None` is a no-op write-through. This method can widen as well as
    /// narrow a scope; widening is a privilege escalation that belongs behind
    /// whatever authorization the calling CLI enforces.
    ///
    /// # Errors
    /// Returns [`FileError`] if the named token does not exist, if the scopes
    /// reference unknown devices or tools, or on I/O or validation failure.
    pub fn set_scopes(
        path: &Path,
        name: &str,
        devices: Option<ScopeSet>,
        tools: Option<ScopeSet>,
        known: &KnownNames<'_>,
    ) -> Result<(), FileError> {
        let current = Self::read_store(path)?;

        if !current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                    "token '{name}' does not exist"
                ))),
            });
        }

        let entries: Vec<TokenEntry<G>> = current
            .entries()
            .iter()
            .map(|entry| {
                if entry.name == name {
                    TokenEntry {
                        name: entry.name.clone(),
                        digest: entry.digest.clone(),
                        devices: devices.clone().unwrap_or_else(|| entry.devices.clone()),
                        tools: tools.clone().unwrap_or_else(|| entry.tools.clone()),
                        created_at: entry.created_at,
                        expires_at: entry.expires_at,
                        grant: entry.grant.clone(),
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        validate_references(&updated, known).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        write_atomic(path, updated.entries())?;
        Ok(())
    }

    /// Idempotently revoke one named token.
    ///
    /// # Errors
    /// Returns [`FileError`] on I/O or validation failure. Returns `Ok(false)`
    /// if the token was not present.
    pub fn revoke(
        path: &Path,
        name: &str,
        known: &KnownNames<'_>,
    ) -> Result<bool, FileError> {
        let current = Self::read_store(path)?;
        let mut entries = current.entries().to_vec();
        let before = entries.len();
        entries.retain(|entry| entry.name != name);
        let removed = before != entries.len();

        if removed {
            let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
                path: path.to_path_buf(),
                source,
            })?;

            validate_references(&updated, known).map_err(|error| FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
            })?;

            write_atomic(path, updated.entries())?;
        }

        Ok(removed)
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

/// Validate device and tool references against the known registries.
///
/// Reference-validation is deliberately NOT run during [`TokenStoreFile::load`],
/// only during the mutating operations that mint new scopes. Running it on
/// every load would mean a device decommissioned from the inventory would stop
/// every token in the file from loading and take authentication offline
/// server-wide. Catching a typo when a token is minted is worth it; refusing to
/// start because inventory drifted is not.
fn validate_references<G: Grant>(
    store: &TokenStore<G>,
    known: &KnownNames<'_>,
) -> Result<(), String> {
    for entry in store.entries() {
        if let ScopeSet::Allowlist(devices) = &entry.devices {
            for device in devices {
                if !known.devices.iter().any(|known| known == device) {
                    return Err(format!(
                        "token '{}' references unknown device '{device}'",
                        entry.name
                    ));
                }
            }
        }
        if let ScopeSet::Allowlist(tools) = &entry.tools {
            for tool in tools {
                if !known.tools.iter().any(|known| known == tool) {
                    return Err(format!(
                        "token '{}' references unknown tool '{tool}'",
                        entry.name
                    ));
                }
            }
        }
    }
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
    use crate::grant::GrantError;
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

    fn known_devices() -> Vec<String> {
        vec!["edge-fw".to_owned(), "core-fw".to_owned()]
    }

    #[test]
    fn add_then_load_authenticates_the_minted_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            &known,
        )
        .expect("add");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        let entry = store.authenticate(secret.expose_secret()).expect("auth");
        assert_eq!(entry.name, "lab");
    }

    #[test]
    fn add_with_duplicate_name_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("first add");

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("lab"));
                assert!(err.to_string().contains("already exists"));
            }
            Ok(_) => panic!("second add should fail"),
        }
    }

    #[test]
    fn add_naming_unknown_device_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["missing-fw".to_owned()]),
            ScopeSet::Wildcard,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing-fw"));
                assert!(err.to_string().contains("unknown device"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn add_naming_unknown_tool_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec!["not_a_tool".to_owned()]),
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("not_a_tool"));
                assert!(err.to_string().contains("unknown tool"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn add_with_wildcard_scopes_passes_even_when_known_lists_are_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &[],
            tools: &[],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("wildcard scopes bypass reference validation");

        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert!(file.store().authenticate(secret.expose_secret()).is_some());
    }

    #[test]
    fn rotate_preserves_scopes_expiry_and_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        // Use a far-future timestamp so the token is not expired
        let expires_at = DateTime::from_timestamp(4_102_444_800, 0);

        let original_secret = TokenStoreFile::<NoGrant>::add_with_options(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            expires_at,
            None,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before rotate");
        let store_before = before.store();
        let entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry");

        let rotated_secret = TokenStoreFile::<NoGrant>::rotate(&path, "lab", &known).expect("rotate");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after rotate");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry");

        // Old secret must not work
        assert!(
            store_after.authenticate(original_secret.expose_secret()).is_none(),
            "old secret must be invalidated"
        );

        // New secret must work
        assert!(
            store_after.authenticate(rotated_secret.expose_secret()).is_some(),
            "new secret must authenticate"
        );

        // All other fields must be preserved
        assert_eq!(entry_after.devices, entry_before.devices, "devices must be preserved");
        assert_eq!(entry_after.tools, entry_before.tools, "tools must be preserved");
        assert_eq!(entry_after.expires_at, entry_before.expires_at, "expires_at must be preserved");
        assert_eq!(entry_after.grant, entry_before.grant, "grant must be preserved");

        // created_at should be updated
        assert!(
            entry_after.created_at >= entry_before.created_at,
            "created_at should be refreshed"
        );
    }

    #[test]
    fn rotate_on_missing_name_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let result = TokenStoreFile::<NoGrant>::rotate(&path, "missing", &known);
        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing"));
                assert!(err.to_string().contains("does not exist"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn revoke_removes_token_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let removed = TokenStoreFile::<NoGrant>::revoke(&path, "lab", &known).expect("revoke");
        assert!(removed, "first revoke should return true");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        assert!(
            store.authenticate(secret.expose_secret()).is_none(),
            "revoked token must not authenticate"
        );

        let removed_again = TokenStoreFile::<NoGrant>::revoke(&path, "lab", &known).expect("revoke again");
        assert!(!removed_again, "second revoke should return false");
    }

    #[test]
    fn lifecycle_operations_write_mode_0600_with_no_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let bytes = std::fs::read(&path).expect("read file");
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains(secret.expose_secret()),
            "plaintext secret must never appear in file"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path).expect("metadata");
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file must be mode 0600");
        }

        let rotated = TokenStoreFile::<NoGrant>::rotate(&path, "lab", &known).expect("rotate");
        let bytes_after = std::fs::read(&path).expect("read after rotate");
        let body_after = String::from_utf8_lossy(&bytes_after);
        assert!(
            !body_after.contains(rotated.expose_secret()),
            "rotated plaintext must never appear in file"
        );
    }

    #[test]
    fn set_scopes_narrows_tools_from_wildcard_and_preserves_the_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            &known,
        )
        .expect("set_scopes");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();

        // Original secret must still work
        let entry = store.authenticate(secret.expose_secret()).expect("original secret must authenticate");
        assert_eq!(entry.name, "lab");

        // Tools scope must be narrowed
        assert_eq!(
            entry.tools,
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])
        );

        // Devices scope must be unchanged
        assert_eq!(entry.devices, ScopeSet::Wildcard);
    }

    #[test]
    fn set_scopes_can_change_devices_and_tools_independently() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        // Change only devices
        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            Some(ScopeSet::Allowlist(vec!["core-fw".to_owned()])),
            None,
            &known,
        )
        .expect("set devices");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        let entry = store.entries().iter().find(|e| e.name == "lab").expect("entry");

        assert_eq!(entry.devices, ScopeSet::Allowlist(vec!["core-fw".to_owned()]));
        assert_eq!(entry.tools, ScopeSet::Wildcard);

        // Now change only tools
        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            &known,
        )
        .expect("set tools");

        let file_after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = file_after.store();
        let entry_after = store_after.entries().iter().find(|e| e.name == "lab").expect("entry after");

        assert_eq!(entry_after.devices, ScopeSet::Allowlist(vec!["core-fw".to_owned()]));
        assert_eq!(entry_after.tools, ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]));
    }

    #[test]
    fn set_scopes_preserves_expires_at_and_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let expires_at = DateTime::from_timestamp(4_102_444_800, 0);

        TokenStoreFile::<NoGrant>::add_with_options(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            expires_at,
            None,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before.entries().iter().find(|e| e.name == "lab").expect("entry before");

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after.entries().iter().find(|e| e.name == "lab").expect("entry after");

        assert_eq!(entry_after.expires_at, entry_before.expires_at);
        assert_eq!(entry_after.grant, entry_before.grant);
    }

    #[test]
    fn set_scopes_leaves_other_entries_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add lab");

        let secret2 = TokenStoreFile::<NoGrant>::add(
            &path,
            "ci",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            &known,
        )
        .expect("add ci");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let ci_entry_before = store_before.entries().iter().find(|e| e.name == "ci").expect("ci before");
        let ci_digest_before = ci_entry_before.digest.clone();
        let ci_created_at_before = ci_entry_before.created_at;
        let ci_devices_before = ci_entry_before.devices.clone();
        let ci_tools_before = ci_entry_before.tools.clone();

        // Modify only lab
        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let ci_entry_after = store_after.entries().iter().find(|e| e.name == "ci").expect("ci after");

        // ci token must be completely untouched
        assert_eq!(ci_entry_after.digest, ci_digest_before);
        assert_eq!(ci_entry_after.created_at, ci_created_at_before);
        assert_eq!(ci_entry_after.devices, ci_devices_before);
        assert_eq!(ci_entry_after.tools, ci_tools_before);

        // And its secret must still work
        assert!(store_after.authenticate(secret2.expose_secret()).is_some());
    }

    #[test]
    fn set_scopes_on_nonexistent_token_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let result = TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "missing",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing"));
                assert!(err.to_string().contains("does not exist"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn set_scopes_with_unknown_device_is_rejected_and_file_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let bytes_before = std::fs::read(&path).expect("read before");

        let result = TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            Some(ScopeSet::Allowlist(vec!["unknown-device".to_owned()])),
            None,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("unknown-device"));
                assert!(err.to_string().contains("unknown device"));
            }
            Ok(_) => panic!("should fail"),
        }

        let bytes_after = std::fs::read(&path).expect("read after");
        assert_eq!(bytes_before, bytes_after, "file must be unchanged after failed validation");
    }

    #[test]
    fn set_scopes_with_unknown_tool_is_rejected_and_file_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let bytes_before = std::fs::read(&path).expect("read before");

        let result = TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["unknown_tool".to_owned()])),
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("unknown_tool"));
                assert!(err.to_string().contains("unknown tool"));
            }
            Ok(_) => panic!("should fail"),
        }

        let bytes_after = std::fs::read(&path).expect("read after");
        assert_eq!(bytes_before, bytes_after, "file must be unchanged after failed validation");
    }

    #[test]
    fn set_scopes_does_not_refresh_created_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before.entries().iter().find(|e| e.name == "lab").expect("entry before");
        let created_at_before = entry_before.created_at;

        // Small delay to ensure time has advanced
        std::thread::sleep(std::time::Duration::from_millis(10));

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after.entries().iter().find(|e| e.name == "lab").expect("entry after");

        assert_eq!(entry_after.created_at, created_at_before, "created_at must not be refreshed");
    }

    #[test]
    fn set_scopes_with_both_none_is_a_validating_no_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config"],
        };

        let expires_at = DateTime::from_timestamp(4_102_444_800, 0);

        let secret = TokenStoreFile::<NoGrant>::add_with_options(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            expires_at,
            None,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before.entries().iter().find(|e| e.name == "lab").expect("entry before");

        TokenStoreFile::<NoGrant>::set_scopes(&path, "lab", None, None, &known)
            .expect("set_scopes with both None");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after.entries().iter().find(|e| e.name == "lab").expect("entry after");

        assert_eq!(entry_after.digest, entry_before.digest);
        assert_eq!(entry_after.devices, entry_before.devices);
        assert_eq!(entry_after.tools, entry_before.tools);
        assert_eq!(entry_after.created_at, entry_before.created_at);
        assert_eq!(entry_after.expires_at, entry_before.expires_at);
        assert_eq!(entry_after.grant, entry_before.grant);

        assert!(
            store_after.authenticate(secret.expose_secret()).is_some(),
            "original secret must still authenticate"
        );
    }

    #[test]
    fn set_scopes_preserves_a_non_default_grant() {
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct TestGrant {
            subjects: Vec<String>,
        }
        impl Grant for TestGrant {
            type Action = ();
            fn allows_action(&self, _action: ()) -> bool {
                true
            }
            fn allows_subject(&self, subject: &str) -> bool {
                self.subjects.iter().any(|s| s == subject)
            }
            fn validate(&self) -> Result<(), GrantError> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: &known_devices(),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        let grant = TestGrant {
            subjects: vec!["/configuration".to_owned(), "/system".to_owned()],
        };

        TokenStoreFile::<TestGrant>::add_with_options(
            &path,
            "writer",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            None,
            Some(grant.clone()),
            &known,
        )
        .expect("add");

        TokenStoreFile::<TestGrant>::set_scopes(
            &path,
            "writer",
            None,
            Some(ScopeSet::Allowlist(vec!["load_and_commit_config".to_owned()])),
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<TestGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after.entries().iter().find(|e| e.name == "writer").expect("entry after");

        let grant_after = entry_after.grant.as_ref().expect("grant must be present");
        assert_eq!(grant_after, &grant, "grant must be preserved exactly");
        assert!(grant_after.allows_subject("/configuration"));
        assert!(grant_after.allows_subject("/system"));
        assert!(!grant_after.allows_subject("/other"));
    }
}
