//! Atomic persistence of changeset state with schema versioning.

use crate::{ChangeSetRecord, OperationRecord, digest::validate_fingerprint};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};

/// Error type for persistence operations.
#[derive(Debug)]
pub struct PersistenceError {
    message: String,
}

impl PersistenceError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PersistenceError {}

/// In-memory changeset state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesetState {
    /// Operations by operation ID.
    #[serde(default)]
    pub operations: BTreeMap<String, OperationRecord>,
    /// Change sets by change-set ID.
    #[serde(default)]
    pub change_sets: BTreeMap<String, ChangeSetRecord>,
}

/// On-disk state format with version header.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnDiskChangesetState {
    version: u32,
    state: ChangesetState,
}

/// Reads and validates the changeset state from disk.
///
/// # Errors
///
/// Returns an error if the file does not exist, has incorrect permissions,
/// contains an unsupported version, or fails validation.
pub fn read_state(path: &Path, max_state_bytes: u64) -> Result<ChangesetState, PersistenceError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        PersistenceError::new(format!(
            "could not inspect changeset state '{}': {error}",
            path.display()
        ))
    })?;

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PersistenceError::new(
            "changeset state must be a regular non-symlink file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(PersistenceError::new(
                "changeset state must not permit group/other access",
            ));
        }
        let owner = metadata.uid();
        let effective = rustix::process::geteuid().as_raw();
        if owner != effective && owner != 0 {
            return Err(PersistenceError::new(format!(
                "changeset state owner uid {owner} is neither effective uid {effective} nor root"
            )));
        }
    }

    if metadata.len() > max_state_bytes {
        return Err(PersistenceError::new(format!(
            "changeset state exceeds {max_state_bytes} bytes"
        )));
    }

    let file = fs::File::open(path).map_err(|error| {
        PersistenceError::new(format!(
            "could not open changeset state '{}': {error}",
            path.display()
        ))
    })?;

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_state_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PersistenceError::new(format!("could not read changeset state: {error}"))
        })?;

    let on_disk: OnDiskChangesetState = serde_json::from_slice(&bytes)
        .map_err(|error| PersistenceError::new(format!("invalid changeset state JSON: {error}")))?;

    if on_disk.version != 1 {
        return Err(PersistenceError::new(format!(
            "unsupported changeset state version {}",
            on_disk.version
        )));
    }

    validate_state(&on_disk.state)?;
    Ok(on_disk.state)
}

/// Validates the in-memory state for consistency.
///
/// # Errors
///
/// Returns an error if the state contains invalid or inconsistent records.
pub fn validate_state(state: &ChangesetState) -> Result<(), PersistenceError> {
    const MAX_OPERATIONS: usize = 1024;
    const MAX_CHANGE_SETS: usize = 1024;
    const MAX_CHANGE_SET_ACTIONS: usize = 64;

    if state.operations.len() > MAX_OPERATIONS || state.change_sets.len() > MAX_CHANGE_SETS {
        return Err(PersistenceError::new(
            "changeset state contains too many records",
        ));
    }

    for (id, record) in &state.operations {
        validate_operation_id(id)?;
        if id != &record.id || record.owner.is_empty() || record.device.is_empty() {
            return Err(PersistenceError::new(
                "changeset state contains an inconsistent operation record",
            ));
        }
        validate_fingerprint(&record.current).map_err(|error| {
            PersistenceError::new(format!("operation fingerprint invalid: {error}"))
        })?;
        if !record.endpoint.starts_with("https://") || record.actions.is_empty() {
            return Err(PersistenceError::new(
                "changeset state operation is missing endpoint/action metadata",
            ));
        }
    }

    for (id, record) in &state.change_sets {
        validate_operation_id(id)?;
        if id != &record.id || record.owner.is_empty() || record.device.is_empty() {
            return Err(PersistenceError::new(
                "changeset state contains an inconsistent change-set record",
            ));
        }
        validate_fingerprint(&record.expected_candidate_fingerprint).map_err(|error| {
            PersistenceError::new(format!("change-set fingerprint invalid: {error}"))
        })?;
        crate::digest::validate_digest(&record.digest, "digest").map_err(|error| {
            PersistenceError::new(format!("change-set digest invalid: {error}"))
        })?;
        if record.actions.is_empty() || record.actions.len() > MAX_CHANGE_SET_ACTIONS {
            return Err(PersistenceError::new(
                "changeset state change set has an invalid action count",
            ));
        }
        // Note: We do NOT recompute the digest here because that requires vendor-specific
        // action types. The digest format is validated above, which is sufficient for
        // detecting corruption. Digest verification at apply-time is the consumer's
        // responsibility using their own action types.
    }

    Ok(())
}

/// Writes the changeset state to disk atomically.
///
/// # Errors
///
/// Returns an error if serialization fails, the file is too large, or the write operation fails.
pub fn write_state(
    path: &Path,
    state: &ChangesetState,
    max_state_bytes: u64,
) -> Result<(), PersistenceError> {
    let parent = path
        .parent()
        .ok_or_else(|| PersistenceError::new("changeset state path has no parent"))?;

    let payload = serde_json::to_vec_pretty(&OnDiskChangesetState {
        version: 1,
        state: ChangesetState {
            operations: state.operations.clone(),
            change_sets: state.change_sets.clone(),
        },
    })
    .map_err(|error| {
        PersistenceError::new(format!("could not serialize changeset state: {error}"))
    })?;

    if payload.len() as u64 > max_state_bytes {
        return Err(PersistenceError::new(format!(
            "serialized changeset state exceeds {max_state_bytes} bytes"
        )));
    }

    let mut temporary = tempfile::Builder::new()
        .prefix(".mecmcp-changeset-state-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| {
            PersistenceError::new(format!("could not create changeset state: {error}"))
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                PersistenceError::new(format!("could not secure changeset state: {error}"))
            })?;
    }

    temporary.write_all(&payload).map_err(|error| {
        PersistenceError::new(format!("could not write changeset state: {error}"))
    })?;

    temporary.as_file().sync_all().map_err(|error| {
        PersistenceError::new(format!("could not sync changeset state: {error}"))
    })?;

    temporary.persist(path).map_err(|error| {
        PersistenceError::new(format!(
            "could not replace changeset state: {}",
            error.error
        ))
    })?;

    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            PersistenceError::new(format!("could not sync state directory: {error}"))
        })?;

    Ok(())
}

fn validate_operation_id(value: &str) -> Result<(), PersistenceError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(PersistenceError::new(
            "value must contain exactly 64 hexadecimal characters",
        ))
    }
}
