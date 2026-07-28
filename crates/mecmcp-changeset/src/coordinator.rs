//! Changeset coordinator for managing in-memory state and endpoint locking.

use crate::{
    lifecycle::{ChangeSetState, LifecycleState},
    persistence::{ChangesetState, PersistenceError, read_state, write_state},
    records::{ChangeSetRecord, OperationRecord},
    types::OperationLimits,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

/// Error type for coordinator operations.
#[derive(Debug)]
pub struct CoordinatorError {
    field: &'static str,
    message: String,
}

impl CoordinatorError {
    /// Creates a new coordinator error for a specific field.
    pub fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the field name associated with this error.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for CoordinatorError {}

impl From<PersistenceError> for CoordinatorError {
    fn from(error: PersistenceError) -> Self {
        Self::new("state", error.to_string())
    }
}

/// Changeset coordinator managing in-memory state, endpoint locks, and persistence.
///
/// This coordinator is vendor-agnostic and manages the lifecycle of operations and
/// change sets across device endpoints. It provides per-endpoint mutual exclusion
/// and atomic persistence of state updates.
#[derive(Debug)]
pub struct ChangesetCoordinator {
    state: Mutex<ChangesetState>,
    endpoint_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    state_path: Option<PathBuf>,
    limits: OperationLimits,
    approval_ttl: Duration,
    lab_mode: bool,
}

impl Default for ChangesetCoordinator {
    fn default() -> Self {
        Self {
            state: Mutex::new(ChangesetState::default()),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: None,
            limits: OperationLimits::default(),
            approval_ttl: Duration::from_secs(15 * 60),
            lab_mode: false,
        }
    }
}

impl ChangesetCoordinator {
    /// Loads the coordinator from disk, applying restart recovery if needed.
    ///
    /// On restart, any in-flight operations (`Staging`, `Validating`, `Committing`) are
    /// marked `Indeterminate` and any in-flight change sets (`Applying`) are marked `Failed`.
    /// The recovery is persisted back to disk only if state was modified.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not absolute, the file cannot be read, or the
    /// state is invalid.
    pub fn load(
        path: Option<&Path>,
        limits: OperationLimits,
        approval_ttl: Duration,
        lab_mode: bool,
    ) -> Result<Self, CoordinatorError> {
        let Some(path) = path else {
            return Ok(Self {
                state: Mutex::new(ChangesetState::default()),
                endpoint_locks: Mutex::new(BTreeMap::new()),
                state_path: None,
                limits,
                approval_ttl,
                lab_mode,
            });
        };

        if !path.is_absolute() {
            return Err(CoordinatorError::new(
                "path",
                "changeset state path must be absolute",
            ));
        }

        let mut state = if path.exists() {
            read_state(path, limits.max_state_bytes)?
        } else {
            ChangesetState::default()
        };

        // Restart recovery: mark in-flight operations as indeterminate
        let mut recovered = false;
        for record in state.operations.values_mut() {
            if matches!(
                record.state,
                LifecycleState::Staging | LifecycleState::Validating | LifecycleState::Committing
            ) {
                record.state = LifecycleState::Indeterminate;
                record.details = Some(
                    "server restarted during a non-terminal operation; manual reconciliation required"
                        .to_owned(),
                );
                recovered = true;
            }
        }

        // Mark in-flight change sets as failed
        for record in state.change_sets.values_mut() {
            if record.state == ChangeSetState::Applying {
                record.state = ChangeSetState::Failed;
                recovered = true;
            }
        }

        // Persist recovery only if we changed something
        if recovered {
            write_state(path, &state, limits.max_state_bytes)?;
        }

        Ok(Self {
            state: Mutex::new(state),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: Some(path.to_path_buf()),
            limits,
            approval_ttl,
            lab_mode,
        })
    }

    /// Acquires a per-endpoint guard, serializing concurrent access to the same endpoint.
    ///
    /// Different endpoints may proceed concurrently. The guard is cancellable via the
    /// provided cancellation token.
    ///
    /// # Errors
    ///
    /// Returns an error if the cancellation token is triggered before the lock is acquired.
    pub async fn device_guard(
        &self,
        endpoint: &str,
        cancellation: &CancellationToken,
    ) -> Result<OwnedMutexGuard<()>, CoordinatorError> {
        let lock = {
            let mut locks = self.endpoint_locks.lock().await;
            locks
                .entry(endpoint.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        tokio::select! {
            () = cancellation.cancelled() => Err(CoordinatorError::new("device", "operation cancelled")),
            guard = lock.lock_owned() => Ok(guard),
        }
    }

    /// Retrieves an operation record by ID, validating ownership.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation does not exist or is not owned by the
    /// specified principal and device.
    pub async fn record(
        &self,
        operation_id: &str,
        owner: &str,
        device: &str,
    ) -> Result<OperationRecord, CoordinatorError> {
        validate_operation_id(operation_id)?;
        let state = self.state.lock().await;
        let record = state
            .operations
            .get(operation_id)
            .ok_or_else(|| CoordinatorError::new("operation_id", "unknown operation"))?;
        if record.owner != owner || record.device != device {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation is not owned by this principal and device",
            ));
        }
        Ok(record.clone())
    }

    /// Inserts a new operation record.
    ///
    /// If the operation store is at capacity, terminal records are evicted first.
    /// If still at capacity, the insert fails. Only one active operation per endpoint
    /// is allowed.
    ///
    /// On persistence failure, the in-memory insert is rolled back.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation store is full after evicting terminal records
    /// - The device already has an active or unreconciled operation
    /// - Persistence fails
    pub async fn insert(&self, record: OperationRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;

        // Evict terminal records if at capacity
        if state.operations.len() >= self.limits.max_operations {
            state
                .operations
                .retain(|_, record| !record.state.terminal());
        }

        if state.operations.len() >= self.limits.max_operations {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation store is full",
            ));
        }

        // Enforce one active operation per device (keyed on trusted device name,
        // not endpoint, because a device can have multiple valid addresses).
        if state
            .operations
            .values()
            .any(|existing| existing.device == record.device && !existing.state.terminal())
        {
            return Err(CoordinatorError::new(
                "operation_id",
                "the device already has an active or unreconciled operation",
            ));
        }

        let id = record.id.clone();
        state.operations.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            state.operations.remove(&id);
            return Err(error);
        }

        Ok(())
    }

    /// Updates an existing operation record.
    ///
    /// On persistence failure, the in-memory update is rolled back to the previous value.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn update(&self, record: OperationRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        let previous = state.operations.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.operations.insert(id, previous);
                }
                None => {
                    state.operations.remove(&id);
                }
            }
            return Err(error);
        }

        Ok(())
    }

    /// Removes an operation record.
    ///
    /// Persistence failures are logged but do not error; the operation is removed from
    /// memory regardless.
    pub async fn remove(&self, operation_id: &str) {
        let mut state = self.state.lock().await;
        state.operations.remove(operation_id);
        if let Err(error) = self.persist_locked(&state) {
            // Log the error but do not fail the remove operation
            eprintln!("changeset state persistence failed during remove: {error}");
        }
    }

    /// Inserts a new change-set record.
    ///
    /// If the change-set store is at capacity, terminal records (`Applied`, `Expired`,
    /// `Failed`) are evicted first. If still at capacity, the insert fails. Only one
    /// pending change set per principal and device is allowed.
    ///
    /// On persistence failure, the in-memory insert is rolled back.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change-set store is full after evicting terminal records
    /// - The principal already has a pending change set on the device
    /// - Persistence fails
    pub async fn insert_change_set(&self, record: ChangeSetRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;

        // Evict terminal change sets if at capacity
        if state.change_sets.len() >= self.limits.max_change_sets {
            state.change_sets.retain(|_, existing| {
                !matches!(
                    existing.state,
                    ChangeSetState::Applied | ChangeSetState::Expired | ChangeSetState::Failed
                )
            });
        }

        if state.change_sets.len() >= self.limits.max_change_sets {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set store is full",
            ));
        }

        // Enforce one pending change set per principal and device
        if state.change_sets.values().any(|existing| {
            existing.owner == record.owner
                && existing.device == record.device
                && matches!(
                    existing.state,
                    ChangeSetState::Planned | ChangeSetState::Approved | ChangeSetState::Applying
                )
        }) {
            return Err(CoordinatorError::new(
                "change_set_id",
                "this principal already has a pending change set on the device",
            ));
        }

        let id = record.id.clone();
        state.change_sets.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            state.change_sets.remove(&id);
            return Err(error);
        }

        Ok(())
    }

    /// Retrieves a change-set record by ID, validating the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the change set does not exist or belongs to a different device.
    pub async fn change_set(
        &self,
        id: &str,
        device: &str,
    ) -> Result<ChangeSetRecord, CoordinatorError> {
        validate_operation_id(id)?;
        let state = self.state.lock().await;
        let record = state
            .change_sets
            .get(id)
            .ok_or_else(|| CoordinatorError::new("change_set_id", "unknown change set"))?;
        if record.device != device {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set belongs to another device",
            ));
        }
        Ok(record.clone())
    }

    /// Updates an existing change-set record.
    ///
    /// On persistence failure, the in-memory update is rolled back to the previous value.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn update_change_set(&self, record: ChangeSetRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        let previous = state.change_sets.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.change_sets.insert(id, previous);
                }
                None => {
                    state.change_sets.remove(&id);
                }
            }
            return Err(error);
        }

        Ok(())
    }

    /// Returns the configured approval TTL.
    #[must_use]
    pub fn approval_ttl(&self) -> Duration {
        self.approval_ttl
    }

    /// Returns the configured operation limits.
    #[must_use]
    pub fn limits(&self) -> &OperationLimits {
        &self.limits
    }

    /// Returns whether lab mode is enabled.
    ///
    /// When lab mode is enabled, change sets can be applied without a second
    /// principal approval, and the approval is recorded as waived rather than
    /// fabricating an approver.
    #[must_use]
    pub fn lab_mode(&self) -> bool {
        self.lab_mode
    }

    /// Persists the state to disk atomically.
    ///
    /// This is a low-level method called by insert/update/remove. It assumes the caller
    /// holds the state lock.
    fn persist_locked(&self, state: &ChangesetState) -> Result<(), CoordinatorError> {
        if let Some(path) = &self.state_path {
            write_state(path, state, self.limits.max_state_bytes)?;
        }
        Ok(())
    }
}

fn validate_operation_id(value: &str) -> Result<(), CoordinatorError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "operation_id",
            "value must contain exactly 64 hexadecimal characters",
        ))
    }
}
