//! Changeset coordinator for managing in-memory state and endpoint locking.

use crate::{
    lifecycle::{ChangeSetState, LifecycleState},
    persistence::{ChangesetState, PersistenceError, read_state, write_state},
    records::{ChangeSetRecord, OperationRecord},
    types::OperationLimits,
};
use mecmcp_audit::recorder::EvidenceRecorder;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

/// Whether a change set still occupies the one-pending-per-principal slot.
///
/// `Expired`, `Applied`, `Failed`, and `Cancelled` are terminal and block nothing.
fn is_pending(state: ChangeSetState) -> bool {
    matches!(
        state,
        ChangeSetState::Planned | ChangeSetState::Approved | ChangeSetState::Applying
    )
}

/// Whether the approval deadline may still retire this change set.
///
/// Narrower than [`is_pending`], and deliberately so. `Applying` means a device
/// transaction is in flight against this record — the deadline bounds how long
/// an approval may sit unused, not how long an apply may take. Retiring an
/// `Applying` record would rewrite the lifecycle out from under the running
/// apply, make it evictable at capacity, and admit a second change set for the
/// same principal and device. A crash would then leave the live operation paired
/// with an expired or absent change set, instead of the `Failed` state that
/// restart recovery assigns to anything caught mid-apply.
pub(crate) fn is_expirable(state: ChangeSetState) -> bool {
    matches!(state, ChangeSetState::Planned | ChangeSetState::Approved)
}

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
    /// Emits the four evidence records, when a server wants an evidence trail.
    ///
    /// Optional because evidence is a deployment choice: a server with no sink
    /// configured should not be forced to build chains nothing will read. When
    /// absent, every emission point is a no-op (mecmcp#292).
    evidence: Option<Arc<EvidenceRecorder>>,
}

impl ChangesetCoordinator {
    /// Emit evidence records for every change this coordinator handles.
    ///
    /// Consuming a recorder rather than borrowing one: the chain must have a
    /// single writer per `(tier, server_id)`, and sharing one coordinator's
    /// recorder with another would fork it — a fork verifies as two valid
    /// chains rather than as an error (ssdf#47).
    #[must_use]
    pub fn with_evidence(mut self, recorder: Arc<EvidenceRecorder>) -> Self {
        self.evidence = Some(recorder);
        self
    }

    /// The evidence recorder, if this coordinator has one.
    pub(crate) fn evidence(&self) -> Option<&EvidenceRecorder> {
        self.evidence.as_deref()
    }
}

impl Default for ChangesetCoordinator {
    fn default() -> Self {
        Self {
            state: Mutex::new(ChangesetState::default()),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: None,
            limits: OperationLimits::default(),
            approval_ttl: Duration::from_secs(15 * 60),
            evidence: None,
            lab_mode: false,
        }
    }
}

/// Whether a `Staged` operation can survive a server restart.
///
/// The answer is a property of the vendor's staged handle, not of the change-set
/// model, so the coordinator cannot decide it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedRecovery {
    /// Mark `Staged` operations `Indeterminate` on load.
    ///
    /// Correct where the handle is a live device session — Junos holds an open
    /// NETCONF session and a locked candidate, both of which die with the process.
    Discard,
    /// Leave `Staged` operations staged on load.
    ///
    /// Correct where the device owns the candidate and the handle is reconstructible
    /// from the persisted record, as on PAN-OS.
    Retain,
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
        Self::load_with_recovery(
            path,
            limits,
            approval_ttl,
            lab_mode,
            StagedRecovery::Discard,
        )
    }

    /// Loads the coordinator, choosing how `Staged` operations survive a restart.
    ///
    /// [`load`](Self::load) defaults to [`StagedRecovery::Discard`], which is right
    /// wherever the staged handle is a live device session: Junos holds an open
    /// NETCONF session and a locked candidate that die with the process, so the
    /// operation genuinely cannot continue.
    ///
    /// [`StagedRecovery::Retain`] suits a vendor whose device owns the candidate and
    /// whose staged handle is reconstructible from the record — PAN-OS keeps the
    /// candidate server-side and identifies it by operation id, so a restart does not
    /// invalidate it.
    ///
    /// This is a parameter rather than something a consumer patches afterwards
    /// because the fix has to land while the state is being loaded. Rewriting the
    /// state file after construction leaves the coordinator's memory and the file
    /// divergent — the API answering from one and the offline recovery tool reading
    /// the other — which strands the operation beyond use or resolution
    /// (rustpanosmcp#72).
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not absolute, the file cannot be read, or the
    /// state is invalid.
    pub fn load_with_recovery(
        path: Option<&Path>,
        limits: OperationLimits,
        approval_ttl: Duration,
        lab_mode: bool,
        staged_recovery: StagedRecovery,
    ) -> Result<Self, CoordinatorError> {
        let Some(path) = path else {
            return Ok(Self {
                state: Mutex::new(ChangesetState::default()),
                endpoint_locks: Mutex::new(BTreeMap::new()),
                state_path: None,
                limits,
                approval_ttl,
                lab_mode,
                evidence: None,
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

        // Restart recovery: mark in-flight operations as indeterminate.
        // `Staged` is included because the opaque `T::Staged` handle only exists
        // in memory and cannot be reconstructed after a restart. Without the handle,
        // the operation cannot proceed through diff/validate/commit or be discarded.
        // The operator must manually reconcile the device state.
        let mut recovered = false;
        for record in state.operations.values_mut() {
            // A `Staged` operation the vendor can genuinely resume is left alone.
            // It must have no `job_id`: once a job exists the operation reached
            // validation or commit, and whether that job landed is exactly the
            // question `Indeterminate` exists to flag.
            if staged_recovery == StagedRecovery::Retain
                && record.state == LifecycleState::Staged
                && record.job_id.is_none()
            {
                continue;
            }

            if matches!(
                record.state,
                LifecycleState::Staging
                    | LifecycleState::Staged
                    | LifecycleState::Validating
                    | LifecycleState::Committing
            ) {
                record.state = LifecycleState::Indeterminate;
                record.details = Some(
                    "server restarted during a non-terminal operation; manual reconciliation required"
                        .to_owned(),
                );
                recovered = true;
            }
        }

        // Settle in-flight change sets, but only the ones nothing can be asked
        // about.
        //
        // A record carrying a `task_id` names a vendor operation that is still
        // running, or has finished and holds its own answer. Marking it
        // `Failed` here would assert an outcome nobody observed — and the
        // likelier outcome is success, because the vendor accepted the
        // operation before this process died. It would also hide the record
        // from the caller's re-probe, which looks for `Applying` plus a
        // handle, so the feature that field exists for would never fire.
        //
        // Without a handle there is genuinely nothing to ask, and `Failed` is
        // the existing behaviour for those.
        for record in state.change_sets.values_mut() {
            if record.state == ChangeSetState::Applying && record.task_id.is_none() {
                record.state = ChangeSetState::Failed;
                recovered = true;
            }
        }

        // Persist recovery only if we changed something
        if recovered {
            write_state(path, &state, limits.max_state_bytes)?;
        }

        Ok(Self {
            evidence: None,
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

    /// Snapshot of every persisted operation.
    ///
    /// Exists for vendor-specific recovery that has to run *after* [`load`](Self::load):
    /// the coordinator promotes non-terminal operations to `Indeterminate` on load
    /// because a staged candidate generally cannot survive a restart, but a vendor
    /// whose device holds the candidate independently can legitimately restore them.
    ///
    /// Such a pass must go through [`update`](Self::update) on these records rather
    /// than rewriting the state file directly. Editing the file behind a loaded
    /// coordinator leaves the two permanently divergent — the API answers from
    /// memory while the offline recovery tool reads the file — and the affected
    /// operation can then be neither used nor resolved (rustpanosmcp#72).
    pub async fn operations(&self) -> Vec<OperationRecord> {
        let state = self.state.lock().await;
        state.operations.values().cloned().collect()
    }

    /// Every change set currently held, for enumeration by a consumer's tool.
    ///
    /// Mirrors [`ChangesetCoordinator::operations`]. This exists because not being able
    /// to ask "what change sets exist for this device?" is what turned a stale
    /// record into a lockout: the status path requires an id, and an operator
    /// who never recorded it had no supported way to find out (#193). The
    /// reporter escaped only by reading the state file on the container, which
    /// is not an API.
    ///
    /// Returns records as stored. Filtering by device or owner, and deciding
    /// what a caller is allowed to see, is the consumer's scope policy — this
    /// crate has never made that decision and should not start here.
    pub async fn change_sets(&self) -> Vec<ChangeSetRecord> {
        let state = self.state.lock().await;
        state.change_sets.values().cloned().collect()
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

        // Enforce one active operation per device or endpoint. Two inventory names
        // can legitimately resolve to the same endpoint (management IP + DNS name),
        // and if both passed the device-only check, two operations could mutate
        // one candidate concurrently. Reject when EITHER the device name matches
        // OR the canonical endpoint matches.
        for existing in state.operations.values() {
            if existing.state.terminal() {
                continue;
            }
            // Check device match
            if existing.device == record.device {
                return Err(CoordinatorError::new(
                    "operation_id",
                    "the device already has an active or unreconciled operation",
                ));
            }
            // Check canonical endpoint match
            if existing.endpoint == record.endpoint {
                return Err(CoordinatorError::new(
                    "operation_id",
                    "the device already has an active or unreconciled operation",
                ));
            }
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
        // The configured ceilings, enforced where the limits are in scope.
        // `validate_state` sees no limits, so it checks structure only — a file
        // that was legal when written must not become unloadable because a
        // ceiling was lowered afterwards. Nothing called either of these before,
        // so `max_targets_per_set` and `max_preview_bytes` had no effect at all.
        record
            .validate_target_set(self.limits.max_targets_per_set)
            .map_err(|error| CoordinatorError::new("targets", error.to_string()))?;
        record
            .validate_preview(self.limits.max_preview_bytes)
            .map_err(|error| CoordinatorError::new("preview", error.to_string()))?;

        let mut state = self.state.lock().await;

        // Retire anything past its approval deadline before doing anything else.
        //
        // A change set only became `Expired` lazily, when someone tried to apply
        // it. One that simply ran out of time kept its `Approved` state
        // indefinitely, went on blocking the guard below, and was never eligible
        // for the capacity eviction either — that only retains terminal states.
        // An operator who had lost the id was then locked out of change sets for
        // that device with no MCP-reachable remedy (#193).
        let now = crate::changeset::now_unix()?;
        // No log line here: this crate has no `tracing` dependency and adding
        // one for a single message is not worth it. The transition is durable
        // in the state file and visible through `change_sets()`.
        //
        // What each retirement replaced is kept so the sweep can be undone if
        // the persist below fails.
        let mut retired: Vec<(String, ChangeSetState)> = Vec::new();
        for (id, existing) in &mut state.change_sets {
            // Two deadlines can retire a record: its own approval TTL, and the
            // expiry of the waiver that approved it (#284). The second is
            // checked through the same predicate the apply gate uses.
            if is_expirable(existing.state)
                && (existing.expires_at_unix <= now || crate::apply::waiver_lapsed(existing, now))
            {
                retired.push((id.clone(), existing.state));
                existing.state = ChangeSetState::Expired;
            }
        }

        // Evict terminal change sets if at capacity
        let mut evicted: Vec<ChangeSetRecord> = Vec::new();
        if state.change_sets.len() >= self.limits.max_change_sets {
            state.change_sets.retain(|_, existing| {
                let terminal = matches!(
                    existing.state,
                    ChangeSetState::Applied
                        | ChangeSetState::Expired
                        | ChangeSetState::Failed
                        | ChangeSetState::Cancelled
                );
                if terminal {
                    evicted.push(existing.clone());
                }
                !terminal
            });
        }

        // Both of those changed the store regardless of whether this insert goes
        // on to succeed, so persist them now rather than on the success path
        // alone. Every rejection below returns early; leaving the sweep unwritten
        // would let memory report a record `Expired` while the file still says
        // `Approved`, and a restart would resurrect the blocker this sweep just
        // retired — #193 again, with the fix in place.
        let swept = !retired.is_empty() || !evicted.is_empty();
        if swept && let Err(error) = self.persist_locked(&state) {
            for (id, previous) in retired {
                if let Some(existing) = state.change_sets.get_mut(&id) {
                    existing.state = previous;
                }
            }
            for record in evicted {
                state.change_sets.insert(record.id.clone(), record);
            }
            return Err(error);
        }

        if state.change_sets.len() >= self.limits.max_change_sets {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set store is full",
            ));
        }

        // Enforce one pending change set per principal and device.
        //
        // Expiry is handled above rather than here, so anything still pending at
        // this point is genuinely live.
        if let Some(blocker) = state.change_sets.values().find(|existing| {
            existing.owner == record.owner
                && existing.device == record.device
                && is_pending(existing.state)
        }) {
            // Name the blocker. The bare refusal was a dead end: the status tool
            // requires an id, there was no way to list, and the message did not
            // say which record was in the way (#193).
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "this principal already has a pending change set on the device \
                     (id {}, state {:?}, expires at unix {})",
                    blocker.id, blocker.state, blocker.expires_at_unix
                ),
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
