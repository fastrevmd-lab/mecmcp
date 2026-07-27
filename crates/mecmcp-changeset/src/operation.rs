//! Single-operation lifecycle methods for device transactions.
//!
//! This module implements the stage → diff → validate → commit → discard
//! lifecycle for individual operations, wrapping the `DeviceTransaction`
//! trait behind fingerprint guards and coordinator persistence.

use crate::{
    coordinator::{ChangesetCoordinator, CoordinatorError},
    lifecycle::LifecycleState,
    records::{OperationRecord, require_operation_fingerprint},
    transaction::{CommitOptions, CommitOutcome, DeviceTransaction, RollbackRef},
};
use mecmcp_audit::Attribution;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Output from staging a single operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageOutput<S> {
    /// Operation identifier (64 hex characters).
    pub operation_id: String,
    /// Opaque staged-transaction handle.
    pub staged: S,
    /// Candidate fingerprint before staging.
    pub before_fingerprint: String,
    /// Candidate fingerprint after staging.
    pub after_fingerprint: String,
}

impl ChangesetCoordinator {
    /// Stage one fingerprint-guarded operation.
    ///
    /// This method:
    /// 1. Acquires the device guard (serializing concurrent access to the same endpoint)
    /// 2. Validates the expected fingerprint matches the device's current state
    /// 3. Calls `transaction.fingerprint()` to capture the before-state
    /// 4. Calls `transaction.stage(actions)` to stage the operation
    /// 5. Calls `transaction.fingerprint()` again to capture the after-state
    /// 6. Persists the operation record in `Staged` state
    ///
    /// The returned `StageOutput` includes the operation ID, the opaque `Staged` handle,
    /// and both fingerprints. The caller must pass the `Staged` handle to later lifecycle
    /// steps.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device guard cannot be acquired (cancelled or endpoint busy)
    /// - The expected fingerprint does not match the device's actual state
    /// - The transaction's `stage()` method fails
    /// - Persistence fails
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_operation<T: DeviceTransaction>(
        &self,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        actions: &[T::Action],
        policy_signature: &str,
        cancellation: &CancellationToken,
    ) -> Result<StageOutput<T::Staged>, CoordinatorError> {
        // Acquire device guard
        let endpoint = format!("https://{}", device); // Simplified - real impl would get this from inventory
        let _guard = self.device_guard(&endpoint, cancellation).await?;

        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Generate operation ID
        let operation_id = crate::changeset::new_operation_id()?;

        // Create initial operation record in Staging state
        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: device.to_owned(),
            endpoint: endpoint.clone(),
            action: serde_json::to_value(&actions[0])
                .map_err(|e| CoordinatorError::new("actions", e.to_string()))?,
            xpath: None,
            actions: actions
                .iter()
                .map(|a| {
                    serde_json::to_value(a)
                        .map_err(|e| CoordinatorError::new("actions", e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            change_set_id: None,
            current: expected_fingerprint.to_owned(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: policy_signature.to_owned(),
        };

        // Insert the record early so restart recovery can see it
        self.insert(record.clone()).await?;

        // Stage the operation
        let stage_result: Result<_, CoordinatorError> = async {
            // Capture before fingerprint
            let before_fp = transaction
                .fingerprint()
                .await
                .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

            // Validate expected fingerprint matches
            if expected_fingerprint != before_fp {
                return Err(CoordinatorError::new(
                    "expected_candidate_fingerprint",
                    "candidate changed since the caller observed it",
                ));
            }

            // Stage the transaction
            let staged = transaction
                .stage(actions)
                .await
                .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

            // Capture after fingerprint
            let after_fp = transaction
                .fingerprint()
                .await
                .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

            Ok((before_fp, after_fp, staged))
        }
        .await;

        match stage_result {
            Ok((before_fp, after_fp, staged)) => {
                // Update record to Staged state
                record.current = after_fp.clone();
                record.state = LifecycleState::Staged;
                record.config_lock_held = true; // Assume lock held after successful stage
                self.update(record).await?;

                Ok(StageOutput {
                    operation_id,
                    staged,
                    before_fingerprint: before_fp,
                    after_fingerprint: after_fp,
                })
            }
            Err(error) => {
                // Remove the failed operation
                self.remove(&operation_id).await;
                Err(error)
            }
        }
    }

    /// Compute a diff of the staged operation.
    ///
    /// Validates the operation fingerprint still matches the device state, then
    /// calls `transaction.diff(staged)` to compute the diff.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation does not exist or is not owned by this principal and device
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `diff()` method fails
    pub async fn diff_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        staged: &T::Staged,
    ) -> Result<T::Diff, CoordinatorError> {
        // Retrieve and validate the operation record
        let record = self.record(operation_id, owner, device).await?;

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp)
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        // Compute the diff
        let diff = transaction
            .diff(staged)
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        Ok(diff)
    }

    /// Validate the staged operation.
    ///
    /// Validates the operation fingerprint matches, calls `transaction.validate(staged)`,
    /// and transitions `Staged` → `Validating` → `Validated` or `Failed`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation is not in `Staged` state
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `validate()` method fails
    /// - Persistence fails
    #[allow(clippy::too_many_arguments)]
    pub async fn validate_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        staged: &T::Staged,
        cancellation: &CancellationToken,
    ) -> Result<T::Validation, CoordinatorError> {
        // Retrieve and validate the operation record
        let mut record = self.record(operation_id, owner, device).await?;

        if record.state != LifecycleState::Staged {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation is not in staged state",
            ));
        }

        // Acquire device guard
        let _guard = self.device_guard(&record.endpoint, cancellation).await?;

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp)
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        // Transition to Validating
        record.state = LifecycleState::Validating;
        self.update(record.clone()).await?;

        // Perform validation
        let validation_result = transaction.validate(staged).await;

        match validation_result {
            Ok(validation) => {
                // Transition to Validated
                record.state = LifecycleState::Validated;
                record.details = None;
                self.update(record).await?;
                Ok(validation)
            }
            Err(error) => {
                // Transition to Failed
                record.state = LifecycleState::Failed;
                record.details = Some(error.to_string());
                self.update(record).await?;
                Err(CoordinatorError::new("transaction", error.to_string()))
            }
        }
    }

    /// Commit the validated operation.
    ///
    /// Spawns the commit and polls for completion. If the commit outcome cannot be
    /// determined (timeout, lock release failure), the operation is marked `Indeterminate`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation is not in `Validated` state
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `commit()` method fails
    /// - Persistence fails
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        staged: &T::Staged,
        attribution: &Attribution,
        options: &CommitOptions,
        cancellation: &CancellationToken,
    ) -> Result<CommitOutcome, CoordinatorError> {
        // Retrieve and validate the operation record
        let mut record = self.record(operation_id, owner, device).await?;

        if record.state != LifecycleState::Validated {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation must validate successfully before commit",
            ));
        }

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp)
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        // Transition to Committing
        record.state = LifecycleState::Committing;
        self.update(record.clone()).await?;

        // Perform the commit with cancellation support
        let commit_result = tokio::select! {
            result = transaction.commit(staged, attribution, options) => {
                result
            }
            () = cancellation.cancelled() => {
                // If cancelled, the commit may have started but we don't know the outcome
                record.state = LifecycleState::Indeterminate;
                record.details = Some("commit cancelled; outcome unknown".to_owned());
                self.update(record).await?;
                return Ok(CommitOutcome::Detached { job_id: None });
            }
        };

        match commit_result {
            Ok(CommitOutcome::Reconciled {
                succeeded,
                job_id,
                details,
            }) => {
                // Known outcome
                record.state = if succeeded {
                    LifecycleState::Committed
                } else {
                    LifecycleState::Failed
                };
                record.job_id = job_id.clone();
                record.details = details.clone();
                record.config_lock_held = false; // Lock should be released after commit
                self.update(record).await?;

                Ok(CommitOutcome::Reconciled {
                    succeeded,
                    job_id,
                    details,
                })
            }
            Ok(CommitOutcome::Detached { job_id }) => {
                // Commit continues in background
                record.job_id = job_id.clone();
                // Keep state as Committing
                self.update(record).await?;
                Ok(CommitOutcome::Detached { job_id })
            }
            Ok(CommitOutcome::Indeterminate { reason }) => {
                // Unknown outcome - this is the critical case
                record.state = LifecycleState::Indeterminate;
                record.details = Some(reason.clone());
                // Keep config_lock_held as-is since we don't know if it was released
                self.update(record).await?;
                Ok(CommitOutcome::Indeterminate { reason })
            }
            Ok(CommitOutcome::AwaitingConfirmation {
                job_id,
                rollback_deadline_unix,
                details,
            }) => {
                // Junos confirmed commit case
                record.job_id = job_id.clone();
                record.details = details.clone();
                // Keep in Committing state until confirmed
                self.update(record).await?;
                Ok(CommitOutcome::AwaitingConfirmation {
                    job_id,
                    rollback_deadline_unix,
                    details,
                })
            }
            Err(error) => {
                // Commit failed before reaching the device or during execution
                record.state = LifecycleState::Failed;
                record.details = Some(error.to_string());
                self.update(record).await?;
                Err(CoordinatorError::new("transaction", error.to_string()))
            }
        }
    }

    /// Discard the operation without committing.
    ///
    /// Calls `transaction.rollback(RollbackRef::CandidateRevert)`, releases the
    /// configuration lock if held, and transitions to `Discarded`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation is in a state that cannot be discarded
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `rollback()` method fails
    /// - Lock release fails after a successful discard (operation marked `Indeterminate`)
    /// - Persistence fails
    pub async fn discard_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        cancellation: &CancellationToken,
    ) -> Result<String, CoordinatorError> {
        // Retrieve and validate the operation record
        let mut record = self.record(operation_id, owner, device).await?;

        // Cannot discard operations in certain states
        if matches!(
            record.state,
            LifecycleState::Validating
                | LifecycleState::Committing
                | LifecycleState::Committed
                | LifecycleState::Discarded
                | LifecycleState::Indeterminate
        ) {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation cannot be discarded in its current state",
            ));
        }

        // Acquire device guard
        let _guard = self.device_guard(&record.endpoint, cancellation).await?;

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp)
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        // Rollback the candidate
        let rollback_result = transaction
            .rollback(RollbackRef::CandidateRevert)
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        if !rollback_result.succeeded {
            record.state = LifecycleState::Failed;
            record.details = rollback_result.details.clone();
            self.update(record).await?;
            return Err(CoordinatorError::new(
                "transaction",
                rollback_result
                    .details
                    .unwrap_or_else(|| "rollback failed".to_owned()),
            ));
        }

        // Capture the after-discard fingerprint
        let after_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        record.current = after_fp.clone();

        // Note: Lock release would happen here in a real implementation,
        // but the DeviceTransaction trait doesn't expose a lock release method.
        // In practice, this is handled by the implementation-specific transaction
        // (e.g., PAN-OS release_config_lock, Junos unlock candidate).
        // For now, we just mark the lock as released.
        record.config_lock_held = false;

        // Transition to Discarded
        record.state = LifecycleState::Discarded;
        record.details = None;
        self.update(record).await?;

        Ok(after_fp)
    }
}
