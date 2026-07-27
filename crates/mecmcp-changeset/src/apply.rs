//! Change-set apply operation.

use crate::{
    changeset::{new_operation_id, now_unix},
    coordinator::{ChangesetCoordinator, CoordinatorError},
    digest::validate_digest,
    lifecycle::{ChangeSetState, LifecycleState},
    records::OperationRecord,
    transaction::DeviceTransaction,
};
use mecmcp_audit::Attribution;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// Output from applying a change set.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutput<S> {
    /// Operation identifier assigned during apply.
    pub operation_id: String,
    /// Candidate fingerprint before the change set was applied.
    pub before_fingerprint: String,
    /// Candidate fingerprint after the change set was applied.
    pub after_fingerprint: String,
    /// Vendor-specific staged handle returned by the transaction.
    #[serde(skip)]
    pub staged: S,
}

impl ChangesetCoordinator {
    /// Applies an independently approved change set.
    ///
    /// This is the apply step: the caller provides an approved change-set ID and the
    /// coordinator validates the approval is fresh, acquires the device guard, stages
    /// all actions through the device transaction, and records the operation.
    ///
    /// On partial failure (e.g., the third action fails), the coordinator auto-reverts
    /// any staged changes and marks the change set as `Failed`. The change set must NOT
    /// be left looking `Applied` after a partial failure.
    ///
    /// # Lab mode
    ///
    /// A change set approved by waiver (lab mode enabled, `ApprovalRecord.waived` is
    /// `Some`) is legitimately applicable. The approval check accepts both genuine
    /// two-person approvals and waived approvals.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected digest or fingerprint format is invalid
    /// - The change set does not exist or belongs to another device
    /// - The change set is not owned by the specified owner
    /// - The change set is not in `Approved` state
    /// - The approval has expired
    /// - The supplied digest or fingerprint does not match the stored values exactly
    /// - The device guard cannot be acquired (cancellation)
    /// - Any action fails to stage (after auto-revert, the change set is marked `Failed`)
    /// - Persistence fails
    ///
    /// # Attribution
    ///
    /// `attribution` is accepted but not yet consumed. Applying a change set only
    /// *stages* it; nothing is written to the device's running configuration here,
    /// and it is [`commit_operation`](Self::commit_operation) that puts attribution
    /// into the commit log. The parameter is on this signature so the call site
    /// carries it from the start rather than acquiring it later — but be aware that
    /// today an apply records no attribution of its own.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_change_set<T: DeviceTransaction>(
        &self,
        change_set_id: String,
        device: String,
        owner: String,
        expected_digest: String,
        expected_fingerprint: String,
        transaction: &T,
        _attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<ApplyOutput<T::Staged>, CoordinatorError> {
        // Validate inputs
        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;
        crate::digest::validate_fingerprint(&expected_fingerprint)
            .map_err(|e| CoordinatorError::new("expected_fingerprint", e.to_string()))?;

        // Retrieve and validate the change set before acquiring the device guard
        let mut change_set = self.change_set(&change_set_id, &device).await?;

        if change_set.owner != owner {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the principal that created the change set may apply it",
            ));
        }

        if change_set.state != ChangeSetState::Approved {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set requires approval before apply",
            ));
        }

        // Validate approval is present and either genuine or waived
        let approval = change_set.approval.as_ref().ok_or_else(|| {
            CoordinatorError::new(
                "change_set_id",
                "approved change set missing approval record",
            )
        })?;

        // Accept both genuine approvals (approver present) and waived approvals
        if approval.approver.is_none() && approval.waived.is_none() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "approval record must contain either an approver or a waiver",
            ));
        }

        let now = now_unix()?;
        if now >= change_set.expires_at_unix {
            change_set.state = ChangeSetState::Expired;
            self.update_change_set(change_set).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "approved change set expired",
            ));
        }

        if change_set.digest != expected_digest
            || change_set.expected_candidate_fingerprint != expected_fingerprint
        {
            return Err(CoordinatorError::new(
                "expected_digest",
                "apply input does not match the exact approved plan",
            ));
        }

        // Acquire device guard to serialize concurrent operations
        let _guard = self.device_guard(&device, cancellation).await?;

        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Re-check the change set after acquiring the guard
        change_set = self.change_set(&change_set_id, &device).await?;

        if change_set.owner != owner
            || change_set.state != ChangeSetState::Approved
            || change_set.digest != expected_digest
            || change_set.expected_candidate_fingerprint != expected_fingerprint
            || now_unix()? >= change_set.expires_at_unix
        {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is no longer the exact unexpired approved plan",
            ));
        }

        // Capture the before fingerprint
        let before_fingerprint = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("device", format!("fingerprint failed: {e}")))?;

        // Validate the device state matches the expected fingerprint
        if before_fingerprint != expected_fingerprint {
            return Err(CoordinatorError::new(
                "expected_fingerprint",
                format!(
                    "device fingerprint changed: expected {}, found {}",
                    expected_fingerprint, before_fingerprint
                ),
            ));
        }

        // Generate operation ID
        let operation_id = new_operation_id()?;

        // Mark change set as Applying
        change_set.state = ChangeSetState::Applying;
        change_set.operation_id = Some(operation_id.clone());
        self.update_change_set(change_set.clone()).await?;

        // Deserialize actions
        let actions: Vec<T::Action> = change_set
            .actions
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                serde_json::from_value(value.clone()).map_err(|e| {
                    CoordinatorError::new(
                        "actions",
                        format!("failed to deserialize action {}: {}", idx, e),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Stage all actions through the transaction
        let staged = match transaction.stage(&actions).await {
            Ok(staged) => staged,
            Err(error) => {
                // `stage` takes the whole batch, but nothing in the trait
                // promises the implementation applies it atomically — PAN-OS
                // walks the actions issuing one XPath call each, so a failure
                // partway through leaves the earlier actions sitting in the
                // candidate. Marking the change set Failed and walking away
                // would leave those uncommitted changes on the device for the
                // next commit to sweep up, so revert before giving up.
                let revert = transaction
                    .rollback(crate::transaction::RollbackRef::CandidateRevert)
                    .await;

                change_set.state = ChangeSetState::Failed;
                self.update_change_set(change_set).await?;

                return Err(match revert {
                    Ok(outcome) if outcome.succeeded => CoordinatorError::new(
                        "device",
                        format!("staging failed and the candidate was reverted: {error}"),
                    ),
                    // A failed revert is the dangerous case: the device may
                    // still hold a partial candidate and no one has been told.
                    // Say so in the error rather than reporting a clean failure.
                    Ok(outcome) => CoordinatorError::new(
                        "device",
                        format!(
                            "staging failed: {error}; the candidate revert did not succeed ({}), \
                             so the device may still hold partial changes",
                            outcome.details.as_deref().unwrap_or("no detail")
                        ),
                    ),
                    Err(revert_error) => CoordinatorError::new(
                        "device",
                        format!(
                            "staging failed: {error}; the candidate revert also failed \
                             ({revert_error}), so the device may still hold partial changes"
                        ),
                    ),
                });
            }
        };

        // Capture the after fingerprint
        let after_fingerprint = match transaction.fingerprint().await {
            Ok(fp) => fp,
            Err(error) => {
                // Fingerprint read failed; attempt to revert
                let revert_result = transaction
                    .rollback(crate::transaction::RollbackRef::CandidateRevert)
                    .await;

                change_set.state = ChangeSetState::Failed;
                self.update_change_set(change_set).await?;

                return match revert_result {
                    Ok(_) => Err(CoordinatorError::new(
                        "device",
                        format!("fingerprint read failed after staging (reverted): {error}"),
                    )),
                    Err(revert_error) => Err(CoordinatorError::new(
                        "device",
                        format!(
                            "fingerprint read failed after staging: {error}; revert also failed: {revert_error}"
                        ),
                    )),
                };
            }
        };

        // Create operation record
        let operation_record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.clone(),
            device: device.clone(),
            endpoint: device.clone(), // Transaction doesn't expose endpoint; use device name
            action: change_set.actions.first().cloned().unwrap_or_default(),
            xpath: None, // Vendor-specific; not used in shared crate
            actions: change_set.actions.clone(),
            change_set_id: Some(change_set_id.clone()),
            current: after_fingerprint.clone(),
            state: LifecycleState::Staged,
            job_id: None,
            details: Some(format!(
                "applied change set {} with {} actions",
                change_set_id,
                actions.len()
            )),
            config_lock_held: false, // Transaction manages lock; we don't track it here
            policy_signature: String::new(), // Not used in apply path
        };

        self.insert(operation_record).await?;

        // Mark change set as Applied
        change_set.state = ChangeSetState::Applied;
        self.update_change_set(change_set).await?;

        Ok(ApplyOutput {
            operation_id,
            before_fingerprint,
            after_fingerprint,
            staged,
        })
    }
}
