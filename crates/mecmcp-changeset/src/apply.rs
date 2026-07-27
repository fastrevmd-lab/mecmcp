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

/// Canonicalizes an endpoint URL to a consistent form for use as a device guard key.
///
/// This function:
/// - Validates the URL starts with `https://`
/// - Lowercases the scheme and host
/// - Removes trailing slashes from the path
/// - Rejects malformed URLs
///
/// # Errors
///
/// Returns an error if the endpoint is not a valid HTTPS URL.
fn canonicalize_endpoint(endpoint: &str) -> Result<String, CoordinatorError> {
    if !endpoint.starts_with("https://") && !endpoint.starts_with("HTTPS://") {
        return Err(CoordinatorError::new(
            "endpoint",
            "endpoint must start with https://",
        ));
    }

    // Parse the URL to validate structure
    let url = url::Url::parse(endpoint)
        .map_err(|e| CoordinatorError::new("endpoint", format!("invalid endpoint URL: {e}")))?;

    if url.scheme() != "https" {
        return Err(CoordinatorError::new(
            "endpoint",
            "endpoint must use https scheme",
        ));
    }

    // Rebuild with normalized components
    let host = url
        .host_str()
        .ok_or_else(|| CoordinatorError::new("endpoint", "endpoint must contain a valid host"))?;

    let mut canonical = format!("https://{}", host.to_lowercase());

    if let Some(port) = url.port() {
        canonical.push_str(&format!(":{port}"));
    }

    let path = url.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        canonical.push_str(path);
    }

    Ok(canonical)
}

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
    /// # Cross-process atomicity limitation
    ///
    /// The in-process device guard serializes concurrent `apply_change_set` calls within
    /// this process, but it cannot exclude external sessions (other processes, SSH, GUI).
    /// Between the fingerprint check and the `stage()` call, an external session could
    /// mutate the candidate, causing actions to be staged onto a state that was never
    /// approved.
    ///
    /// To narrow the window, this method re-reads the fingerprint immediately before
    /// staging and compares it to the expected value. This is not true atomicity —
    /// that requires a device-side lock held across the check-then-stage sequence —
    /// but it detects drift that happens in the (now much smaller) window. A future
    /// task will add a device-lock primitive to close the window entirely.
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
    /// - The endpoint format is invalid (must start with `https://`)
    /// - The change set does not exist or belongs to another device
    /// - The change set is not owned by the specified owner
    /// - The change set is not in `Approved` state
    /// - The approval has expired
    /// - The supplied digest or fingerprint does not match the stored values exactly
    /// - The device guard cannot be acquired (cancellation)
    /// - Any action fails to stage (the change set is marked `Failed`)
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
        endpoint: String,
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

        // Canonicalize and validate the endpoint before using it as a device guard key
        let endpoint = canonicalize_endpoint(&endpoint)?;

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

        // Validate approval is present and either genuine or waived.
        // Legacy compatibility: records created before the approval-digest feature have
        // `approver: Some(...)` but `approval: None`. Accept both forms.
        if let Some(approval) = &change_set.approval {
            // New tamper-evident approval: must have either an approver or a waiver
            if approval.approver.is_none() && approval.waived.is_none() {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "approval record must contain either an approver or a waiver",
                ));
            }
        } else {
            // Legacy approval: must have an approver in the top-level field
            if change_set.approver.is_none() {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "approved change set missing approval record",
                ));
            }
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
        let _guard = self.device_guard(&endpoint, cancellation).await?;

        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Re-check the change set after acquiring the guard
        change_set = self.change_set(&change_set_id, &device).await?;

        let now_after_guard = now_unix()?;

        if change_set.owner != owner
            || change_set.state != ChangeSetState::Approved
            || change_set.digest != expected_digest
            || change_set.expected_candidate_fingerprint != expected_fingerprint
        {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is no longer the exact unexpired approved plan",
            ));
        }

        // Check expiration after acquiring the guard. If the TTL elapses while waiting
        // for a busy guard, transition the change set to Expired rather than proceeding.
        if now_after_guard >= change_set.expires_at_unix {
            change_set.state = ChangeSetState::Expired;
            self.update_change_set(change_set).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set expired while waiting for device guard",
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

        // CRITICAL: The in-process guard cannot exclude external sessions (other processes,
        // SSH, GUI). Between the fingerprint read above and the stage() call below, another
        // session could mutate the candidate. To narrow the window, re-read the fingerprint
        // immediately before staging and compare. This is not true atomicity — that requires
        // a device-side lock held across the check — but it detects drift that happens in
        // the (now much smaller) window.
        let pre_stage_fingerprint = transaction.fingerprint().await.map_err(|e| {
            CoordinatorError::new("device", format!("pre-stage fingerprint failed: {e}"))
        })?;

        if pre_stage_fingerprint != expected_fingerprint {
            return Err(CoordinatorError::new(
                "expected_fingerprint",
                format!(
                    "device fingerprint changed between check and stage: expected {}, found {}",
                    expected_fingerprint, pre_stage_fingerprint
                ),
            ));
        }

        // Deserialize actions before marking the change set as Applying
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

        // Generate operation ID
        let operation_id = new_operation_id()?;

        // Create operation record in staging state BEFORE calling the device
        let operation_record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.clone(),
            device: device.clone(),
            endpoint: endpoint.clone(),
            action: change_set.actions.first().cloned().unwrap_or_default(),
            xpath: None,
            actions: change_set.actions.clone(),
            change_set_id: Some(change_set_id.clone()),
            current: before_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: Some(format!(
                "staging change set {} with {} actions",
                change_set_id,
                actions.len()
            )),
            config_lock_held: false,
            policy_signature: change_set.policy_signature.clone(),
        };

        self.insert(operation_record).await?;

        // Mark change set as Applying. On failure, remove the operation reservation
        // to unblock the endpoint.
        change_set.state = ChangeSetState::Applying;
        change_set.operation_id = Some(operation_id.clone());
        if let Err(error) = self.update_change_set(change_set.clone()).await {
            self.remove(&operation_id).await;
            return Err(error);
        }

        // Stage all actions through the transaction
        let staged = match transaction.stage(&actions).await {
            Ok(staged) => staged,
            Err(error) => {
                // The DeviceTransaction::stage contract guarantees that on partial
                // failure (e.g., action 2 fails after action 1 succeeds), the
                // implementation reverts action 1 before returning an error.
                // A failed partial-stage revert obliges the implementation to mark
                // the session tainted and close it. Therefore, the coordinator does
                // NOT revert here — doing so would be redundant and dangerous
                // (a candidate revert clears ALL uncommitted changes, including
                // pre-existing operator work).
                change_set.state = ChangeSetState::Failed;
                self.update_change_set(change_set).await?;

                // Remove the staging operation record
                self.remove(&operation_id).await;

                return Err(CoordinatorError::new(
                    "device",
                    format!("staging failed: {error}"),
                ));
            }
        };

        // Capture the after fingerprint
        let after_fingerprint = match transaction.fingerprint().await {
            Ok(fp) => fp,
            Err(error) => {
                // Fingerprint read failed after a successful stage. DO NOT revert:
                // 1. The approved fingerprint may legitimately include pre-existing
                //    uncommitted work.
                // 2. Both Junos rollback-0 and PAN-OS partial admin revert clear more
                //    than just this change set — they would destroy unrelated operator work.
                //
                // Instead, mark the operation as Indeterminate and leave the change set
                // as Failed. The operator must inspect the device and decide whether to
                // commit or revert manually.
                change_set.state = ChangeSetState::Failed;
                self.update_change_set(change_set).await?;

                let mut record = self.record(&operation_id, &owner, &device).await?;
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!(
                    "fingerprint read failed after staging: {error}; staged changes remain on device"
                ));
                self.update(record).await?;

                return Err(CoordinatorError::new(
                    "device",
                    format!(
                        "fingerprint read failed after staging: {error}; operation is indeterminate"
                    ),
                ));
            }
        };

        // Update operation record to Staged state with the after fingerprint
        let mut operation_record = self.record(&operation_id, &owner, &device).await?;
        operation_record.current = after_fingerprint.clone();
        operation_record.state = LifecycleState::Staged;
        operation_record.details = Some(format!(
            "applied change set {} with {} actions",
            change_set_id,
            actions.len()
        ));
        // A successful stage may hold a configuration lock (PAN-OS) or candidate lock (Junos).
        // The trait does not expose whether a lock is held, so we conservatively record that
        // a lock may be held. Later discard/commit operations must attempt to release it.
        operation_record.config_lock_held = true;

        // Persist the operation update. On failure, mark the operation as Indeterminate
        // rather than leaving it in Staging — the device candidate is changed but we
        // cannot confirm the persisted state matches.
        if let Err(persist_error) = self.update(operation_record.clone()).await {
            operation_record.state = LifecycleState::Indeterminate;
            operation_record.details = Some(format!(
                "staging succeeded but state persistence failed: {persist_error}"
            ));
            // Try once more to persist the indeterminate state; if this also fails,
            // the operation remains Staging in memory and will be marked Indeterminate
            // on restart.
            let _ = self.update(operation_record).await;
            return Err(persist_error);
        }

        // Mark change set as Applied. On failure, the operation is already Staged,
        // so we leave it terminal and mark the change set as Failed.
        change_set.state = ChangeSetState::Applied;
        if let Err(persist_error) = self.update_change_set(change_set.clone()).await {
            change_set.state = ChangeSetState::Failed;
            let _ = self.update_change_set(change_set).await;
            return Err(persist_error);
        }

        Ok(ApplyOutput {
            operation_id,
            before_fingerprint,
            after_fingerprint,
            staged,
        })
    }
}
