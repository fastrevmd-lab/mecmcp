//! Change-set lifecycle operations: create, approve, status.

use crate::{
    coordinator::{ChangesetCoordinator, CoordinatorError},
    digest::{
        change_set_digest, compute_approval_digest, compute_waiver_digest_v3, validate_digest,
        validate_principal_for_digest,
    },
    lifecycle::ChangeSetState,
    records::{ApprovalRecord, ChangeSetRecord, WaiverKind, WaiverRecord},
};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Output from change-set lifecycle operations.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeSetOutput {
    /// Change-set identifier.
    pub change_set_id: String,
    /// Owner principal.
    pub owner: String,
    /// Device name.
    pub device: String,
    /// SHA-256 digest binding the plan.
    pub digest: String,
    /// Current lifecycle state.
    pub state: ChangeSetState,
    /// Approver principal (distinct from owner), if approved.
    pub approver: Option<String>,
    /// Unix timestamp when approval expires.
    pub expires_at_unix: u64,
    /// Number of actions in the change set.
    pub action_count: usize,
    /// Why approval was waived, when it was.
    ///
    /// `None` on an ordinary change set. `Some("lab-mode")` when a single-operator
    /// server approved it without a second principal.
    ///
    /// `approver` alone cannot carry this: it is `None` both for a change set
    /// still awaiting approval and for one that was waived, and those are very
    /// different facts. A reader — operator or SIEM — needs to tell "nobody has
    /// approved this yet" from "this was deliberately approved without review".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_waiver: Option<String>,
    /// The staged actions, when requested for review.
    ///
    /// Absent by default. Populated only when the caller explicitly requests the
    /// actions via `change_set_status_with_actions`. This allows approvers to see
    /// what they are approving, and SIEM to audit terminal change sets.
    ///
    /// Exposure is gated server-side (e.g., `--web-enabled-approver` in
    /// rust-junosmcp) — not all deployments want staged config content readable
    /// through the status tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<serde_json::Value>>,
}

impl From<ChangeSetRecord> for ChangeSetOutput {
    fn from(record: ChangeSetRecord) -> Self {
        Self {
            change_set_id: record.id,
            owner: record.owner,
            device: record.device,
            digest: record.digest,
            state: record.state,
            approver: record.approver,
            expires_at_unix: record.expires_at_unix,
            action_count: record.actions.len(),
            approval_waiver: record
                .approval
                .as_ref()
                .and_then(|approval| approval.waived.as_ref())
                .map(|waiver| waiver.reason.clone()),
            actions: None,
        }
    }
}

/// Returns the current Unix timestamp in seconds.
///
/// # Errors
///
/// Returns an error if the system clock is set before the Unix epoch.
pub(crate) fn now_unix() -> Result<u64, CoordinatorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| CoordinatorError::new("time", "system clock is before the Unix epoch"))
}

/// Generates a new 64-character hex operation/change-set identifier.
///
/// # Errors
///
/// Returns an error if the system's random number generator is unavailable.
pub(crate) fn new_operation_id() -> Result<String, CoordinatorError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        CoordinatorError::new("operation_id", format!("RNG unavailable: {error}"))
    })?;
    Ok(hex::encode(bytes))
}

impl ChangesetCoordinator {
    /// Creates and persists a new change set without mutating the device.
    ///
    /// This is the plan step: the caller provides ordered actions and an expected
    /// candidate fingerprint. The coordinator computes a digest binding
    /// `(owner, device, expected_fingerprint, actions)`, assigns an expiry based on
    /// the configured approval TTL, and persists the plan as `Planned`.
    ///
    /// The digest is the approval target: an independent principal must approve the
    /// exact digest to advance the change set to `Approved`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected fingerprint format is invalid
    /// - Actions are empty or exceed operational limits
    /// - The principal already has a pending change set on the device
    /// - The change-set store is full after evicting terminal records
    /// - Persistence fails
    pub async fn create_change_set<A: Serialize>(
        &self,
        device: String,
        actions: Vec<A>,
        owner: String,
        expected_fingerprint: String,
        policy_signature: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        crate::digest::validate_fingerprint(&expected_fingerprint)
            .map_err(|e| CoordinatorError::new("expected_candidate_fingerprint", e.to_string()))?;

        crate::records::validate_change_set_actions(&actions, self.limits())
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        let now = now_unix()?;
        let id = new_operation_id()?;

        // Serialize actions as serde_json::Value for storage
        let actions_value: Vec<serde_json::Value> = actions
            .into_iter()
            .map(|action| {
                serde_json::to_value(&action).map_err(|e| {
                    CoordinatorError::new("actions", format!("failed to serialize action: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let digest = change_set_digest(&owner, &device, &expected_fingerprint, &actions_value)
            .map_err(|e| CoordinatorError::new("digest", e.to_string()))?;

        let record = ChangeSetRecord {
            id: id.clone(),
            owner,
            device,
            expected_candidate_fingerprint: expected_fingerprint,
            actions: actions_value,
            digest: digest.clone(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: now.saturating_add(self.approval_ttl().as_secs()),
            operation_id: None,
            policy_signature,
            // Single-target, so both stay absent and the record still writes as
            // version 1 — which is what LXC 608 is running.
            targets: Vec::new(),
            preview: None,
        };

        self.insert_change_set(record.clone()).await?;

        // A change was proposed. `request_id` is the change-set id: this call
        // has no MCP request id to hand, and the two later records key on
        // `changeset_id` anyway, which is what carries context across the
        // lifecycle (mecmcp#292).
        if let Some(evidence) = self.evidence() {
            evidence.proposal(&id, &id, &record.device, &record.owner, &record.digest);
        }

        Ok(record.into())
    }

    /// Approves an unexpired change set with an independent principal.
    ///
    /// This is the approval gate: the approver must be distinct from the owner,
    /// the change set must be in `Planned` state, the approval window must not
    /// have expired, and the provided digest must match the stored digest exactly.
    ///
    /// On success, the change set transitions to `Approved`, the approver is recorded,
    /// and an approval digest is computed over `(change_set_id, plan_digest, owner,
    /// approver, approved_at)` and stored for tamper detection on load.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected digest format is invalid
    /// - The change set does not exist or belongs to another device
    /// - The approver is the same as the owner (self-approval denied)
    /// - The change set is not in `Planned` state
    /// - The approval window has expired
    /// - The provided digest does not match the stored digest
    /// - Persistence fails
    pub async fn approve_change_set(
        &self,
        change_set_id: String,
        device: String,
        approver: String,
        expected_digest: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;

        let mut record = self.change_set(&change_set_id, &device).await?;

        if record.owner == approver {
            return Err(CoordinatorError::new(
                "change_set_id",
                "the change-set owner cannot approve their own plan",
            ));
        }

        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }

        let now = now_unix()?;
        if now >= record.expires_at_unix {
            record.state = ChangeSetState::Expired;
            self.update_change_set(record).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set approval window expired",
            ));
        }

        if record.digest != expected_digest {
            return Err(CoordinatorError::new(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }

        // The v4 encoding is unambiguous by construction, so this check is no
        // longer what keeps pairings apart. It stays as an input rule: a `|` in
        // a principal is a sign of a malformed token name, and letting one in
        // here would also make the record unverifiable if it ever had to be read
        // back by a binary predating #283.
        validate_principal_for_digest("owner", &record.owner)
            .map_err(|msg| CoordinatorError::new("owner", msg))?;
        validate_principal_for_digest("approver", &approver)
            .map_err(|msg| CoordinatorError::new("approver", msg))?;

        // v4: a serialized tuple over
        // (marker, change_set_id, plan_digest, owner, approver, approved_at).
        // Digests held in memory are always the current version; the legacy
        // encoding survives only on disk, and `read_state` migrates it.
        let approval_digest = compute_approval_digest(
            &change_set_id,
            &record.digest,
            &record.owner,
            &approver,
            now,
        );

        record.state = ChangeSetState::Approved;
        record.approver = Some(approver.clone());
        record.approval = Some(ApprovalRecord {
            approver: Some(approver.clone()),
            approved_at_unix: now,
            digest: approval_digest,
            waived: None,
        });

        self.update_change_set(record.clone()).await?;

        // A human decided. Recorded after the state write, so the trail cannot
        // claim an approval the coordinator failed to persist.
        if let Some(evidence) = self.evidence() {
            evidence.approval(&change_set_id, &change_set_id, &approver, "approved");
        }

        Ok(record.into())
    }

    /// Waives approval for a change set in lab mode, allowing single-operator application.
    ///
    /// This is the lab-mode path: when lab mode is enabled, a change set can transition
    /// directly from `Planned` to `Approved` without a second principal. The approval is
    /// recorded as **waived**, never as obtained — no approver is written, and the waiver
    /// reason documents that this was a lab-mode operation.
    ///
    /// The waiver digest covers `(change_set_id, plan_digest, owner, waived_at, "lab-mode-waived")`,
    /// making it tamper-evident but distinct from genuine two-person approvals.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Lab mode is not enabled
    /// - The expected digest format is invalid
    /// - The change set does not exist or belongs to another device
    /// - The change set is not in `Planned` state
    /// - The approval window has expired
    /// - The provided digest does not match the stored digest
    /// - Persistence fails
    pub async fn waive_approval(
        &self,
        change_set_id: String,
        device: String,
        owner: String,
        expected_digest: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        if !self.lab_mode() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "approval waiver requires lab mode to be enabled",
            ));
        }

        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;

        let mut record = self.change_set(&change_set_id, &device).await?;

        if record.owner != owner {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the change-set owner can waive approval in lab mode",
            ));
        }

        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }

        let now = now_unix()?;
        if now >= record.expires_at_unix {
            record.state = ChangeSetState::Expired;
            self.update_change_set(record).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set approval window expired",
            ));
        }

        if record.digest != expected_digest {
            return Err(CoordinatorError::new(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }

        let waiver = WaiverRecord {
            kind: WaiverKind::LabMode,
            reason: "lab-mode".to_owned(),
            expires_at_unix: None,
            ticket: None,
        };
        let waived_as = (
            waiver.kind,
            waiver.reason.clone(),
            waiver.expires_at_unix,
            waiver.ticket.clone(),
        );
        let waiver_digest =
            compute_waiver_digest_v3(&change_set_id, &record.digest, &record.owner, now, &waiver);

        record.state = ChangeSetState::Approved;
        record.approver = None;
        record.approval = Some(ApprovalRecord {
            approver: None,
            approved_at_unix: now,
            digest: waiver_digest,
            waived: Some(waiver),
        });

        self.update_change_set(record.clone()).await?;

        // Every prod server in this fleet runs lab mode, so this — not
        // `approve_change_set` — is the path a real change takes. Emitting
        // nothing here would leave the trail jumping proposal to apply intent,
        // which reads exactly like a bypassed approval gate.
        if let Some(evidence) = self.evidence() {
            evidence.approval_waived(
                &change_set_id,
                &change_set_id,
                waived_as.0.as_str(),
                &waived_as.1,
                waived_as.2,
                waived_as.3.as_deref(),
            );
        }

        Ok(record.into())
    }

    /// Grants an operator-level approval waiver for the specified change set.
    ///
    /// Unlike `waive_approval`, this method does **not** require lab mode and
    /// records a documented exception granted under an active control. The
    /// waiver binds a kind, optional expiry, and optional ticket reference into
    /// its digest to prevent post-hoc relabelling or time-box extension.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The waiver `kind` is `WaiverKind::LabMode` (use `waive_approval` for that)
    /// - The `expires_at_unix` is already in the past (configuration error, not a valid waiver)
    /// - The change set does not exist or belongs to another device
    /// - Only the change-set owner can grant the waiver
    /// - The change set is not in `Planned` state
    /// - The approval window has expired
    /// - The expected digest does not match the stored digest
    #[allow(clippy::too_many_arguments)]
    pub async fn waive_approval_operator(
        &self,
        change_set_id: String,
        device: String,
        owner: String,
        expected_digest: String,
        kind: WaiverKind,
        reason: String,
        expires_at_unix: Option<u64>,
        ticket: Option<String>,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        if kind == WaiverKind::LabMode {
            return Err(CoordinatorError::new(
                "kind",
                "use waive_approval for a lab-mode waiver; this path records an \
                 operator-granted exception under a control that is still on",
            ));
        }

        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;

        let mut record = self.change_set(&change_set_id, &device).await?;

        if record.owner != owner {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the change-set owner can waive approval",
            ));
        }

        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }

        let now = now_unix()?;
        if now >= record.expires_at_unix {
            record.state = ChangeSetState::Expired;
            self.update_change_set(record).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set approval window expired",
            ));
        }

        if record.digest != expected_digest {
            return Err(CoordinatorError::new(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }

        if let Some(expires) = expires_at_unix
            && expires <= now
        {
            return Err(CoordinatorError::new(
                "expires_at_unix",
                "waiver expiry is already in the past; a waiver that is dead on \
                 arrival is a configuration error, not a waiver",
            ));
        }

        let waiver = WaiverRecord {
            kind,
            reason,
            expires_at_unix,
            ticket,
        };
        let waived_as = (
            waiver.kind,
            waiver.reason.clone(),
            waiver.expires_at_unix,
            waiver.ticket.clone(),
        );
        let waiver_digest =
            compute_waiver_digest_v3(&change_set_id, &record.digest, &record.owner, now, &waiver);

        record.state = ChangeSetState::Approved;
        record.approver = None;
        record.approval = Some(ApprovalRecord {
            approver: None,
            approved_at_unix: now,
            digest: waiver_digest,
            waived: Some(waiver),
        });

        self.update_change_set(record.clone()).await?;

        // Same reasoning as the lab-mode path, and more pointed: an operator
        // waiver is a bounded, ticketed exception, and the trail is where that
        // boundedness is visible. The ticket rides in metadata so an auditor can
        // follow the exception back to what authorised it.
        if let Some(evidence) = self.evidence() {
            evidence.approval_waived(
                &change_set_id,
                &change_set_id,
                waived_as.0.as_str(),
                &waived_as.1,
                waived_as.2,
                waived_as.3.as_deref(),
            );
        }

        Ok(record.into())
    }

    /// Retire `record` in place if either of its deadlines has passed.
    ///
    /// Two deadlines apply. A `Planned` record is retired by its own approval
    /// TTL, which is the long-standing rule and is left exactly as it was. A
    /// record approved by a time-boxed waiver is retired once that waiver has
    /// lapsed (#284) — before, `apply` refused such a record while every read
    /// path went on reporting it `Approved`, so the state the operator was shown
    /// contradicted the one the state machine enforced.
    ///
    /// The waiver check is deliberately not folded into the first condition.
    /// Widening the approval-TTL rule from `Planned` to every expirable state
    /// would retire `Approved` records on read for a reason unrelated to this
    /// defect, which is a larger behaviour change than the one being fixed.
    async fn retire_if_deadline_passed(
        &self,
        record: &mut ChangeSetRecord,
    ) -> Result<(), CoordinatorError> {
        let now = now_unix()?;

        let approval_ttl_passed =
            record.state == ChangeSetState::Planned && now >= record.expires_at_unix;
        let waiver_lapsed = crate::coordinator::is_expirable(record.state)
            && crate::apply::waiver_lapsed(record, now);

        if approval_ttl_passed || waiver_lapsed {
            record.state = ChangeSetState::Expired;
            self.update_change_set(record.clone()).await?;
        }

        Ok(())
    }

    /// Retrieves the status of a change set, auto-expiring if needed.
    ///
    /// If the change set is in `Planned` state and the current time is past
    /// `expires_at_unix`, it is transitioned to `Expired` and persisted before
    /// returning.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change set does not exist or belongs to another device
    /// - Persistence fails (when auto-expiring)
    pub async fn change_set_status(
        &self,
        change_set_id: String,
        device: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        let mut record = self.change_set(&change_set_id, &device).await?;

        self.retire_if_deadline_passed(&mut record).await?;

        Ok(record.into())
    }

    /// Retrieves the status of a change set WITH the stored actions, auto-expiring if needed.
    ///
    /// This is the review-enabled variant of `change_set_status`. It returns the same
    /// metadata as the base method but also populates the `actions` field with the
    /// exact stored actions. This allows approvers to see what they are approving and
    /// SIEM to audit terminal change sets.
    ///
    /// Authorization semantics are identical to `change_set_status` — no additional
    /// principal checks. Exposure is gated server-side (e.g., via `--web-enabled-approver`
    /// in rust-junosmcp).
    ///
    /// If the change set is in `Planned` state and the current time is past
    /// `expires_at_unix`, it is transitioned to `Expired` and persisted before
    /// returning.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change set does not exist or belongs to another device
    /// - Persistence fails (when auto-expiring)
    pub async fn change_set_status_with_actions(
        &self,
        change_set_id: String,
        device: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        let mut record = self.change_set(&change_set_id, &device).await?;

        self.retire_if_deadline_passed(&mut record).await?;

        let mut output: ChangeSetOutput = record.clone().into();
        output.actions = Some(record.actions);
        Ok(output)
    }

    /// Cancels a change set, freeing the per-principal pending slot.
    ///
    /// A change set may be cancelled by its owner or by an approver-class principal.
    /// Valid from states `Planned` or `Approved` (not yet applied). Transitions the
    /// record to a terminal `Cancelled` state and frees the per-principal pending slot,
    /// allowing a new change set to be created immediately. Records are never deleted —
    /// the audit trail is preserved.
    ///
    /// Idempotent: cancelling an already-`Cancelled` set returns its current state
    /// without error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change set does not exist or belongs to another device
    /// - The principal is neither the owner nor an approver
    /// - The change set is in `Applied` or `Applying` state (cannot cancel an in-flight or completed apply)
    /// - Persistence fails
    pub async fn cancel_change_set(
        &self,
        change_set_id: String,
        device: String,
        principal: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        let mut record = self.change_set(&change_set_id, &device).await?;

        // Idempotent: return current state if already cancelled
        if record.state == ChangeSetState::Cancelled {
            return Ok(record.into());
        }

        // Check authorization: principal must be owner or approver
        let is_owner = record.owner == principal;
        let is_approver = record.approver.as_ref() == Some(&principal);

        if !is_owner && !is_approver {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the change-set owner or approver may cancel it",
            ));
        }

        // Reject if state is Applying or Applied
        if matches!(
            record.state,
            ChangeSetState::Applying | ChangeSetState::Applied
        ) {
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "cannot cancel a change set in state {:?}",
                    record.state.as_str()
                ),
            ));
        }

        // Transition to Cancelled (valid from Planned, Approved, Expired, or Failed)
        record.state = ChangeSetState::Cancelled;
        self.update_change_set(record.clone()).await?;

        Ok(record.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::compute_approval_digest;

    #[test]
    fn test_approval_digest_is_deterministic() {
        let digest1 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        let digest2 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_approval_digest_changes_with_approver() {
        let digest1 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        let digest2 =
            compute_approval_digest("abc123", "sha256:plan", "alice", "charlie", 1700000000);
        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_approval_digest_changes_with_owner() {
        let digest1 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        let digest2 = compute_approval_digest("abc123", "sha256:plan", "eve", "bob", 1700000000);
        assert_ne!(digest1, digest2);
    }
}
