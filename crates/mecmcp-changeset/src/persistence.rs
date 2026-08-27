//! Atomic persistence of changeset state with schema versioning.

use crate::{
    ChangeSetRecord, OperationRecord,
    digest::{
        compute_approval_digest, compute_approval_digest_legacy, compute_waiver_digest,
        compute_waiver_digest_v3, validate_fingerprint, validate_principal_for_digest,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

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
    // One implementation of the symlink / regular-file / mode / owner / size
    // checks, shared with `mecmcp-auth`, `mecmcp-inventory` and `mecmcp-secret`
    // (#173, #187). The copy that used to live here called `symlink_metadata`
    // and then `File::open` — two operations on the same path, so the file could
    // be swapped in between. Opening once with `O_NOFOLLOW` and validating the
    // descriptor closes that race.
    //
    // The caller's `max_state_bytes` is honoured rather than
    // `FileLimits::default()`: 608's live state file is already 26 KB and grows
    // with change-set history, and the product owns that budget.
    let limits = mecmcp_secret::FileLimits {
        max_bytes: usize::try_from(max_state_bytes).unwrap_or(usize::MAX),
    };
    let bytes = mecmcp_secret::read_hardened_file(path, limits).map_err(|error| {
        PersistenceError::new(format!(
            "could not read changeset state '{}': {error}",
            path.display()
        ))
    })?;
    let bytes = bytes.expose();

    let on_disk: OnDiskChangesetState = serde_json::from_slice(bytes)
        .map_err(|error| PersistenceError::new(format!("invalid changeset state JSON: {error}")))?;

    if !(1..=5).contains(&on_disk.version) {
        return Err(PersistenceError::new(format!(
            "unsupported changeset state version {}",
            on_disk.version
        )));
    }

    validate_state(&on_disk.state, on_disk.version)?;

    // Defect 1 fix: migrate legacy waiver digests to v3 after successful validation.
    // This is safe precisely because the legacy digest was just verified — we are
    // re-signing evidence we have already authenticated. Without this migration, the
    // next write_state would stamp the file version 3 (waivers_need_v3 triggers on
    // any waiver), but the digest stays legacy, causing the next read_state to fail
    // with a mismatch.
    let mut state = on_disk.state;
    if on_disk.version < 3 {
        for record in state.change_sets.values_mut() {
            if let Some(approval) = record.approval.as_mut()
                && let Some(waiver) = approval.waived.as_ref()
            {
                // Re-compute the digest using v3 over the same inputs
                approval.digest = crate::digest::compute_waiver_digest_v3(
                    &record.id,
                    &record.digest,
                    &record.owner,
                    approval.approved_at_unix,
                    waiver,
                );
            }
        }
    }

    // Same reasoning for approvals (mecmcp#283): re-sign under v4 once the
    // legacy digest has verified. Without it, the next `write_state` stamps the
    // file version 4 — `approvals_need_v4` triggers on any real approval — while
    // the digest stays legacy, and the following `read_state` rejects the file.
    //
    // Re-signing launders nothing here. The legacy approval digest already
    // covers all five fields v4 binds, so promoting it authenticates no value
    // that was previously unsigned. That is what made the waiver migration need
    // its `reason == "lab-mode"` guard — `reason` was outside the legacy digest
    // — and there is no analogue for approvals.
    if on_disk.version < 4 {
        for record in state.change_sets.values_mut() {
            let id = record.id.clone();
            let owner = record.owner.clone();
            let change_set_digest = record.digest.clone();
            if let Some(approval) = record.approval.as_mut()
                && let Some(approver) = approval.approver.as_ref()
            {
                approval.digest = crate::digest::compute_approval_digest(
                    &id,
                    &change_set_digest,
                    &owner,
                    approver,
                    approval.approved_at_unix,
                );
            }
        }
    }

    Ok(state)
}

/// Validates the in-memory state for consistency.
///
/// # Errors
///
/// Returns an error if the state contains invalid or inconsistent records.
pub fn validate_state(state: &ChangesetState, version: u32) -> Result<(), PersistenceError> {
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
        // The endpoint identifies a device; it is not required to be HTTPS.
        // PAN-OS's management interface genuinely is an HTTPS XML API, but Junos
        // is NETCONF over SSH and has no HTTPS endpoint at all. Demanding the
        // scheme forced a vendor to persist a false address to satisfy a
        // validator, which is the class of fabrication this crate exists to
        // avoid. What the field must be is a stable, parseable device
        // identifier — that is what makes it usable as a guard key (#69).
        if url::Url::parse(&record.endpoint).is_err() || record.actions.is_empty() {
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
        // Structure first, because the digest is computed over the target list:
        // a record whose targets are unsorted or duplicated has a digest that is
        // a function of how the caller built the list rather than of what the
        // change set does. `usize::MAX` because the count ceiling is a resource
        // limit the coordinator enforces at insert, and `validate_state` has no
        // limits to consult — a file that was legal when written must not become
        // unloadable because the ceiling was lowered afterwards.
        record
            .validate_target_set(usize::MAX)
            .map_err(|error| PersistenceError::new(format!("changeset state {error}")))?;

        // Recompute the digest to detect tampering. With preserve_order enabled on
        // serde_json::Value, the key order from the file is preserved and this check
        // reproduces the original digest exactly. Without preserve_order, this would
        // reject all production state files due to key reordering.
        //
        // Target-aware: a multi-target record is written with the five-tuple
        // digest, so recomputing the four-tuple here rejected every one of them
        // on the next load and made the feature unusable across restarts.
        // `change_set_digest_with_targets` reproduces the four-tuple byte for
        // byte when `targets` is empty, so single-target records are unaffected.
        let expected = crate::digest::change_set_digest_with_targets(
            &record.owner,
            &record.device,
            &record.expected_candidate_fingerprint,
            &record.actions,
            &record.targets,
        )
        .map_err(|error| {
            PersistenceError::new(format!("could not recompute change-set digest: {error}"))
        })?;
        if expected != record.digest {
            return Err(PersistenceError::new(
                "changeset state change-set digest mismatch",
            ));
        }

        // Same reasoning as the target ceiling: verify the preview's digest
        // here, and leave the size ceiling to the insert boundary.
        record
            .validate_preview(usize::MAX)
            .map_err(|error| PersistenceError::new(format!("changeset state {error}")))?;

        // Validate approval digest if present (Issue #50: approval tamper-evidence)
        if let Some(approval) = &record.approval {
            crate::digest::validate_digest(&approval.digest, "approval_digest").map_err(
                |error| PersistenceError::new(format!("approval digest invalid: {error}")),
            )?;

            // Defect 5 fix: reject records with both approver and waived set.
            // These fields are mutually exclusive by construction — waive_approval
            // sets approver = None. A record with both is malformed and likely an
            // injection attempt. Rejecting this shape before the digest branch
            // prevents the migration from corrupting a genuine approval that has
            // a waived object injected.
            if approval.approver.is_some() && approval.waived.is_some() {
                return Err(PersistenceError::new(
                    "changeset state approval record has both approver and waived fields set (mutually exclusive)",
                ));
            }

            let expected_approval_digest = if let Some(approver) = &approval.approver {
                if version >= 4 {
                    // The tuple encoding is unambiguous by construction, so the
                    // separator rule is not needed to make it safe.
                    compute_approval_digest(
                        id,
                        &record.digest,
                        &record.owner,
                        approver,
                        approval.approved_at_unix,
                    )
                } else {
                    // Legacy: the `|`-joined encoding, which is only safe for
                    // values that cannot move a field boundary. Version decides
                    // the rule outright — accepting "either digest verifies"
                    // would let a forged legacy digest pass on a v4 record,
                    // which is the downgrade hole #275 refused for waivers.
                    validate_principal_for_digest("owner", &record.owner)
                        .map_err(PersistenceError::new)?;
                    validate_principal_for_digest("approver", approver)
                        .map_err(PersistenceError::new)?;
                    compute_approval_digest_legacy(
                        id,
                        &record.digest,
                        &record.owner,
                        approver,
                        approval.approved_at_unix,
                    )
                }
            } else if let Some(waiver) = approval.waived.as_ref() {
                // Defect 2 fix: reject v1/v2 waivers carrying v3-only metadata.
                // A genuine legacy waiver could not have carried kind != LabMode,
                // expires_at_unix, or ticket. Accepting them here lets someone
                // relabel a lab-mode waiver as operator_file and forge its authority.
                if version < 3 {
                    use crate::records::WaiverKind;
                    if waiver.kind != WaiverKind::LabMode {
                        return Err(PersistenceError::new(format!(
                            "changeset state v{version} waiver cannot carry kind {:?} (v3-only metadata)",
                            waiver.kind
                        )));
                    }
                    if waiver.expires_at_unix.is_some() {
                        return Err(PersistenceError::new(format!(
                            "changeset state v{version} waiver cannot carry expires_at_unix (v3-only metadata)"
                        )));
                    }
                    if waiver.ticket.is_some() {
                        return Err(PersistenceError::new(format!(
                            "changeset state v{version} waiver cannot carry ticket (v3-only metadata)"
                        )));
                    }
                    // Defect 4 fix: reject v1/v2 waivers with unexpected reason text.
                    // The legacy digest does NOT cover reason, so it can be edited
                    // freely. The migration then re-signs with v3, which DOES include
                    // reason, promoting unauthenticated text into signed evidence.
                    // waive_approval emits the literal "lab-mode", so require exactly
                    // that before re-signing. This check protects both validate_state
                    // and the migration.
                    if waiver.reason != "lab-mode" {
                        return Err(PersistenceError::new(format!(
                            "changeset state v{version} waiver has unexpected reason {:?} (expected \"lab-mode\")",
                            waiver.reason
                        )));
                    }
                }

                // Version decides the rule outright. Accepting "either digest
                // verifies" would let a forged legacy digest pass on a v3
                // record, which defeats the point of binding the kind.
                if version >= 3 {
                    compute_waiver_digest_v3(
                        id,
                        &record.digest,
                        &record.owner,
                        approval.approved_at_unix,
                        waiver,
                    )
                } else {
                    // Legacy waiver: validate owner before digest computation.
                    validate_principal_for_digest("owner", &record.owner)
                        .map_err(PersistenceError::new)?;
                    compute_waiver_digest(
                        id,
                        &record.digest,
                        &record.owner,
                        approval.approved_at_unix,
                    )
                }
            } else {
                // Legacy waiver without waived field: validate owner before digest computation.
                validate_principal_for_digest("owner", &record.owner)
                    .map_err(PersistenceError::new)?;
                compute_waiver_digest(id, &record.digest, &record.owner, approval.approved_at_unix)
            };

            if expected_approval_digest != approval.digest {
                return Err(PersistenceError::new(
                    "changeset state approval digest mismatch: approval evidence has been tampered with",
                ));
            }
        }
        // Legacy compatibility: records created before the approval-digest feature have
        // no `approval` field. The `approver` field may be populated from legacy data.
        // We accept these records without approval digest validation, but a future
        // operator examining the state file can distinguish them from tamper-evident
        // approvals by the presence/absence of the `approval` field.
    }

    Ok(())
}

/// Writes the changeset state to disk atomically.
///
/// Writes version 2 if any operation record contains `attribution` or
/// `rollback_deadline_unix`, otherwise writes version 1 for backward compatibility.
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

    // Drop an empty task handle before anything else looks at the state.
    //
    // `Some("")` names no vendor operation, so it carries no information and
    // nothing can re-probe it — but it is still `Some`, so a recovery path
    // asking `is_none()` would read it as "this apply is recoverable" and hold
    // the record `Applying` across every restart, pinning the principal/device
    // pending slot against a task that does not exist.
    //
    // Normalised here rather than rejected in `validate_state`, and the
    // distinction matters: `write_state` does not validate, so a rejection
    // would only fire on the *next* load and would refuse the whole file —
    // turning one bad handle into a server that will not start. Dropping the
    // field loses nothing and guarantees no file this binary writes contains
    // one. Files written by older binaries still reach recovery, which treats
    // an empty handle as absent.
    //
    // Cloned only when there is something to fix, so the common path does not
    // copy the state on every write.
    let normalised;
    let state = if state
        .change_sets
        .values()
        .any(|cs| cs.task_id.as_deref().is_some_and(str::is_empty))
    {
        let mut copy = state.clone();
        for record in copy.change_sets.values_mut() {
            if record.task_id.as_deref().is_some_and(str::is_empty) {
                record.task_id = None;
            }
        }
        normalised = copy;
        &normalised
    } else {
        state
    };

    // Write version 2 only when a record actually carries a field the version-1
    // reader does not know. Both record types are `deny_unknown_fields`, so a
    // previous binary handed an unexpected key rejects the WHOLE file, not one
    // record — and rolling a release back is a documented step in these servers'
    // deploy procedure. A deployment that uses none of these fields keeps
    // producing files the older binary reads.
    let operations_need_v2 = state
        .operations
        .values()
        .any(|op| op.attribution.is_some() || op.rollback_deadline_unix.is_some());
    let change_sets_need_v2 = state.change_sets.values().any(|cs| {
        // `targets`, `preview` and `task_id` join `policy_signature` here for
        // the same reason: `ChangeSetRecord` is `deny_unknown_fields`, so a
        // binary that predates a field rejects the WHOLE file rather than the
        // one record, and rolling a release back is a documented deploy step.
        // A deployment using none of them keeps producing version-1 files the
        // older binary reads — which is what LXC 608 is doing today.
        //
        // `task_id` is the sharpest case of the three. It is written while an
        // apply is in flight, so a rollback performed *during* an apply is
        // exactly when the file would carry one — the moment an unreadable
        // state file hurts most.
        !cs.policy_signature.is_empty()
            || !cs.targets.is_empty()
            || cs.preview.is_some()
            || cs.task_id.is_some()
    });
    // Version 5 is required by `apply_without_handle`, and it needs a generation
    // of its own rather than a place in the v2 list: version selection takes the
    // highest match, so a file with a real approval is v4 whatever v2 says, and
    // 0.21.0 accepts 1..=4. It would read such a file as a supported schema and
    // then reject the record on the unknown field, which is the failure the
    // version gate exists to prevent.
    //
    // The sharpest case of the same reason `task_id` is gated. This field is
    // only ever true while a handleless apply is in flight, and unlike a task
    // handle that record cannot be settled by re-probing — so an unreadable
    // state file is the difference between "a human checks the guest" and
    // "nothing can read the state at all".
    let handleless_applies_need_v5 = state.change_sets.values().any(|cs| cs.apply_without_handle);
    // A non-HTTPS endpoint is a version-2 record too. It is not a new *field*,
    // but the version-1 reader validated `starts_with("https://")` and would
    // reject the whole file over it — which is the same practical consequence
    // the version gate exists to prevent, so it gets the same treatment (#69).
    let endpoints_need_v2 = state
        .operations
        .values()
        .any(|op| !op.endpoint.starts_with("https://"));
    // Version 3 is required if any waiver record is present. `WaiverRecord::kind`
    // always serializes (no `skip_serializing_if`), so every waiver — lab mode
    // included — writes a `"kind"` key, and the pre-#275 `WaiverRecord` is
    // `deny_unknown_fields` over `reason` alone. An older binary rejects any
    // file containing any waiver regardless of version. Deployments with no
    // waivers are unaffected and keep selecting v1/v2 by the existing rules.
    let waivers_need_v3 = state.change_sets.values().any(|cs| {
        cs.approval
            .as_ref()
            .and_then(|a| a.waived.as_ref())
            .is_some()
    });
    // Version 4 is required once a record carries a genuine two-person approval,
    // because its digest is computed under the unambiguous tuple encoding
    // (mecmcp#283) and a v1–v3 reader would recompute the `|`-joined one and
    // reject the file. Content-based, like every rule above it: a deployment
    // with no real approvals keeps writing the version it wrote before.
    let approvals_need_v4 = state
        .change_sets
        .values()
        .any(|cs| cs.approval.as_ref().is_some_and(|a| a.approver.is_some()));
    let version = if handleless_applies_need_v5 {
        5
    } else if approvals_need_v4 {
        4
    } else if waivers_need_v3 {
        3
    } else if operations_need_v2 || change_sets_need_v2 || endpoints_need_v2 {
        2
    } else {
        1
    };

    let payload = serde_json::to_vec_pretty(&OnDiskChangesetState {
        version,
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

    // Preserve the destination's ownership across the replacement.
    //
    // Without this, offline recovery run under `sudo` against a service-owned
    // state file leaves a root-owned 0600 file that the non-root service cannot
    // open at all — the server then fails to start with a permission error that
    // never mentions ownership. The shared reader permits uid 0 as a *reader*
    // precisely so `sudo` operator commands work, which is what makes this
    // reachable.
    //
    // `mecmcp-auth::write_atomic` already does this for tokens.json and its
    // comment describes the same failure; this is the same fix for the same
    // reason. Best-effort by design: no destination means nothing to preserve,
    // and failing to chown means we are almost certainly already the owner.
    #[cfg(unix)]
    if let Ok(existing) = fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        let _ =
            std::os::unix::fs::chown(temporary.path(), Some(existing.uid()), Some(existing.gid()));
    }

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
