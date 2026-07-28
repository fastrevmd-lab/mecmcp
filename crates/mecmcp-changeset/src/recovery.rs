//! Indeterminate operation recovery.

use crate::{
    coordinator::CoordinatorError,
    lifecycle::LifecycleState,
    persistence::{read_state, write_state},
    types::OperationLimits,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Recovery disposition for an operation being resolved offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDisposition {
    /// Device evidence proves the operation committed.
    Committed,
    /// Device evidence proves the candidate changes were discarded.
    Discarded,
}

/// Output from resolving a persisted operation offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedOperationOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Device name.
    pub device: String,
    /// Final lifecycle state (committed or discarded).
    pub state: String,
    /// Job identifier from the device, if any.
    pub job_id: Option<String>,
    /// Candidate fingerprint.
    pub candidate_fingerprint: String,
    /// Human-readable details about the resolution.
    pub details: Option<String>,
}

/// Resolve one persisted non-terminal operation after offline manual reconciliation.
///
/// This function is designed to be called while the server is stopped, to repair state
/// after an operation was left unresolvable through the normal lifecycle. The operator
/// must have examined the device and determined what is actually true there.
///
/// Two cases reach this: a commit that left an unknown outcome (`Indeterminate`), and
/// an operation whose candidate was changed outside this server, which the fingerprint
/// guard then correctly refuses to discard. Both leave a record that blocks the device,
/// and both are settled by the same operator assertion.
///
/// # Safety Gate
///
/// The `confirmation` string must exactly match:
/// - `"RESOLVED {operation_id} AS COMMITTED"` if `disposition` is [`RecoveryDisposition::Committed`]
/// - `"RESOLVED {operation_id} AS DISCARDED"` if `disposition` is [`RecoveryDisposition::Discarded`]
///
/// This exact-match requirement prevents accidental resolution. No trimming, case normalization,
/// or partial matching is performed.
///
/// # Operation Requirements
///
/// - The operation must exist in the persisted state
/// - The operation must not already be terminal ([`LifecycleState::Committed`] or
///   [`LifecycleState::Discarded`]); re-resolving a settled record could only
///   overwrite a fact, not reconcile one
/// - The state path must be absolute
///
/// # State Changes
///
/// On success:
/// - The operation's state is updated to [`LifecycleState::Committed`] or [`LifecycleState::Discarded`]
/// - The `config_lock_held` flag is cleared
/// - The `details` field is updated to record the manual resolution
/// - The state file is written back to disk atomically
///
/// # Errors
///
/// Returns an error if:
/// - The path is not absolute
/// - The operation ID is invalid (not 64 lowercase hex characters)
/// - The confirmation string does not match exactly
/// - The operation ID is unknown
/// - The operation is not in the `Indeterminate` state
/// - The state file cannot be read or written
///
/// # Example
///
/// ```no_run
/// use mecmcp_changeset::recovery::{RecoveryDisposition, resolve_persisted_operation};
/// use mecmcp_changeset::OperationLimits;
/// use std::path::Path;
///
/// let path = Path::new("/var/lib/mecmcp/state.json");
/// let operation_id = "a1b2c3d4e5f6..."; // 64 hex chars
/// let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");
///
/// // Pass the same limits the server runs with, so the file this repairs is
/// // the same file the server can read.
/// let output = resolve_persisted_operation(
///     path,
///     operation_id,
///     RecoveryDisposition::Committed,
///     &confirmation,
///     OperationLimits::default(),
/// )?;
///
/// println!("Resolved operation {} as {}", output.operation_id, output.state);
/// # Ok::<(), mecmcp_changeset::CoordinatorError>(())
/// ```
pub fn resolve_persisted_operation(
    path: &Path,
    operation_id: &str,
    disposition: RecoveryDisposition,
    confirmation: &str,
    limits: OperationLimits,
) -> Result<ResolvedOperationOutput, CoordinatorError> {
    // Path must be absolute
    if !path.is_absolute() {
        return Err(CoordinatorError::new(
            "path",
            "changeset state path must be absolute",
        ));
    }

    // Validate operation ID format
    validate_operation_id(operation_id)?;

    // Build expected confirmation string
    let word = match disposition {
        RecoveryDisposition::Committed => "COMMITTED",
        RecoveryDisposition::Discarded => "DISCARDED",
    };
    let expected = format!("RESOLVED {operation_id} AS {word}");

    // Exact match required - no trimming, no case folding
    if confirmation != expected {
        return Err(CoordinatorError::new(
            "confirmation",
            "offline resolution requires exact 'RESOLVED <operation-id> AS COMMITTED|DISCARDED' confirmation",
        ));
    }

    // Load the state file. The size limit is the caller's, not a default: a
    // deployment that raised `max_state_bytes` would otherwise have a running
    // server that reads its state file happily and a repair tool that refuses
    // to open the very file it exists to fix.
    let mut state = read_state(path, limits.max_state_bytes)?;

    // Find the operation
    let record = state
        .operations
        .get_mut(operation_id)
        .ok_or_else(|| CoordinatorError::new("operation_id", "unknown persisted operation"))?;

    // Any non-terminal operation can be resolved, not only `Indeterminate`.
    //
    // The gate used to accept `Indeterminate` alone, on the reasoning that it is
    // the only "unknown outcome" state. But being stuck is not unique to it: a
    // `Staged` operation whose candidate was changed outside this server is
    // equally unresolvable, because the fingerprint guard correctly refuses to
    // discard against a candidate it no longer recognises and nothing else will
    // clear the record. Since one unreconciled operation is allowed per endpoint,
    // that record then blocks every later change on the device, and the only way
    // out was editing the state file by hand (rustpanosmcp#74).
    //
    // What the operator is asserting is the same in both cases: "I have looked at
    // the device and this is what is true." That assertion is what the exact
    // confirmation string buys, and it is no less valid for a stuck `Staged`
    // record than for an `Indeterminate` one.
    //
    // Terminal records are still refused. Re-resolving something already
    // `Committed` or `Discarded` cannot be a reconciliation — it can only
    // overwrite a settled fact.
    if record.state.terminal() {
        return Err(CoordinatorError::new(
            "operation_id",
            format!(
                "operation is already {}; a terminal operation cannot be resolved",
                record.state.as_str()
            ),
        ));
    }

    // Update the record, recording which state was overridden. An operator
    // reading this later needs to know the record was forced from `staged`
    // rather than settled from a genuine unknown.
    let previous = record.state.as_str().to_owned();
    record.state = match disposition {
        RecoveryDisposition::Committed => LifecycleState::Committed,
        RecoveryDisposition::Discarded => LifecycleState::Discarded,
    };
    record.config_lock_held = false;
    record.details = Some(format!(
        "operator marked {word} from {previous} after external device job/candidate/lock reconciliation"
    ));

    // Build output before writing
    let output = ResolvedOperationOutput {
        operation_id: record.id.clone(),
        device: record.device.clone(),
        state: record.state.as_str().to_owned(),
        job_id: record.job_id.clone(),
        candidate_fingerprint: record.current.clone(),
        details: record.details.clone(),
    };

    // Write the state back atomically
    write_state(path, &state, limits.max_state_bytes)?;

    Ok(output)
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
