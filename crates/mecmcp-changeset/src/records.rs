//! Operation and change-set record types.

use crate::{
    digest::{digest_hex, validate_fingerprint},
    lifecycle::{ChangeSetState, LifecycleState},
    types::OperationLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Persisted operation record.
///
/// This type is vendor-agnostic and uses `serde_json::Value` for the `action` and `actions`
/// fields to allow any device transaction implementation to store its own action types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    /// Operation identifier (64 hex characters).
    pub id: String,
    /// Principal who owns this operation.
    pub owner: String,
    /// Device name from inventory.
    pub device: String,
    /// Device endpoint (must start with `https://`).
    pub endpoint: String,
    /// Primary action type (vendor-specific, serialized as JSON).
    pub action: serde_json::Value,
    /// Primary action target path (vendor-specific, optional).
    ///
    /// PAN-OS operations carry an XPath identifying the config tree node being mutated.
    /// Junos operations have no analogous concept and omit this field.
    /// The field name "xpath" is preserved for on-disk compatibility with the production
    /// state file on LXC 608, but the Rust field name is vendor-neutral.
    #[serde(rename = "xpath")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpath: Option<String>,
    /// All actions in this operation (vendor-specific, serialized as JSON).
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    /// Associated change-set identifier, if this operation was created by applying a change set.
    #[serde(default)]
    pub change_set_id: Option<String>,
    /// Candidate fingerprint when this operation was staged.
    pub current: String,
    /// Lifecycle state of the operation.
    pub state: LifecycleState,
    /// Job identifier from the device, if any.
    pub job_id: Option<String>,
    /// Human-readable details about the operation outcome.
    pub details: Option<String>,
    /// Whether the configuration lock is held by this operation.
    pub config_lock_held: bool,
    /// Policy signature at the time of staging.
    pub policy_signature: String,
}

/// Persisted change-set record.
///
/// This type is vendor-agnostic and uses `serde_json::Value` for the `actions` field
/// to allow any device transaction implementation to store its own action types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetRecord {
    /// Change-set identifier (64 hex characters).
    pub id: String,
    /// Principal who created this change set.
    pub owner: String,
    /// Device name from inventory.
    pub device: String,
    /// Expected candidate fingerprint at apply time.
    pub expected_candidate_fingerprint: String,
    /// Ordered actions (vendor-specific, serialized as JSON).
    pub actions: Vec<serde_json::Value>,
    /// SHA-256 digest binding `(owner, device, fingerprint, actions)`.
    pub digest: String,
    /// Lifecycle state of the change set.
    pub state: ChangeSetState,
    /// Principal who approved this change set (distinct from owner).
    pub approver: Option<String>,
    /// Unix timestamp when the approval expires.
    pub expires_at_unix: u64,
    /// Operation identifier created when this change set was applied.
    pub operation_id: Option<String>,
}

/// Error type for record validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    field: &'static str,
    message: String,
}

impl RecordError {
    fn new(field: &'static str, message: String) -> Self {
        Self { field, message }
    }
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for RecordError {}

/// Validates that an operation's policy signature matches the current policy.
///
/// The policy signature is a stable identifier computed from the policy configuration
/// at the time the operation was staged. If the policy changes before the operation
/// commits, this guard detects the drift and rejects the operation.
///
/// # Errors
///
/// Returns an error if the operation's stored policy signature does not match
/// the current policy signature.
pub fn require_operation_policy<P: AsRef<str>>(
    record: &OperationRecord,
    current_policy_signature: P,
) -> Result<(), RecordError> {
    if record.policy_signature == current_policy_signature.as_ref() {
        Ok(())
    } else {
        Err(RecordError::new(
            "operation_id",
            "policy changed after this operation staged; discard or recover manually".to_string(),
        ))
    }
}

/// Validates that an operation's fingerprint matches the current candidate state.
///
/// This is the fingerprint guard: the caller observed a specific candidate fingerprint
/// and expects it unchanged. The operation staged against a specific fingerprint.
/// Both must match the device's actual current state.
///
/// # Errors
///
/// Returns an error if:
/// - The expected fingerprint format is invalid
/// - The actual fingerprint does not match the expected fingerprint
/// - The operation's stored fingerprint does not match the actual fingerprint
pub fn require_operation_fingerprint(
    record: &OperationRecord,
    expected_candidate_fingerprint: &str,
    actual_candidate_fingerprint: &str,
) -> Result<(), RecordError> {
    validate_fingerprint(expected_candidate_fingerprint)
        .map_err(|e| RecordError::new("expected_candidate_fingerprint", e.to_string()))?;

    if expected_candidate_fingerprint != actual_candidate_fingerprint {
        return Err(RecordError::new(
            "expected_candidate_fingerprint",
            "candidate changed since the caller observed it".to_string(),
        ));
    }

    if record.current != actual_candidate_fingerprint {
        return Err(RecordError::new(
            "operation_id",
            "candidate changed after this operation staged".to_string(),
        ));
    }

    Ok(())
}

/// Computes a stable policy signature from a policy identifier.
///
/// The policy signature binds an operation to the exact policy configuration
/// active when it staged. Implementations pass any stable policy identifier
/// (e.g., a policy name, a serialized config hash) and this function produces
/// a SHA-256 digest suitable for later comparison.
///
/// For vendor-specific policies with multiple fields, the implementation should
/// serialize all relevant fields into a single string before passing to this function.
#[must_use]
pub fn mutation_policy_signature<P: AsRef<str>>(policy_identifier: P) -> String {
    let mut digest = Sha256::new();
    digest.update(policy_identifier.as_ref().as_bytes());
    format!("sha256:{}", digest_hex(&digest.finalize()))
}

/// Validates a change-set's actions against operational limits.
///
/// This is vendor-agnostic validation: the crate validates only structural
/// constraints (non-empty, count limit, serialized size limit). Vendor-specific
/// validation (XPath roots, config format, admin scope) remains the implementation's
/// responsibility.
///
/// # Errors
///
/// Returns an error if:
/// - The actions list is empty
/// - The actions count exceeds `limits.max_actions_per_set`
/// - The serialized actions exceed `limits.max_change_set_bytes`
pub fn validate_change_set_actions<A: Serialize>(
    actions: &[A],
    limits: &OperationLimits,
) -> Result<(), RecordError> {
    if actions.is_empty() {
        return Err(RecordError::new(
            "actions",
            "change set must contain at least 1 action".to_string(),
        ));
    }

    if actions.len() > limits.max_actions_per_set {
        return Err(RecordError::new(
            "actions",
            format!(
                "change set exceeds maximum of {} actions",
                limits.max_actions_per_set
            ),
        ));
    }

    let encoded = serde_json::to_vec(actions).map_err(|error| {
        RecordError::new("actions", format!("could not encode change set: {error}"))
    })?;

    if encoded.len() as u64 > limits.max_change_set_bytes {
        return Err(RecordError::new(
            "actions",
            format!(
                "serialized change set exceeds {} bytes",
                limits.max_change_set_bytes
            ),
        ));
    }

    Ok(())
}

/// Re-export digest functions for use in tests and validation.
pub use crate::digest::change_set_digest;
