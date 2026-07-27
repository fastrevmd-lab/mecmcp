//! Operation and change-set record types.

use crate::lifecycle::{ChangeSetState, LifecycleState};
use serde::{Deserialize, Serialize};

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
    /// XPath for the primary action (vendor-specific).
    pub xpath: String,
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
