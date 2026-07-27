//! Fingerprint-bound change-set lifecycle for multi-vendor device automation.
//!
//! This crate provides two-person change control with digest-bound approval, indeterminate
//! recovery, and atomic persistence. It generalizes the PAN-OS mutation lifecycle behind
//! a vendor-agnostic trait so both PAN-OS and Junos can use the same workflow.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod changeset;
pub mod coordinator;
pub mod digest;
pub mod lifecycle;
pub mod persistence;
pub mod records;
pub mod transaction;
pub mod types;

pub use changeset::ChangeSetOutput;
pub use coordinator::{ChangesetCoordinator, CoordinatorError};
pub use lifecycle::{ChangeSetState, LifecycleState};
pub use persistence::{ChangesetState, PersistenceError, read_state, validate_state, write_state};
pub use records::{
    ApprovalRecord, ChangeSetRecord, OperationRecord, RecordError, WaiverRecord,
    change_set_digest, mutation_policy_signature, require_operation_fingerprint,
    require_operation_policy, validate_change_set_actions,
};
pub use transaction::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
};
pub use types::{Fingerprint, FingerprintError, OperationId, OperationIdError, OperationLimits};
