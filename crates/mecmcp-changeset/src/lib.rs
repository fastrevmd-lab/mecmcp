//! Fingerprint-bound change-set lifecycle for multi-vendor device automation.
//!
//! This crate provides two-person change control with digest-bound approval, indeterminate
//! recovery, and atomic persistence. It generalizes the PAN-OS mutation lifecycle behind
//! a vendor-agnostic trait so both PAN-OS and Junos can use the same workflow.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod apply;
pub mod changeset;
pub mod commit_metadata;
pub mod coordinator;
pub mod digest;
pub mod lifecycle;
pub mod operation;
pub mod persistence;
pub mod records;
pub mod recovery;
pub mod transaction;
pub mod types;

pub use apply::ApplyOutput;
pub use changeset::ChangeSetOutput;
pub use commit_metadata::{
    AttachOutcome, CommitMetaError, CommitMetadataSink, apply_commit_metadata,
};
pub use coordinator::{ChangesetCoordinator, CoordinatorError, StagedRecovery};
pub use lifecycle::{ChangeSetState, LifecycleState};
pub use operation::StageOutput;
pub use persistence::{ChangesetState, PersistenceError, read_state, validate_state, write_state};
pub use records::{
    ApprovalRecord, ChangeSetRecord, OperationRecord, PreviewError, PreviewRecord, RecordError,
    TargetError, WaiverRecord, change_set_digest, change_set_digest_with_targets,
    mutation_policy_signature, preview_digest, require_operation_fingerprint,
    require_operation_policy, validate_change_set_actions, validate_targets,
};
pub use recovery::{RecoveryDisposition, ResolvedOperationOutput, resolve_persisted_operation};
pub use transaction::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef, UnlockOutcome,
};
pub use types::{Fingerprint, FingerprintError, OperationId, OperationIdError, OperationLimits};
