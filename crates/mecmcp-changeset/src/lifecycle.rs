//! Lifecycle state machines for operations and change sets.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a single operation or multi-action apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Operation is being staged on the device.
    Staging,
    /// Operation has been staged successfully.
    Staged,
    /// Operation validation is in progress.
    Validating,
    /// Operation has been validated and is ready to commit.
    Validated,
    /// Commit is in progress.
    Committing,
    /// Operation was committed successfully.
    Committed,
    /// Operation was discarded without commit.
    Discarded,
    /// Operation failed during staging, validation, or commit.
    Failed,
    /// Commit outcome is unknown; manual reconciliation required.
    Indeterminate,
}

impl LifecycleState {
    /// Returns the state as a string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Staged => "staged",
            Self::Validating => "validating",
            Self::Validated => "validated",
            Self::Committing => "committing",
            Self::Committed => "committed",
            Self::Discarded => "discarded",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Returns `true` if this state is terminal (no further transitions allowed).
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Discarded)
    }
}

/// Whether an apply is expected to produce a vendor task handle.
///
/// Passed to [`crate::ChangesetCoordinator::claim_change_set_for_apply`], and
/// what it records decides how a crashed apply is read at the next start. See
/// [`crate::ChangeSetRecord::apply_without_handle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyHandle {
    /// The operation ends in a handle — a UPID, a commit token — that the
    /// caller will persist before polling.
    Expected,
    /// The operation has no handle to persist, so a crash mid-apply leaves an
    /// outcome only the device knows.
    None,
}

/// Lifecycle state of a change set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSetState {
    /// Change set has been created and is awaiting approval.
    Planned,
    /// Change set has been approved by a second principal.
    Approved,
    /// Change set is being applied to the device.
    Applying,
    /// Change set has been successfully applied.
    Applied,
    /// Change set approval has expired.
    Expired,
    /// Change set apply failed.
    Failed,
    /// Change set was cancelled by the owner or an approver.
    Cancelled,
}

impl ChangeSetState {
    /// Returns the state as a string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Approved => "approved",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}
