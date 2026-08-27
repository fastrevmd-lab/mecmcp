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

/// Whether a change set may move from one state to another.
///
/// The closed policy, and the reason it is a table rather than a list of
/// forbidden edges. Rejecting only `Approved -> Applying` left every other
/// route open: `Approved -> Failed -> Applying` reached the same place, and
/// `Applying -> Applying` with the handleless flag cleared, then `-> Approved`,
/// laundered an in-flight apply back into a claimable one. Anything not named
/// here is refused, so a new state or a new caller cannot quietly widen it.
///
/// `Approved -> Applying` is deliberately **absent**. It is legal, but only
/// through [`crate::ChangesetCoordinator::claim_change_set_for_apply`], which
/// does the check and the write under one lock. Routing it through this table
/// would make it writable by anyone holding a record.
///
/// A state may always be written over itself: records carry fields other than
/// `state` — `operation_id`, `task_id` — and updating those is not a
/// transition.
#[must_use]
pub const fn change_set_transition_allowed(from: ChangeSetState, to: ChangeSetState) -> bool {
    use ChangeSetState as S;
    match (from, to) {
        // Field updates, not lifecycle movement.
        (S::Planned, S::Planned)
        | (S::Approved, S::Approved)
        | (S::Applying, S::Applying)
        | (S::Applied, S::Applied)
        | (S::Expired, S::Expired)
        | (S::Failed, S::Failed)
        | (S::Cancelled, S::Cancelled) => true,

        // Awaiting a second principal.
        (S::Planned, S::Approved | S::Expired | S::Cancelled) => true,

        // Approved, but not yet claimed. `Applying` is not reachable here.
        (S::Approved, S::Expired | S::Cancelled) => true,

        // In flight. Only an outcome ends it, which is what keeps an approval
        // spent: there is no route back to `Approved`.
        (S::Applying, S::Applied | S::Failed) => true,

        // A change set that expired or failed can still be cancelled, which is
        // how an owner closes a record out. `cancel_change_set` names the same
        // set — Planned, Approved, Expired, Failed — and refuses `Applying` and
        // `Applied` itself. The table has to agree with it or cancelling an
        // expired record stops working; the first version of this table left
        // these out and did exactly that.
        (S::Expired | S::Failed, S::Cancelled) => true,

        // `Applied` is written after staging but before diff, validation and
        // commit, so a later step failing has to be able to correct it.
        // rustjunosmcp does exactly that — its `settle_change_set` exists to
        // stop a record claiming a change landed when it did not, on the
        // grounds that a wedged device is recoverable by an operator and a
        // false `Applied` is not. Forbidding this edge broke that at runtime
        // while every test here stayed green.
        //
        // It opens no route back: `Failed` reaches only `Cancelled`.
        (S::Applied, S::Failed) => true,

        // Terminal. `Cancelled` is an end, and `Applied` now has the one exit
        // above.
        _ => false,
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
