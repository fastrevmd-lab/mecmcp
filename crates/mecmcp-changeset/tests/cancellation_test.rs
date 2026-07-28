//! Cancellation re-check tests (mecmcp#63 items 1 and 2).
//!
//! `device_guard` can hand back the guard at the same moment the cancellation
//! token fires — `tokio::select!` is free to take the ready-lock branch. Every
//! lifecycle method must therefore re-check the token after acquiring the guard
//! and before touching the device.
//!
//! # Why these tests loop
//!
//! A single attempt proves nothing. `select!` chooses randomly between two ready
//! branches, so with a pre-cancelled token `device_guard` usually rejects on its
//! own and the method under test is never reached — a single-shot test passes
//! whether or not the re-check exists. Measured against a build with the checks
//! removed: the commit case passed 5 of 5 runs, and the validate case failed
//! only 1 of 3.
//!
//! Repeating drives the chance of never entering the window to negligible. Each
//! iteration is an independent coin flip, so an unguarded method that slips
//! through even a fifth of the time survives `ATTEMPTS` iterations with
//! probability 0.8^64 — about 6e-7.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    ChangesetCoordinator, CommitOptions, CommitOutcome, DeviceTransaction, LifecycleState,
    OperationLimits, RollbackOutcome, RollbackRef,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const TEST_ENDPOINT: &str = "https://device.example.com";
/// Enough iterations that an unguarded method is caught with overwhelming
/// probability, while the whole file still runs in well under a second.
const ATTEMPTS: usize = 64;

const POLICY: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Action {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Staged;

#[derive(Debug, thiserror::Error)]
#[error("device error")]
struct DeviceError;

/// Counts device round-trips so a test can assert nothing was sent.
#[derive(Default)]
struct CountingTransaction {
    diffs: AtomicUsize,
    validates: AtomicUsize,
    commits: AtomicUsize,
    /// When set, `fingerprint()` cancels this token before returning.
    ///
    /// `commit_operation` already re-checks cancellation immediately after the
    /// device guard, so a token cancelled up front never reaches the later
    /// check: the earlier one always wins. The window that check actually
    /// guards is the one *after* it — the fingerprint read and the attribution
    /// write — so the only way to exercise it is to have cancellation fire
    /// during one of those awaits. Firing it from inside `fingerprint()` puts
    /// it exactly there, deterministically.
    cancel_on_fingerprint: Option<CancellationToken>,
}

#[async_trait]
impl DeviceTransaction for CountingTransaction {
    type Action = Action;
    type Staged = Staged;
    type Diff = String;
    type Validation = String;
    type Error = DeviceError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        if let Some(token) = &self.cancel_on_fingerprint {
            token.cancel();
        }
        Ok("sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned())
    }

    async fn stage(&self, _actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        Ok(Staged)
    }

    async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        self.diffs.fetch_add(1, Ordering::SeqCst);
        Ok(String::new())
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        self.validates.fetch_add(1, Ordering::SeqCst);
        Ok(String::new())
    }

    async fn commit(
        &self,
        _staged: &Self::Staged,
        _attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: None,
            details: None,
        })
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: None,
            details: None,
        })
    }

    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Ok(RollbackOutcome {
            succeeded: true,
            details: None,
        })
    }
}

/// Stage one operation and return the coordinator plus its id.
async fn staged(transaction: &CountingTransaction) -> (Arc<ChangesetCoordinator>, String, Staged) {
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            None,
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap(),
    );

    let fingerprint = transaction.fingerprint().await.unwrap();
    let out = coordinator
        .stage_operation(
            "device-a",
            "owner-a",
            &fingerprint,
            TEST_ENDPOINT,
            transaction,
            &[Action {
                name: "one".to_owned(),
            }],
            "set",
            None,
            POLICY,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    (coordinator, out.operation_id, out.staged)
}

#[tokio::test]
async fn a_cancelled_diff_never_reaches_the_device() {
    for _ in 0..ATTEMPTS {
        let transaction = CountingTransaction::default();
        let (coordinator, operation_id, staged_handle) = staged(&transaction).await;

        let cancelled = CancellationToken::new();
        cancelled.cancel();

        let fingerprint = transaction.fingerprint().await.unwrap();
        let error = coordinator
            .diff_operation(
                &operation_id,
                "device-a",
                "owner-a",
                &fingerprint,
                &transaction,
                &staged_handle,
                &cancelled,
            )
            .await
            .expect_err("a cancelled diff must not run");

        assert_eq!(error.field(), "device");
        assert_eq!(
            transaction.diffs.load(Ordering::SeqCst),
            0,
            "no diff RPC may be sent once cancelled"
        );
    }
}

#[tokio::test]
async fn a_cancelled_validate_never_reaches_the_device() {
    for _ in 0..ATTEMPTS {
        let transaction = CountingTransaction::default();
        let (coordinator, operation_id, staged_handle) = staged(&transaction).await;

        let cancelled = CancellationToken::new();
        cancelled.cancel();

        let fingerprint = transaction.fingerprint().await.unwrap();
        let error = coordinator
            .validate_operation(
                &operation_id,
                "device-a",
                "owner-a",
                &fingerprint,
                &transaction,
                &staged_handle,
                &cancelled,
            )
            .await
            .expect_err("a cancelled validate must not run");

        assert_eq!(error.field(), "device");
        assert_eq!(
            transaction.validates.load(Ordering::SeqCst),
            0,
            "no validate RPC may be sent once cancelled"
        );
    }
}

/// The operation must survive as `Staged`. Dropping it would strand the
/// candidate already sitting on the device with no record pointing at it.
#[tokio::test]
async fn a_commit_cancelled_before_dispatch_leaves_the_operation_staged() {
    let transaction = CountingTransaction::default();
    let (coordinator, operation_id, staged_handle) = staged(&transaction).await;
    let fingerprint = transaction.fingerprint().await.unwrap();

    // Commit requires a validated operation, so get there first.
    coordinator
        .validate_operation(
            &operation_id,
            "device-a",
            "owner-a",
            &fingerprint,
            &transaction,
            &staged_handle,
            &CancellationToken::new(),
        )
        .await
        .expect("validation should succeed");

    // Cancellation fires during the commit's own fingerprint read: past the
    // guard and past the existing re-check, but before anything is dispatched.
    let token = CancellationToken::new();
    let armed = CountingTransaction {
        cancel_on_fingerprint: Some(token.clone()),
        ..Default::default()
    };

    let error = coordinator
        .commit_operation(
            &operation_id,
            "device-a",
            "owner-a",
            &fingerprint,
            POLICY,
            &armed,
            &staged_handle,
            &Attribution::stdio(),
            &CommitOptions::default(),
            &token,
        )
        .await
        .expect_err("a commit cancelled before dispatch must not proceed");

    assert_eq!(error.field(), "device");
    assert_eq!(
        armed.commits.load(Ordering::SeqCst),
        0,
        "no commit RPC may be sent once cancelled"
    );

    let record = coordinator
        .record(&operation_id, "owner-a", "device-a")
        .await
        .expect("the operation must still exist");
    assert_eq!(
        record.state,
        LifecycleState::Validated,
        "a commit that never left the process must not be recorded as Indeterminate, \
         and must not be dropped — the candidate is still on the device, so the \
         operation stays exactly as it was and can be retried or discarded"
    );
}
