//! Device-lock ordering tests (mecmcp#60).
//!
//! The fingerprint check and staging are only atomic against other sessions
//! while a device-side lock is held. These assert the ordering the coordinator
//! promises, not merely that the methods exist: a lock taken *after* the
//! fingerprint read would compile, pass every other test, and close nothing.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    ChangesetCoordinator, CommitOptions, CommitOutcome, DeviceTransaction, OperationLimits,
    RollbackOutcome, RollbackRef, UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const TEST_ENDPOINT: &str = "https://device.example.com";
const FINGERPRINT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Action {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Staged;

#[derive(Debug, thiserror::Error)]
enum LockTestError {
    #[error("lock refused: held by another administrator")]
    LockRefused,
}

/// Records every trait call in order, so a test can assert on the sequence.
struct RecordingTransaction {
    calls: Arc<Mutex<Vec<&'static str>>>,
    wants_lock: bool,
    lock_fails: bool,
    /// Fingerprint this device reports. A value other than [`FINGERPRINT`]
    /// simulates the candidate having moved before the lock was taken.
    fingerprint: String,
}

impl RecordingTransaction {
    fn new(wants_lock: bool) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            wants_lock,
            lock_fails: false,
            fingerprint: FINGERPRINT.to_owned(),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, what: &'static str) {
        self.calls.lock().unwrap().push(what);
    }
}

#[async_trait]
impl DeviceTransaction for RecordingTransaction {
    type Action = Action;
    type Staged = Staged;
    type Diff = String;
    type Validation = String;
    type Error = LockTestError;

    fn requires_config_lock(&self) -> bool {
        self.wants_lock
    }

    async fn lock(&self, _comment: &str) -> Result<(), Self::Error> {
        self.record("lock");
        if self.lock_fails {
            return Err(LockTestError::LockRefused);
        }
        Ok(())
    }

    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        self.record("unlock");
        Ok(UnlockOutcome::Released)
    }

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        self.record("fingerprint");
        Ok(self.fingerprint.clone())
    }

    async fn stage(&self, _actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        self.record("stage");
        Ok(Staged)
    }

    async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(String::new())
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        Ok(String::new())
    }

    async fn commit(
        &self,
        _staged: &Self::Staged,
        _attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
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

fn coordinator() -> ChangesetCoordinator {
    ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap()
}

async fn stage(
    transaction: &RecordingTransaction,
    expected: &str,
) -> Result<(), mecmcp_changeset::CoordinatorError> {
    let actions = vec![Action {
        name: "one".to_owned(),
    }];
    coordinator()
        .stage_operation(
            "device-a",
            "owner-a",
            expected,
            TEST_ENDPOINT,
            transaction,
            &actions,
            "set",
            None,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            &CancellationToken::new(),
        )
        .await
        .map(|_| ())
}

/// The whole point of the primitive: the lock must precede the fingerprint
/// read. Taking it afterwards leaves exactly the window #60 describes.
#[tokio::test]
async fn the_lock_is_taken_before_the_fingerprint_is_read() {
    let transaction = RecordingTransaction::new(true);
    stage(&transaction, FINGERPRINT).await.unwrap();

    let calls = transaction.calls();
    assert_eq!(
        calls.first(),
        Some(&"lock"),
        "the lock must be the first device call, got {calls:?}"
    );
    let lock_at = calls.iter().position(|c| *c == "lock").unwrap();
    let first_fingerprint = calls.iter().position(|c| *c == "fingerprint").unwrap();
    let stage_at = calls.iter().position(|c| *c == "stage").unwrap();
    assert!(
        lock_at < first_fingerprint && first_fingerprint < stage_at,
        "expected lock -> fingerprint -> stage, got {calls:?}"
    );
}

/// A vendor with no lock concept must be untouched by this.
#[tokio::test]
async fn no_lock_is_taken_when_the_implementation_does_not_want_one() {
    let transaction = RecordingTransaction::new(false);
    stage(&transaction, FINGERPRINT).await.unwrap();

    let calls = transaction.calls();
    assert!(
        !calls.contains(&"lock"),
        "requires_config_lock() is false, so lock() must never be called: {calls:?}"
    );
    assert!(calls.contains(&"stage"), "staging should still happen");
}

/// A refused lock must stop the operation. Proceeding unlocked is the exact
/// condition the lock was requested to prevent.
#[tokio::test]
async fn a_refused_lock_fails_the_operation_without_staging() {
    let mut transaction = RecordingTransaction::new(true);
    transaction.lock_fails = true;

    let error = stage(&transaction, FINGERPRINT)
        .await
        .expect_err("a refused lock must fail the operation");

    assert_eq!(error.field(), "config_lock");
    let calls = transaction.calls();
    assert!(
        !calls.contains(&"stage"),
        "nothing may be staged once the lock was refused: {calls:?}"
    );
}

/// Failing out while holding a lock must release it. Dropping the reservation
/// with the device still locked leaves no record and a device that refuses
/// every later change.
#[tokio::test]
async fn a_held_lock_is_released_when_the_candidate_has_already_moved() {
    let mut transaction = RecordingTransaction::new(true);
    transaction.fingerprint =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_owned();

    stage(&transaction, FINGERPRINT)
        .await
        .expect_err("a moved candidate must fail the fingerprint check");

    let calls = transaction.calls();
    assert!(
        calls.contains(&"unlock"),
        "the lock taken on the way in must be released: {calls:?}"
    );
    assert!(
        !calls.contains(&"stage"),
        "nothing may be staged after a failed fingerprint check: {calls:?}"
    );
}
