//! `RUST_LOG` must not be able to switch the audit trail off (#330).
//!
//! Its own test binary, and a real child process, on purpose.
//!
//! `RUST_LOG` is read by `EnvFilter::try_from_default_env` when `init_tracing`
//! runs, and `init_tracing` installs a *process-global* subscriber that can be
//! set once. So the value has to be in the environment before the process
//! starts: an in-process test cannot stage this, and the workspace forbids
//! `unsafe_code`, which rules out `std::env::set_var` under edition 2024.
//!
//! The test therefore re-invokes its own binary with `RUST_LOG` set to a
//! target-specific value — the ordinary way an operator turns up logging for
//! one crate — and asserts from the parent that the audit record still reached
//! the file. That is the shape the defect actually had in production: not a
//! filter built by hand in a test, but an environment variable set by someone
//! debugging one server.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

/// Set in the child to tell it to act as the subject rather than the harness.
const CHILD_MARKER: &str = "MECMCP_AUDIT_330_CHILD";

/// A target-specific filter. This is the value that used to silence auditing:
/// it enables one crate and, by naming a target at all, produces a filter that
/// does not enable the `audit` target.
const NOISY_TARGET_FILTER: &str = "mecmcp_audit=debug";

/// The child role is its own `#[ignore]`d test, selected explicitly with
/// `--ignored --exact`. It deliberately does *not* share a name with the tests
/// that spawn it: when the role was chosen by reading the marker at the top of
/// those tests, an ambient `MECMCP_AUDIT_330_CHILD` in the environment made
/// both of them take the child path and return before asserting anything —
/// they reported success with the fix reverted. An ambient variable must not be
/// able to turn a regression test into a no-op.
const CHILD_TEST_NAME: &str = "child_emits_an_audit_event";

/// The subject: install tracing under whatever `RUST_LOG` says, then emit the
/// record a privileged mutation would emit.
fn run_as_child(audit_log: &Path) {
    let sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::Json,
        audit_log_file: Some(audit_log.to_path_buf()),
        redaction: None,
        journald: false,
    })
    .expect("installation must succeed");
    assert!(sink.is_some(), "the rotation handle must be returned");

    // The field names matter, not just the target. `EnvFilter` supports
    // field-qualified directives, so a record carrying `tool` can be aimed at
    // by `audit[{tool}]=off` in a way a bare target filter cannot reach. This
    // mirrors what the servers actually emit — rust-proxmoxmcp's token audit
    // record is `tool="token_set_scopes" action=... result=...` — so the
    // hostile-filter test below is exercising the real shape rather than a
    // synthetic one that happens to have no matching field.
    tracing::info!(
        target: "audit",
        tool = "token_set_scopes",
        action = "set_scopes",
        result = "ok",
        "scopes widened"
    );

    // Explicit, so the child cannot exit with the record still buffered and
    // make this test pass or fail for the wrong reason.
    drop(sink);
}

/// The subject, run only as a spawned child. Panics rather than skipping when
/// the marker is absent, so a mis-spawned child fails loudly instead of
/// passing silently.
#[test]
#[ignore = "child role: spawned with RUST_LOG set by the tests below"]
fn child_emits_an_audit_event() {
    let path = std::env::var(CHILD_MARKER)
        .expect("child role requires MECMCP_AUDIT_330_CHILD; it is spawned, not run directly");
    run_as_child(Path::new(&path));
}

#[test]
fn a_target_specific_rust_log_does_not_silence_the_audit_trail() {
    let dir = tempfile::tempdir().unwrap();
    let audit_log = dir.path().join("audit.log");

    // `--exact` plus the test name keeps the child to this one test, so it does
    // not recurse into the harness role or run anything else.
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(&exe)
        .args([CHILD_TEST_NAME, "--exact", "--ignored", "--nocapture"])
        .env("RUST_LOG", NOISY_TARGET_FILTER)
        .env(CHILD_MARKER, audit_log.to_str().unwrap())
        .output()
        .expect("the child must run");

    assert!(
        output.status.success(),
        "child failed under RUST_LOG={NOISY_TARGET_FILTER}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let written = std::fs::read_to_string(&audit_log).unwrap_or_default();
    assert!(
        written.contains("token_set_scopes"),
        "RUST_LOG={NOISY_TARGET_FILTER} silenced the audit trail: the mutation \
         was recorded nowhere.\naudit file: {written:?}\nchild stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The filters that were specifically aimed at the audit trail.
///
/// A target-name filter is the accidental case — someone debugging one crate.
/// These are the deliberate ones. `audit=off` names the target; `audit[{tool}]=off`
/// is worse, because `EnvFilter` picks the most specific matching directive, so a
/// field-qualified value beats a target-only one. rust-proxmoxmcp measured exactly
/// that against its token CLI: `audit=off` left the record, `audit[{tool}]=off`
/// removed it while the scope widening still applied.
///
/// The fix has to be structural for this reason. Adding an `audit=info` directive
/// to the parsed filter would lose to both of these; taking the filter off the
/// audit layers entirely does not.
#[test]
fn a_filter_aimed_at_the_audit_target_cannot_silence_it() {
    for hostile in ["audit=off", "audit[{tool}]=off", "off", "audit=error"] {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = dir.path().join("audit.log");
        let exe = std::env::current_exe().unwrap();
        let output = Command::new(&exe)
            .args([CHILD_TEST_NAME, "--exact", "--ignored", "--nocapture"])
            .env("RUST_LOG", hostile)
            .env(CHILD_MARKER, audit_log.to_str().unwrap())
            .output()
            .expect("the child must run");
        assert!(
            output.status.success(),
            "child failed under RUST_LOG={hostile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let written = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(
            written.contains("token_set_scopes"),
            "RUST_LOG={hostile} silenced the audit trail. An environment variable \
             must not be able to aim at the audit target and hit it.\naudit file: {written:?}"
        );
    }
}

/// The console layer must still honour `RUST_LOG`, or the fix would have traded
/// one defect for another: an operator who narrows logging still expects a
/// quieter console, and an audit sink that is always on is not a reason to
/// print everything to stderr.
#[test]
fn the_console_layer_still_honours_rust_log() {
    let dir = tempfile::tempdir().unwrap();
    let audit_log = dir.path().join("audit.log");

    let exe = std::env::current_exe().unwrap();
    let output = Command::new(&exe)
        .args([CHILD_TEST_NAME, "--exact", "--ignored", "--nocapture"])
        // `error` only: the child's `info!` must not reach stderr.
        .env("RUST_LOG", "error")
        .env(CHILD_MARKER, audit_log.to_str().unwrap())
        .output()
        .expect("the child must run");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("scopes widened"),
        "RUST_LOG=error must still quieten the console; stderr was: {stderr}"
    );
    // ...while the audit file still has it.
    let written = std::fs::read_to_string(&audit_log).unwrap_or_default();
    assert!(
        written.contains("token_set_scopes"),
        "the audit sink must be reachable regardless of RUST_LOG; file: {written:?}"
    );
}
