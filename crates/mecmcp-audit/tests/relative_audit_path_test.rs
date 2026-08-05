//! A relative audit path is anchored before it is stored (#200).
//!
//! Its own test binary because it changes the process working directory, which
//! would corrupt any test running beside it.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::FileHandle;
use std::path::Path;

/// A process that changes directory after initialization — daemonizing is the
/// ordinary case — keeps writing through the open descriptor, while `reopen`
/// resolved the stored relative string against the *new* directory and silently
/// moved audit records to a different file.
#[test]
fn a_relative_path_is_resolved_before_it_is_stored() {
    let dir = tempfile::tempdir().unwrap();
    let anchor = dir.path().canonicalize().unwrap();
    std::env::set_current_dir(&anchor).unwrap();

    let handle = FileHandle::open(Path::new("audit.log")).unwrap();
    assert!(
        handle.path().is_absolute(),
        "stored path must be absolute, got {}",
        handle.path().display()
    );
    assert_eq!(handle.path(), anchor.join("audit.log"));

    // Move away, then rotate. The reopened file must be the one that was
    // configured, not one named the same in wherever the process now stands.
    let elsewhere = tempfile::tempdir().unwrap();
    std::env::set_current_dir(elsewhere.path()).unwrap();
    std::fs::rename(anchor.join("audit.log"), anchor.join("audit.log.1")).unwrap();
    handle.reopen().unwrap();

    assert!(
        anchor.join("audit.log").exists(),
        "reopen must recreate the configured file"
    );
    assert!(
        !elsewhere.path().join("audit.log").exists(),
        "reopen must not have followed the new working directory"
    );
}
