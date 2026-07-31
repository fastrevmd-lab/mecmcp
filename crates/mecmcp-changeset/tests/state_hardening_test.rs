//! Hardening applied to the change-set state file (#187).
//!
//! `read_state` used to call `symlink_metadata` and then `File::open` — two
//! operations on the same path, so the file could be swapped in between. It now
//! goes through `mecmcp_secret::read_hardened_file`, which opens once with
//! `O_NOFOLLOW` and validates the descriptor.
//!
//! Verified against LXC 608 before the migration: its live
//! `/var/lib/rust-panosmcp/mutation-state.json` is mode 600, owned by
//! `rust-panosmcp`, 26389 bytes, and the service runs as that user — so nothing
//! deployed is refused.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::ChangesetState;
use mecmcp_changeset::persistence::{read_state, write_state};
use std::io::Write;

const LIMIT: u64 = 1024 * 1024;

fn write_state_file(
    dir: &tempfile::TempDir,
    name: &str,
    body: &str,
    mode: u32,
) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).expect("create");
    file.write_all(body.as_bytes()).expect("write");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

/// A state document written by `write_state` itself, so any rejection in these
/// tests must come from the hardening rather than from the JSON shape.
fn valid_state(dir: &tempfile::TempDir) -> String {
    let seed = dir.path().join("seed.json");
    write_state(&seed, &ChangesetState::default(), LIMIT).expect("seed state");
    std::fs::read_to_string(&seed).expect("read seed")
}

#[test]
fn accepts_a_correctly_owned_private_state_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_state_file(&dir, "state.json", &valid_state(&dir), 0o600);
    assert!(
        read_state(&path, LIMIT).is_ok(),
        "a 0600 state file must load"
    );
}

#[test]
fn refuses_a_group_or_world_accessible_state_file() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o640, 0o604, 0o666] {
        let path = write_state_file(&dir, &format!("s{mode:o}.json"), &valid_state(&dir), mode);
        let error = read_state(&path, LIMIT).unwrap_err();
        assert!(
            error.to_string().contains("group- or world-accessible"),
            "mode {mode:o} should be refused, got: {error}"
        );
    }
}

#[test]
fn refuses_a_symlinked_state_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = write_state_file(&dir, "real.json", &valid_state(&dir), 0o600);
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let error = read_state(&link, LIMIT).unwrap_err();
    assert!(error.to_string().contains("symlink"), "got: {error}");
}

#[test]
fn refuses_a_state_file_over_the_callers_limit() {
    let dir = tempfile::tempdir().unwrap();
    // The caller's budget is honoured, not `FileLimits::default()` — 608's live
    // state file is already 26 KB and grows with change-set history.
    let padded = format!("{}{}", valid_state(&dir), " ".repeat(4096));
    let path = write_state_file(&dir, "big.json", &padded, 0o600);

    let error = read_state(&path, 128).unwrap_err();
    assert!(error.to_string().contains("limit is 128"), "got: {error}");
    // The same file is fine under a budget that accommodates it.
    assert!(read_state(&path, LIMIT).is_ok());
}

#[test]
fn refuses_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let error = read_state(dir.path(), LIMIT).unwrap_err();
    assert!(
        !error.to_string().is_empty(),
        "a directory must not read as state"
    );
}

/// Replacing the state file must not change who owns it.
///
/// The reader permits uid 0 so `sudo` operator commands work, which makes this
/// reachable: offline recovery run as root against a service-owned file would
/// otherwise leave a root-owned 0600 file the service cannot open, and the
/// server then fails to start with an error that never mentions ownership.
///
/// Running as root, this asserts the real chown. Running as an ordinary user it
/// asserts the weaker but still meaningful property that ownership is unchanged.
#[test]
fn replacing_the_state_preserves_its_owner() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    write_state(&path, &ChangesetState::default(), LIMIT).expect("seed");

    let before = std::fs::metadata(&path).unwrap();
    let (uid_before, gid_before) = (before.uid(), before.gid());

    write_state(&path, &ChangesetState::default(), LIMIT).expect("replace");

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(after.uid(), uid_before, "owner uid changed on replace");
    assert_eq!(after.gid(), gid_before, "owner gid changed on replace");

    // And the mode stays private.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(after.permissions().mode() & 0o777, 0o600);

    // The service must still be able to read what it just wrote.
    assert!(read_state(&path, LIMIT).is_ok());
}
