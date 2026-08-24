//! Test that evidence files (outbox and ledger) are created and tightened to 0600
//! regardless of process umask or pre-existing file permissions.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::sinks::ssdf::{SsdfSink, SsdfSinkConfig};
use rustix::fs::Mode;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::Duration;
use tempfile::TempDir;

/// Guard that restores the previous umask when dropped. umask is process-global
/// so this ensures tests don't interfere with each other.
struct UmaskGuard {
    previous: Mode,
}

impl UmaskGuard {
    fn set(new_mask: Mode) -> Self {
        let previous = rustix::process::umask(new_mask);
        Self { previous }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.previous);
    }
}

#[test]
fn test_new_files_created_0600_despite_umask() {
    // Set permissive umask that would create files 0644
    let _guard = UmaskGuard::set(Mode::from_raw_mode(0o022));

    let temp_dir = TempDir::new().unwrap();
    let outbox_path = temp_dir.path().join("outbox.jsonl");
    let ledger_path = temp_dir.path().join("ledger.jsonl");

    let config = SsdfSinkConfig {
        endpoint: "http://localhost:9999".to_string(),
        database: "test".to_string(),
        username: "test".to_string(),
        password: "test".to_string(),
        verify_username: "test_verify".to_string(),
        verify_password: "test_verify".to_string(),
        outbox_path: outbox_path.clone(),
        ledger_path: ledger_path.clone(),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };

    // Create the sink, which opens both files
    let _sink = SsdfSink::new(config).unwrap();

    // Both files must be 0600
    let outbox_mode = fs::metadata(&outbox_path).unwrap().permissions().mode();
    let ledger_mode = fs::metadata(&ledger_path).unwrap().permissions().mode();

    assert_eq!(
        outbox_mode & 0o777,
        0o600,
        "Outbox should be 0600 but is {:o}",
        outbox_mode & 0o777
    );
    assert_eq!(
        ledger_mode & 0o777,
        0o600,
        "Ledger should be 0600 but is {:o}",
        ledger_mode & 0o777
    );
}

#[test]
fn test_pre_existing_0644_tightened_to_0600() {
    let temp_dir = TempDir::new().unwrap();
    let outbox_path = temp_dir.path().join("outbox.jsonl");
    let ledger_path = temp_dir.path().join("ledger.jsonl");

    // Create pre-existing files with 0644 permissions
    {
        let mut outbox = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o644)
            .open(&outbox_path)
            .unwrap();
        // Write a valid JSONL line for the outbox
        outbox.write_all(b"{\"test\":\"data\"}\n").unwrap();
    }
    {
        let mut ledger = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o644)
            .open(&ledger_path)
            .unwrap();
        // Write a valid ledger entry (server_id, run_id, segment_seq, status)
        ledger.write_all(b"{\"server_id\":\"test-server\",\"run_id\":\"test-run\",\"segment_seq\":1,\"status\":\"delivered\",\"delivered_at\":\"2024-01-01T00:00:00Z\"}\n").unwrap();
    }

    // Verify they are indeed 0644
    assert_eq!(
        fs::metadata(&outbox_path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(&ledger_path).unwrap().permissions().mode() & 0o777,
        0o644
    );

    // Open the sink, which should tighten them to 0600
    let config = SsdfSinkConfig {
        endpoint: "http://localhost:9999".to_string(),
        database: "test".to_string(),
        username: "test".to_string(),
        password: "test".to_string(),
        verify_username: "test_verify".to_string(),
        verify_password: "test_verify".to_string(),
        outbox_path: outbox_path.clone(),
        ledger_path: ledger_path.clone(),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };

    let _sink = SsdfSink::new(config).unwrap();

    // Both files must now be 0600
    let outbox_mode = fs::metadata(&outbox_path).unwrap().permissions().mode();
    let ledger_mode = fs::metadata(&ledger_path).unwrap().permissions().mode();

    assert_eq!(
        outbox_mode & 0o777,
        0o600,
        "Outbox should be tightened to 0600 but is {:o}",
        outbox_mode & 0o777
    );
    assert_eq!(
        ledger_mode & 0o777,
        0o600,
        "Ledger should be tightened to 0600 but is {:o}",
        ledger_mode & 0o777
    );

    // Verify contents were not destroyed
    let outbox_contents = fs::read_to_string(&outbox_path).unwrap();
    assert!(
        outbox_contents.contains("test"),
        "Outbox contents should be preserved"
    );

    let ledger_contents = fs::read_to_string(&ledger_path).unwrap();
    assert!(
        ledger_contents.contains("delivered"),
        "Ledger contents should be preserved"
    );
}

#[test]
fn test_already_0600_left_alone() {
    let temp_dir = TempDir::new().unwrap();
    let outbox_path = temp_dir.path().join("outbox.jsonl");
    let ledger_path = temp_dir.path().join("ledger.jsonl");

    // Create pre-existing files with exactly 0600 permissions
    {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&outbox_path)
            .unwrap();
    }
    {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&ledger_path)
            .unwrap();
    }

    let config = SsdfSinkConfig {
        endpoint: "http://localhost:9999".to_string(),
        database: "test".to_string(),
        username: "test".to_string(),
        password: "test".to_string(),
        verify_username: "test_verify".to_string(),
        verify_password: "test_verify".to_string(),
        outbox_path: outbox_path.clone(),
        ledger_path: ledger_path.clone(),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };

    let _sink = SsdfSink::new(config).unwrap();

    // Should still be 0600
    let outbox_mode = fs::metadata(&outbox_path).unwrap().permissions().mode();
    let ledger_mode = fs::metadata(&ledger_path).unwrap().permissions().mode();

    assert_eq!(outbox_mode & 0o777, 0o600);
    assert_eq!(ledger_mode & 0o777, 0o600);
}

#[test]
fn test_already_0400_not_widened() {
    let temp_dir = TempDir::new().unwrap();
    let outbox_path = temp_dir.path().join("outbox.jsonl");
    let ledger_path = temp_dir.path().join("ledger.jsonl");

    // Create pre-existing files with 0400 permissions (read-only)
    {
        let outbox = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o400)
            .open(&outbox_path)
            .unwrap();
        drop(outbox);
        // File is now read-only, can't append to it
    }
    {
        let ledger = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o400)
            .open(&ledger_path)
            .unwrap();
        drop(ledger);
        // File is now read-only, can't append to it
    }

    let config = SsdfSinkConfig {
        endpoint: "http://localhost:9999".to_string(),
        database: "test".to_string(),
        username: "test".to_string(),
        password: "test".to_string(),
        verify_username: "test_verify".to_string(),
        verify_password: "test_verify".to_string(),
        outbox_path: outbox_path.clone(),
        ledger_path: ledger_path.clone(),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };

    // The sink will fail to open because the files are read-only
    // This is expected - we don't widen permissions
    let result = SsdfSink::new(config);
    assert!(
        result.is_err(),
        "Should fail to open read-only files for append"
    );
}

/// A numeric `mode > 0o600` comparison is not the same as "wider than 0600".
///
/// The outbox is opened append-only, so it needs owner **write** but not owner
/// read. `0o244` — owner write-only, group- and world-readable — therefore
/// opens successfully, yet is numerically 164, *below* `0o600` (384). A
/// magnitude comparison leaves it untouched and the evidence stays
/// world-readable, which is the exact exposure this fix exists to close.
///
/// (`0o044` is not a counterexample: with no owner-write bit the append open
/// fails first, so that case fails closed rather than leaking.)
///
/// The predicate must test for bits outside owner-rw — `mode & 0o177` — rather
/// than magnitude.
#[test]
fn outbox_write_only_owner_with_world_read_is_tightened() {
    let dir = tempfile::tempdir().unwrap();
    let outbox_path = dir.path().join("outbox.ndjson");
    let ledger_path = dir.path().join("ledger.ndjson");

    {
        let _ = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&outbox_path)
            .unwrap();
        let mut ledger = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&ledger_path)
            .unwrap();
        ledger.write_all(b"{\"server_id\":\"test-server\",\"run_id\":\"test-run\",\"segment_seq\":1,\"status\":\"delivered\",\"delivered_at\":\"2024-01-01T00:00:00Z\"}\n").unwrap();
    }

    // Owner write-only, group + world readable. Numerically 164 < 384.
    fs::set_permissions(&outbox_path, fs::Permissions::from_mode(0o244)).unwrap();

    let config = SsdfSinkConfig {
        endpoint: "http://localhost:9999".to_string(),
        database: "test".to_string(),
        username: "test".to_string(),
        password: "test".to_string(),
        verify_username: "test_verify".to_string(),
        verify_password: "test_verify".to_string(),
        outbox_path: outbox_path.clone(),
        ledger_path: ledger_path.clone(),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };
    let _sink = SsdfSink::new(config).unwrap();

    let mode = fs::metadata(&outbox_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "outbox at 0o244 is group- and world-readable and must be tightened to 0600, got {mode:o}"
    );
}
