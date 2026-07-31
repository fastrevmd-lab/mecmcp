//! Demonstration of error messages for unrecognized shapes.
//!
//! This is not a test — it's a program that shows what error messages
//! an operator would see for each malformed inventory file.

use mecmcp_inventory::FileInventory;
use serde::{Deserialize, Serialize};

/// Mode 0600, matching the deployed `devices.json` on 608 and 609.
///
/// Without this these tests still *pass* — they only assert that some error
/// occurs — but `--nocapture` would print permission failures instead of the
/// malformed-shape messages they exist to demonstrate. A test that passes while
/// no longer exercising its subject is worse than one that fails.
fn write_mode_600(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture");
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestDevice {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TestPolicy {}

#[test]
fn show_typo_devicez() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("typo.json");
    std::fs::write(
        &path,
        r#"{"version": 1, "devicez": {"r1": {"name": "r1"}}}"#,
    )
    .expect("should write");

    write_mode_600(&path);
    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(e) => eprintln!("typo_devicez        => Err: {e}"),
        Ok(_) => panic!("should fail"),
    }
}

#[test]
fn show_version_wrong_type() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("version.json");
    std::fs::write(
        &path,
        r#"{"version": "not-a-number", "devices": {"r1": {"name": "r1"}}}"#,
    )
    .expect("should write");

    write_mode_600(&path);
    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(e) => eprintln!("version_wrong_type  => Err: {e}"),
        Ok(_) => panic!("should fail"),
    }
}

#[test]
fn show_unrelated_doc() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("unrelated.json");
    std::fs::write(&path, r#"{"app": "unrelated", "config": {"timeout": 30}}"#)
        .expect("should write");

    write_mode_600(&path);
    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(e) => eprintln!("unrelated_doc       => Err: {e}"),
        Ok(_) => panic!("should fail"),
    }
}

#[test]
fn show_json_array() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("array.json");
    std::fs::write(&path, r#"[{"name": "r1"}]"#).expect("should write");

    write_mode_600(&path);
    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(e) => eprintln!("json_array          => Err: {e}"),
        Ok(_) => panic!("should fail"),
    }
}
