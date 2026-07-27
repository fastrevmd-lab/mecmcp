//! Demonstration of error messages for unrecognized shapes.
//!
//! This is not a test — it's a program that shows what error messages
//! an operator would see for each malformed inventory file.

use mecmcp_inventory::FileInventory;
use serde::{Deserialize, Serialize};

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

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(e) => eprintln!("json_array          => Err: {e}"),
        Ok(_) => panic!("should fail"),
    }
}
