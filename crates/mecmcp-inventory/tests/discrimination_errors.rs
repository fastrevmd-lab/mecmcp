//! Tests for shape discrimination error messages.
//!
//! These tests verify that unrecognized inventory shapes produce useful,
//! specific error messages that name the detected issue and guide the operator.

use mecmcp_inventory::{FileInventory, InventoryError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestDevice {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TestPolicy {}

/// Test that a typo in the "devices" key produces a specific error naming
/// the found keys and the expected shape.
#[test]
fn typo_in_devices_key_produces_specific_error() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("typo.json");
    std::fs::write(
        &path,
        r#"{"version": 1, "devicez": {"r1": {"name": "r1"}}}"#,
    )
    .expect("should write typo file");

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("typo should fail to parse"),
    };

    match err {
        InventoryError::ParseError(msg) => {
            assert!(
                msg.contains("found \"version\" but no \"devices\" key"),
                "message should mention the missing \"devices\" key, got: {msg}"
            );
            assert!(
                msg.contains("devicez"),
                "message should mention the typo'd key \"devicez\", got: {msg}"
            );
            assert!(
                msg.contains("canonical envelope") || msg.contains("legacy PAN-OS"),
                "message should mention expected shapes, got: {msg}"
            );
        }
        _ => panic!("expected ParseError, got: {err:?}"),
    }
}

/// Test that a wrong-typed "version" (e.g., a string instead of a number)
/// produces a field-specific error from the chosen shape's deserializer.
#[test]
fn version_wrong_type_produces_field_error() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("version_wrong_type.json");
    std::fs::write(
        &path,
        r#"{"version": "not-a-number", "devices": {"r1": {"name": "r1"}}}"#,
    )
    .expect("should write version wrong type file");

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("wrong version type should fail to parse"),
    };

    match err {
        InventoryError::ParseError(msg) => {
            assert!(
                msg.contains("canonical envelope") || msg.contains("version"),
                "message should mention the shape or field being parsed, got: {msg}"
            );
        }
        _ => panic!("expected ParseError, got: {err:?}"),
    }
}

/// Test that a completely unrelated JSON document (e.g., a config for a
/// different tool) produces an error indicating what structure is expected.
#[test]
fn unrelated_document_produces_shape_guidance() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("unrelated.json");
    std::fs::write(&path, r#"{"app": "unrelated", "config": {"timeout": 30}}"#)
        .expect("should write unrelated file");

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("unrelated document should fail to parse"),
    };

    match err {
        InventoryError::ParseError(msg) => {
            // Legacy Junos flat map will be detected, but deserialization should fail
            // because the device payload doesn't match
            assert!(
                msg.contains("legacy Junos") || msg.contains("missing field"),
                "message should indicate the detected shape or missing field, got: {msg}"
            );
        }
        _ => panic!("expected ParseError, got: {err:?}"),
    }
}

/// Test that a top-level JSON array produces a clear "must be object" error.
#[test]
fn top_level_array_produces_must_be_object_error() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("array.json");
    std::fs::write(&path, r#"[{"name": "r1"}]"#).expect("should write array file");

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("top-level array should fail to parse"),
    };

    match err {
        InventoryError::ParseError(msg) => {
            assert!(
                msg.contains("must be a JSON object") || msg.contains("found array"),
                "message should say inventory must be an object, got: {msg}"
            );
        }
        _ => panic!("expected ParseError, got: {err:?}"),
    }
}

/// Test that having "devices" but no "version" is flagged as ambiguous.
#[test]
fn devices_without_version_is_ambiguous() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("no_version.json");
    std::fs::write(&path, r#"{"devices": {"r1": {"name": "r1"}}}"#)
        .expect("should write no-version file");

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("devices without version should fail"),
    };

    match err {
        InventoryError::ParseError(msg) => {
            assert!(
                msg.contains("found \"devices\" but no \"version\""),
                "message should mention missing version, got: {msg}"
            );
            assert!(
                msg.contains("ambiguous"),
                "message should say the shape is ambiguous, got: {msg}"
            );
        }
        _ => panic!("expected ParseError, got: {err:?}"),
    }
}

/// Test that "devices" as a primitive (e.g., a string) produces a specific error.
#[test]
fn devices_wrong_type_produces_specific_error() {
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("devices_wrong_type.json");
    std::fs::write(
        &path,
        r#"{"version": 1, "devices": "not-an-object-or-array"}"#,
    )
    .expect("should write devices wrong type file");

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("devices as string should fail"),
    };

    match err {
        InventoryError::ParseError(msg) => {
            assert!(
                msg.contains("\"devices\" is not an object or array"),
                "message should say devices must be object or array, got: {msg}"
            );
        }
        _ => panic!("expected ParseError, got: {err:?}"),
    }
}
