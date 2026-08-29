//! Tests for unknown top-level key rejection.
//!
//! Issue #340: mecmcp-inventory silently accepted unknown top-level keys, so
//! a misplaced credential was neither used nor refused. This test verifies that
//! unknown keys are now rejected in envelope shapes (1 and 2) while still
//! allowing arbitrary device names in the legacy flat-map shape (3).

use mecmcp_inventory::{FileInventory, Inventory, InventoryError};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
fn write_mode_600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod fixture");
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestDevice {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TestPolicy {}

/// Test that a stray top-level key in the canonical envelope (shape 1) is rejected.
#[test]
fn canonical_envelope_rejects_unknown_top_level_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("canonical_stray_key.json");
    std::fs::write(
        &path,
        r#"{"version": 1, "api_key": "secret", "devices": {"r1": {"name": "r1"}}}"#,
    )
    .expect("write");

    #[cfg(unix)]
    write_mode_600(&path);

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(InventoryError::ParseError(msg)) => {
            assert!(
                msg.contains("unknown field") || msg.contains("api_key"),
                "error should mention unknown field, got: {msg}"
            );
        }
        Err(e) => panic!("expected ParseError, got: {e:?}"),
        Ok(_) => panic!("stray key should be rejected"),
    }
}

/// Test that a stray top-level key in the legacy PAN-OS envelope (shape 2) is rejected.
#[test]
fn panos_envelope_rejects_unknown_top_level_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("panos_stray_key.json");
    std::fs::write(
        &path,
        r#"{"version": 1, "api_secret": "abc123", "devices": [{"name": "fw1"}]}"#,
    )
    .expect("write");

    #[cfg(unix)]
    write_mode_600(&path);

    let result: Result<FileInventory<TestDevice, TestPolicy>, _> = FileInventory::load(&path);
    match result {
        Err(InventoryError::ParseError(msg)) => {
            assert!(
                msg.contains("unknown field") || msg.contains("api_secret"),
                "error should mention unknown field, got: {msg}"
            );
        }
        Err(e) => panic!("expected ParseError, got: {e:?}"),
        Ok(_) => panic!("stray key should be rejected"),
    }
}

/// Test that the legacy Junos flat map (shape 3) still accepts arbitrary
/// top-level keys as device names.
#[test]
fn junos_flat_map_still_accepts_arbitrary_device_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("junos_flat.json");
    // A flat map with device names "router1" and "firewall-prod"
    std::fs::write(
        &path,
        r#"{"router1": {"name": "router1"}, "firewall-prod": {"name": "firewall-prod"}}"#,
    )
    .expect("write");

    #[cfg(unix)]
    write_mode_600(&path);

    let inventory: FileInventory<TestDevice, TestPolicy> =
        FileInventory::load(&path).expect("should load flat map with arbitrary device names");

    let names = inventory.names();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"router1".to_string()));
    assert!(names.contains(&"firewall-prod".to_string()));
}

/// Test that a device name that looks like a credential key still loads
/// in the flat map shape, demonstrating the documented ambiguity.
#[test]
fn junos_flat_map_accepts_device_named_api_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("junos_api_key_device.json");
    // Deliberately name a device "api_key" to show the ambiguity
    std::fs::write(&path, r#"{"api_key": {"name": "api_key"}}"#).expect("write");

    #[cfg(unix)]
    write_mode_600(&path);

    let inventory: FileInventory<TestDevice, TestPolicy> =
        FileInventory::load(&path).expect("flat map should accept device named api_key");

    let names = inventory.names();
    assert_eq!(names, vec!["api_key"]);
}
