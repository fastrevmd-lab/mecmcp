//! Migrating a legacy inventory to the canonical envelope (mecmcp#48).
//!
//! #27 delivered the read side: three shapes understood, none emitted. So the
//! schema was supported and not adopted, and every live file stayed legacy —
//! which is why junos still cannot version its schema and `_blocklist_defaults`
//! still shares the device namespace.
//!
//! The rule these tests pin is that migration is **explicit**. Nothing converts
//! a file as a side effect of writing to it: an operator's inventory changing
//! shape because they added a device is a surprise, and on a `protected` server
//! it is a surprise during an outage.

#![allow(clippy::unwrap_used)]

use mecmcp_inventory::{FileInventory, migrate_to_canonical};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt as _;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Device {
    host: String,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct Policy {
    #[serde(default)]
    blocklist: Vec<String>,
}

fn stage(name: &str, body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}

const JUNOS_FLAT: &str = r#"{
    "_blocklist_defaults": {"blocklist": ["request system reboot"]},
    "edge-fw": {"host": "10.0.0.1", "port": 830},
    "core-fw": {"host": "10.0.0.2"}
}"#;

const PANOS_ARRAY: &str = r#"{
    "version": 1,
    "devices": [
        {"name": "panosvm", "host": "10.0.1.1"},
        {"name": "panosvm-writer", "host": "10.0.1.1", "port": 443}
    ]
}"#;

/// The whole point: what the file means must not change when its shape does.
#[test]
fn migrating_a_junos_flat_map_preserves_every_device_and_the_policy() {
    let (_dir, path) = stage("devices.json", JUNOS_FLAT);

    let before: FileInventory<Device, Policy> = FileInventory::load(&path).unwrap();
    let before_edge = before.get_device("edge-fw").unwrap();
    let before_policy = before.get_policy();

    let report = migrate_to_canonical::<Device, Policy>(&path).unwrap();
    assert!(report.converted, "a legacy file must report as converted");

    let after: FileInventory<Device, Policy> = FileInventory::load(&path).unwrap();
    assert_eq!(after.get_device("edge-fw").unwrap(), before_edge);
    assert_eq!(after.get_device("core-fw").unwrap().host, "10.0.0.2");
    assert_eq!(
        after.get_policy(),
        before_policy,
        "`_blocklist_defaults` must survive the move out of the device namespace"
    );

    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["version"], 1, "{raw}");
    assert!(raw["devices"].is_object(), "{raw}");
    assert!(
        raw["devices"].get("_blocklist_defaults").is_none(),
        "the magic key must not reappear as a device: {raw}"
    );
}

#[test]
fn migrating_a_panos_array_preserves_every_device() {
    let (_dir, path) = stage("devices.json", PANOS_ARRAY);

    let report = migrate_to_canonical::<Device, Policy>(&path).unwrap();
    assert!(report.converted);

    let after: FileInventory<Device, Policy> = FileInventory::load(&path).unwrap();
    assert_eq!(after.get_device("panosvm").unwrap().host, "10.0.1.1");
    assert_eq!(after.get_device("panosvm-writer").unwrap().port, Some(443));

    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        raw["devices"].is_object(),
        "the array becomes a map keyed by name: {raw}"
    );
}

/// Running it twice must be safe: an operator who is unsure whether a file was
/// migrated should be able to just run it.
#[test]
fn migrating_an_already_canonical_file_changes_nothing() {
    let (_dir, path) = stage("devices.json", JUNOS_FLAT);
    migrate_to_canonical::<Device, Policy>(&path).unwrap();
    let first = std::fs::read(&path).unwrap();

    let report = migrate_to_canonical::<Device, Policy>(&path).unwrap();

    assert!(
        !report.converted,
        "already-canonical must report no conversion"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        first,
        "a no-op migration must not rewrite the file"
    );
}

/// The file is credentials-adjacent, so the mode must survive the rewrite —
/// `FileInventory::load` refuses a group- or world-readable inventory (#173),
/// and a migration that widened the mode would take the server down at its next
/// restart, which is the worst possible time to discover it.
#[test]
fn migration_preserves_the_restrictive_file_mode() {
    let (_dir, path) = stage("devices.json", JUNOS_FLAT);

    migrate_to_canonical::<Device, Policy>(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "migrated file must stay owner-only, got {mode:o}"
    );
}

/// A backup is what makes this reversible without a snapshot.
#[test]
fn migration_leaves_the_original_beside_it() {
    let (_dir, path) = stage("devices.json", JUNOS_FLAT);
    let original = std::fs::read_to_string(&path).unwrap();

    let report = migrate_to_canonical::<Device, Policy>(&path).unwrap();

    let backup = report.backup.expect("a conversion must leave a backup");
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), original);
    let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the backup holds the same secrets as the file");
}
