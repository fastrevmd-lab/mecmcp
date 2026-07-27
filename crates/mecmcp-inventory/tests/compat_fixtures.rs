//! Golden fixture tests for backward-compatibility with existing on-disk schemas.
//!
//! These five fixtures are derived from REAL production files (credentials
//! replaced, IPs normalized to TEST-NET-2). Every one must parse successfully
//! and round-trip with all fields preserved.

use mecmcp_inventory::Inventory;
use serde::{Deserialize, Serialize};

/// Generic device payload for Junos fixtures (flat-map schema).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct JunosDevice {
    ip: String,
    port: u16,
    username: String,
    auth: serde_json::Value,
}

/// Generic device payload for PAN-OS fixtures (envelope schema).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct PanosDevice {
    name: String,
    endpoint: String,
    vsys: String,
    api_key: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connect_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_concurrency: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_response_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation: Option<serde_json::Value>,
}

/// Policy payload for Junos blocklist defaults.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct JunosPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    config: Vec<String>,
}

/// Load and parse each golden fixture, asserting:
/// 1. The file parses successfully
/// 2. The expected number of devices is present
/// 3. Spot-check key fields to ensure they were not lost or corrupted
/// 4. For legacy-junos with blocklist, verify policy is captured and NOT in devices
#[test]
fn all_golden_fixtures_parse() {
    // Legacy Junos: flat map with password auth
    {
        let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
            mecmcp_inventory::FileInventory::load("tests/compat/junos-flat-password.json")
                .expect("junos-flat-password.json should parse");
        let names = inv.names();
        assert_eq!(names.len(), 1, "junos-flat-password should have 1 device");
        assert_eq!(names[0], "r1");
        let r1 = inv.get_device("r1").expect("r1 should exist");
        assert_eq!(r1.ip, "198.51.100.10");
        assert_eq!(r1.port, 830);
        assert_eq!(r1.username, "netops");
        assert_eq!(r1.auth["type"], "password");
        assert!(
            inv.get_policy().is_none(),
            "no policy in flat-password fixture"
        );
    }

    // Legacy Junos: flat map with SSH key auth (3 devices)
    {
        let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
            mecmcp_inventory::FileInventory::load("tests/compat/junos-flat-sshkey.json")
                .expect("junos-flat-sshkey.json should parse");
        let names = inv.names();
        assert_eq!(names.len(), 3, "junos-flat-sshkey should have 3 devices");
        assert!(names.contains(&"br1-fw".to_string()));
        assert!(names.contains(&"br2-fw".to_string()));
        assert!(names.contains(&"br3-fw".to_string()));
        let br1 = inv.get_device("br1-fw").expect("br1-fw should exist");
        assert_eq!(br1.ip, "198.51.100.10");
        assert_eq!(br1.port, 22);
        assert_eq!(br1.auth["type"], "ssh_key");
        assert_eq!(br1.auth["private_key_path"], "/etc/jmcp/test_key");
        assert!(
            inv.get_policy().is_none(),
            "no policy in flat-sshkey fixture"
        );
    }

    // Legacy Junos: flat map with _blocklist_defaults (MAGIC KEY TEST)
    {
        let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
            mecmcp_inventory::FileInventory::load(
                "tests/compat/junos-flat-with-blocklist-defaults.json",
            )
            .expect("junos-flat-with-blocklist-defaults.json should parse");
        let names = inv.names();
        assert_eq!(
            names.len(),
            1,
            "blocklist fixture should have 1 device, not including _blocklist_defaults"
        );
        assert_eq!(names[0], "br1-fw");
        assert!(
            !names.contains(&"_blocklist_defaults".to_string()),
            "_blocklist_defaults must NOT appear as a device"
        );
        let policy = inv.get_policy().expect("policy should be present");
        assert_eq!(policy.commands, vec!["request system reboot"]);
        assert_eq!(policy.config, vec!["system root-authentication"]);
    }

    // Legacy PAN-OS: minimal envelope (1 device)
    {
        let inv: mecmcp_inventory::FileInventory<PanosDevice, ()> =
            mecmcp_inventory::FileInventory::load("tests/compat/panos-envelope-minimal.json")
                .expect("panos-envelope-minimal.json should parse");
        let names = inv.names();
        assert_eq!(
            names.len(),
            1,
            "panos-envelope-minimal should have 1 device"
        );
        assert_eq!(names[0], "lab-fw-01");
        let fw = inv.get_device("lab-fw-01").expect("lab-fw-01 should exist");
        assert_eq!(fw.endpoint, "https://198.51.100.20");
        assert_eq!(fw.vsys, "vsys1");
        assert_eq!(fw.api_key["type"], "env");
        assert_eq!(fw.api_key["name"], "PANOS_TEST_API_KEY");
        assert!(fw.tls.is_none());
        assert!(fw.tags.is_empty());
        assert!(fw.mutation.is_none());
        assert!(
            inv.get_policy().is_none(),
            "no policy in panos minimal fixture"
        );
    }

    // Legacy PAN-OS: rich envelope (2 devices with all optional fields)
    {
        let inv: mecmcp_inventory::FileInventory<PanosDevice, ()> =
            mecmcp_inventory::FileInventory::load("tests/compat/panos-envelope-rich.json")
                .expect("panos-envelope-rich.json should parse");
        let names = inv.names();
        assert_eq!(names.len(), 2, "panos-envelope-rich should have 2 devices");
        assert!(names.contains(&"panosvm".to_string()));
        assert!(names.contains(&"panosvm-writer".to_string()));

        let panosvm = inv.get_device("panosvm").expect("panosvm should exist");
        assert_eq!(panosvm.endpoint, "https://198.51.100.20");
        assert_eq!(panosvm.vsys, "vsys1");
        assert!(panosvm.tls.is_some(), "tls should be present");
        assert_eq!(panosvm.tags, vec!["lab", "vmid-900", "read-only"]);
        assert_eq!(panosvm.connect_timeout_secs, Some(10));
        assert_eq!(panosvm.request_timeout_secs, Some(30));
        assert_eq!(panosvm.max_concurrency, Some(4));
        assert_eq!(panosvm.max_response_bytes, Some(5242880));
        assert!(
            panosvm.mutation.is_none(),
            "read-only device has no mutation"
        );

        let writer = inv
            .get_device("panosvm-writer")
            .expect("panosvm-writer should exist");
        assert!(
            writer.mutation.is_some(),
            "writer device should have mutation config"
        );
        assert_eq!(writer.max_concurrency, Some(1));
        assert!(
            inv.get_policy().is_none(),
            "no policy in panos rich fixture"
        );
    }
}

/// Test that canonical envelope shape can be parsed (once implemented).
/// This will initially fail because the canonical shape doesn't exist yet.
#[test]
fn canonical_envelope_parses() {
    // Create a temp file with the canonical shape
    let dir = tempfile::tempdir().expect("should create tempdir");
    let path = dir.path().join("canonical.json");
    std::fs::write(
        &path,
        r#"{
  "version": 1,
  "policy": {
    "commands": ["request system halt"],
    "config": ["delete system"]
  },
  "devices": {
    "r1": {
      "ip": "198.51.100.30",
      "port": 830,
      "username": "admin",
      "auth": {
        "type": "password",
        "password": "test"
      }
    },
    "r2": {
      "ip": "198.51.100.31",
      "port": 830,
      "username": "admin",
      "auth": {
        "type": "ssh_key",
        "private_key_path": "/tmp/key"
      }
    }
  }
}"#,
    )
    .expect("should write canonical fixture");

    let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
        mecmcp_inventory::FileInventory::load(&path).expect("canonical envelope should parse");

    let names = inv.names();
    assert_eq!(names.len(), 2, "canonical should have 2 devices");
    assert!(names.contains(&"r1".to_string()));
    assert!(names.contains(&"r2".to_string()));

    let r1 = inv.get_device("r1").expect("r1 should exist");
    assert_eq!(r1.ip, "198.51.100.30");
    assert_eq!(r1.port, 830);

    let policy = inv.get_policy().expect("policy should be present");
    assert_eq!(policy.commands, vec!["request system halt"]);
    assert_eq!(policy.config, vec!["delete system"]);
}

/// Test empty devices behavior: canonical and legacy-junos accept empty,
/// but we should be able to parse both.
#[test]
fn empty_devices_handling() {
    let dir = tempfile::tempdir().expect("should create tempdir");

    // Legacy Junos: empty map is accepted
    {
        let path = dir.path().join("empty_junos.json");
        std::fs::write(&path, "{}").expect("should write empty junos");
        let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
            mecmcp_inventory::FileInventory::load(&path).expect("empty junos map should parse");
        assert_eq!(inv.names().len(), 0);
    }

    // Canonical: empty devices map
    {
        let path = dir.path().join("empty_canonical.json");
        std::fs::write(&path, r#"{"version": 1, "devices": {}}"#)
            .expect("should write empty canonical");
        let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
            mecmcp_inventory::FileInventory::load(&path)
                .expect("empty canonical devices should parse");
        assert_eq!(inv.names().len(), 0);
    }
}
