//! Backward compatibility test for config_authority field addition.
//!
//! HARD CONSTRAINT: devices.json is deployed on LXC 600, 601, 608, and 609.
//! Any new inventory field must be optional with a default so existing files
//! load byte-unchanged.
//!
//! This test MUST be written FIRST and watched to fail before adding defaults.

use mecmcp_inventory::{FileInventory, Inventory};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Device type matching the existing production Junos schema.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct JunosDevice {
    ip: String,
    port: u16,
    username: String,
    auth: serde_json::Value,
    /// NEW FIELD: Config authority. Must be optional with default = unknown.
    #[serde(default)]
    config_authority: Option<mecmcp_inventory::ConfigAuthority<JunosAuthority>>,
}

/// Device type matching the existing production PAN-OS schema.
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
    /// NEW FIELD: Config authority. Must be optional with default = unknown.
    #[serde(default)]
    config_authority: Option<mecmcp_inventory::ConfigAuthority<PanosAuthority>>,
}

/// Junos config authority values (example from issue #256).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JunosAuthority {
    Local,
    Mist,
    SecurityDirectorCloud,
    SecurityDirectorOnprem,
    Unknown,
}

impl mecmcp_inventory::LocalAuthority for JunosAuthority {
    fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }
}

/// PAN-OS config authority values (example from issue #256).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PanosAuthority {
    Local,
    Panorama,
    StrataCloudManager,
    Unknown,
}

impl mecmcp_inventory::LocalAuthority for PanosAuthority {
    fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }
}

/// Stage a fixture at 0600 for the hardened loader.
fn staged(dir: &tempfile::TempDir, fixture: &str) -> std::path::PathBuf {
    let body = std::fs::read(fixture).expect("read fixture");
    let name = Path::new(fixture).file_name().expect("fixture has name");
    let path = dir.path().join(name);
    std::fs::write(&path, body).expect("stage fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture");
    }
    path
}

/// HARD CONSTRAINT TEST: All existing production fixtures must load unchanged.
///
/// This test loads the five golden fixtures derived from real production
/// inventories WITHOUT the config_authority field present. If parsing fails,
/// the new field is not properly defaulted.
#[test]
fn existing_devices_json_files_load_without_config_authority() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Junos fixtures
    {
        let inv: FileInventory<JunosDevice, serde_json::Value> =
            FileInventory::load(staged(&dir, "tests/compat/junos-flat-password.json"))
                .expect("junos-flat-password.json must load without config_authority field");
        let names = inv.names();
        assert_eq!(names.len(), 1);
        let r1 = inv.get_device("r1").expect("r1 exists");
        // The field was not in the file, so it must default to None
        assert!(
            r1.config_authority.is_none(),
            "config_authority must default to None when absent from file"
        );
    }

    {
        let inv: FileInventory<JunosDevice, serde_json::Value> =
            FileInventory::load(staged(&dir, "tests/compat/junos-flat-sshkey.json"))
                .expect("junos-flat-sshkey.json must load");
        assert_eq!(inv.names().len(), 3);
        let br1 = inv.get_device("br1-fw").expect("br1-fw exists");
        assert!(br1.config_authority.is_none());
    }

    {
        let inv: FileInventory<JunosDevice, serde_json::Value> = FileInventory::load(staged(
            &dir,
            "tests/compat/junos-flat-with-blocklist-defaults.json",
        ))
        .expect("junos-flat-with-blocklist-defaults.json must load");
        assert_eq!(inv.names().len(), 1);
        let br1 = inv.get_device("br1-fw").expect("br1-fw exists");
        assert!(br1.config_authority.is_none());
    }

    // PAN-OS fixtures
    {
        let inv: FileInventory<PanosDevice, ()> =
            FileInventory::load(staged(&dir, "tests/compat/panos-envelope-minimal.json"))
                .expect("panos-envelope-minimal.json must load");
        assert_eq!(inv.names().len(), 1);
        let fw = inv.get_device("lab-fw-01").expect("lab-fw-01 exists");
        assert!(fw.config_authority.is_none());
    }

    {
        let inv: FileInventory<PanosDevice, ()> =
            FileInventory::load(staged(&dir, "tests/compat/panos-envelope-rich.json"))
                .expect("panos-envelope-rich.json must load");
        assert_eq!(inv.names().len(), 2);
        let panosvm = inv.get_device("panosvm").expect("panosvm exists");
        assert!(panosvm.config_authority.is_none());
        let writer = inv.get_device("panosvm-writer").expect("writer exists");
        assert!(writer.config_authority.is_none());
    }
}

/// Test that when config_authority IS present, it parses correctly.
#[test]
fn config_authority_field_parses_when_present() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("with-authority.json");

    // Junos device with config_authority = mist
    std::fs::write(
        &path,
        r#"{
  "version": 1,
  "devices": {
    "r1": {
      "ip": "198.51.100.10",
      "port": 830,
      "username": "netops",
      "auth": {"type": "password", "password": "test"},
      "config_authority": "mist"
    }
  }
}"#,
    )
    .expect("write fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    let inv: FileInventory<JunosDevice, serde_json::Value> =
        FileInventory::load(&path).expect("parse with authority");
    let r1 = inv.get_device("r1").expect("r1 exists");
    let authority = r1.config_authority.as_ref().expect("authority present");
    assert_eq!(authority.authority(), &JunosAuthority::Mist);
    assert!(!authority.is_local());
}
