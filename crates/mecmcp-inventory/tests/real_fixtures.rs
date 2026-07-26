//! Integration test loading real fixture files from both server repos.

#![allow(clippy::unwrap_used)]

use mecmcp_inventory::Inventory;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct JunosDevice {
    ip: String,
    #[serde(default)]
    port: Option<u16>,
    username: String,
    #[serde(default)]
    ssh_config: Option<String>,
    auth: serde_json::Value,
    #[serde(default)]
    blocklist: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct JunosPolicy {
    #[serde(default)]
    commands: Vec<serde_json::Value>,
    #[serde(default)]
    config: Vec<serde_json::Value>,
    #[serde(default)]
    pfe_commands: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct PanosDevice {
    name: String,
    endpoint: String,
    #[serde(default)]
    vsys: Option<String>,
    api_key: serde_json::Value,
    #[serde(default)]
    tls: Option<serde_json::Value>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    connect_timeout_secs: Option<u64>,
    #[serde(default)]
    request_timeout_secs: Option<u64>,
    #[serde(default)]
    max_concurrency: Option<usize>,
    #[serde(default)]
    max_response_bytes: Option<usize>,
    #[serde(default)]
    mutation: Option<serde_json::Value>,
}

#[test]
fn loads_real_junos_fixture() {
    let junos_path = "/home/mharman/Projects/RustJunosMCP/devices-template.json";
    if !std::path::Path::new(junos_path).exists() {
        eprintln!("Skipping test: {} not found", junos_path);
        return;
    }

    let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
        mecmcp_inventory::FileInventory::load(junos_path).expect("load junos fixture");
    let names = inv.names();

    assert!(
        names.len() >= 2,
        "expected at least 2 devices, got {}",
        names.len()
    );
    assert!(names.contains(&"r1".to_string()), "expected r1");
    assert!(names.contains(&"r2".to_string()), "expected r2");
}

#[test]
fn loads_real_panos_fixture() {
    let panos_path = "/home/mharman/Projects/rust-panosmcp/config/devices.example.json";
    if !std::path::Path::new(panos_path).exists() {
        eprintln!("Skipping test: {} not found", panos_path);
        return;
    }

    let inv: mecmcp_inventory::FileInventory<PanosDevice, ()> =
        mecmcp_inventory::FileInventory::load(panos_path).expect("load panos fixture");
    let names = inv.names();

    assert!(
        !names.is_empty(),
        "expected at least 1 device, got {}",
        names.len()
    );
    assert!(
        names.contains(&"lab-fw-01".to_string()),
        "expected lab-fw-01"
    );
}

#[test]
fn junos_accepts_empty_inventory() {
    let empty = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(empty.path(), r#"{}"#).unwrap();

    let inv: mecmcp_inventory::FileInventory<JunosDevice, JunosPolicy> =
        mecmcp_inventory::FileInventory::load(empty.path()).expect("junos accepts empty");
    assert!(inv.names().is_empty());
}

#[test]
fn panos_parses_empty_devices_array() {
    let empty = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(empty.path(), r#"{"version": 1, "devices": []}"#).unwrap();

    // The loader parses it successfully; the server decides to reject it
    let inv: mecmcp_inventory::FileInventory<PanosDevice, ()> =
        mecmcp_inventory::FileInventory::load(empty.path()).expect("panos parses empty array");
    assert!(inv.names().is_empty());
}
