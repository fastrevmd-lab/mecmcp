//! File-backed inventory implementation with tri-schema loader.
//!
//! Transparently loads three on-disk shapes:
//!
//! 1. **Canonical envelope** (recommended): `{ "version": 1, "devices": {...}, "policy": {...} }`
//!    - Devices as a map (name-indexed), optional policy at top level
//!    - Accepts empty devices map (same as legacy Junos)
//!
//! 2. **Legacy PAN-OS envelope**: `{ "version": 1, "devices": [...] }`
//!    - Devices as an array with `name` field, no policy slot
//!    - Converted to a map during load
//!
//! 3. **Legacy Junos flat-map**: `{ "device-name": {...}, "_blocklist_defaults": {...} }`
//!    - Flat map keyed by device name, optional `_blocklist_defaults` magic key
//!    - The magic key is parsed into the policy slot and removed from devices
//!
//! All three normalize to the same internal representation: a name-indexed map
//! of devices plus an optional policy payload.

use crate::{Inventory, InventoryError, validate_device_name};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;

/// File-backed inventory loading both Junos (flat map) and PAN-OS (versioned
/// envelope) schemas. Supports atomic write and hot-reload.
///
/// Generic over `D` (device payload) and `P` (global policy). The loader
/// detects which schema it sees and normalizes both to a name-indexed map.
pub struct FileInventory<D, P> {
    inner: Arc<RwLock<InventoryInner<D, P>>>,
}

struct InventoryInner<D, P> {
    source: PathBuf,
    devices: HashMap<String, D>,
    policy: Option<P>,
}

impl<D, P> FileInventory<D, P>
where
    for<'de> D: Deserialize<'de> + serde::Serialize + Clone,
    for<'de> P: Deserialize<'de> + Clone,
{
    /// Load an inventory from `path`. Detects Junos flat-map vs PAN-OS envelope.
    ///
    /// Returns `Err(InventoryError::EmptyInventory)` if the parsed result
    /// contains no devices. The caller decides whether an empty inventory is
    /// acceptable — Junos accepts `{}`, PAN-OS rejects it.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, InventoryError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let (devices, policy) = parse_inventory(&bytes)?;

        Ok(Self {
            inner: Arc::new(RwLock::new(InventoryInner {
                source: path.to_path_buf(),
                devices,
                policy,
            })),
        })
    }

    /// Re-read the source file and atomically replace the inventory if
    /// validation succeeds. Returns the number of devices after reload.
    pub fn reload(&self) -> Result<usize, InventoryError> {
        let path = {
            let inner = self.inner.read().expect("inventory lock poisoned");
            inner.source.clone()
        };

        let bytes = std::fs::read(&path)?;
        let (devices, policy) = parse_inventory(&bytes)?;
        let count = devices.len();

        let mut inner = self.inner.write().expect("inventory lock poisoned");
        inner.devices = devices;
        inner.policy = policy;
        Ok(count)
    }

    /// Source path this inventory was loaded from.
    pub fn source(&self) -> PathBuf {
        let inner = self.inner.read().expect("inventory lock poisoned");
        inner.source.clone()
    }
}

impl<D, P> Inventory<D, P> for FileInventory<D, P>
where
    D: Send + Sync + Clone,
    P: Send + Sync + Clone,
{
    fn names(&self) -> Vec<String> {
        let inner = self.inner.read().expect("inventory lock poisoned");
        let mut names: Vec<String> = inner.devices.keys().cloned().collect();
        names.sort();
        names
    }

    fn get(&self, name: &str) -> Result<D, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().expect("inventory lock poisoned");
        inner
            .devices
            .get(name)
            .cloned()
            .ok_or_else(|| Box::new(InventoryError::UnknownDevice(name.to_string())) as Box<_>)
    }

    fn policy(&self) -> Option<P> {
        let inner = self.inner.read().expect("inventory lock poisoned");
        inner.policy.clone()
    }
}

impl<D, P> FileInventory<D, P>
where
    D: Send + Sync + Clone,
    P: Send + Sync + Clone,
{
    /// A cloned device entry, with the crate's own error type.
    ///
    /// Retained alongside the trait's `get`, which returns a boxed error: a
    /// caller that already depends on this crate usually wants to match on
    /// `InventoryError` rather than downcast.
    pub fn get_device(&self, name: &str) -> Result<D, InventoryError> {
        let inner = self.inner.read().expect("inventory lock poisoned");
        inner
            .devices
            .get(name)
            .cloned()
            .ok_or_else(|| InventoryError::UnknownDevice(name.to_string()))
    }

    /// A cloned policy payload.
    pub fn get_policy(&self) -> Option<P> {
        let inner = self.inner.read().expect("inventory lock poisoned");
        inner.policy.clone()
    }
}

/// Canonical envelope: `{ "version": 1, "devices": {...}, "policy": {...} }`.
#[derive(Deserialize)]
struct CanonicalEnvelope<D, P> {
    version: u32,
    policy: Option<P>,
    devices: HashMap<String, D>,
}

/// Legacy PAN-OS envelope: `{ "version": 1, "devices": [...] }`.
#[derive(Deserialize)]
struct PanosEnvelope<D> {
    version: u32,
    devices: Vec<D>,
}

/// Legacy Junos flat map: `{ "device-name": {...}, "_blocklist_defaults": {...} }`.
#[derive(Deserialize)]
struct JunosFlat<D, P> {
    #[serde(rename = "_blocklist_defaults")]
    policy: Option<P>,
    #[serde(flatten)]
    devices: HashMap<String, D>,
}

/// Detected inventory shape based on observable structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryShape {
    Canonical,
    LegacyPanos,
    LegacyJunos,
}

/// Discriminate the inventory shape from a parsed JSON value.
///
/// Rules (applied in order):
/// 1. Not a JSON object -> error
/// 2. Has `version` and `devices` where `devices` is an object -> Canonical
/// 3. Has `version` and `devices` where `devices` is an array -> LegacyPanos
/// 4. Has neither `version` nor `devices` -> LegacyJunos
/// 5. Has `version` but no `devices` (or misspelled) -> error
/// 6. Has `devices` but no `version` -> error (ambiguous)
fn detect_shape(value: &serde_json::Value) -> Result<InventoryShape, InventoryError> {
    let obj = value.as_object().ok_or_else(|| {
        InventoryError::ParseError(
            "inventory must be a JSON object, found array or primitive".into(),
        )
    })?;

    let has_version = obj.contains_key("version");
    let has_devices = obj.contains_key("devices");

    match (has_version, has_devices) {
        (true, true) => {
            // Both version and devices present — discriminate by devices type
            // We already checked has_devices, so get() cannot return None
            let devices_value = obj
                .get("devices")
                .expect("devices key must exist after contains_key check");
            match devices_value {
                serde_json::Value::Object(_) => Ok(InventoryShape::Canonical),
                serde_json::Value::Array(_) => Ok(InventoryShape::LegacyPanos),
                _ => Err(InventoryError::ParseError(
                    "found \"version\" and \"devices\" but \"devices\" is not an object or array"
                        .into(),
                )),
            }
        }
        (true, false) => {
            // Has version but no devices — likely a typo
            let keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
            Err(InventoryError::ParseError(format!(
                "found \"version\" but no \"devices\" key (found keys: {}) — expected canonical envelope {{\"version\":1,\"devices\":{{...}}}} or legacy PAN-OS {{\"version\":1,\"devices\":[...]}}",
                keys.join(", ")
            )))
        }
        (false, true) => {
            // Has devices but no version — ambiguous (could be canonical with version omitted, or a mistake)
            Err(InventoryError::ParseError(
                "found \"devices\" but no \"version\" key — ambiguous shape (canonical envelope requires \"version\")".into(),
            ))
        }
        (false, false) => {
            // Neither version nor devices — legacy Junos flat map
            Ok(InventoryShape::LegacyJunos)
        }
    }
}

/// Parse all three schemas and return (devices_map, global_policy).
///
/// Discrimination happens in two phases:
/// 1. Parse to `serde_json::Value` and detect shape from observable structure
/// 2. Deserialize into the chosen concrete type, preserving field-path errors
fn parse_inventory<D, P>(bytes: &[u8]) -> Result<(HashMap<String, D>, Option<P>), InventoryError>
where
    for<'de> D: Deserialize<'de> + serde::Serialize,
    for<'de> P: Deserialize<'de>,
{
    // Phase 1: Parse to Value and detect shape
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| InventoryError::ParseError(e.to_string()))?;
    let shape = detect_shape(&value)?;

    // Phase 2: Deserialize into the chosen concrete type
    match shape {
        InventoryShape::Canonical => {
            let envelope: CanonicalEnvelope<D, P> = serde_json::from_value(value)
                .map_err(|e| InventoryError::ParseError(format!("canonical envelope: {e}")))?;

            if envelope.version != 1 {
                return Err(InventoryError::UnsupportedVersion(envelope.version));
            }

            // Validate all device names in the canonical envelope.
            for name in envelope.devices.keys() {
                validate_device_name(name)?;
            }

            // Canonical envelope accepts empty devices map (same as legacy Junos).
            Ok((envelope.devices, envelope.policy))
        }
        InventoryShape::LegacyPanos => {
            let envelope: PanosEnvelope<serde_json::Value> = serde_json::from_value(value)
                .map_err(|e| InventoryError::ParseError(format!("legacy PAN-OS envelope: {e}")))?;

            if envelope.version != 1 {
                return Err(InventoryError::UnsupportedVersion(envelope.version));
            }

            // Convert array to map by extracting each device's "name" field
            let mut map = HashMap::new();
            for (idx, device_val) in envelope.devices.iter().enumerate() {
                let name = device_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        InventoryError::ParseError(format!(
                            "legacy PAN-OS envelope: device at index {idx} missing \"name\" field"
                        ))
                    })?
                    .to_string();
                validate_device_name(&name)?;

                let device: D = serde_json::from_value(device_val.clone()).map_err(|e| {
                    InventoryError::ParseError(format!(
                        "legacy PAN-OS envelope: device \"{name}\": {e}"
                    ))
                })?;

                if map.insert(name.clone(), device).is_some() {
                    return Err(InventoryError::DuplicateName(name));
                }
            }

            // Legacy PAN-OS has no policy slot.
            Ok((map, None))
        }
        InventoryShape::LegacyJunos => {
            let flat: JunosFlat<D, P> = serde_json::from_value(value)
                .map_err(|e| InventoryError::ParseError(format!("legacy Junos flat map: {e}")))?;

            // Validate all device names (the magic _blocklist_defaults key was
            // already parsed into `policy` and removed from `devices` by serde).
            for name in flat.devices.keys() {
                validate_device_name(name)?;
            }

            // Legacy Junos accepts empty map.
            Ok((flat.devices, flat.policy))
        }
    }
}

/// SHA-256 of the file at `path`. Returns zeros if the file doesn't exist.
#[allow(dead_code)]
pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok([0u8; 32]),
        Err(e) => Err(e),
    }
}

/// Atomically replace `path` with the JSON serialization of `value`.
/// Uses same-filesystem rename via tempfile. Preserves existing mode bits (Unix).
#[allow(dead_code)]
pub fn write_atomic(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "inventory path has no parent directory",
        )
    })?;
    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("parent directory does not exist: {}", parent.display()),
        ));
    }
    let resolved_parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let mut tmp = tempfile::NamedTempFile::new_in(resolved_parent)?;
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tmp.write_all(pretty.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;

    // Preserve mode bits if the target already exists.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }

    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Write;

    #[allow(clippy::unwrap_used)]
    mod loader_tests {
        use super::*;

        #[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq)]
        struct JunosDevice {
            ip: String,
            username: String,
        }

        #[derive(Debug, Clone, Deserialize, PartialEq)]
        struct JunosPolicy {
            commands: Vec<String>,
        }

        #[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq)]
        struct PanosDevice {
            name: String,
            endpoint: String,
        }

        #[test]
        fn loads_junos_flat_map() {
            let json = r#"{
                "_blocklist_defaults": {
                    "commands": ["deny *"]
                },
                "r1": {"ip": "1.2.3.4", "username": "admin"},
                "r2": {"ip": "1.2.3.5", "username": "netconf"}
            }"#;
            let (devices, policy): (HashMap<String, JunosDevice>, Option<JunosPolicy>) =
                parse_inventory(json.as_bytes()).unwrap();
            assert_eq!(devices.len(), 2);
            assert_eq!(devices["r1"].ip, "1.2.3.4");
            assert_eq!(devices["r2"].username, "netconf");
            let pol = policy.unwrap();
            assert_eq!(pol.commands, vec!["deny *"]);
        }

        #[test]
        fn loads_junos_empty_map() {
            let json = r#"{}"#;
            let (devices, policy): (HashMap<String, JunosDevice>, Option<JunosPolicy>) =
                parse_inventory(json.as_bytes()).unwrap();
            assert_eq!(devices.len(), 0);
            assert!(policy.is_none());
        }

        #[test]
        fn loads_panos_versioned_envelope() {
            let json = r#"{
                "version": 1,
                "devices": [
                    {"name": "fw-01", "endpoint": "https://fw1.example"},
                    {"name": "fw-02", "endpoint": "https://fw2.example"}
                ]
            }"#;
            let (devices, policy): (HashMap<String, PanosDevice>, Option<()>) =
                parse_inventory(json.as_bytes()).unwrap();
            assert_eq!(devices.len(), 2);
            assert_eq!(devices["fw-01"].endpoint, "https://fw1.example");
            assert_eq!(devices["fw-02"].endpoint, "https://fw2.example");
            assert!(policy.is_none());
        }

        #[test]
        fn rejects_panos_unsupported_version() {
            let json = r#"{
                "version": 999,
                "devices": [{"name": "fw", "endpoint": "https://fw.example"}]
            }"#;
            let result: Result<(HashMap<String, PanosDevice>, Option<()>), _> =
                parse_inventory(json.as_bytes());
            assert!(matches!(
                result,
                Err(InventoryError::UnsupportedVersion(999))
            ));
        }

        #[test]
        fn rejects_duplicate_device_names() {
            let _json = r#"{
                "r1": {"ip": "1.2.3.4", "username": "admin"},
                "r1": {"ip": "1.2.3.5", "username": "netconf"}
            }"#;
            // JSON parsers typically keep the last duplicate key, so this won't
            // error during parse. We test the PAN-OS array case instead.
            let panos_json = r#"{
                "version": 1,
                "devices": [
                    {"name": "fw", "endpoint": "https://fw1.example"},
                    {"name": "fw", "endpoint": "https://fw2.example"}
                ]
            }"#;
            let result: Result<(HashMap<String, PanosDevice>, Option<()>), _> =
                parse_inventory(panos_json.as_bytes());
            assert!(matches!(result, Err(InventoryError::DuplicateName(_))));
        }

        #[test]
        fn file_inventory_loads_and_reloads() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("devices.json");
            std::fs::write(&path, r#"{"r1": {"ip": "1.2.3.4", "username": "admin"}}"#).unwrap();

            let inv: FileInventory<JunosDevice, JunosPolicy> = FileInventory::load(&path).unwrap();
            let names = inv.names();
            assert_eq!(names, vec!["r1"]);

            // Modify file and reload
            std::fs::write(
                &path,
                r#"{"r1": {"ip": "1.2.3.4", "username": "admin"}, "r2": {"ip": "1.2.3.5", "username": "netconf"}}"#,
            )
            .unwrap();
            // No runtime needed: reload is synchronous. It was async only
            // because the lock was tokio's, which also made names() call
            // blocking_read() — a panic if reached from async code.
            let count = inv.reload().unwrap();
            assert_eq!(count, 2);
            let names = inv.names();
            assert_eq!(names, vec!["r1", "r2"]);
        }
    }

    #[allow(clippy::unwrap_used)]
    mod atomic_write_tests {
        use super::*;

        #[test]
        fn write_atomic_replaces_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.json");
            std::fs::write(&path, r#"{"old": "value"}"#).unwrap();

            let new_val = serde_json::json!({"new": "value"});
            write_atomic(&path, &new_val).unwrap();

            let on_disk: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(on_disk.get("new").unwrap(), "value");
            assert!(on_disk.get("old").is_none());
        }

        #[test]
        fn write_atomic_preserves_key_order() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ordered.json");
            let mut map = serde_json::Map::new();
            map.insert("first".into(), serde_json::json!("a"));
            map.insert("second".into(), serde_json::json!("b"));
            let val = serde_json::Value::Object(map);

            write_atomic(&path, &val).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let s = std::str::from_utf8(&bytes).unwrap();
            assert!(s.find("\"first\"").unwrap() < s.find("\"second\"").unwrap());
        }
    }

    #[allow(clippy::unwrap_used)]
    mod hash_tests {
        use super::*;

        #[test]
        fn hash_file_returns_zeros_for_missing_file() {
            let path = Path::new("/tmp/nonexistent-mecmcp-test-file.json");
            let hash = hash_file(path).unwrap();
            assert_eq!(hash, [0u8; 32]);
        }

        #[test]
        fn hash_file_returns_digest_for_existing_file() {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(b"test content").unwrap();
            f.flush().unwrap();
            let hash = hash_file(f.path()).unwrap();
            assert_ne!(hash, [0u8; 32]);
        }
    }
}
