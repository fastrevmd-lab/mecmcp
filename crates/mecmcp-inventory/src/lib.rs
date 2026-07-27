//! Generic device inventory abstraction.
//!
//! The `Inventory` trait provides a common interface for device lookup and
//! policy retrieval, abstracting over vendor-specific storage formats. This
//! crate ships a file-backed implementation that reads both Junos's flat-map
//! schema and PAN-OS's versioned-envelope schema without requiring migration.

mod file;
pub use file::FileInventory;

use std::error::Error;

/// Device inventory providing name-indexed access and optional global policy.
///
/// Generic over the device payload `D` and policy payload `P`. Both Junos and
/// PAN-OS server implementations supply their vendor-specific device types.
pub trait Inventory<D, P>: Send + Sync {
    /// Return all device names in stable order.
    fn names(&self) -> Vec<String>;

    /// Resolve a device by exact name, returning an **owned** value.
    ///
    /// Owned rather than borrowed because any hot-reloadable inventory needs
    /// interior mutability — SIGHUP swaps the contents under live readers — and
    /// a reference cannot outlive the lock guard that protects it.
    ///
    /// This trait originally returned `Result<&D, _>`, which `FileInventory`
    /// could not honour: its `get` returned `Err` unconditionally and `policy`
    /// returned `None`, with comments telling callers to use inherent methods
    /// instead. Two of three methods were inert, and no test caught it because
    /// every test used the concrete type rather than the trait.
    fn get(&self, name: &str) -> Result<D, Box<dyn Error + Send + Sync>>;

    /// The inventory-wide policy payload, owned for the same reason.
    fn policy(&self) -> Option<P>;
}

/// Validate a device name per the constraints both servers enforce:
/// 1-64 bytes, ASCII alphanumeric + `_`, `.`, `-`, no leading `-`.
pub fn validate_device_name(name: &str) -> Result<(), InventoryError> {
    if name.is_empty() || name.len() > 64 {
        return Err(InventoryError::InvalidName(
            "device name must be 1-64 bytes".into(),
        ));
    }
    if name.starts_with('-') {
        return Err(InventoryError::InvalidName(
            "device name cannot start with '-'".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(InventoryError::InvalidName(
            "device name may only contain ASCII alphanumeric, '_', '.', or '-'".into(),
        ));
    }
    Ok(())
}

/// Errors raised during inventory loading or reload.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// Device name failed validation.
    #[error("invalid device name: {0}")]
    InvalidName(String),

    /// Duplicate device name detected.
    #[error("duplicate device name: {0}")]
    DuplicateName(String),

    /// Device not found in the inventory.
    #[error("unknown device: {0}")]
    UnknownDevice(String),

    /// JSON parse error.
    #[error("inventory parse failed: {0}")]
    ParseError(String),

    /// File I/O error.
    #[error("inventory file I/O: {0}")]
    IoError(#[from] std::io::Error),

    /// Unsupported schema version (PAN-OS envelope only).
    #[error("unsupported inventory version: {0}")]
    UnsupportedVersion(u32),

    /// Empty inventory (behavior decision is the server's, not the trait's).
    #[error("inventory contains no devices")]
    EmptyInventory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_device_name_accepts_typical_names() {
        for name in ["r1", "core-3", "user.name", "user_name", "lab-fw-01"] {
            assert!(validate_device_name(name).is_ok(), "should accept {name}");
        }
    }

    #[test]
    fn validate_device_name_rejects_bad_forms() {
        for name in ["", " ", "bad name", "-leading", "a/b", &"x".repeat(65)] {
            assert!(
                validate_device_name(name).is_err(),
                "should reject {name:?}"
            );
        }
    }
}
