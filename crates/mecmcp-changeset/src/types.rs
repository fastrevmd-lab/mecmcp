//! Input/output types and operation limits.

use serde::{Deserialize, Serialize};

/// Operational capacity limits for change-set and operation storage.
#[derive(Debug, Clone, Copy)]
pub struct OperationLimits {
    /// Maximum number of operations that may be stored concurrently.
    pub max_operations: usize,
    /// Maximum number of change sets that may be stored concurrently.
    pub max_change_sets: usize,
    /// Maximum number of actions in a single change set.
    pub max_actions_per_set: usize,
    /// Maximum serialized size of a single change set in bytes.
    pub max_change_set_bytes: u64,
    /// Maximum serialized size of the state file in bytes.
    pub max_state_bytes: u64,
    /// Maximum number of targets in a single change set.
    pub max_targets_per_set: usize,
    /// Maximum size of a stored preview artifact, in bytes.
    ///
    /// `max_change_set_bytes` bounds the record as a whole, but a preview is the
    /// part a vendor API controls the size of, so it gets its own ceiling.
    pub max_preview_bytes: usize,
}

impl Default for OperationLimits {
    fn default() -> Self {
        Self {
            max_operations: 1024,
            max_change_sets: 1024,
            max_actions_per_set: 64,
            max_change_set_bytes: 256 * 1024, // 256KB per change set
            max_state_bytes: 8 * 1024 * 1024, // 8MB total state file
            max_targets_per_set: 64,
            max_preview_bytes: 64 * 1024,
        }
    }
}

/// Validated candidate configuration fingerprint.
///
/// The format is `sha256:<64 lowercase hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Validates and constructs a fingerprint from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the value does not match the `sha256:<64 lowercase hex>` format.
    pub fn new(value: String) -> Result<Self, FingerprintError> {
        validate_fingerprint(&value)?;
        Ok(Self(value))
    }

    /// Returns the fingerprint as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Fingerprint {
    type Error = FingerprintError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Fingerprint> for String {
    fn from(value: Fingerprint) -> Self {
        value.0
    }
}

impl AsRef<str> for Fingerprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error type for fingerprint validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintError {
    message: &'static str,
}

impl FingerprintError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FingerprintError {}

fn validate_fingerprint(value: &str) -> Result<(), FingerprintError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(FingerprintError::new(
            "value must use the sha256:<64 lowercase hex> format",
        ));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(FingerprintError::new(
            "value must use the sha256:<64 lowercase hex> format",
        ))
    }
}

/// Validated operation identifier.
///
/// The format is exactly 64 lowercase hexadecimal characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    /// Validates and constructs an operation identifier from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the value does not contain exactly 64 hexadecimal characters.
    pub fn new(value: String) -> Result<Self, OperationIdError> {
        validate_operation_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the operation identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = OperationIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

impl AsRef<str> for OperationId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error type for operation identifier validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationIdError {
    message: &'static str,
}

impl OperationIdError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for OperationIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OperationIdError {}

fn validate_operation_id(value: &str) -> Result<(), OperationIdError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(OperationIdError::new(
            "value must contain exactly 64 hexadecimal characters",
        ))
    }
}
