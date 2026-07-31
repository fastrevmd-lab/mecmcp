//! Digest computation and validation for change sets and fingerprints.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Error type for digest operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestError {
    field: &'static str,
    message: &'static str,
}

impl DigestError {
    fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }
}

impl std::fmt::Display for DigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for DigestError {}

/// Computes a change-set digest from its inputs.
///
/// The digest binds `(owner, device, fingerprint, ordered-actions)` as a single tuple.
/// Changing any component changes the digest.
///
/// # Errors
///
/// Returns an error if the inputs cannot be serialized.
pub fn change_set_digest<A: Serialize>(
    owner: &str,
    device: &str,
    fingerprint: &str,
    actions: &[A],
) -> Result<String, DigestError> {
    let canonical = serde_json::to_vec(&(owner, device, fingerprint, actions))
        .map_err(|_| DigestError::new("actions", "could not encode change-set digest"))?;
    Ok(format!("sha256:{}", digest_hex(&canonical)))
}

/// Computes a change-set digest that also binds a multi-target set.
///
/// A change set whose target list can be edited without invalidating the digest
/// is not digest-bound, so the targets have to be inside it.
///
/// **An empty `targets` produces the byte-identical digest
/// [`change_set_digest`] does**, by serialising the original four-tuple
/// unchanged rather than a five-tuple with an empty list. That is not a
/// micro-optimisation: LXC 608 holds ten change sets whose stored digests were
/// computed by the old function, and any change to the single-target encoding
/// invalidates all of them on the next approval.
///
/// # Errors
///
/// Returns an error if the inputs cannot be serialized.
pub fn change_set_digest_with_targets<A: Serialize>(
    owner: &str,
    device: &str,
    fingerprint: &str,
    actions: &[A],
    targets: &[String],
) -> Result<String, DigestError> {
    if targets.is_empty() {
        return change_set_digest(owner, device, fingerprint, actions);
    }
    let canonical = serde_json::to_vec(&(owner, device, fingerprint, actions, targets))
        .map_err(|_| DigestError::new("actions", "could not encode change-set digest"))?;
    Ok(format!("sha256:{}", digest_hex(&canonical)))
}

/// Validates a digest value.
///
/// The format must be `sha256:<64 lowercase hex>`.
///
/// # Errors
///
/// Returns an error if the value does not match the required format.
pub fn validate_digest(value: &str, field: &'static str) -> Result<(), DigestError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(DigestError::new(
            field,
            "value must use sha256:<64 lowercase hex> format",
        ));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(DigestError::new(
            field,
            "value must use sha256:<64 lowercase hex> format",
        ))
    }
}

/// Validates a fingerprint value.
///
/// The format must be `sha256:<64 lowercase hex>`.
///
/// # Errors
///
/// Returns an error if the value does not match the required format.
pub fn validate_fingerprint(value: &str) -> Result<(), DigestError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(DigestError::new(
            "expected_candidate_fingerprint",
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
        Err(DigestError::new(
            "expected_candidate_fingerprint",
            "value must use the sha256:<64 lowercase hex> format",
        ))
    }
}

/// Converts a byte slice to lowercase hexadecimal.
#[must_use]
pub fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Computes a SHA-256 digest of the input and returns it as lowercase hex.
#[must_use]
pub fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    bytes_hex(&digest)
}

/// Computes an approval digest binding the approval act to the plan.
///
/// The approval digest covers `(change_set_id, plan_digest, owner, approver, approved_at)`.
/// This makes the approval itself tamper-evident: anyone editing the state file to swap
/// the approver or mask a self-approval will invalidate the digest.
#[must_use]
pub fn compute_approval_digest(
    change_set_id: &str,
    plan_digest: &str,
    owner: &str,
    approver: &str,
    approved_at_unix: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(change_set_id.as_bytes());
    hasher.update(b"|");
    hasher.update(plan_digest.as_bytes());
    hasher.update(b"|");
    hasher.update(owner.as_bytes());
    hasher.update(b"|");
    hasher.update(approver.as_bytes());
    hasher.update(b"|");
    hasher.update(approved_at_unix.to_string().as_bytes());

    format!("sha256:{}", bytes_hex(&hasher.finalize()))
}

/// Computes a waiver digest for lab-mode approvals without a second principal.
///
/// The waiver digest covers `(change_set_id, plan_digest, owner, approved_at, "lab-mode-waived")`.
/// The literal marker makes the digest fundamentally different from a genuine approval digest,
/// preventing any confusion or masking of self-approval attempts.
#[must_use]
pub fn compute_waiver_digest(
    change_set_id: &str,
    plan_digest: &str,
    owner: &str,
    waived_at_unix: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(change_set_id.as_bytes());
    hasher.update(b"|");
    hasher.update(plan_digest.as_bytes());
    hasher.update(b"|");
    hasher.update(owner.as_bytes());
    hasher.update(b"|");
    hasher.update(waived_at_unix.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(b"lab-mode-waived");

    format!("sha256:{}", bytes_hex(&hasher.finalize()))
}
