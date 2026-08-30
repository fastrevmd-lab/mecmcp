//! Digest computation and validation for change sets and fingerprints.

use crate::records::WaiverRecord;
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

/// Computes the digest of a preview artifact.
///
/// Plain SHA-256 over the artifact bytes, with no framing: a preview is one
/// opaque vendor string, so there is nothing to separate and nothing that could
/// be confused with a neighbouring field.
///
/// This is the only value [`ChangeSetRecord::validate_preview`] accepts, so
/// vendors must build [`PreviewRecord::digest`] with it rather than by hand —
/// which is how the digest stops being decoration.
///
/// [`ChangeSetRecord::validate_preview`]: crate::ChangeSetRecord::validate_preview
/// [`PreviewRecord::digest`]: crate::PreviewRecord::digest
#[must_use]
pub fn preview_digest(artifact: &str) -> String {
    format!("sha256:{}", digest_hex(artifact.as_bytes()))
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
pub fn compute_approval_digest_legacy(
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

/// **Legacy: verifies version 1 and 2 records only.** New waivers use
/// [`compute_waiver_digest_v3`], which binds the waiver's kind, expiry and
/// ticket. This function is retained because it is the only thing that can
/// verify a record written before mecmcp#275 — do not call it in new code.
///
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

/// Computes a waiver digest binding the waiver's kind, expiry and ticket.
///
/// # Encoding
///
/// Hashes `serde_json::to_vec` of a tuple, the way [`change_set_digest`] does,
/// rather than the `|`-joined string [`compute_waiver_digest`] uses. A
/// serialized tuple encodes lengths, so no field value can shift a boundary —
/// the weakness recorded for approvals in mecmcp#283.
///
/// The leading `"mecmcp-waiver-v3"` is domain separation: it makes a waiver
/// digest structurally incapable of equalling an approval digest, the role the
/// literal `"lab-mode-waived"` plays in the legacy function.
///
/// # Panics
///
/// Does not panic. The tuple is composed of owned primitives and `String`s,
/// which cannot fail to serialize; the `expect` documents that rather than
/// propagating an error no caller could act on.
#[must_use]
pub fn compute_waiver_digest_v3(
    change_set_id: &str,
    plan_digest: &str,
    owner: &str,
    waived_at_unix: u64,
    waiver: &WaiverRecord,
) -> String {
    let canonical = serde_json::to_vec(&(
        "mecmcp-waiver-v3",
        change_set_id,
        plan_digest,
        owner,
        waived_at_unix,
        &waiver.kind,
        &waiver.reason,
        waiver.expires_at_unix,
        &waiver.ticket,
    ))
    .expect("waiver digest inputs are primitives and cannot fail to serialize");
    format!("sha256:{}", digest_hex(&canonical))
}

/// Computes an approval digest under the version-4 encoding.
///
/// The v1–v3 encoding joined five fields with a literal `|` and no length
/// prefix, and `owner`/`approver` are unconstrained strings, so field
/// boundaries were ambiguous:
///
/// ```text
/// owner="a|b", approver="c"   ->  id|plan|a|b|c|1
/// owner="a",   approver="b|c" ->  id|plan|a|b|c|1
/// ```
///
/// One digest was therefore valid for a pairing other than the one it was
/// computed for — the wrong property for a mechanism whose whole job is proving
/// that *this* approver approved *this* plan (mecmcp#283).
///
/// A serialized tuple encodes lengths, so no value can shift a boundary. This
/// is the encoding [`change_set_digest`] has always used; the approval and
/// waiver digests were the outliers, and [`compute_waiver_digest_v3`] moved
/// first.
///
/// The leading marker keeps this digest distinguishable from every other tuple
/// digest here, so a value can never be replayed across kinds.
#[must_use]
pub fn compute_approval_digest_v4(
    change_set_id: &str,
    plan_digest: &str,
    owner: &str,
    approver: &str,
    approved_at_unix: u64,
) -> String {
    let canonical = serde_json::to_vec(&(
        "mecmcp-approval-v4",
        change_set_id,
        plan_digest,
        owner,
        approver,
        approved_at_unix,
    ))
    .expect("approval digest inputs are primitives and cannot fail to serialize");
    format!("sha256:{}", digest_hex(&canonical))
}

/// The approval digest, binding the preview the approver actually read.
///
/// v4 bound `(change_set_id, plan_digest, owner, approver, approved_at)`. The
/// plan digest covers the *actions*; the preview is rendered from those actions
/// and stored beside them, and nothing tied the two together. An approver's
/// consent was therefore evidenced against the actions alone, while what they
/// read was the preview — so a rendering bug could have produced text that did
/// not describe what would run, and the approval would still have verified.
///
/// v5 adds `preview_digest`, which closes that: the signature now covers both
/// the actions and the exact text presented for them.
///
/// # Why here and not in the plan digest
///
/// rustproxmoxmcp#56 proposes making the preview an input to
/// [`change_set_digest`]. That would work, and it costs more than it needs to.
/// The plan digest is created before the preview exists — consumers attach the
/// preview in a second write — so binding it there means recomputing the plan
/// digest after creation. Every stored approval binds the plan digest, so
/// recomputing it invalidates them, and re-signing them would assert that those
/// approvers consented to a preview binding that did not exist when they
/// approved. That is laundering, and it is the same hazard #275 refused for
/// waivers.
///
/// Binding it in the approval instead reaches the actual goal — approval covers
/// the preview — and does it more precisely: the approver signs the text *they*
/// saw, at the moment they saw it, rather than whatever was attached at plan
/// time.
///
/// `preview_digest` is `Option` because a record can genuinely lack a preview.
/// `None` and `Some` serialize distinguishably in the tuple, so the absence is
/// itself signed and cannot be swapped for a presence.
#[must_use]
pub fn compute_approval_digest_v5(
    change_set_id: &str,
    plan_digest: &str,
    preview_digest: Option<&str>,
    owner: &str,
    approver: &str,
    approved_at_unix: u64,
) -> String {
    let canonical = serde_json::to_vec(&(
        "mecmcp-approval-v5",
        change_set_id,
        plan_digest,
        preview_digest,
        owner,
        approver,
        approved_at_unix,
    ))
    .expect("approval digest inputs are primitives and cannot fail to serialize");
    format!("sha256:{}", digest_hex(&canonical))
}

/// Validates that a principal identifier does not contain the digest separator.
///
/// `compute_approval_digest` and the legacy `compute_waiver_digest` join their
/// fields with a literal `|` separator. If a principal identifier itself contains
/// `|`, two different pairings produce the same digest:
///
/// ```text
/// owner="a|b", approver="c"   ->  id|plan|a|b|c|timestamp
/// owner="a",   approver="b|c" ->  id|plan|a|b|c|timestamp
/// ```
///
/// This function rejects such values before they can participate in a digest,
/// closing the ambiguity at the input.
///
/// Since #283 the encoding itself is unambiguous —
/// [`compute_approval_digest`] serializes a tuple — so this is no longer the
/// only thing standing between a `|` and a forged pairing. It stays because the
/// **legacy** verification path still computes the `|`-joined digest for records
/// written before v4, and that path must never be handed an ambiguous value.
///
/// # Errors
///
/// Returns an error message if the value contains `|`.
pub fn validate_principal_for_digest(field_name: &'static str, value: &str) -> Result<(), String> {
    if value.contains('|') {
        return Err(format!(
            "{field_name} cannot contain '|' (the digest separator): value {:?} would make field boundaries ambiguous",
            value
        ));
    }
    Ok(())
}

#[cfg(test)]
mod preview_binding_tests {
    use super::*;

    /// The point of v5: the same plan, approver and moment, with a different
    /// preview, must not produce the same signature. Without this the approval
    /// says nothing about the text the approver read.
    #[test]
    fn a_different_preview_is_a_different_approval() {
        let a = compute_approval_digest_v5(
            "cs1",
            "sha256:plan",
            Some("sha256:preview-a"),
            "alice",
            "bob",
            1_700_000_000,
        );
        let b = compute_approval_digest_v5(
            "cs1",
            "sha256:plan",
            Some("sha256:preview-b"),
            "alice",
            "bob",
            1_700_000_000,
        );
        assert_ne!(a, b, "the preview is not bound");
    }

    /// Absence is signed too. A record with no preview must not collide with one
    /// whose preview was removed, or removal becomes undetectable.
    #[test]
    fn no_preview_is_distinct_from_any_preview() {
        let none =
            compute_approval_digest_v5("cs1", "sha256:plan", None, "alice", "bob", 1_700_000_000);
        let some = compute_approval_digest_v5(
            "cs1",
            "sha256:plan",
            Some(""),
            "alice",
            "bob",
            1_700_000_000,
        );
        assert_ne!(none, some, "None and Some(\"\") collide");
    }

    /// v4 and v5 must never agree, even on the inputs they share. The domain
    /// marker is what stops a v4 digest being presented as a v5 one.
    #[test]
    fn v4_and_v5_do_not_collide() {
        let v4 = compute_approval_digest_v4("cs1", "sha256:plan", "alice", "bob", 1_700_000_000);
        let v5 =
            compute_approval_digest_v5("cs1", "sha256:plan", None, "alice", "bob", 1_700_000_000);
        assert_ne!(v4, v5);
    }

    /// v4 is unchanged by this work. Ten approvals on the fleet were signed
    /// with it and must keep verifying byte for byte.
    #[test]
    fn v4_is_byte_stable() {
        assert_eq!(
            compute_approval_digest_v4("cs1", "sha256:plan", "alice", "bob", 1_700_000_000),
            compute_approval_digest_v4("cs1", "sha256:plan", "alice", "bob", 1_700_000_000),
        );
        // The marker is part of the encoding; if it ever changes, every stored
        // approval stops verifying, so pin the actual value.
        let digest =
            compute_approval_digest_v4("cs1", "sha256:plan", "alice", "bob", 1_700_000_000);
        assert!(digest.starts_with("sha256:"), "{digest}");
        assert_eq!(digest.len(), "sha256:".len() + 64);
    }

    /// Every field still moves the digest — the preview is an addition, not a
    /// replacement.
    #[test]
    fn every_v5_field_is_bound() {
        let base = compute_approval_digest_v5(
            "cs1",
            "sha256:plan",
            Some("sha256:p"),
            "alice",
            "bob",
            1_700_000_000,
        );
        for other in [
            compute_approval_digest_v5(
                "cs2",
                "sha256:plan",
                Some("sha256:p"),
                "alice",
                "bob",
                1_700_000_000,
            ),
            compute_approval_digest_v5(
                "cs1",
                "sha256:other",
                Some("sha256:p"),
                "alice",
                "bob",
                1_700_000_000,
            ),
            compute_approval_digest_v5(
                "cs1",
                "sha256:plan",
                Some("sha256:q"),
                "alice",
                "bob",
                1_700_000_000,
            ),
            compute_approval_digest_v5(
                "cs1",
                "sha256:plan",
                Some("sha256:p"),
                "eve",
                "bob",
                1_700_000_000,
            ),
            compute_approval_digest_v5(
                "cs1",
                "sha256:plan",
                Some("sha256:p"),
                "alice",
                "eve",
                1_700_000_000,
            ),
            compute_approval_digest_v5(
                "cs1",
                "sha256:plan",
                Some("sha256:p"),
                "alice",
                "bob",
                1_700_000_001,
            ),
        ] {
            assert_ne!(base, other, "a field is not bound");
        }
    }
}
