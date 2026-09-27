//! Fingerprints computed over unredacted data.
//!
//! Change detection (`mecmcp-changeset`'s fingerprint-bound apply, and any
//! server that diffs a device's config across two polls) has to keep working
//! after redaction is switched on. If the digest were computed on the
//! *redacted* text, two configs that differ only in a secret's value would
//! hash identically once that secret's field is denylisted — a rotated PSK
//! would look like no change at all.
//!
//! [`digest_hex`] uses the same `sha256:<64 lowercase hex>` convention as
//! `mecmcp_changeset::digest`, so an operator correlating fingerprints across
//! crates sees one format. This crate does not depend on `mecmcp-changeset`
//! for it — the convention is a string format, not a shared type, and this is
//! a leaf crate.

use sha2::{Digest as _, Sha256};

/// `sha256:<64 lowercase hex>` over `data`.
#[must_use]
pub fn digest_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in out {
        use std::fmt::Write as _;
        // A `write!` to a `String` is infallible.
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_content_addressed() {
        let a = digest_hex(b"hello");
        let b = digest_hex(b"hello");
        let c = digest_hex(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.strip_prefix("sha256:").unwrap().len(), 64);
    }

    /// The load-bearing property: digesting the unredacted bytes and then
    /// separately redacting them must not change the digest that was already
    /// computed. There is no shared mutable state between the two calls —
    /// this is really a test that the API shape makes the correct order
    /// (digest first, from the original bytes) the only order there is.
    #[test]
    fn digest_of_unredacted_input_is_unaffected_by_later_redaction() {
        let raw = r#"{"password": "FAKEsupersecret123"}"#;
        let digest_before = digest_hex(raw.as_bytes());

        let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
        crate::json::redact(&mut value);
        assert_ne!(
            value["password"], "FAKEsupersecret123",
            "sanity: redaction must actually have changed the value"
        );

        // Re-hashing the *original* bytes — the only input the digest API
        // ever sees — reproduces the same digest no matter what redaction
        // subsequently did to a derived copy.
        let digest_after = digest_hex(raw.as_bytes());
        assert_eq!(digest_before, digest_after);
    }
}
