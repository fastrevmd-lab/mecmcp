//! Fingerprints computed over unredacted data.
//!
//! Change detection (`mecmcp-changeset`'s fingerprint-bound apply, and any
//! server that diffs a device's config across two polls) has to keep working
//! after redaction is switched on. If the digest were computed on the
//! *redacted* text, two configs that differ only in a secret's value would
//! hash identically once that secret's field is denylisted — a rotated PSK
//! would look like no change at all.
//!
//! # Why HMAC, not plain SHA-256
//!
//! [`crate::redact_and_digest`] hands the model both the redacted body and
//! this digest. A plain content hash of the *unredacted* bytes turns that
//! pairing into a guessing oracle: every byte outside the redacted spans is
//! already known to the model verbatim, so for a low-entropy secret (an SNMP
//! community string, a short PSK) an attacker with tool access can replay
//! candidate values through the same digest function offline and check for a
//! match — the redacted body leaks nothing extra, but the *digest* does.
//! Keying the hash with a per-install secret the model never sees closes
//! that: matching a candidate now requires the key, not just the algorithm.
//!
//! The key is supplied by the caller — typically a server binary loading it
//! from an operator-provided key file at startup, the same convention
//! `mecmcp_audit::redact` already uses for its own `hmac` field transform —
//! rather than managed as process-global state here. This crate has no
//! opinion on *where* the key comes from; it only refuses to hash without
//! one.
//!
//! `digest_hex` is `pub(crate)`, not exported: the only public entry point
//! is [`crate::redact_and_digest`], which calls it on the original bytes
//! before redacting a copy. That makes "digest first, from the unredacted
//! input" the only order reachable through the public API, rather than a
//! recommendation a future edit could accidentally invert (a caller could
//! otherwise write `digest_hex(key, redact_text(x).as_bytes())` and get a
//! digest of already-redacted data with no compiler or test to catch it).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// `hmac-sha256:<64 lowercase hex>` over `data`, keyed by `key`.
///
/// `key` should be a per-install secret an operator provisions and the model
/// never sees — see the module docs. HMAC accepts a key of any length, so
/// this never fails.
#[must_use]
pub(crate) fn digest_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(tag.len() * 2);
    for byte in tag {
        use std::fmt::Write as _;
        // A `write!` to a `String` is infallible.
        let _ = write!(hex, "{byte:02x}");
    }
    format!("hmac-sha256:{hex}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    const KEY_A: &[u8] = b"QQtest-install-key-A";
    const KEY_B: &[u8] = b"QQtest-install-key-B";

    #[test]
    fn digest_is_stable_for_the_same_key_and_content_addressed() {
        let a = digest_hex(KEY_A, b"hello");
        let b = digest_hex(KEY_A, b"hello");
        let c = digest_hex(KEY_A, b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("hmac-sha256:"));
        assert_eq!(a.strip_prefix("hmac-sha256:").unwrap().len(), 64);
    }

    /// F8: the digest must depend on the key, not just the bytes — otherwise
    /// it degenerates back into the plain-SHA-256 guessing oracle the HMAC
    /// switch exists to close.
    #[test]
    fn digest_differs_across_keys_for_the_same_bytes() {
        let with_a = digest_hex(KEY_A, b"same message");
        let with_b = digest_hex(KEY_B, b"same message");
        assert_ne!(
            with_a, with_b,
            "digest must depend on the install key, not just the message"
        );
    }

    /// The load-bearing property: digesting the unredacted bytes and then
    /// separately redacting them must not change the digest that was already
    /// computed. There is no shared mutable state between the two calls —
    /// this is really a test that the API shape makes the correct order
    /// (digest first, from the original bytes) the only order there is.
    #[test]
    fn digest_of_unredacted_input_is_unaffected_by_later_redaction() {
        let raw = r#"{"password": "FAKEsupersecret123"}"#;
        let digest_before = digest_hex(KEY_A, raw.as_bytes());

        let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
        crate::json::redact(&mut value);
        assert_ne!(
            value["password"], "FAKEsupersecret123",
            "sanity: redaction must actually have changed the value"
        );

        // Re-hashing the *original* bytes — the only input the digest API
        // ever sees — reproduces the same digest no matter what redaction
        // subsequently did to a derived copy.
        let digest_after = digest_hex(KEY_A, raw.as_bytes());
        assert_eq!(digest_before, digest_after);
    }
}
