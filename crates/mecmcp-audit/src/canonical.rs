//! Deterministic JSON serialization and hashing.
//!
//! The hash chain is only meaningful if the same logical event always produces
//! the same bytes. `serde_json` preserves struct field order, but map key order
//! is not guaranteed across versions or platforms, so we canonicalize
//! explicitly: object keys sorted, no incidental whitespace, array order kept.

use sha2::{Digest as Sha256Digest, Sha256};

/// The `prev_hash` of the first record in any chain.
///
/// This constant matches entsafe-audit's genesis value, ensuring cross-system
/// hash-chain compatibility where applicable.
pub const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Maximum nesting depth accepted by [`canonical_json`].
///
/// Evidence records carry arbitrary JSON in metadata fields, so the
/// canonicaliser must not recurse without bound. Real audit payloads nest a
/// handful of levels; 128 is far above anything legitimate and far below what
/// would exhaust the stack.
pub const MAX_CANONICAL_DEPTH: usize = 128;

/// Why a value could not be canonicalised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// The value nested deeper than [`MAX_CANONICAL_DEPTH`].
    #[error("value nests deeper than the {MAX_CANONICAL_DEPTH} level canonicalisation limit")]
    TooDeep,
}

/// Render a JSON value canonically: sorted object keys, compact separators.
pub fn canonical_json(value: &serde_json::Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_canonical(value, &mut out, 0)?;
    Ok(out)
}

fn write_canonical(
    value: &serde_json::Value,
    out: &mut String,
    depth: usize,
) -> Result<(), CanonicalError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Reuse serde_json for correct string escaping.
                out.push_str(&serde_json::Value::String((*key).clone()).to_string());
                out.push(':');
                write_canonical(&map[*key], out, depth + 1)?;
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out, depth + 1)?;
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
    Ok(())
}

/// Hex-encoded SHA-256 of arbitrary bytes, without a prefix.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// SHA-256 over the canonical rendering of a value, as a `sha256:`-prefixed string.
pub fn digest_of(value: &serde_json::Value) -> Result<String, CanonicalError> {
    Ok(format!(
        "sha256:{}",
        sha256_hex(canonical_json(value)?.as_bytes())
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_are_sorted_regardless_of_input_order() {
        let a = json!({"b": 1, "a": 2, "c": {"z": 1, "y": 2}});
        let b = json!({"c": {"y": 2, "z": 1}, "a": 2, "b": 1});
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(
            canonical_json(&a).unwrap(),
            r#"{"a":2,"b":1,"c":{"y":2,"z":1}}"#
        );
    }

    #[test]
    fn array_order_is_preserved() {
        let v = json!({"xs": [3, 1, 2]});
        assert_eq!(canonical_json(&v).unwrap(), r#"{"xs":[3,1,2]}"#);
    }

    #[test]
    fn no_incidental_whitespace() {
        let v = json!({"a": "x y", "b": [1, 2]});
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":"x y","b":[1,2]}"#);
    }

    #[test]
    fn digest_is_stable_and_prefixed() {
        let v = json!({"a": 1});
        let d1 = digest_of(&v).unwrap();
        let d2 = digest_of(&json!({"a": 1})).unwrap();
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
        assert_eq!(d1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn different_content_yields_different_digest() {
        assert_ne!(
            digest_of(&json!({"a": 1})).unwrap(),
            digest_of(&json!({"a": 2})).unwrap()
        );
    }

    #[test]
    fn genesis_prev_hash_is_sixty_four_zeroes() {
        assert_eq!(GENESIS_PREV_HASH, format!("sha256:{}", "0".repeat(64)));
    }

    #[test]
    fn nesting_within_the_limit_is_accepted() {
        let mut value = serde_json::json!(1);
        for _ in 0..(MAX_CANONICAL_DEPTH - 1) {
            value = serde_json::json!({ "n": value });
        }
        assert!(canonical_json(&value).is_ok());
    }

    #[test]
    fn nesting_beyond_the_limit_is_rejected_not_crashed() {
        let mut value = serde_json::json!(1);
        for _ in 0..(MAX_CANONICAL_DEPTH + 10) {
            value = serde_json::json!({ "n": value });
        }
        assert_eq!(canonical_json(&value), Err(CanonicalError::TooDeep));
    }

    #[test]
    fn deep_arrays_are_capped_too() {
        let mut value = serde_json::json!(1);
        for _ in 0..(MAX_CANONICAL_DEPTH + 10) {
            value = serde_json::json!([value]);
        }
        assert_eq!(canonical_json(&value), Err(CanonicalError::TooDeep));
    }

    #[test]
    fn keys_needing_escaping_go_through_serde_json() {
        let value = serde_json::json!({ "a\"b": 1, "c\\d": 2, "e\nf": 3 });
        let out = canonical_json(&value).unwrap();
        assert_eq!(out, r#"{"a\"b":1,"c\\d":2,"e\nf":3}"#);
    }

    #[test]
    fn unicode_keys_sort_and_escape_consistently() {
        let a = serde_json::json!({ "zebra": 1, "\u{00e9}clair": 2, "apple": 3 });
        let b = serde_json::json!({ "apple": 3, "zebra": 1, "\u{00e9}clair": 2 });
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
    }

    #[test]
    fn empty_containers_and_null_render_predictably() {
        let value = serde_json::json!({ "obj": {}, "arr": [], "nil": null });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"arr":[],"nil":null,"obj":{}}"#
        );
    }
}
