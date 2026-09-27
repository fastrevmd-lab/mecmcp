//! Recursive denylist-and-shape redaction over a parsed [`serde_json::Value`].
//!
//! Structure is preserved — this walks every object and array, so a secret
//! nested ten levels deep under an array of objects is redacted in place
//! rather than requiring a caller to know the shape in advance. That is the
//! point of the denylist approach versus [`crate::projection`]: it costs
//! nothing to add a new nested shape, at the cost of never being a positive
//! guarantee the way an allowlist projection is.

use crate::denylist::is_denylisted_key;
use crate::shape::{looks_like_embedded_blob, looks_like_secret_value};
use serde_json::Value;

const PLACEHOLDER: &str = "[REDACTED]";

/// Redact `value` in place.
pub fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if is_denylisted_key(key) {
                    *v = redact_leaf(v);
                } else {
                    redact(v);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact(item);
            }
        }
        Value::String(s) => {
            if looks_like_secret_value(s) {
                *s = PLACEHOLDER.to_string();
            } else if looks_like_embedded_blob(s) {
                *s = crate::text::redact(s);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// A denylisted key's value: strings and numbers become the placeholder
/// string outright (a denylisted key is redacted regardless of shape).
/// Objects and arrays are walked recursively rather than nuked wholesale, so
/// a denylisted container key (unlikely, but not impossible for a vendor to
/// name e.g. `secrets: { ... }`) still preserves the structure — but every
/// scalar leaf inside that subtree is force-redacted regardless of its own
/// key or shape: once a caller has said "this container is secret", a value
/// two levels down (`secrets.wifi`, `pre_shared_keys[0]`) must not survive
/// just because its own immediate key or shape is not independently
/// suspicious.
fn redact_leaf(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_leaf(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_leaf).collect()),
        Value::Null => Value::Null,
        _ => Value::String(PLACEHOLDER.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn top_level_denylisted_key_is_redacted() {
        let mut v = json!({"password": "FAKEsecret123", "hostname": "r1.example.net"});
        redact(&mut v);
        assert_eq!(v["password"], "[REDACTED]");
        assert_eq!(v["hostname"], "r1.example.net");
    }

    #[test]
    fn nested_denylisted_key_under_array_of_objects_is_redacted() {
        let mut v = json!({
            "peers": [
                {"name": "peer1", "pre_shared_key": "FAKEpsk1"},
                {"name": "peer2", "pre_shared_key": "FAKEpsk2"}
            ]
        });
        redact(&mut v);
        assert_eq!(v["peers"][0]["pre_shared_key"], "[REDACTED]");
        assert_eq!(v["peers"][1]["pre_shared_key"], "[REDACTED]");
        assert_eq!(v["peers"][0]["name"], "peer1");
    }

    #[test]
    fn value_shape_catch_all_applies_to_unknown_keys() {
        let mut v = json!({"totally_new_vendor_field": "$6$fakesaltfakehash"});
        redact(&mut v);
        assert_eq!(v["totally_new_vendor_field"], "[REDACTED]");
    }

    #[test]
    fn numbers_and_booleans_under_denylisted_keys_become_placeholder_strings() {
        let mut v = json!({"api_key": 12345, "enabled": true});
        redact(&mut v);
        assert_eq!(v["api_key"], "[REDACTED]");
        // `enabled` is not denylisted and not a secret-shaped string, so a
        // non-string, non-denylisted value is left completely alone.
        assert_eq!(v["enabled"], true);
    }

    #[test]
    fn null_under_denylisted_key_stays_null() {
        let mut v = json!({"password": null});
        redact(&mut v);
        assert_eq!(v["password"], Value::Null);
    }

    #[test]
    fn f3_array_under_denylisted_key_has_every_element_redacted() {
        let mut v = json!({"pre_shared_keys": ["QQ1", "QQ2"]});
        redact(&mut v);
        assert_eq!(v["pre_shared_keys"][0], "[REDACTED]");
        assert_eq!(v["pre_shared_keys"][1], "[REDACTED]");
    }

    #[test]
    fn f3_nested_object_under_denylisted_key_has_every_leaf_redacted() {
        let mut v = json!({"secrets": {"wifi": "QQ3", "count": 2}});
        redact(&mut v);
        assert_eq!(v["secrets"]["wifi"], "[REDACTED]");
        // A non-string leaf still becomes a placeholder string, matching the
        // existing top-level `numbers_and_booleans_...` contract.
        assert_eq!(v["secrets"]["count"], "[REDACTED]");
    }

    #[test]
    fn f3_combined_repro_from_review_leaks_nothing() {
        let mut v = json!({
            "pre_shared_keys": ["QQ1", "QQ2"],
            "secrets": {"wifi": "QQ3"}
        });
        redact(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("QQ1") && !s.contains("QQ2") && !s.contains("QQ3"),
            "got: {s}"
        );
    }

    #[test]
    fn f4b_embedded_blob_in_an_unlisted_string_field_is_scrubbed() {
        let mut v = json!({
            "output": "set interfaces ge-0/0/0 unit 0\nset security ike policy p1 pre-shared-key ascii-text \"$9$fakehashvalue\"; ## SECRET-DATA\n"
        });
        redact(&mut v);
        let s = v["output"].as_str().expect("output is a string");
        assert!(!s.contains("fakehashvalue"), "got: {s}");
        assert!(
            s.contains("set interfaces ge-0/0/0 unit 0"),
            "unrelated config lines must survive: {s}"
        );
    }

    #[test]
    fn unrelated_structure_is_untouched() {
        let mut v = json!({"hostname": "r1.example.net", "vlan": 100, "up": true});
        let original = v.clone();
        redact(&mut v);
        assert_eq!(v, original);
    }
}
