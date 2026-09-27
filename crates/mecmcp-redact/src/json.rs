//! Recursive denylist-and-shape redaction over a parsed [`serde_json::Value`].
//!
//! Structure is preserved — this walks every object and array, so a secret
//! nested ten levels deep under an array of objects is redacted in place
//! rather than requiring a caller to know the shape in advance. That is the
//! point of the denylist approach versus [`crate::projection`]: it costs
//! nothing to add a new nested shape, at the cost of never being a positive
//! guarantee the way an allowlist projection is.

use crate::denylist::is_denylisted_key;
use crate::shape::looks_like_secret_value;
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
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// A denylisted key's value: strings and numbers become the placeholder
/// string outright (a denylisted key is redacted regardless of shape).
/// Objects and arrays are walked recursively rather than nuked wholesale, so
/// a denylisted container key (unlikely, but not impossible for a vendor to
/// name e.g. `secrets: { ... }`) still preserves any non-secret siblings
/// inside it instead of destroying structure a caller might depend on.
fn redact_leaf(v: &Value) -> Value {
    match v {
        Value::Object(_) | Value::Array(_) => {
            let mut cloned = v.clone();
            redact(&mut cloned);
            cloned
        }
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
    fn unrelated_structure_is_untouched() {
        let mut v = json!({"hostname": "r1.example.net", "vlan": 100, "up": true});
        let original = v.clone();
        redact(&mut v);
        assert_eq!(v, original);
    }
}
