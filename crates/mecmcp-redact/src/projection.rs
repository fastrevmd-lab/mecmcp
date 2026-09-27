//! Allowlist-shaped redaction for structured data.
//!
//! The denylist in `crate::json` and `crate::text` answers "does this
//! look like one of the secret shapes we know about" — a negative test that,
//! by construction, cannot cover a field it has never seen. For the handful
//! of resource shapes a server controls completely — UniFi's `list`/
//! `get_resource` results, SDC's certificate inventory — a positive test is
//! available instead: declare the fields the model is allowed to see, and
//! nothing else survives, known or not.
//!
//! [`FieldAllowlist`] is the shared building block; the actual field lists
//! for UniFi and SDC resources are declared by those servers, not here — this
//! crate has no dependency on either vendor's schema.

use serde_json::{Map, Value};

/// A fixed set of top-level field names a projection may keep.
///
/// Construct with [`FieldAllowlist::new`] as a `const`, so a server declares
/// its resource shapes once, at compile time, rather than building a list
/// per call.
#[derive(Debug, Clone, Copy)]
pub struct FieldAllowlist {
    fields: &'static [&'static str],
}

impl FieldAllowlist {
    /// Build an allowlist from a fixed field-name list.
    #[must_use]
    pub const fn new(fields: &'static [&'static str]) -> Self {
        Self { fields }
    }

    /// Project a single JSON object down to only the allowlisted top-level
    /// fields. Any other shape (array, string, number, ...) is dropped
    /// entirely and returned as [`Value::Null`] — a projection only knows how
    /// to keep fields of an object, and returning the input unfiltered on a
    /// shape mismatch would defeat the point of an allowlist.
    ///
    /// An allowlisted field is meant to name a scalar (`id`, `name`, `ip`).
    /// If a caller allowlists a field that happens to be a container (object
    /// or array), that whole container is kept verbatim by field-name alone —
    /// so as defence in depth, `crate::json::redact` still runs over the
    /// projected result: a secret nested inside a wholesale-kept container
    /// field is caught by the denylist-and-shape scan even though the
    /// allowlist itself does not look inside it.
    #[must_use]
    pub fn project(&self, value: &Value) -> Value {
        let Value::Object(map) = value else {
            return Value::Null;
        };
        let mut kept = Map::new();
        for field in self.fields {
            if let Some(v) = map.get(*field) {
                kept.insert((*field).to_string(), v.clone());
            }
        }
        let mut projected = Value::Object(kept);
        crate::json::redact(&mut projected);
        projected
    }

    /// Project a JSON array of objects element-wise, e.g. a `list` result.
    /// A non-array input projects as a single element, matching
    /// [`FieldAllowlist::project`].
    #[must_use]
    pub fn project_many(&self, value: &Value) -> Value {
        match value {
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.project(item)).collect())
            }
            other => self.project(other),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;
    use serde_json::json;

    const CLIENT_FIELDS: FieldAllowlist = FieldAllowlist::new(&["id", "name", "ip"]);

    #[test]
    fn project_keeps_only_allowlisted_fields() {
        let resource = json!({
            "id": "abc123",
            "name": "laptop-1",
            "ip": "192.0.2.10",
            "x_passphrase": "FAKEwifikey",
            "encrypted_password_hash": "$9$fakehash",
        });
        let projected = CLIENT_FIELDS.project(&resource);
        assert_eq!(projected["id"], "abc123");
        assert_eq!(projected["name"], "laptop-1");
        assert_eq!(projected["ip"], "192.0.2.10");
        assert!(projected.get("x_passphrase").is_none());
        assert!(projected.get("encrypted_password_hash").is_none());
    }

    #[test]
    fn project_missing_field_is_simply_absent() {
        let resource = json!({"id": "abc123"});
        let projected = CLIENT_FIELDS.project(&resource);
        assert_eq!(projected["id"], "abc123");
        assert!(projected.get("name").is_none());
    }

    #[test]
    fn project_many_maps_a_list_result_element_wise() {
        let list = json!([
            {"id": "1", "name": "a", "secret": "FAKEsecret1"},
            {"id": "2", "name": "b", "secret": "FAKEsecret2"},
        ]);
        let projected = CLIENT_FIELDS.project_many(&list);
        let arr = projected.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(|item| item.get("secret").is_none()));
    }

    #[test]
    fn f10_allowlisted_container_field_still_has_nested_secrets_redacted() {
        const CONFIG_FIELDS: FieldAllowlist = FieldAllowlist::new(&["id", "config"]);
        let resource = json!({
            "id": "abc123",
            "config": {"wlan": {"password": "QQwifisecret1"}},
        });
        let projected = CONFIG_FIELDS.project(&resource);
        let s = projected.to_string();
        assert!(!s.contains("QQwifisecret1"), "got: {s}");
        assert_eq!(projected["id"], "abc123");
    }

    #[test]
    fn non_object_input_projects_to_null() {
        assert_eq!(CLIENT_FIELDS.project(&json!("not an object")), Value::Null);
        assert_eq!(CLIENT_FIELDS.project(&json!(42)), Value::Null);
    }
}
