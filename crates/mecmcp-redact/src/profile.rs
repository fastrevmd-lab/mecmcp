//! Vendor-declared extensions to the denylist-and-shape JSON scan.
//!
//! `crate::json::redact` already covers the secret shapes common to every
//! vendor. Two kinds of policy are not generic, and the shared crate cannot
//! infer either from a vendor's schema on its own — it has no dependency on
//! any vendor's schema, the same reason [`crate::projection::FieldAllowlist`]
//! takes its field list from the caller:
//!
//! - **Wholesale fields**: a field whose value is a vendor-specific rendered
//!   body (device config, generated IPsec config) that can embed a secret in
//!   a shape the generic line/key scan is not guaranteed to recognize. The
//!   whole value is withheld as a unit rather than trusted to a best-effort
//!   scan.
//! - **Key exemptions**: a field name that collides with a denylist entry by
//!   substring in this vendor's schema, but is not a secret (an opaque paging
//!   cursor, a logging flag). Redacting it is a functional regression (MEC-440
//!   B1: redacting `continuation_token` breaks paging) or a security
//!   regression in the *other* direction (MEC-973 F1: hiding a policy rule's
//!   real logging state from the model reviewing a write).
//!
//! A vendor server declares a [`Profile`] once, as a `const`, the same way
//! [`crate::projection::FieldAllowlist`] is declared, and calls
//! [`crate::redact_json_value_with_profile`] instead of
//! [`crate::redact_json_value`]. Everything [`crate::redact_json_value`]
//! already catches is still caught — a `Profile` only adds exceptions and
//! extra withholding, it never narrows the generic scan.
//!
//! # Why exemption needs a guard/unguard round trip, not a skip list
//!
//! An exempted field cannot simply be skipped during the generic scan: the
//! scan walks the whole tree by key name, so "skip this key" has to mean
//! "hide this key's name from the scan for exactly one pass," not "delete
//! it." The guard step renames each exempted key to an opaque,
//! counter-suffixed placeholder that cannot itself collide with a denylist
//! term (a prefix that embedded the original name would still carry whatever
//! substring made it match in the first place — `continuation_token`
//! normalizes to a string that still contains `token`), runs the generic
//! scan, then restores the original names from the recorded order. This is
//! exactly the technique rustsdcmcp's pre-migration `redact.rs` used
//! locally; it is generalized here only to the extent of taking its field
//! lists from the caller.

use serde_json::Value;

use crate::denylist::normalize;
use crate::json::PLACEHOLDER;

/// A vendor's extensions to the generic denylist-and-shape scan: fields
/// withheld as a whole, and field names exempted from the denylist despite a
/// substring collision.
///
/// Construct with [`Profile::new`] as a `const`, so a server declares its
/// vendor-specific exceptions once, at compile time, rather than building the
/// lists per call.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    wholesale_redact_keys: &'static [&'static str],
    key_exemptions: &'static [&'static str],
}

impl Profile {
    /// Build a profile from fixed field-name lists. Each entry is matched
    /// against a JSON key after normalizing (lowercased, separators
    /// stripped) — `"site_config"`, `"siteConfig"`, and `"site-config"` are
    /// one entry, not three.
    #[must_use]
    pub const fn new(
        wholesale_redact_keys: &'static [&'static str],
        key_exemptions: &'static [&'static str],
    ) -> Self {
        Self {
            wholesale_redact_keys,
            key_exemptions,
        }
    }
}

/// Prefix used to hide an exempt key from the generic scan for the duration
/// of that pass. A null byte either side keeps this outside the range of any
/// normal JSON key a vendor API would plausibly send, so it cannot collide
/// with a real field even by accident.
const GUARD_PREFIX: &str = "\u{0}mecmcp-redact-profile-guard\u{0}";

/// Redact `value` in place under the generic denylist-and-shape scan, then
/// apply `profile`'s vendor-specific extensions.
///
/// Order matters and is fixed, not a caller choice: wholesale fields are
/// withheld *before* the generic scan ever sees them (so the scan cannot
/// partially rewrite a body this profile says should be withheld as a unit),
/// and key exemptions are guarded out *before* the generic scan and restored
/// *after* (so an exempted field's value is never scanned or rewritten at
/// all, by either pass).
pub fn redact_json_value_with_profile(value: &mut Value, profile: &Profile) {
    redact_wholesale_fields(value, profile.wholesale_redact_keys);
    let guarded = guard_exempt_keys(value, profile.key_exemptions);
    crate::json::redact(value);
    unguard_exempt_keys(value, &guarded);
}

/// Replace every value under a [`Profile::wholesale_redact_keys`] key with
/// the redaction placeholder, at any depth, before the generic scan runs.
/// `null` stays `null`: it carries no secret, and rewriting it would claim
/// one existed.
fn redact_wholesale_fields(value: &mut Value, wholesale_redact_keys: &[&str]) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if wholesale_redact_keys.contains(&normalize(key).as_str()) {
                    if !child.is_null() {
                        *child = Value::String(PLACEHOLDER.to_owned());
                    }
                } else {
                    redact_wholesale_fields(child, wholesale_redact_keys);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_wholesale_fields(item, wholesale_redact_keys)),
        _ => {}
    }
}

/// Rename every [`Profile::key_exemptions`] key to an opaque,
/// counter-suffixed placeholder so the generic scan's substring denylist
/// match never sees the name it would otherwise match, and record the
/// original names in assignment order so [`unguard_exempt_keys`] can restore
/// them exactly.
#[must_use]
fn guard_exempt_keys(value: &mut Value, key_exemptions: &[&str]) -> Vec<String> {
    let mut originals = Vec::new();
    guard_inner(value, key_exemptions, &mut originals);
    originals
}

fn guard_inner(value: &mut Value, key_exemptions: &[&str], originals: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if key_exemptions.contains(&normalize(&key).as_str())
                    && let Some(v) = map.remove(&key)
                {
                    let marker = format!("{GUARD_PREFIX}{}", originals.len());
                    originals.push(key);
                    map.insert(marker, v);
                }
            }
            for child in map.values_mut() {
                guard_inner(child, key_exemptions, originals);
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| guard_inner(item, key_exemptions, originals)),
        _ => {}
    }
}

/// Reverse [`guard_exempt_keys`], restoring the original key names from
/// `originals` by the counter each placeholder carries.
fn unguard_exempt_keys(value: &mut Value, originals: &[String]) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let Some(index) = key
                    .strip_prefix(GUARD_PREFIX)
                    .and_then(|suffix| suffix.parse::<usize>().ok())
                else {
                    continue;
                };
                let Some(original) = originals.get(index) else {
                    continue;
                };
                if let Some(v) = map.remove(&key) {
                    map.insert(original.clone(), v);
                }
            }
            for child in map.values_mut() {
                unguard_exempt_keys(child, originals);
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| unguard_exempt_keys(item, originals)),
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_PROFILE: Profile = Profile::new(
        &["siteconfig", "cpeconfig"],
        &["continuationtoken", "nextpagetoken", "maxsessions"],
    );

    #[test]
    fn wholesale_key_is_withheld_as_a_unit_regardless_of_case_or_separator() {
        for key in ["site_config", "siteConfig", "site-config"] {
            let mut v = json!({ key: {"body": "set security ike ... pre-shared-key leak"} });
            redact_json_value_with_profile(&mut v, &TEST_PROFILE);
            assert_eq!(v[key], PLACEHOLDER, "{key} must be withheld wholesale");
        }
    }

    #[test]
    fn wholesale_key_null_value_stays_null() {
        let mut v = json!({"site_config": null});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert!(v["site_config"].is_null());
    }

    #[test]
    fn exempted_key_survives_despite_denylist_substring_collision() {
        let mut v = json!({"continuation_token": "page-cursor-abc", "accessToken": "QQsecret"});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["continuation_token"], "page-cursor-abc");
        assert_eq!(v["accessToken"], PLACEHOLDER);
    }

    #[test]
    fn unexempted_key_with_the_same_denylist_substring_is_still_redacted() {
        // Only the exact exempted names survive; an unlisted `session*`
        // field must still be caught by the generic scan — an exemption
        // list is not a way to carve out a whole denylist term.
        let mut v = json!({"session_id": "s1", "max_session_number": 5});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["session_id"], PLACEHOLDER);
        assert_eq!(v["max_session_number"], PLACEHOLDER);
    }

    #[test]
    fn exempted_key_matching_full_name_survives_while_sibling_is_redacted() {
        let mut v = json!({"max_sessions": 5, "session_id": "s1"});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["max_sessions"], 5);
        assert_eq!(v["session_id"], PLACEHOLDER);
    }

    #[test]
    fn exemption_and_wholesale_withholding_both_apply_in_one_pass() {
        let mut v = json!({
            "nextPageToken": "abc",
            "cpe_config": {"body": "pre-shared-key leak"},
            "password": "hunter2",
        });
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["nextPageToken"], "abc");
        assert_eq!(v["cpe_config"], PLACEHOLDER);
        assert_eq!(v["password"], PLACEHOLDER);
    }

    #[test]
    fn nested_exempted_and_wholesale_keys_are_handled_at_any_depth() {
        let mut v = json!({"site": {"cpe_devices": [{
            "cpe_config": {"body": "..."},
            "continuation_token": "cursor",
            "psk": "shared"
        }]}});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        let device = &v["site"]["cpe_devices"][0];
        assert_eq!(device["cpe_config"], PLACEHOLDER);
        assert_eq!(device["continuation_token"], "cursor");
        assert_eq!(device["psk"], PLACEHOLDER);
    }

    #[test]
    fn an_empty_profile_behaves_exactly_like_the_generic_scan() {
        const EMPTY: Profile = Profile::new(&[], &[]);
        let mut a = json!({"password": "hunter2", "name": "a"});
        let mut b = a.clone();
        redact_json_value_with_profile(&mut a, &EMPTY);
        crate::redact_json_value(&mut b);
        assert_eq!(a, b);
    }

    /// Guard markers must never leak into output even when a value happens
    /// to collide with the guard scheme in some other way (defence in depth
    /// for the round trip itself, not just the common case).
    #[test]
    fn guard_markers_never_survive_in_output() {
        let mut v = json!({
            "continuation_token": "a",
            "continuation_token2": "b",
            "nextPageToken": "c",
        });
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        let serialized = serde_json::to_string(&v).unwrap();
        assert!(!serialized.contains("mecmcp-redact-profile-guard"));
    }
}
