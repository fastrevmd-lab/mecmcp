//! The element/key denylist for unstructured redaction.
//!
//! Matching is substring-on-normalized-key, not exact-match, on purpose: vendor
//! field names vary in case and separator (`pre-shared-key`, `pre_shared_key`,
//! `preSharedKey`) and are sometimes compounded (`wifiPassword`,
//! `adminApiKey`). A denylist that only matched the literal spelling would miss
//! every variant a vendor happens to use. The cost is the occasional field that
//! merely *contains* a denylisted word — an over-redaction, which is the safe
//! direction to be wrong in. See the crate README for what this still misses.

/// Canonical secret-bearing field names. Each is normalized (lowercased,
/// separators stripped) before comparison, so this list only needs one form
/// of each word.
pub const DENYLISTED_KEYS: &[&str] = &[
    "secret",
    "privatekey",
    "presharedkey",
    "psk",
    "passphrase",
    "xpassphrase",
    "xsecret",
    "phash",
    "community",
    "apikey",
    "token",
    "authenticationkey",
    "password",
    "sharedkey",
    "sharedsecret",
    "credential",
    "bindpw",
    "encryptionkey",
    "privkey",
    "authorization",
    "bearer",
    "cookie",
    "passwd",
    "pwd",
    "session",
    "keystring",
    "messagedigestkey",
    "authkey",
    "keywrap",
    "partnerkey",
    "accountkey",
    "clientkey",
];

/// Field names that must match the *whole* normalized key, not a substring.
///
/// `"key"` is deliberately not in [`DENYLISTED_KEYS`]: as a substring it would
/// match half of every config (`keys`, `keyword`, `keychain`, an interface
/// named `key0`, ...). But the bare field name `key` alone is exactly the
/// PAN-OS keygen response shape (`<result><key>` is the API key itself), so it
/// still needs to be denylisted — just under exact match instead.
const DENYLISTED_EXACT_KEYS: &[&str] = &["key"];

/// Whether `key` is a WEP key-material field, identifiable only by the shape
/// of its enclosing object rather than its own name.
///
/// A bare `keys` field is too generic to add to [`DENYLISTED_KEYS`] as a
/// substring: it would over-match every unrelated `keys` array or map in a
/// vendor payload (interface lists, route tables, ...). But Mist's
/// `wlan_auth` schema (MEC-711) uses exactly `keys` for its WEP key table,
/// always either alongside a sibling `type: "wep"` field on the same object,
/// or nested directly under a parent field named `auth`. Both are narrow
/// enough that a caller walking the JSON tree can check them without
/// widening the denylist's blast radius.
#[must_use]
pub fn is_wep_keys_field(key: &str, parent_key: Option<&str>, sibling_type: Option<&str>) -> bool {
    if normalize(key) != "keys" {
        return false;
    }
    if sibling_type.is_some_and(|t| normalize(t) == "wep") {
        return true;
    }
    parent_key.is_some_and(|p| normalize(p) == "auth")
}

/// Lowercase `s` and drop every non-alphanumeric byte, so `pre-shared-key`,
/// `pre_shared_key`, and `preSharedKey` all normalize to `presharedkey`.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Whether `key` matches a denylisted field name, under normalization.
///
/// Substring, not equality: a normalized denylist term appearing anywhere in
/// the normalized key is enough. `is_denylisted_key("x_shared_key")` and
/// `is_denylisted_key("wifi_password")` both match even though neither is a
/// literal entry in [`DENYLISTED_KEYS`].
#[must_use]
pub fn is_denylisted_key(key: &str) -> bool {
    let normalized = normalize(key);
    if normalized.is_empty() {
        return false;
    }
    if DENYLISTED_EXACT_KEYS.iter().any(|term| normalized == *term) {
        return true;
    }
    DENYLISTED_KEYS.iter().any(|term| normalized.contains(term))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spec_key_matches_its_own_variants() {
        let cases: &[(&str, &[&str])] = &[
            ("secret", &["secret", "Secret", "SECRET"]),
            ("private-key", &["private-key", "private_key", "privateKey"]),
            (
                "pre-shared-key",
                &["pre-shared-key", "pre_shared_key", "preSharedKey"],
            ),
            ("psk", &["psk", "PSK"]),
            ("passphrase", &["passphrase", "passPhrase"]),
            ("x_passphrase", &["x_passphrase", "x-passphrase"]),
            ("x_secret", &["x_secret", "x-secret"]),
            ("phash", &["phash", "x_phash"]),
            ("community", &["community", "community-string"]),
            ("api_key", &["api_key", "apiKey", "api-key"]),
            ("token", &["token", "auth_token", "bearerToken"]),
            (
                "authentication-key",
                &["authentication-key", "authentication_key"],
            ),
            ("password", &["password", "adminPassword", "wifi_password"]),
        ];
        for (spec_key, variants) in cases {
            for variant in *variants {
                assert!(
                    is_denylisted_key(variant),
                    "expected '{variant}' (variant of spec key '{spec_key}') to be denylisted"
                );
            }
        }
    }

    #[test]
    fn unrelated_keys_are_not_denylisted() {
        for key in ["description", "hostname", "interface", "vlan_id", "name"] {
            assert!(!is_denylisted_key(key), "'{key}' must not be denylisted");
        }
    }

    #[test]
    fn f7_new_field_names_are_denylisted() {
        for key in [
            "authorization",
            "Authorization",
            "bearer",
            "bearer_token",
            "cookie",
            "passwd",
            "pwd",
            "session",
            "session_id",
        ] {
            assert!(is_denylisted_key(key), "'{key}' must be denylisted");
        }
    }

    #[test]
    fn bare_key_matches_exactly_but_not_as_a_substring() {
        assert!(is_denylisted_key("key"));
        assert!(is_denylisted_key("Key"));
        for key in ["keys", "keyword", "keychain", "monkey", "key0", "hotkey"] {
            assert!(
                !is_denylisted_key(key),
                "'{key}' must not match the exact-only 'key' entry"
            );
        }
    }

    #[test]
    fn empty_key_is_not_denylisted() {
        assert!(!is_denylisted_key(""));
    }

    /// MEC-711: Mist OpenAPI secret fields Percy's sweep found missing from
    /// the denylist at the mecmcp rev rustmistmcp#137 pinned
    /// (`auth_key`/`auth_keys`, `keywrap_kek`/`keywrap_mack`, and the
    /// lower-confidence `partner_key`/`account_key`/`*client_key` set).
    #[test]
    fn mec_711_mist_secret_fields_are_denylisted() {
        let cases: &[(&str, &[&str])] = &[
            ("auth_key", &["auth_key", "authKey", "bgpAuthKey"]),
            ("auth_keys", &["auth_keys", "authKeys"]),
            ("keywrap_kek", &["keywrap_kek", "keywrapKek"]),
            ("keywrap_mack", &["keywrap_mack", "keywrapMack"]),
            ("partner_key", &["partner_key", "partnerKey"]),
            ("account_key", &["account_key", "accountKey"]),
            ("ldap_client_key", &["ldap_client_key", "ldapClientKey"]),
            (
                "openroaming_wba_client_key",
                &["openroaming_wba_client_key", "openroamingWbaClientKey"],
            ),
        ];
        for (spec_key, variants) in cases {
            for variant in *variants {
                assert!(
                    is_denylisted_key(variant),
                    "expected '{variant}' (variant of spec key '{spec_key}') to be denylisted"
                );
            }
        }
    }

    #[test]
    fn mec_711_wep_keys_field_needs_context() {
        // Bare "keys" with no context (no sibling type, no "auth" parent)
        // must not be denylisted — that would over-match every unrelated
        // `keys` field in a vendor payload.
        assert!(!is_wep_keys_field("keys", None, None));
        assert!(!is_wep_keys_field("keys", Some("wlan"), Some("psk")));

        // Sibling `type: "wep"` on the same object is enough regardless of
        // the parent key name.
        assert!(is_wep_keys_field("keys", None, Some("wep")));
        assert!(is_wep_keys_field("keys", Some("wlan"), Some("WEP")));

        // Parent key "auth" is enough even without a sibling type.
        assert!(is_wep_keys_field("keys", Some("auth"), None));
        assert!(is_wep_keys_field("keys", Some("auth"), Some("open")));

        // Only the "keys" field name itself is eligible.
        assert!(!is_wep_keys_field("key_ids", Some("auth"), Some("wep")));
    }
}
