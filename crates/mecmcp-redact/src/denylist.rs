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
];

/// Field names that must match the *whole* normalized key, not a substring.
///
/// `"key"` is deliberately not in [`DENYLISTED_KEYS`]: as a substring it would
/// match half of every config (`keys`, `keyword`, `keychain`, an interface
/// named `key0`, ...). But the bare field name `key` alone is exactly the
/// PAN-OS keygen response shape (`<result><key>` is the API key itself), so it
/// still needs to be denylisted — just under exact match instead.
const DENYLISTED_EXACT_KEYS: &[&str] = &["key"];

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
}
