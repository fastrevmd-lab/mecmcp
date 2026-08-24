#![allow(clippy::unwrap_used)]
//! Backward compatibility: old token file format must keep parsing.
//!
//! This file exercises the pre-rename serde aliases. If any alias is deleted,
//! these tests fail at deserialization time. Do not "clean this up".

use mecmcp_auth::entry::TokenEntry;
use mecmcp_auth::grant::NoGrant;
use mecmcp_auth::scope::ScopeSet;

#[test]
fn old_routers_field_name_deserializes() {
    // Old rustjunosmcp format using "routers" and "hash"
    let old_json = r#"{
        "name": "legacy",
        "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "routers": ["r1", "r2"],
        "tools": ["*"],
        "created_at": "2026-07-12T10:00:00Z"
    }"#;

    // New format using "devices" and "digest"
    let new_json = r#"{
        "name": "modern",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "devices": ["r1", "r2"],
        "tools": ["*"],
        "created_at": "2026-07-12T10:00:00Z"
    }"#;

    let old_entry: TokenEntry<NoGrant> =
        serde_json::from_str(old_json).expect("old field names must deserialize");
    let new_entry: TokenEntry<NoGrant> =
        serde_json::from_str(new_json).expect("new field names must deserialize");

    // Both must produce identical device scopes
    assert_eq!(old_entry.devices, new_entry.devices);
    assert_eq!(
        old_entry.devices,
        ScopeSet::Allowlist(vec!["r1".to_owned(), "r2".to_owned()])
    );
}

#[test]
fn mixed_old_and_new_spellings_in_same_file() {
    // Realistic on-disk scenario: file contains mix of old and new entries
    let mixed_json = r#"{
        "tokens": [
            {
                "name": "old-style",
                "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "routers": ["legacy-router"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            },
            {
                "name": "new-style",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["modern-device"],
                "tools": ["*"],
                "created_at": "2026-07-12T10:00:00Z"
            }
        ]
    }"#;

    #[derive(serde::Deserialize)]
    struct TokenDocument {
        tokens: Vec<TokenEntry<NoGrant>>,
    }

    let doc: TokenDocument = serde_json::from_str(mixed_json).expect("mixed file must parse");
    assert_eq!(doc.tokens.len(), 2);

    assert_eq!(doc.tokens[0].name, "old-style");
    assert_eq!(
        doc.tokens[0].devices,
        ScopeSet::Allowlist(vec!["legacy-router".to_owned()])
    );

    assert_eq!(doc.tokens[1].name, "new-style");
    assert_eq!(
        doc.tokens[1].devices,
        ScopeSet::Allowlist(vec!["modern-device".to_owned()])
    );
}
