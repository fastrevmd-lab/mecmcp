//! Task 4 tests: operation fingerprint guards, policy signature, change-set validation.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    LifecycleState,
    digest::{change_set_digest, validate_digest},
    records::{
        OperationRecord, mutation_policy_signature, require_operation_fingerprint,
        require_operation_policy, validate_change_set_actions,
    },
    types::OperationLimits,
};
use serde_json::json;

#[test]
fn test_digest_changes_on_owner_change() {
    let owner1 = "alice";
    let owner2 = "bob";
    let device = "router-01";
    let fingerprint = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let actions = vec![json!({"action": "set", "xpath": "/config/devices"})];

    let digest1 = change_set_digest(owner1, device, fingerprint, &actions).unwrap();
    let digest2 = change_set_digest(owner2, device, fingerprint, &actions).unwrap();

    assert_ne!(digest1, digest2, "changing owner must change the digest");
    validate_digest(&digest1, "digest1").unwrap();
    validate_digest(&digest2, "digest2").unwrap();
}

#[test]
fn test_digest_changes_on_device_change() {
    let owner = "alice";
    let device1 = "router-01";
    let device2 = "router-02";
    let fingerprint = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let actions = vec![json!({"action": "set", "xpath": "/config/devices"})];

    let digest1 = change_set_digest(owner, device1, fingerprint, &actions).unwrap();
    let digest2 = change_set_digest(owner, device2, fingerprint, &actions).unwrap();

    assert_ne!(digest1, digest2, "changing device must change the digest");
    validate_digest(&digest1, "digest1").unwrap();
    validate_digest(&digest2, "digest2").unwrap();
}

#[test]
fn test_digest_changes_on_fingerprint_change() {
    let owner = "alice";
    let device = "router-01";
    let fingerprint1 = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let fingerprint2 = "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let actions = vec![json!({"action": "set", "xpath": "/config/devices"})];

    let digest1 = change_set_digest(owner, device, fingerprint1, &actions).unwrap();
    let digest2 = change_set_digest(owner, device, fingerprint2, &actions).unwrap();

    assert_ne!(
        digest1, digest2,
        "changing fingerprint must change the digest"
    );
    validate_digest(&digest1, "digest1").unwrap();
    validate_digest(&digest2, "digest2").unwrap();
}

#[test]
fn test_digest_changes_on_actions_change() {
    let owner = "alice";
    let device = "router-01";
    let fingerprint = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let actions1 = vec![json!({"action": "set", "xpath": "/config/devices"})];
    let actions2 = vec![json!({"action": "delete", "xpath": "/config/vlans"})];

    let digest1 = change_set_digest(owner, device, fingerprint, &actions1).unwrap();
    let digest2 = change_set_digest(owner, device, fingerprint, &actions2).unwrap();

    assert_ne!(digest1, digest2, "changing actions must change the digest");
    validate_digest(&digest1, "digest1").unwrap();
    validate_digest(&digest2, "digest2").unwrap();
}

#[test]
fn test_validate_change_set_actions_rejects_empty() {
    let actions: Vec<serde_json::Value> = vec![];
    let limits = OperationLimits::default();

    let result = validate_change_set_actions(&actions, &limits);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("change set must contain at least 1 action"),
        "Expected empty actions error, got: {error_message}"
    );
}

#[test]
fn test_validate_change_set_actions_rejects_over_default_limit() {
    // Default limit is 64
    let actions: Vec<serde_json::Value> = (0..65)
        .map(|i| json!({"action": "set", "xpath": format!("/config/item-{}", i)}))
        .collect();
    let limits = OperationLimits::default();

    let result = validate_change_set_actions(&actions, &limits);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("change set exceeds maximum of 64 actions"),
        "Expected over-limit error, got: {error_message}"
    );
}

#[test]
fn test_validate_change_set_actions_rejects_over_custom_limit() {
    // Custom limit of 10
    let actions: Vec<serde_json::Value> = (0..11)
        .map(|i| json!({"action": "set", "xpath": format!("/config/item-{}", i)}))
        .collect();
    let limits = OperationLimits {
        max_actions_per_set: 10,
        ..Default::default()
    };

    let result = validate_change_set_actions(&actions, &limits);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("change set exceeds maximum of 10 actions"),
        "Expected custom limit error, got: {error_message}"
    );
}

#[test]
fn test_validate_change_set_actions_accepts_at_limit() {
    // Exactly at the limit should pass
    let actions: Vec<serde_json::Value> = (0..64)
        .map(|i| json!({"action": "set", "xpath": format!("/config/item-{}", i)}))
        .collect();
    let limits = OperationLimits::default();

    let result = validate_change_set_actions(&actions, &limits);
    assert!(result.is_ok(), "64 actions should be accepted");
}

#[test]
fn test_validate_change_set_actions_rejects_oversized_serialized() {
    // Create a change set that will exceed max_change_set_bytes when serialized
    let limits = OperationLimits {
        max_change_set_bytes: 1024, // 1KB limit
        ..Default::default()
    };

    // Create actions with large elements that will exceed the limit
    let large_element = "x".repeat(500);
    let actions: Vec<serde_json::Value> = (0..10)
        .map(|i| {
            json!({
                "action": "set",
                "xpath": format!("/config/item-{}", i),
                "element": large_element
            })
        })
        .collect();

    let result = validate_change_set_actions(&actions, &limits);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("serialized change set exceeds 1024 bytes"),
        "Expected size limit error, got: {error_message}"
    );
}

#[test]
fn test_mutation_policy_signature_stable() {
    // Same inputs should produce the same signature
    let policy = "panos-api-admin";
    let sig1 = mutation_policy_signature(policy);
    let sig2 = mutation_policy_signature(policy);
    assert_eq!(sig1, sig2, "policy signature must be stable");
    assert!(sig1.starts_with("sha256:"), "signature must be sha256");
    assert_eq!(sig1.len(), 71, "signature must be sha256: + 64 hex chars");
}

#[test]
fn test_mutation_policy_signature_differs_on_policy_change() {
    let policy1 = "panos-api-admin";
    let policy2 = "junos-api-admin";
    let sig1 = mutation_policy_signature(policy1);
    let sig2 = mutation_policy_signature(policy2);
    assert_ne!(
        sig1, sig2,
        "different policies must produce different signatures"
    );
}

#[test]
fn test_require_operation_policy_accepts_matching() {
    let policy_sig = "sha256:1775c53ee96aec8e1841a5e6a9facc62ad4cbb229b782bcb314d5934eb75151f";
    let record = OperationRecord {
        id: "a".repeat(64),
        owner: "alice".to_string(),
        device: "router-01".to_string(),
        endpoint: "https://192.0.2.1".to_string(),
        action: json!({"action": "set"}),
        xpath: None,
        actions: vec![],
        change_set_id: None,
        current: "sha256:abcd".to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: policy_sig.to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let result = require_operation_policy(&record, policy_sig);
    assert!(result.is_ok(), "matching policy should be accepted");
}

#[test]
fn test_require_operation_policy_rejects_mismatch() {
    let record_sig = "sha256:1775c53ee96aec8e1841a5e6a9facc62ad4cbb229b782bcb314d5934eb75151f";
    let current_sig = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
    let record = OperationRecord {
        id: "a".repeat(64),
        owner: "alice".to_string(),
        device: "router-01".to_string(),
        endpoint: "https://192.0.2.1".to_string(),
        action: json!({"action": "set"}),
        xpath: None,
        actions: vec![],
        change_set_id: None,
        current: "sha256:abcd".to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: record_sig.to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let result = require_operation_policy(&record, current_sig);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("policy changed after this operation staged"),
        "Expected policy mismatch error, got: {error_message}"
    );
}

#[test]
fn test_require_operation_fingerprint_accepts_matching() {
    let fingerprint = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let record = OperationRecord {
        id: "a".repeat(64),
        owner: "alice".to_string(),
        device: "router-01".to_string(),
        endpoint: "https://192.0.2.1".to_string(),
        action: json!({"action": "set"}),
        xpath: None,
        actions: vec![],
        change_set_id: None,
        current: fingerprint.to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: "sha256:policy".to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let result = require_operation_fingerprint(&record, fingerprint, fingerprint);
    assert!(result.is_ok(), "matching fingerprint should be accepted");
}

#[test]
fn test_require_operation_fingerprint_rejects_current_mismatch() {
    let expected = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let actual = "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let record = OperationRecord {
        id: "a".repeat(64),
        owner: "alice".to_string(),
        device: "router-01".to_string(),
        endpoint: "https://192.0.2.1".to_string(),
        action: json!({"action": "set"}),
        xpath: None,
        actions: vec![],
        change_set_id: None,
        current: expected.to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: "sha256:policy".to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let result = require_operation_fingerprint(&record, expected, actual);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("candidate changed since the caller observed it"),
        "Expected current fingerprint mismatch error, got: {error_message}"
    );
}

#[test]
fn test_require_operation_fingerprint_rejects_record_mismatch() {
    let expected = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let record_fp = "sha256:111111111111111111111111111111111111111111111111111111111111111";
    let record = OperationRecord {
        id: "a".repeat(64),
        owner: "alice".to_string(),
        device: "router-01".to_string(),
        endpoint: "https://192.0.2.1".to_string(),
        action: json!({"action": "set"}),
        xpath: None,
        actions: vec![],
        change_set_id: None,
        current: record_fp.to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: "sha256:policy".to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let result = require_operation_fingerprint(&record, expected, expected);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("candidate changed after this operation staged"),
        "Expected record fingerprint mismatch error, got: {error_message}"
    );
}

#[test]
fn test_operation_record_xpath_optional_roundtrip() {
    // PAN-OS operation with xpath
    let panos_record = OperationRecord {
        id: "a".repeat(64),
        owner: "alice".to_string(),
        device: "panos-01".to_string(),
        endpoint: "https://192.0.2.1".to_string(),
        action: json!({"action": "set"}),
        xpath: Some("/config/devices/entry[@name='localhost.localdomain']".to_string()),
        actions: vec![],
        change_set_id: None,
        current: "sha256:abcd".to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: "sha256:policy".to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let serialized = serde_json::to_string(&panos_record).unwrap();
    assert!(
        serialized.contains("\"xpath\""),
        "PAN-OS record must serialize xpath"
    );

    let deserialized: OperationRecord = serde_json::from_str(&serialized).unwrap();
    assert_eq!(
        deserialized.xpath,
        Some("/config/devices/entry[@name='localhost.localdomain']".to_string()),
        "xpath must round-trip"
    );

    // Junos operation without xpath
    let junos_record = OperationRecord {
        id: "b".repeat(64),
        owner: "bob".to_string(),
        device: "junos-01".to_string(),
        endpoint: "https://192.0.2.2".to_string(),
        action: json!({"payload": "set system host-name test"}),
        xpath: None,
        actions: vec![],
        change_set_id: None,
        current: "sha256:efgh".to_string(),
        state: LifecycleState::Staged,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: "sha256:policy2".to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    };

    let junos_serialized = serde_json::to_string(&junos_record).unwrap();
    assert!(
        !junos_serialized.contains("\"xpath\""),
        "Junos record must not serialize xpath when None"
    );

    let junos_deserialized: OperationRecord = serde_json::from_str(&junos_serialized).unwrap();
    assert_eq!(
        junos_deserialized.xpath, None,
        "xpath must deserialize as None"
    );
}
