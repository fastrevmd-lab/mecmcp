//! Backward compatibility: old API names must keep compiling.
//!
//! This file exercises ONLY the pre-rename public API. If any deprecated shim
//! is deleted, this file stops COMPILING — there is no way for it to silently
//! pass. Do not "clean this up" — it is a compile-time gate.

#![allow(deprecated)]

use mecmcp_transport::LimitsConfig;

#[test]
fn old_config_field_accessor_compiles() {
    let cfg = LimitsConfig::default();

    // OLD: method accessor for max_inflight_requests_per_router
    #[allow(deprecated)]
    let _old_value = cfg.max_inflight_requests_per_router();

    // Verify it returns the same value as the new field
    assert_eq!(_old_value, cfg.max_inflight_requests_per_device);
}

#[test]
fn old_serde_field_names_deserialize() {
    // Config using old "max_inflight_requests_per_router" key
    let old_json = r#"{
        "max_request_body_bytes": 1000,
        "max_inflight_requests": 10,
        "max_inflight_requests_per_token": 5,
        "max_requests_per_second_per_ip": 0,
        "max_request_burst_per_ip": 0,
        "max_requests_per_second_per_token": 0,
        "max_request_burst_per_token": 0,
        "max_inflight_requests_per_router": 3,
        "max_sessions": 50,
        "max_sessions_per_token": 10,
        "session_idle_timeout_secs": 300,
        "session_max_lifetime_secs": 3600
    }"#;

    // Config using new "max_inflight_requests_per_device" key
    let new_json = r#"{
        "max_request_body_bytes": 1000,
        "max_inflight_requests": 10,
        "max_inflight_requests_per_token": 5,
        "max_requests_per_second_per_ip": 0,
        "max_request_burst_per_ip": 0,
        "max_requests_per_second_per_token": 0,
        "max_request_burst_per_token": 0,
        "max_inflight_requests_per_device": 3,
        "max_sessions": 50,
        "max_sessions_per_token": 10,
        "session_idle_timeout_secs": 300,
        "session_max_lifetime_secs": 3600
    }"#;

    let old_config: LimitsConfig =
        serde_json::from_str(old_json).expect("old key must deserialize");
    let new_config: LimitsConfig =
        serde_json::from_str(new_json).expect("new key must deserialize");

    // Both spellings must produce identical config
    assert_eq!(
        old_config.max_inflight_requests_per_device,
        new_config.max_inflight_requests_per_device
    );
    assert_eq!(old_config.max_inflight_requests_per_device, 3);
}

#[test]
fn old_target_alias_deserializes() {
    // Intermediate alias "max_inflight_requests_per_target"
    let target_json = r#"{
        "max_request_body_bytes": 1000,
        "max_inflight_requests": 10,
        "max_inflight_requests_per_token": 5,
        "max_requests_per_second_per_ip": 0,
        "max_request_burst_per_ip": 0,
        "max_requests_per_second_per_token": 0,
        "max_request_burst_per_token": 0,
        "max_inflight_requests_per_target": 7,
        "max_sessions": 50,
        "max_sessions_per_token": 10,
        "session_idle_timeout_secs": 300,
        "session_max_lifetime_secs": 3600
    }"#;

    let config: LimitsConfig =
        serde_json::from_str(target_json).expect("target alias must deserialize");
    assert_eq!(config.max_inflight_requests_per_device, 7);
}
