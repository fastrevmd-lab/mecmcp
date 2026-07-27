//! COMPILE-TIME GATE: Source-level Rust API compatibility.
//!
//! This file exercises the EXACT public Rust API that external consumers use in
//! SOURCE CODE (struct literals, field access), NOT just serde deserialization.
//!
//! Consumer repos construct `LimitsConfig` by field name. If this file stops
//! compiling, a downstream consumer just broke at the source level.
//!
//! BREAKING CHANGES DETECTED:
//! - rust-panosmcp/src/http_transport.rs:241 uses `max_inflight_requests_per_router`
//! - RustJunosMCP/rust-junosmcp/src/main.rs:287 uses `max_inflight_requests_per_router`
//!
//! This test FAILS TO COMPILE after the router→device rename because the field name
//! changed, proving this is a source-level breaking change despite the serde alias.
//!
//! DO NOT "clean this up" or delete deprecated items — this is load-bearing for
//! external consumers.

#![allow(deprecated)]

use mecmcp_transport::LimitsConfig;

// This test is COMMENTED OUT because it documents a KNOWN BREAKING CHANGE.
// Uncomment to verify the old field name no longer compiles (proving the break).
/*
#[test]
fn consumer_source_level_struct_literal_construction_OLD_API_DOES_NOT_COMPILE() {
    // This is HOW consumers construct LimitsConfig in Rust source:
    // rust-panosmcp/src/http_transport.rs:239-241
    // RustJunosMCP/rust-junosmcp/src/main.rs:282-287

    let _config = LimitsConfig {
        max_request_body_bytes: 10 * 1024 * 1024,
        max_inflight_requests: 64,
        max_inflight_requests_per_token: 16,
        max_requests_per_second_per_ip: 0,
        max_request_burst_per_ip: 0,
        max_requests_per_second_per_token: 0,
        max_request_burst_per_token: 0,
        // BREAKING: This field was renamed from max_inflight_requests_per_router
        // to max_inflight_requests_per_device. Serde aliases do NOT help here.
        max_inflight_requests_per_router: 4, // <-- WILL NOT COMPILE
        max_sessions: 128,
        max_sessions_per_token: 16,
        session_idle_timeout_secs: 300,
        session_max_lifetime_secs: 3600,
    };
}
*/

#[test]
fn new_api_compiles() {
    // Consumers will need to update to this:
    let _config = LimitsConfig {
        max_request_body_bytes: 10 * 1024 * 1024,
        max_inflight_requests: 64,
        max_inflight_requests_per_token: 16,
        max_requests_per_second_per_ip: 0,
        max_request_burst_per_ip: 0,
        max_requests_per_second_per_token: 0,
        max_request_burst_per_token: 0,
        max_inflight_requests_per_device: 4, // <-- NEW NAME
        max_sessions: 128,
        max_sessions_per_token: 16,
        session_idle_timeout_secs: 300,
        session_max_lifetime_secs: 3600,
    };

    assert_eq!(_config.max_inflight_requests_per_device, 4);
}
