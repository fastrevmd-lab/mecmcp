//! `RedactionPolicy` is a process-global `OnceLock`
//! (`mecmcp_redact::policy::install`/`active`), so this scenario — nothing
//! ever calls `install` — needs its own process to mean anything. Every
//! `tests/*.rs` file is its own binary, which is why this lives here rather
//! than as a unit test alongside `tests/policy_operator_override.rs`.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{RedactionPolicy, active};

#[test]
fn redaction_is_on_by_default_when_the_operator_never_installs_a_policy() {
    assert_eq!(active(), RedactionPolicy::Enabled);

    // And the effect, not just the enum: a denylisted field is actually
    // scrubbed with no `install` call anywhere in this process.
    let redacted = mecmcp_redact::redact_json_str(r#"{"password": "FAKEhunter2"}"#).unwrap();
    assert!(!redacted.contains("FAKEhunter2"), "got: {redacted}");
}
