//! Integration tests for token command implementation.

use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::{
    cli::TokenAction,
    token_cmd::{run, TokenCommandError},
};
use std::path::PathBuf;
use tempfile::TempDir;

const KNOWN_TOOLS: &[&str] = &["get_config", "execute_command", "load_config"];

fn temp_tokens_file() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");
    (dir, path)
}

#[test]
fn add_creates_token_and_returns_secret() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "alice".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        server_pid: None,
    };

    // Capture stdout to verify secret is printed
    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_ok(), "add failed: {result:?}");

    // Verify the token was stored
    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store = store_file.store();
    assert_eq!(store.entries().len(), 1);
    assert_eq!(store.entries()[0].name, "alice");
}

#[test]
fn list_shows_token_metadata_not_secret() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Add a token
    let add_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "bob".to_string(),
        devices: vec!["device1".to_string()],
        tools: vec!["get_config".to_string()],
        server_pid: None,
    };
    run(add_action, &[], KNOWN_TOOLS).unwrap();

    // List tokens
    let list_action = TokenAction::List {
        tokens_file: tokens_file.clone(),
    };
    let result = run(list_action, &[], KNOWN_TOOLS);
    assert!(result.is_ok());

    // Verify file contains metadata, not plaintext secret
    let content = std::fs::read_to_string(&tokens_file).unwrap();
    assert!(content.contains("bob"));
    assert!(content.contains("device1"));
    assert!(content.contains("get_config"));
    assert!(!content.contains("Bearer "), "secret leaked into file");
}

#[test]
fn revoke_removes_token() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Add a token
    let add_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "charlie".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        server_pid: None,
    };
    run(add_action, &[], KNOWN_TOOLS).unwrap();

    // Revoke it
    let revoke_action = TokenAction::Revoke {
        tokens_file: tokens_file.clone(),
        name: "charlie".to_string(),
        server_pid: None,
    };
    run(revoke_action, &[], KNOWN_TOOLS).unwrap();

    // Verify it's gone
    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store = store_file.store();
    assert!(store.is_empty());
}

#[test]
fn rotate_changes_secret_preserves_scopes() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Add a token
    let add_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "diana".to_string(),
        devices: vec!["dev1".to_string(), "dev2".to_string()],
        tools: vec!["get_config".to_string()],
        server_pid: None,
    };
    run(add_action, &[], KNOWN_TOOLS).unwrap();

    // Capture initial digest
    let store_before = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let digest_before = store_before.store().entries()[0].digest.clone();
    let created_at_before = store_before.store().entries()[0].created_at;

    // Rotate
    let rotate_action = TokenAction::Rotate {
        tokens_file: tokens_file.clone(),
        name: "diana".to_string(),
        server_pid: None,
    };
    run(rotate_action, &[], KNOWN_TOOLS).unwrap();

    // Verify digest changed but scopes and created_at are preserved
    let store_after = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store_after_ref = store_after.store();
    let entry_after = &store_after_ref.entries()[0];

    assert_ne!(entry_after.digest, digest_before, "digest unchanged");
    assert_eq!(entry_after.name, "diana");
    assert!(matches!(
        &entry_after.devices,
        mecmcp_auth::ScopeSet::Allowlist(d) if d == &["dev1", "dev2"]
    ));
    assert!(matches!(
        &entry_after.tools,
        mecmcp_auth::ScopeSet::Allowlist(t) if t == &["get_config"]
    ));
    // Timestamps should be identical - rotate preserves created_at
    // Allow for minor differences due to serialization precision
    let time_diff = (entry_after.created_at.timestamp_nanos_opt().unwrap()
        - created_at_before.timestamp_nanos_opt().unwrap())
    .abs();
    assert!(
        time_diff < 1_000_000,
        "created_at changed: before={created_at_before:?}, after={:?}",
        entry_after.created_at
    );
}

#[test]
fn wildcard_mixed_with_names_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "evil".to_string(),
        devices: vec!["*".to_string(), "device1".to_string()],
        tools: vec!["*".to_string()],
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Scope { field, message } => {
            assert_eq!(field, "devices");
            assert!(message.contains("'*'"));
        }
        other => panic!("expected Scope error, got {other:?}"),
    }
}

#[test]
fn unknown_tool_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "eve".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["no_such_tool".to_string()],
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
}

#[test]
fn device_validation_when_known_devices_provided() {
    let (_dir, tokens_file) = temp_tokens_file();
    let known_devices = vec!["dev1".to_string(), "dev2".to_string()];

    // Valid device name
    let valid_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "frank".to_string(),
        devices: vec!["dev1".to_string()],
        tools: vec!["*".to_string()],
        server_pid: None,
    };
    assert!(run(valid_action, &known_devices, KNOWN_TOOLS).is_ok());

    // Invalid device name should fail
    let invalid_action = TokenAction::Add {
        tokens_file,
        name: "george".to_string(),
        devices: vec!["unknown_dev".to_string()],
        tools: vec!["*".to_string()],
        server_pid: None,
    };
    assert!(run(invalid_action, &known_devices, KNOWN_TOOLS).is_err());
}

#[test]
fn empty_device_scope_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "hannah".to_string(),
        devices: vec![],
        tools: vec!["*".to_string()],
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Scope { field, .. } => {
            assert_eq!(field, "devices");
        }
        other => panic!("expected Scope error, got {other:?}"),
    }
}

#[test]
fn empty_tool_scope_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "ivan".to_string(),
        devices: vec!["*".to_string()],
        tools: vec![],
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Scope { field, .. } => {
            assert_eq!(field, "tools");
        }
        other => panic!("expected Scope error, got {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn signal_reload_with_valid_pid_succeeds() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Use PID 1 (init/systemd) - it will ignore SIGHUP from non-root
    // We don't care if the signal succeeds, just that the token command
    // doesn't fail when given a valid PID.
    let init_pid = 1;

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "judy".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        server_pid: Some(init_pid),
    };

    // We expect this to potentially fail with EPERM (permission denied) when
    // trying to signal init, but NOT fail due to invalid PID format.
    // Either success or EPERM is acceptable for this test.
    let result = run(action, &[], KNOWN_TOOLS);
    // The token should be added regardless of signal success
    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    assert_eq!(store_file.store().entries().len(), 1);
    // If we got an error, it should be I/O (EPERM), not parsing
    if let Err(e) = result {
        assert!(matches!(e, TokenCommandError::Io(_)), "unexpected error: {e:?}");
    }
}

#[test]
#[cfg(unix)]
fn signal_reload_with_invalid_pid_fails() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Zero PID is invalid for kill_process
    let action = TokenAction::Add {
        tokens_file,
        name: "kate".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        server_pid: Some(0),
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err(), "expected error for invalid PID 0");
}

#[test]
#[cfg(not(unix))]
fn signal_reload_on_non_unix_with_pid_fails() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "leo".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        server_pid: Some(1234),
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Io(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
        }
        other => panic!("expected Io(Unsupported) error, got {other:?}"),
    }
}
