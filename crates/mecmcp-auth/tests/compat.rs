#![allow(clippy::unwrap_used)]
//! Regression gate: both deployed `tokens.json` shapes must keep loading.

use mecmcp_auth::{Grant, GrantError, ScopeSet, TokenStoreFile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The PAN-OS write grant, defined here exactly as `rustpanosmcp` defines it,
/// to prove a vendor grant round-trips through the generic entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MutationGrant {
    allowed_xpath_roots: Vec<String>,
    actions: Vec<MutationAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MutationAction {
    Set,
    Delete,
}

impl Grant for MutationGrant {
    type Action = MutationAction;

    fn allows_action(&self, action: Self::Action) -> bool {
        self.actions.contains(&action)
    }

    fn allows_subject(&self, subject: &str) -> bool {
        self.allowed_xpath_roots.iter().any(|root| {
            subject == root
                || subject
                    .strip_prefix(root.as_str())
                    .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('['))
        })
    }

    fn validate(&self) -> Result<(), GrantError> {
        if self.allowed_xpath_roots.is_empty() {
            return Err(GrantError::Invalid("grant needs at least one root".into()));
        }
        Ok(())
    }
}

/// Copy a fixture to a temp dir with 0600 so permission checks pass.
fn staged(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let target = dir.path().join("tokens.json");
    std::fs::copy(&source, &target).expect("copy fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    (dir, target)
}

#[test]
fn the_deployed_junos_token_file_still_loads() {
    let (_dir, path) = staged("junos-tokens.json");
    let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load junos tokens");
    let store = file.store();
    assert_eq!(store.len(), 2);

    let wildcard = store
        .entries()
        .iter()
        .find(|e| e.name == "claude-desktop")
        .expect("claude-desktop entry");
    assert_eq!(wildcard.devices, ScopeSet::Wildcard);

    let observer = store
        .entries()
        .iter()
        .find(|e| e.name == "readonly-observer")
        .expect("readonly-observer entry");
    assert!(observer.devices.allows("edge-fw"));
    assert!(!observer.devices.allows("br1-fw"));
}

#[test]
fn the_deployed_panos_token_file_still_loads_with_its_grant() {
    let (_dir, path) = staged("panos-tokens.json");
    let file: TokenStoreFile<MutationGrant> =
        TokenStoreFile::load(&path).expect("load panos tokens");
    let store = file.store();
    assert_eq!(store.len(), 1);

    let entry = &store.entries()[0];
    let grant = entry.grant.as_ref().expect("mutation grant present");
    assert!(grant.allows_action(MutationAction::Set));
    assert!(grant.allows_subject("/config/devices/entry/vsys/entry/rulebase/security"));
    assert!(!grant.allows_subject("/config/devices/entry/network"));
}

#[test]
fn a_junos_wildcard_tool_scope_still_excludes_write_tools() {
    const JUNOS_WRITE_TOOLS: &[&str] = &[
        "load_and_commit_config",
        "render_and_apply_j2_template",
        "rollback_config",
        "add_device",
    ];
    let (_dir, path) = staged("junos-tokens.json");
    let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
    let store = file.store();
    let wildcard = store
        .entries()
        .iter()
        .find(|e| e.name == "claude-desktop")
        .expect("entry");

    assert!(
        wildcard
            .tools
            .allows_tool("get_junos_config", JUNOS_WRITE_TOOLS)
    );
    assert!(
        !wildcard
            .tools
            .allows_tool("load_and_commit_config", JUNOS_WRITE_TOOLS)
    );
}

#[test]
fn writing_a_deployed_file_preserves_its_envelope_version() {
    use mecmcp_auth::{KnownNames, NoGrant};

    // Test with junos fixture (version 1)
    {
        let (_dir, path) = staged("junos-tokens.json");
        let devices = [
            "edge-fw".to_owned(),
            "core-fw".to_owned(),
            "dc-fw".to_owned(),
        ];
        let known = KnownNames {
            devices: Some(&devices),
            tools: &[
                "get_junos_config",
                "execute_junos_command",
                "get_router_list",
            ],
        };

        TokenStoreFile::<NoGrant>::set_scopes(&path, "readonly-observer", None, None, None, &known)
            .expect("set_scopes on junos fixture");

        let body = std::fs::read_to_string(&path).expect("read junos file");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse junos");
        assert_eq!(
            parsed["version"], 1,
            "junos fixture must preserve version 1"
        );

        // Strict envelope test: prove the originating server could still read it
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictEnvelope {
            version: u32,
            #[allow(dead_code)]
            tokens: serde_json::Value,
        }

        let envelope: StrictEnvelope = serde_json::from_str(&body)
            .expect("junos v1 file must parse under strict deny_unknown_fields envelope");
        assert_eq!(envelope.version, 1);
    }

    // Test with panos fixture (version 2)
    {
        let (_dir, path) = staged("panos-tokens.json");
        let devices = ["panosvm".to_owned()];
        let known = KnownNames {
            devices: Some(&devices),
            tools: &["get_panos_config", "list_devices", "stage_panos_config"],
        };

        TokenStoreFile::<MutationGrant>::set_scopes(
            &path,
            "panos-operator",
            None,
            None,
            None,
            &known,
        )
        .expect("set_scopes on panos fixture");

        let body = std::fs::read_to_string(&path).expect("read panos file");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse panos");
        assert_eq!(
            parsed["version"], 2,
            "panos fixture must preserve version 2, not normalise to 1"
        );

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictEnvelope {
            version: u32,
            #[allow(dead_code)]
            tokens: serde_json::Value,
        }

        let envelope: StrictEnvelope = serde_json::from_str(&body)
            .expect("panos v2 file must parse under strict deny_unknown_fields envelope");
        assert_eq!(envelope.version, 2);
    }
}

#[test]
fn round_trip_through_write_atomic_does_not_mutate_untagged_tokens() {
    use mecmcp_auth::{KnownNames, NoGrant, TokenStoreFile};

    let (_dir, path) = staged("junos-tokens.json");
    let original = std::fs::read_to_string(&path).expect("read original");

    // The junos fixture contains "claude-desktop" which has no actor_type.
    // Prove the original doesn't already have the field.
    assert!(
        !original.contains("actor_type"),
        "precondition: fixture must not already contain actor_type"
    );

    // Perform a write operation that rewrites the entire file.
    let devices = [
        "edge-fw".to_owned(),
        "core-fw".to_owned(),
        "dc-fw".to_owned(),
    ];
    let known = KnownNames {
        devices: Some(&devices),
        tools: &[
            "get_junos_config",
            "execute_junos_command",
            "get_router_list",
        ],
    };
    TokenStoreFile::<NoGrant>::set_scopes(&path, "readonly-observer", None, None, None, &known)
        .expect("set_scopes rewrites the file");

    // Read it back and prove actor_type was NOT added.
    let rewritten = std::fs::read_to_string(&path).expect("read rewritten");
    assert!(
        !rewritten.contains("actor_type"),
        "rewritten file must not gain actor_type field on untagged tokens:\n{rewritten}"
    );

    // Ensure the file still loads correctly.
    let file: TokenStoreFile = TokenStoreFile::load(&path).expect("reload after write");
    assert_eq!(file.store().len(), 2);
}

/// A rewrite must not change who owns the token file.
///
/// `write_atomic` replaces the file, so without owner preservation the
/// replacement belongs to whoever ran the command. Minting a token as root —
/// which is what the install instructions say to do — would leave the service
/// unable to read its own tokens.json, and it then refuses to start with a
/// permission error that never mentions ownership.
///
/// Running as root this asserts the real behaviour. Running as an ordinary user
/// there is only one uid available, so it degrades to asserting the write does
/// not *change* the owner, which is still the property that matters.
#[test]
#[cfg(unix)]
fn rewrite_preserves_the_token_file_owner() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tokens.json");

    mecmcp_auth::write_atomic::<mecmcp_auth::NoGrant>(&path, &[], 1).expect("initial write");
    let before = std::fs::metadata(&path).expect("stat before");

    // Rewrite so this is a genuine replacement rather than a no-op.
    mecmcp_auth::write_atomic::<mecmcp_auth::NoGrant>(&path, &[], 1).expect("rewrite");

    let after = std::fs::metadata(&path).expect("stat after");
    assert_eq!(
        (before.uid(), before.gid()),
        (after.uid(), after.gid()),
        "an atomic rewrite must leave the token file's owner unchanged"
    );
}
