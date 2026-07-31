//! Multi-target change sets (#195, #90 phase 5).
//!
//! The compatibility tests here matter more than the feature tests. This crate
//! is pinned by both shipping servers, `ChangeSetRecord` is
//! `deny_unknown_fields`, and LXC 608 is running it right now against a live
//! version-1 state file holding ten change sets.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetRecord, ChangesetState, OperationLimits, PreviewRecord, TargetError,
    change_set_digest, change_set_digest_with_targets, read_state, validate_targets, write_state,
};

fn record(device: &str, targets: Vec<String>) -> ChangeSetRecord {
    // A real digest, because `read_state` recomputes and checks it. That check
    // is also why the digest-stability test above matters: a changed encoding
    // does not merely produce different digests, it stops the deployed state
    // file loading at all.
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let digest = if targets.is_empty() {
        change_set_digest("alice", device, &fingerprint, &actions).unwrap()
    } else {
        change_set_digest_with_targets("alice", device, &fingerprint, &actions, &targets).unwrap()
    };

    ChangeSetRecord {
        id: "a".repeat(64),
        owner: "alice".to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state: mecmcp_changeset::ChangeSetState::Planned,
        approver: None,
        approval: None,
        expires_at_unix: 0,
        operation_id: None,
        policy_signature: String::new(),
        targets,
        preview: None,
    }
}

#[test]
fn a_single_target_record_reports_its_device() {
    let record = record("fw-01", Vec::new());
    assert_eq!(record.targets(), vec!["fw-01".to_string()]);
}

#[test]
fn a_multi_target_record_reports_its_set() {
    let record = record("fw-01", vec!["fw-01".into(), "fw-02".into()]);
    assert_eq!(
        record.targets(),
        vec!["fw-01".to_string(), "fw-02".to_string()]
    );
}

/// The single-target digest must be byte-identical to what shipped.
///
/// 608 holds ten change sets whose digests were computed by the original
/// function. Any change to the single-target encoding invalidates every one of
/// them at the next approval, so this asserts against a fixed value rather than
/// against a freshly computed one — a recomputed expectation would move with the
/// bug.
#[test]
fn the_single_target_digest_is_unchanged() {
    let actions = vec![serde_json::json!({"op": "set", "path": "/a"})];
    let original = change_set_digest("alice", "fw-01", "sha256:abc", &actions).unwrap();

    // Hard-coded, and taken from `main` before this change rather than from this
    // branch: recomputing it here would move with the bug. Verified by building
    // `main` in a scratch worktree and printing the value.
    assert_eq!(
        original, "sha256:0a434734755db876c1df689b02ce31177641135f54b48fca2a650f07820a9014",
        "the single-target digest encoding changed; every digest on LXC 608 is now stale"
    );

    // And the targets-aware function must agree when there are no extra targets.
    let via_targets =
        change_set_digest_with_targets("alice", "fw-01", "sha256:abc", &actions, &[]).unwrap();
    assert_eq!(
        via_targets, original,
        "an empty target set changed the digest"
    );
}

#[test]
fn targets_are_bound_into_the_digest() {
    let actions = vec![serde_json::json!({"op": "set"})];
    let one = change_set_digest_with_targets(
        "alice",
        "fw-01",
        "sha256:abc",
        &actions,
        &["fw-01".into(), "fw-02".into()],
    )
    .unwrap();
    let other = change_set_digest_with_targets(
        "alice",
        "fw-01",
        "sha256:abc",
        &actions,
        &["fw-01".into(), "fw-03".into()],
    )
    .unwrap();

    assert_ne!(one, other, "editing the target list left the digest intact");
}

#[test]
fn a_target_set_must_be_sorted_unique_and_bounded() {
    let cases: Vec<(Vec<String>, TargetError)> = vec![
        (vec![], TargetError::Empty),
        (
            vec!["b".into(), "a".into()],
            TargetError::Unsorted("a".into()),
        ),
        (
            vec!["a".into(), "a".into()],
            TargetError::Duplicate("a".into()),
        ),
        (vec![String::new()], TargetError::EmptyName),
    ];

    for (targets, expected) in cases {
        assert_eq!(
            validate_targets(&targets, 64),
            Err(expected),
            "target set {targets:?} was not refused correctly"
        );
    }

    let too_many: Vec<String> = (0..65).map(|n| format!("fw-{n:03}")).collect();
    assert_eq!(
        validate_targets(&too_many, 64),
        Err(TargetError::TooMany {
            count: 65,
            maximum: 64
        })
    );

    // The legal shape passes.
    assert!(validate_targets(&["a".into(), "b".into()], 64).is_ok());
}

/// A record using no new field must still be written as version 1.
///
/// 608's live file is version 1. A version-2 file that a rolled-back binary
/// cannot parse is not a degraded experience, it is a server that will not
/// start — and rolling back is a documented deploy step.
#[test]
fn a_single_target_deployment_still_writes_version_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut state = ChangesetState::default();
    state
        .change_sets
        .insert("a".repeat(64), record("fw-01", Vec::new()));

    write_state(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 1, "a single-target record forced v2");

    // The absent fields must genuinely be absent, not null or empty.
    let stored = &on_disk["state"]["change_sets"][&"a".repeat(64)];
    assert!(stored.get("targets").is_none(), "targets was serialised");
    assert!(stored.get("preview").is_none(), "preview was serialised");
}

/// Using a new field moves the file to version 2, as the gate intends.
#[test]
fn a_multi_target_record_forces_version_two() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut state = ChangesetState::default();
    state.change_sets.insert(
        "a".repeat(64),
        record("fw-01", vec!["fw-01".into(), "fw-02".into()]),
    );

    write_state(&path, &state, OperationLimits::default().max_state_bytes).unwrap();
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 2, "multi-target must gate to v2");
}

#[test]
fn a_preview_record_forces_version_two_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut changeset = record("fw-01", Vec::new());
    changeset.preview = Some(PreviewRecord {
        artifact: "+ set address x".to_owned(),
        digest: format!("sha256:{}", "d".repeat(64)),
        job_id: Some("job-7".to_owned()),
    });

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 2);

    let reloaded = read_state(&path, OperationLimits::default().max_state_bytes).unwrap();
    let preview = reloaded.change_sets[&"a".repeat(64)]
        .preview
        .as_ref()
        .unwrap();
    assert_eq!(preview.job_id.as_deref(), Some("job-7"));
    assert_eq!(preview.artifact, "+ set address x");
}

/// A version-1 file with none of the new fields must load unchanged.
///
/// The shape here is copied from LXC 608's real `mutation-state.json`: version
/// 1, change sets carrying no `policy_signature`, no `approval`, no `targets`.
#[test]
fn a_deployed_version_one_file_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let id = "a".repeat(64);
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let digest = change_set_digest("alice", "panosvm-writer", &fingerprint, &actions).unwrap();
    let body = serde_json::json!({
        "version": 1,
        "state": {
            "change_sets": {
                &id: {
                    "id": &id,
                    "owner": "alice",
                    "device": "panosvm-writer",
                    "expected_candidate_fingerprint": fingerprint,
                    "actions": actions,
                    "digest": digest,
                    "state": "planned",
                    "approver": serde_json::Value::Null,
                    "expires_at_unix": 0,
                    "operation_id": serde_json::Value::Null
                }
            },
            "operations": {}
        }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let state = read_state(&path, OperationLimits::default().max_state_bytes).unwrap();
    let loaded = &state.change_sets[&id];
    assert_eq!(loaded.device, "panosvm-writer");
    assert!(loaded.targets.is_empty(), "targets must default to absent");
    assert!(loaded.preview.is_none());
    // And the accessor still answers.
    assert_eq!(loaded.targets(), vec!["panosvm-writer".to_string()]);
}
