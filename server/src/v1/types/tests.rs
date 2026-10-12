use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::command::{CommandSpecRead, CommandSpecWrite, EnvNames};
use super::config::{ConfigCreate, ConfigPatch, ConfigRead};
use super::event::{FlushIncompleteDetails, Notice, NoticeEvent};
use super::network::{EmptyEntries, NetworkRead, NetworkWrite};
use super::problem::{ConflictType, CreateConflictProblem};
use super::process::{ProcessRecord, ProcessState};
use super::sandbox::{
    CreateSandboxRequest, DesiredState, PatchSandboxRequest, SandboxDocument, Status,
};

fn parse<T: DeserializeOwned>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|e| e.to_string())
}

fn create_body() -> Value {
    json!({
        "name": "sb",
        "namespace": "ns",
        "config": {
            "backend": "libkrun",
            "backend_options": {"image": {"uri": "docker.io/library/alpine:3"}},
            "network": {"mode": "allowlist", "entries": ["github.com:443"]},
            "mounts": [{"host_path": "/w", "guest_path": "/w", "read_only": false}],
            "env": {"A": "1"},
            "main": {"command": ["sh"], "env": {}, "cwd": "/"}
        }
    })
}

fn command_body() -> Value {
    json!({"command": ["sh"], "env": {}, "cwd": "/", "uid": 1000, "gid": 1000})
}

/// Sets `body[path] = null`, walking objects by member name.
fn with_null(mut body: Value, path: &[&str]) -> Value {
    let (last, parents) = path.split_last().expect("non-empty path");
    let mut target = &mut body;
    for member in parents {
        target = target.get_mut(*member).expect("path exists");
    }
    target[*last] = Value::Null;
    body
}

fn assert_null_rejected<T: DeserializeOwned + std::fmt::Debug>(body: Value, path: &[&str]) {
    let err = parse::<T>(with_null(body, path)).expect_err(&format!("null at {path:?}"));
    assert!(
        err.contains("invalid type: null"),
        "null at {path:?}: unexpected error {err}"
    );
}

#[test]
fn patch_main_absent_null_and_object_are_distinct() {
    let absent: ConfigPatch = parse(json!({})).unwrap();
    assert!(absent.main.is_none());

    let null: ConfigPatch = parse(json!({"main": null})).unwrap();
    assert!(matches!(null.main, Some(None)));

    let object: ConfigPatch =
        parse(json!({"main": {"command": ["sh"], "env": {}, "cwd": "/"}})).unwrap();
    let main = object.main.unwrap().unwrap();
    assert_eq!(main.command, vec!["sh"]);
}

#[test]
fn explicit_null_is_rejected_for_every_optional_create_member() {
    for path in [
        &["desired_state"][..],
        &["config", "backend"],
        &["config", "backend_options"],
        &["config", "network"],
        &["config", "mounts"],
        &["config", "env"],
        &["config", "main"],
    ] {
        assert_null_rejected::<CreateSandboxRequest>(create_body(), path);
    }
}

#[test]
fn explicit_null_is_rejected_for_every_optional_patch_member() {
    let body = json!({
        "if_version": 3,
        "desired_state": "running",
        "clear_reason": "r-1",
        "config": {
            "backend": "libkrun",
            "backend_options": {},
            "network": {"mode": "none"},
            "mounts": [],
            "env": {}
        }
    });
    for path in [
        &["if_version"][..],
        &["desired_state"],
        &["clear_reason"],
        &["config"],
        &["config", "backend"],
        &["config", "backend_options"],
        &["config", "network"],
        &["config", "mounts"],
        &["config", "env"],
    ] {
        assert_null_rejected::<PatchSandboxRequest>(body.clone(), path);
    }
}

#[test]
fn explicit_null_is_rejected_for_command_ids_and_none_entries() {
    assert_null_rejected::<CommandSpecWrite>(command_body(), &["uid"]);
    assert_null_rejected::<CommandSpecWrite>(command_body(), &["gid"]);
    assert_null_rejected::<NetworkWrite>(json!({"mode": "none", "entries": []}), &["entries"]);
}

#[test]
fn guided_required_members_deserialize_to_none_when_omitted() {
    let patch: PatchSandboxRequest = parse(json!({})).unwrap();
    assert!(patch.if_version.is_none());

    let config: ConfigCreate = parse(json!({})).unwrap();
    assert!(config.backend.is_none());
    assert!(config.network.is_none());
}

#[test]
fn unknown_request_members_are_accepted_at_every_level() {
    let mut create = create_body();
    create["extra"] = json!(1);
    create["config"]["extra"] = json!(1);
    create["config"]["network"]["extra"] = json!(1);
    create["config"]["main"]["extra"] = json!(1);
    create["config"]["mounts"][0]["extra"] = json!(1);
    let parsed: CreateSandboxRequest = parse(create).unwrap();
    assert_eq!(parsed.name, "sb");

    let patch: PatchSandboxRequest =
        parse(json!({"if_version": 1, "extra": 1, "config": {"extra": 1}})).unwrap();
    assert_eq!(patch.if_version, Some(1));

    let mut spawn = command_body();
    spawn["extra"] = json!(1);
    let parsed: CommandSpecWrite = parse(spawn).unwrap();
    assert_eq!(parsed.cwd, "/");
}

#[test]
fn network_write_follows_mode_entry_rules() {
    assert!(matches!(
        parse::<NetworkWrite>(json!({"mode": "none"})).unwrap(),
        NetworkWrite::None { entries: None }
    ));
    assert!(matches!(
        parse::<NetworkWrite>(json!({"mode": "none", "entries": []})).unwrap(),
        NetworkWrite::None {
            entries: Some(EmptyEntries)
        }
    ));
    assert!(parse::<NetworkWrite>(json!({"mode": "none", "entries": ["a.com:443"]})).is_err());
    for mode in ["allowlist", "all"] {
        let err = parse::<NetworkWrite>(json!({"mode": mode})).unwrap_err();
        assert!(err.contains("missing field `entries`"), "{mode}: {err}");
    }
    let allowlist: NetworkWrite =
        parse(json!({"mode": "allowlist", "entries": ["github.com:443"]})).unwrap();
    assert!(
        matches!(allowlist, NetworkWrite::Allowlist { entries } if entries == ["github.com:443"])
    );
}

#[test]
fn network_read_echoes_the_written_entries_form() {
    let to_json = |n: &NetworkRead| serde_json::to_value(n).unwrap();
    assert_eq!(
        to_json(&NetworkRead::None { entries: None }),
        json!({"mode": "none"})
    );
    assert_eq!(
        to_json(&NetworkRead::None {
            entries: Some(EmptyEntries)
        }),
        json!({"mode": "none", "entries": []})
    );
    assert_eq!(
        to_json(&NetworkRead::Allowlist { entries: vec![] }),
        json!({"mode": "allowlist", "entries": []})
    );
}

#[test]
fn notice_events_serialize_flat() {
    let flush = NoticeEvent {
        seq: 7,
        at: "2026-10-10T00:00:00Z".into(),
        notice: Notice::FlushIncomplete {
            message: None,
            details: FlushIncompleteDetails {
                phase: "stop".into(),
                waited_ms: 5000,
            },
        },
    };
    assert_eq!(
        serde_json::to_string(&flush).unwrap(),
        r#"{"seq":7,"at":"2026-10-10T00:00:00Z","code":"flush_incomplete","details":{"phase":"stop","waited_ms":5000}}"#
    );

    let resync = NoticeEvent {
        seq: 9,
        at: "2026-10-10T00:00:00Z".into(),
        notice: Notice::Resync { message: None },
    };
    assert_eq!(
        serde_json::to_string(&resync).unwrap(),
        r#"{"seq":9,"at":"2026-10-10T00:00:00Z","code":"resync"}"#
    );
}

#[test]
fn sandbox_document_omits_unset_optional_members() {
    let document = SandboxDocument {
        id: "sb-1".into(),
        name: "sb".into(),
        namespace: "ns".into(),
        version: 1,
        status: Status {
            desired: DesiredState::Running,
            state: None,
            reason: None,
            created_at: "2026-10-10T00:00:00Z".into(),
            last_transition_at: "2026-10-10T00:00:00Z".into(),
            teardown: None,
        },
        config: ConfigRead {
            backend: "libkrun".into(),
            backend_options: None,
            network: NetworkRead::None { entries: None },
            mounts: None,
            env: None,
            main: None,
        },
    };
    assert_eq!(
        serde_json::to_value(&document).unwrap(),
        json!({
            "id": "sb-1",
            "name": "sb",
            "namespace": "ns",
            "version": 1,
            "status": {
                "desired": "running",
                "state": null,
                "created_at": "2026-10-10T00:00:00Z",
                "last_transition_at": "2026-10-10T00:00:00Z"
            },
            "config": {"backend": "libkrun", "network": {"mode": "none"}}
        })
    );
}

fn process_record(state: ProcessState) -> ProcessRecord {
    ProcessRecord {
        id: "p-1".into(),
        boot: 1,
        role: None,
        pid: None,
        command_spec: CommandSpecRead {
            command: vec!["sh".into()],
            env: EnvNames(vec!["A".into()]),
            cwd: "/".into(),
            uid: None,
            gid: None,
        },
        state,
        started_at: None,
        exited_at: None,
        interrupt_requested: false,
    }
}

#[test]
fn process_record_omits_unset_optional_members() {
    assert_eq!(
        serde_json::to_value(process_record(ProcessState::Running)).unwrap(),
        json!({
            "id": "p-1",
            "boot": 1,
            "command_spec": {"command": ["sh"], "env": ["A"], "cwd": "/"},
            "state": {"kind": "running"},
            "interrupt_requested": false
        })
    );
}

#[test]
fn lost_process_record_carries_teardown() {
    let record = process_record(ProcessState::Lost {
        teardown: "BestEffort".into(),
    });
    assert_eq!(
        serde_json::to_value(record).unwrap()["state"],
        json!({"kind": "lost", "teardown": "BestEffort"})
    );
}

#[test]
fn problem_omits_unset_optional_members() {
    let problem = CreateConflictProblem {
        problem_type: ConflictType::Conflict,
        title: None,
        status: None,
        detail: None,
        existing_id: "sb-1".into(),
    };
    assert_eq!(
        serde_json::to_value(problem).unwrap(),
        json!({"type": "https://playpencil.dev/problems/conflict", "existing_id": "sb-1"})
    );
}

fn list_query(uri: &str) -> Result<super::query::ListSandboxesQuery, String> {
    let uri: axum::http::Uri = uri.parse().unwrap();
    axum::extract::Query::<super::query::ListSandboxesQuery>::try_from_uri(&uri)
        .map(|q| q.0)
        .map_err(|e| e.body_text())
}

#[test]
fn state_filter_parses_a_comma_list() {
    use super::query::StateToken;
    let query = list_query("/v1/sandboxes?state=running,stopped,null").unwrap();
    assert_eq!(
        query.state,
        Some(vec![
            StateToken::Running,
            StateToken::Stopped,
            StateToken::Null
        ])
    );
    assert_eq!(list_query("/v1/sandboxes").unwrap().state, None);
    let err = list_query("/v1/sandboxes?state=running,bogus").unwrap_err();
    assert!(err.contains("unknown variant `bogus`"), "{err}");
}

#[test]
fn deny_destination_variants_serialize_their_members() {
    use super::event::{DenyDetails, Destination};
    for (destination, members) in [
        (
            Destination::Name {
                name: "a.com".into(),
            },
            json!({"name": "a.com"}),
        ),
        (
            Destination::Ip {
                ip: "192.0.2.1".into(),
            },
            json!({"ip": "192.0.2.1"}),
        ),
        (
            Destination::NameAndIp {
                name: "a.com".into(),
                ip: "192.0.2.1".into(),
            },
            json!({"name": "a.com", "ip": "192.0.2.1"}),
        ),
    ] {
        let details = DenyDetails {
            destination,
            port: 443,
            protocol: "tcp".into(),
            cause: "unmatched".into(),
            expired_pin: None,
        };
        let mut expected = json!({"port": 443, "protocol": "tcp", "cause": "unmatched"});
        expected
            .as_object_mut()
            .unwrap()
            .extend(members.as_object().unwrap().clone());
        assert_eq!(serde_json::to_value(&details).unwrap(), expected);
    }
}

#[test]
fn response_types_omit_unset_optional_members() {
    use super::event::{HostAddressesChangedDetails, PinRegisteredDetails};
    use super::problem::{
        InternalProblem, InternalType, InvalidInputProblem, InvalidInputType, NotFoundProblem,
        NotFoundType, PatchConflictProblem, Problem, ProcessConflictProblem,
    };
    use super::sandbox::Reason;

    let conflict = || ConflictType::Conflict;
    let cases: Vec<(Value, Value)> = vec![
        (
            serde_json::to_value(Reason {
                id: "r-1".into(),
                code: "crashed".into(),
                message: None,
            })
            .unwrap(),
            json!({"id": "r-1", "code": "crashed"}),
        ),
        (
            serde_json::to_value(Problem {
                problem_type: None,
                title: None,
                status: None,
                detail: None,
            })
            .unwrap(),
            json!({}),
        ),
        (
            serde_json::to_value(NotFoundProblem {
                problem_type: NotFoundType::NotFound,
                title: None,
                status: None,
                detail: None,
            })
            .unwrap(),
            json!({"type": "https://playpencil.dev/problems/not_found"}),
        ),
        (
            serde_json::to_value(InvalidInputProblem {
                problem_type: InvalidInputType::InvalidInput,
                title: None,
                status: None,
                detail: None,
                field: None,
                available_backends: None,
                entries: None,
                reason: None,
            })
            .unwrap(),
            json!({"type": "https://playpencil.dev/problems/invalid_input"}),
        ),
        (
            serde_json::to_value(PatchConflictProblem {
                problem_type: conflict(),
                title: None,
                status: None,
                detail: None,
                current_version: None,
                current_state: None,
                required_state: None,
                reason: None,
            })
            .unwrap(),
            json!({"type": "https://playpencil.dev/problems/conflict"}),
        ),
        (
            serde_json::to_value(ProcessConflictProblem {
                problem_type: conflict(),
                title: None,
                status: None,
                detail: None,
                current_state: None,
            })
            .unwrap(),
            json!({"type": "https://playpencil.dev/problems/conflict"}),
        ),
        (
            serde_json::to_value(InternalProblem {
                problem_type: InternalType::Internal,
                title: None,
                status: None,
                detail: None,
            })
            .unwrap(),
            json!({"type": "https://playpencil.dev/problems/internal"}),
        ),
        (
            serde_json::to_value(PinRegisteredDetails {
                name: "a.com".into(),
                addresses: vec!["192.0.2.1".into()],
                ports: vec!["443".into()],
                expires_at: "2026-10-10T00:00:00Z".into(),
                baseline: None,
            })
            .unwrap(),
            json!({
                "name": "a.com",
                "addresses": ["192.0.2.1"],
                "ports": ["443"],
                "expires_at": "2026-10-10T00:00:00Z"
            }),
        ),
        (
            serde_json::to_value(HostAddressesChangedDetails {
                addresses: vec!["192.0.2.1".into()],
                baseline: None,
            })
            .unwrap(),
            json!({"addresses": ["192.0.2.1"]}),
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(actual, expected);
    }
}

#[test]
fn conflict_current_state_distinguishes_absent_and_null() {
    use super::problem::{PatchConflictProblem, ProcessConflictProblem};
    let patch = |current_state| PatchConflictProblem {
        problem_type: ConflictType::Conflict,
        title: None,
        status: None,
        detail: None,
        current_version: None,
        current_state,
        required_state: Some("stopped".into()),
        reason: None,
    };
    let base = "https://playpencil.dev/problems/conflict";
    assert_eq!(
        serde_json::to_value(patch(Some(None))).unwrap(),
        json!({"type": base, "current_state": null, "required_state": "stopped"})
    );
    assert_eq!(
        serde_json::to_value(patch(Some(Some("running".into())))).unwrap(),
        json!({"type": base, "current_state": "running", "required_state": "stopped"})
    );
    assert_eq!(
        serde_json::to_value(patch(None)).unwrap(),
        json!({"type": base, "required_state": "stopped"})
    );
    let spawn = ProcessConflictProblem {
        problem_type: ConflictType::Conflict,
        title: None,
        status: None,
        detail: Some("the sandbox is not ready yet".into()),
        current_state: Some(None),
    };
    assert_eq!(
        serde_json::to_value(spawn).unwrap(),
        json!({"type": base, "detail": "the sandbox is not ready yet", "current_state": null})
    );
}

#[test]
fn request_structs_and_enums_accept_only_their_json_shape() {
    fn assert_invalid_type<T: DeserializeOwned + std::fmt::Debug>(value: Value) {
        let err = parse::<T>(value.clone()).expect_err(&format!("{value} must be rejected"));
        assert!(
            err.contains("invalid type"),
            "{value}: unexpected error {err}"
        );
    }
    assert_invalid_type::<PatchSandboxRequest>(json!([1]));
    assert_invalid_type::<CommandSpecWrite>(json!([["sh"], {}, "/"]));
    assert_invalid_type::<PatchSandboxRequest>(
        json!({"if_version": 1, "desired_state": {"running": null}}),
    );
    assert_invalid_type::<PatchSandboxRequest>(json!({"if_version": 1, "desired_state": 1}));
    assert_invalid_type::<NetworkWrite>(json!(["allowlist", ["a.com:443"]]));

    let mut create = create_body();
    create["config"] = json!(["libkrun", {}, {"mode": "none"}]);
    assert_invalid_type::<CreateSandboxRequest>(create);
    let mut create = create_body();
    create["config"]["mounts"][0] = json!(["/w", "/w", false]);
    assert_invalid_type::<CreateSandboxRequest>(create);
    let mut create = create_body();
    create["config"]["main"] = json!([["sh"], {}, "/"]);
    assert_invalid_type::<CreateSandboxRequest>(create);
    assert_invalid_type::<PatchSandboxRequest>(
        json!({"if_version": 1, "config": [{"mode": "none"}]}),
    );
}

#[test]
fn if_version_is_bounded_to_the_published_maximum() {
    let max = i64::MAX as u64;
    let patch: PatchSandboxRequest = parse(json!({"if_version": max})).unwrap();
    assert_eq!(patch.if_version, Some(max));
    let err = parse::<PatchSandboxRequest>(json!({"if_version": max + 1})).unwrap_err();
    assert!(err.contains("invalid value"), "{err}");
    let err = parse::<PatchSandboxRequest>(json!({"if_version": -1})).unwrap_err();
    assert!(err.contains("invalid value"), "{err}");
}

#[test]
fn empty_state_filter_is_rejected() {
    let err = list_query("/v1/sandboxes?state=").unwrap_err();
    assert!(err.contains("unknown variant ``"), "{err}");
}

#[test]
fn integer_members_reject_fraction_and_exponent_forms() {
    for raw in ["1.0", "1e0", "-0"] {
        let patch: Value = serde_json::from_str(&format!(r#"{{"if_version": {raw}}}"#)).unwrap();
        let err = parse::<PatchSandboxRequest>(patch).expect_err(raw);
        assert!(err.contains("invalid type"), "if_version {raw}: {err}");
        let spawn: Value = serde_json::from_str(&format!(
            r#"{{"command": ["sh"], "env": {{}}, "cwd": "/", "uid": {raw}}}"#
        ))
        .unwrap();
        let err = parse::<CommandSpecWrite>(spawn).expect_err(raw);
        assert!(err.contains("invalid type"), "uid {raw}: {err}");
    }
}
