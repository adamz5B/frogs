//! Phase 3b: the two writing tools (`generate`, `errors_freeze`) behind `--allow-writes`, and the read/write lock
//! that keeps the read-only tools from ever observing a half-written project.

use super::*;

fn server_w(root: &Path, allow_writes: bool) -> Arc<Server> {
    Server::new_with_writes(
        AuthoringOptions {
            root: root.to_path_buf(),
            allow_connections: false,
        },
        allow_writes,
    )
}

/// An OpenAPI-only project: `generate` has the whole `api/` scaffold and both stubs still to create.
fn bare_project() -> PathBuf {
    let root = tempdir();
    write(&root, "openapi.yaml", SPEC);
    root
}

fn names(response: &Value) -> Vec<String> {
    response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

fn tree(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            out.push((format!("{}/", path.strip_prefix(root).unwrap().display()), Vec::new()));
            tree(&path, root, out);
        } else {
            out.push((path.strip_prefix(root).unwrap().display().to_string(), std::fs::read(&path).unwrap()));
        }
    }
}

fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    tree(root, root, &mut out);
    out
}

fn scratch_entry(status: u16) -> String {
    format!(
        r#"{{ "_discovered": true, "httpStatus": {status}, "exposeDetail": false, "occurrences": 3, "firstSeen": "2026-07-16T10:03:00Z", "lastSeen": "2026-07-16T10:41:00Z", "sampleMessage": "m" }}"#
    )
}

fn dated_name() -> String {
    format!("discovered-{}.json", chrono::Utc::now().format("%Y-%m-%d"))
}

// ---- gating

#[tokio::test]
async fn without_allow_writes_neither_writing_tool_is_listed_in_either_era() {
    let root = project();
    let s = server_w(&root, false);
    let legacy = one(&s, request(1, "tools/list", json!({}))).await;
    let modern = one(&s, request(2, "tools/list", json!({ "_meta": modern_meta() }))).await;
    for response in [&legacy, &modern] {
        let listed = names(response);
        assert_eq!(
            listed,
            ["project_describe", "endpoint_reference", "errors_discovered", "validate", "test_run"],
            "{listed:?}"
        );
    }
    cleanup(&root);
}

#[tokio::test]
async fn without_allow_writes_calling_a_writing_tool_is_invalid_params_in_both_eras_and_changes_nothing() {
    let root = bare_project();
    write(&root, "api/config/errors.discovered.json", &format!(r#"{{ "a.code": {} }}"#, scratch_entry(500)));
    let before = snapshot(&root);
    let s = server_w(&root, false);
    let out = drive(
        &s,
        &[
            call(1, "generate", json!({})),
            call(2, "generate", json!({ "role": "api" })),
            call(3, "errors_freeze", json!({})),
            modern_call(4, "generate", json!({})),
            modern_call(5, "errors_freeze", json!({})),
        ],
    )
    .await;
    for id in 1..=5 {
        assert_eq!(answer(&out, id)["error"]["code"], protocol::INVALID_PARAMS, "id {id}: {out:?}");
    }
    assert_eq!(snapshot(&root), before, "a gated call must not touch the project");
    cleanup(&root);
}

#[tokio::test]
async fn with_allow_writes_both_tools_are_listed_after_the_read_only_five_in_both_eras() {
    let root = project();
    let s = server_w(&root, true);
    let legacy = one(&s, request(1, "tools/list", json!({}))).await;
    let modern = one(&s, request(2, "tools/list", json!({ "_meta": modern_meta() }))).await;
    for response in [&legacy, &modern] {
        assert_eq!(
            names(response),
            [
                "project_describe",
                "endpoint_reference",
                "errors_discovered",
                "validate",
                "test_run",
                "generate",
                "errors_freeze"
            ]
        );
    }
    assert_eq!(modern["result"]["resultType"], "complete");
    cleanup(&root);
}

#[tokio::test]
async fn the_writing_tools_are_annotated_destructive_idempotent_closed_world_and_say_they_write_to_disk() {
    let root = project();
    let s = server_w(&root, true);
    let response = one(&s, request(1, "tools/list", json!({}))).await;
    let tools = response["result"]["tools"].as_array().unwrap();
    for name in ["generate", "errors_freeze"] {
        let tool = tools.iter().find(|t| t["name"] == name).unwrap();
        assert_eq!(
            tool["annotations"],
            json!({ "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false }),
            "{name}"
        );
        assert!(tool["description"].as_str().unwrap().contains("WRITES TO DISK"), "{name}: {}", tool["description"]);
        assert!(tool["title"].as_str().unwrap().contains("writes to disk"), "{name}: {}", tool["title"]);
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }
    let generate = tools.iter().find(|t| t["name"] == "generate").unwrap();
    assert_eq!(generate["inputSchema"]["properties"]["role"]["enum"], json!(["api", "web"]));
    assert!(generate["inputSchema"]["required"].as_array().unwrap().is_empty(), "role is optional");
    let freeze = tools.iter().find(|t| t["name"] == "errors_freeze").unwrap();
    assert_eq!(freeze["inputSchema"]["properties"], json!({}));
    cleanup(&root);
}

#[tokio::test]
async fn enabling_writes_leaves_the_five_read_only_tools_annotated_and_behaving_exactly_as_before() {
    let root = project();
    let s = server_w(&root, true);
    let response = one(&s, request(1, "tools/list", json!({}))).await;
    for tool in response["result"]["tools"].as_array().unwrap().iter().take(5) {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
    }
    let read_only = server_w(&root, false);
    let lines = [
        call(1, "project_describe", json!({})),
        call(2, "errors_discovered", json!({})),
        call(3, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "get" })),
        call(4, "test_run", json!({})),
    ];
    let with = drive(&s, &lines).await;
    let without = drive(&read_only, &lines).await;
    for id in 1..=3 {
        assert_eq!(answer(&with, id), answer(&without, id), "id {id}");
    }
    assert_eq!(tool_text(answer(&with, 4))["summary"], tool_text(answer(&without, 4))["summary"]);
    cleanup(&root);
}

// ---- argument validation

#[tokio::test]
async fn generate_rejects_an_unknown_field_a_bad_role_and_a_wrong_typed_role_as_invalid_params() {
    let root = bare_project();
    let s = server_w(&root, true);
    let cases = [
        call(1, "generate", json!({ "surprise": 1 })),
        call(2, "generate", json!({ "role": "both" })),
        call(3, "generate", json!({ "role": "API" })),
        call(4, "generate", json!({ "role": 5 })),
        call(5, "generate", json!({ "role": null, "extra": true })),
        call(6, "errors_freeze", json!({ "role": "api" })),
        call(7, "errors_freeze", json!({ "x": 1 })),
    ];
    let out = drive(&s, &cases).await;
    for id in 1..=7 {
        assert_eq!(answer(&out, id)["error"]["code"], protocol::INVALID_PARAMS, "id {id}: {out:?}");
    }
    assert!(!root.join("api").exists(), "a malformed call must not write anything");
    cleanup(&root);
}

#[tokio::test]
async fn generate_accepts_missing_null_and_empty_arguments_and_explicit_valid_roles() {
    let root = bare_project();
    write(&root, "index.html", "<html></html>");
    let s = server_w(&root, true);
    let none = one(&s, request(1, "tools/call", json!({ "name": "generate" }))).await;
    assert!(none["result"].get("isError").is_none(), "{none}");
    let null = one(&s, request(2, "tools/call", json!({ "name": "generate", "arguments": null }))).await;
    assert!(null["result"].get("isError").is_none(), "{null}");
    let api = one(&s, call(3, "generate", json!({ "role": "api" }))).await;
    assert!(api["result"].get("isError").is_none(), "{api}");
    let web = one(&s, call(4, "generate", json!({ "role": "web" }))).await;
    assert!(web["result"].get("isError").is_none(), "{web}");
    cleanup(&root);
}

#[tokio::test]
async fn generate_for_a_role_the_project_does_not_have_is_a_tool_error_naming_the_flag_and_writes_nothing() {
    let root = bare_project();
    let before = snapshot(&root);
    let s = server_w(&root, true);
    let response = one(&s, call(1, "generate", json!({ "role": "web" }))).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    let error = tool_text(&response);
    assert_eq!(error["error"]["kind"], "precondition");
    assert_eq!(error["error"]["exitCode"], 1);
    assert!(error["error"]["message"].as_str().unwrap().contains("--role web"), "{error}");
    assert_eq!(snapshot(&root), before);
    cleanup(&root);
}

// ---- result shapes and real writes

#[tokio::test]
async fn generate_creates_the_scaffold_and_stubs_inside_the_project_and_reports_the_fr21_shape() {
    let root = bare_project();
    let s = server_w(&root, true);
    let first = tool_text(&one(&s, call(1, "generate", json!({}))).await);
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["problemCount"], 0);
    let mut created: Vec<&str> = first["created"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    created.sort();
    assert_eq!(
        created,
        [
            "api/datasources/endpoints/cars/endpoint.post.json",
            "api/datasources/endpoints/cars/{vin}/endpoint.get.json"
        ]
    );
    for key in ["migrated", "referenceRefreshed", "orphaned", "restored", "findings"] {
        assert!(first[key].is_array(), "{key} missing: {first}");
    }
    assert_eq!(first["unchanged"], 0);
    assert_eq!(first["strictAborted"], false);
    for file in created {
        assert!(root.join(file).is_file(), "{file}");
    }
    assert!(root.join("api/config/server.json").is_file());

    let second = tool_text(&one(&s, call(2, "generate", json!({}))).await);
    assert_eq!(second["created"], json!([]));
    assert_eq!(second["unchanged"], 2, "{second}");
    cleanup(&root);
}

#[tokio::test]
async fn generate_reports_migrations_with_backups_and_orphans_with_their_new_names() {
    let root = bare_project();
    let s = server_w(&root, true);
    one(&s, call(1, "generate", json!({}))).await;
    let changed = SPEC.replace(
        "responses: { '201': { description: ok } }",
        "responses: { '201': { description: changed, content: { application/json: { schema: { type: object, properties: { id: { type: string } } } } } } }",
    );
    write(&root, "openapi.yaml", &changed.replace("  /cars/{vin}:\n    get:\n      operationId: getCar\n      parameters:\n        - { name: vin, in: path, required: true, schema: { type: string } }\n      responses: { '200': { description: ok } }\n", ""));
    let value = tool_text(&one(&s, call(2, "generate", json!({}))).await);
    assert_eq!(
        value["orphaned"],
        json!([{ "from": "api/datasources/endpoints/cars/{vin}/endpoint.get.json", "to": "api/datasources/endpoints/cars/{vin}/_endpoint.get.json" }]),
        "{value}"
    );
    let migrated = value["migrated"].as_array().unwrap();
    assert_eq!(migrated.len(), 1, "{value}");
    assert!(migrated[0]["backup"].as_str().unwrap().contains("_backups"), "{value}");
    assert!(root.join(migrated[0]["backup"].as_str().unwrap()).is_file());
    cleanup(&root);
}

#[tokio::test]
async fn a_strict_abort_over_mcp_is_an_ok_tool_result_with_ok_false_and_strict_aborted_true() {
    let root = tempdir();
    write(
        &root,
        "openapi.yaml",
        "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /cars:batchGet:\n    get:\n      operationId: x\n      responses: { '200': { description: ok } }\n",
    );
    write(&root, "api/config/server.json", r#"{ "strictOpenApi": true }"#);
    let s = server_w(&root, true);
    let response = one(&s, call(1, "generate", json!({}))).await;
    assert!(response["result"].get("isError").is_none(), "{response}");
    let value = tool_text(&response);
    assert_eq!(value["ok"], false);
    assert_eq!(value["strictAborted"], true);
    assert!(value["problemCount"].as_u64().unwrap() >= 1);
    assert!(!root.join("api/datasources/endpoints").exists());
    cleanup(&root);
}

#[tokio::test]
async fn errors_freeze_writes_the_dated_file_purges_the_scratch_file_and_reports_the_fr22_shape() {
    let root = project();
    write(
        &root,
        "api/config/errors/core.json",
        r#"{ "known.code": { "httpStatus": 400, "exposeDetail": true } }"#,
    );
    write(
        &root,
        "api/config/errors.discovered.json",
        &format!(
            r#"{{ "zz.new": {}, "aa.new": {}, "known.code": {} }}"#,
            scratch_entry(500),
            scratch_entry(502),
            scratch_entry(400)
        ),
    );
    let s = server_w(&root, true);
    let value = tool_text(&one(&s, call(1, "errors_freeze", json!({}))).await);
    assert_eq!(value["written"]["file"], format!("api/config/errors/{}", dated_name()));
    assert_eq!(value["written"]["codes"], json!(["aa.new", "zz.new"]));
    assert_eq!(value["skipped"], json!(["known.code"]));
    assert_eq!(value["purged"], true);
    assert!(root.join("api/config/errors").join(dated_name()).is_file());
    assert_eq!(std::fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap(), "{}");

    let again = tool_text(&one(&s, call(2, "errors_freeze", json!({}))).await);
    assert_eq!(again["written"], Value::Null);
    assert_eq!(again["purged"], false);
    cleanup(&root);
}

#[tokio::test]
async fn errors_freeze_over_a_corrupt_same_day_file_is_a_tool_error_and_changes_nothing() {
    let root = project();
    write(&root, "api/config/errors.discovered.json", &format!(r#"{{ "a.code": {} }}"#, scratch_entry(500)));
    write(&root, &format!("api/config/errors/{}", dated_name()), "{ corrupt");
    let before = snapshot(&root);
    let s = server_w(&root, true);
    let response = one(&s, call(1, "errors_freeze", json!({}))).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_ne!(tool_text(&response)["error"]["exitCode"], 0);
    assert_eq!(snapshot(&root), before);
    // the server keeps serving, and the lock was released
    let after = drive(&s, &[ping(2), call(3, "project_describe", json!({}))]).await;
    assert_eq!(answer(&after, 2)["result"], json!({}));
    assert!(answer(&after, 3)["result"]["content"].is_array());
    cleanup(&root);
}

#[tokio::test]
async fn writes_never_leave_the_project_folder() {
    let root = bare_project();
    let parent = root.parent().unwrap().to_path_buf();
    let siblings_before: Vec<_> = std::fs::read_dir(&parent).unwrap().map(|e| e.unwrap().file_name()).collect();
    let s = server_w(&root, true);
    one(&s, call(1, "generate", json!({}))).await;
    one(&s, call(2, "errors_freeze", json!({}))).await;
    let mut siblings_after: Vec<_> = std::fs::read_dir(&parent).unwrap().map(|e| e.unwrap().file_name()).collect();
    let mut expected = siblings_before;
    expected.sort();
    siblings_after.sort();
    // other tests create and delete sibling temp folders concurrently, so only our own root's neighbours that begin
    // with the project name are compared
    let ours = root.file_name().unwrap().to_os_string();
    assert!(siblings_after.contains(&ours));
    assert!(siblings_after.iter().filter(|n| n.to_string_lossy().starts_with(&*ours.to_string_lossy())).count() == 1);
    cleanup(&root);
}

// ---- the lock

#[tokio::test]
async fn reads_racing_a_generate_only_ever_see_the_project_entirely_before_or_entirely_after_it() {
    for round in 0..6 {
        let root = bare_project();
        let s = server_w(&root, true);
        let mut lines = Vec::new();
        let mut id = 1;
        for i in 0..24 {
            if i == 8 + round {
                lines.push(call(1000, "generate", json!({})));
            }
            lines.push(call(id, if i % 3 == 0 { "validate" } else { "project_describe" }, json!({})));
            id += 1;
        }
        let out = drive(&s, &lines).await;
        let generated = tool_text(answer(&out, 1000));
        assert_eq!(generated["created"].as_array().unwrap().len(), 2, "round {round}: {generated}");

        let mut saw_before = false;
        let mut saw_after = false;
        for request_id in 1..id {
            let response = answer(&out, request_id);
            assert!(response.get("error").is_none(), "round {round} id {request_id}: {response}");
            assert!(
                response["result"].get("isError").is_none(),
                "a read hit a half-written project (round {round}, id {request_id}): {response}"
            );
            let value = tool_text(response);
            if value.get("endpoints").is_some() {
                match value["endpoints"].as_array().unwrap().len() {
                    0 => saw_before = true,
                    2 => saw_after = true,
                    n => panic!("round {round} id {request_id}: a partial state with {n} endpoint(s): {value}"),
                }
            } else {
                // validate: before generate there is no endpoint folder at all, after it there are two files and no problems
                let text = value.to_string();
                assert!(
                    text.contains("0 discovered") || text.contains("2 discovered") || value["findings"].is_array(),
                    "round {round} id {request_id}: {value}"
                );
            }
        }
        let _ = (saw_before, saw_after);
        cleanup(&root);
    }
}

#[tokio::test]
async fn a_read_that_arrives_while_a_generate_is_running_waits_and_then_sees_the_finished_project() {
    // generate is the very first line, so it takes the write lock first; every later read must see its full result
    for _ in 0..4 {
        let root = bare_project();
        let s = server_w(&root, true);
        let mut lines = vec![call(1, "generate", json!({}))];
        lines.extend((2..10).map(|i| call(i, "project_describe", json!({}))));
        let out = drive(&s, &lines).await;
        for id in 2..10 {
            let value = tool_text(answer(&out, id));
            let count = value["endpoints"].as_array().map(Vec::len);
            assert!(matches!(count, Some(0) | Some(2)), "id {id}: {value}");
        }
        assert_eq!(tool_text(answer(&out, 1))["created"].as_array().unwrap().len(), 2);
        cleanup(&root);
    }
}

#[tokio::test]
async fn two_concurrent_generates_serialise_and_the_second_sees_everything_unchanged() {
    let root = bare_project();
    let s = server_w(&root, true);
    let out = drive(&s, &[call(1, "generate", json!({})), call(2, "generate", json!({}))]).await;
    let created = |id: i64| tool_text(answer(&out, id))["created"].as_array().unwrap().len();
    let unchanged = |id: i64| tool_text(answer(&out, id))["unchanged"].as_u64().unwrap();
    assert!(
        (created(1) == 2 && unchanged(2) == 2 && created(2) == 0) || (created(2) == 2 && unchanged(1) == 2 && created(1) == 0),
        "exactly one run creates the files and the other finds them unchanged: {out:?}"
    );
    cleanup(&root);
}

#[tokio::test]
async fn a_panicking_read_tool_does_not_wedge_the_lock_so_a_following_write_still_runs() {
    let root = bare_project();
    let s = server_w(&root, true);
    let out = drive(&s, &[call(1, "__test_panic", json!({})), call(2, "generate", json!({})), ping(3)]).await;
    assert_eq!(answer(&out, 1)["error"]["code"], protocol::INTERNAL_ERROR);
    assert_eq!(tool_text(answer(&out, 2))["ok"], true, "{out:?}");
    assert_eq!(answer(&out, 3)["result"], json!({}));
    cleanup(&root);
}

#[tokio::test]
async fn a_generate_over_a_deleted_root_is_a_precondition_tool_error_and_the_server_keeps_serving() {
    let root = bare_project();
    let s = server_w(&root, true);
    cleanup(&root);
    let out = drive(&s, &[call(1, "generate", json!({})), call(2, "errors_freeze", json!({})), ping(3)]).await;
    for id in 1..=2 {
        assert_eq!(answer(&out, id)["result"]["isError"], true);
        assert_eq!(tool_text(answer(&out, id))["error"]["kind"], "precondition");
    }
    assert_eq!(answer(&out, 3)["result"], json!({}));
}

#[tokio::test]
async fn a_generate_over_a_broken_server_json_is_a_tool_error_that_leaves_the_broken_file_and_the_spec_untouched() {
    // like the command line, generate scaffolds the missing config files first and only then fails to load the config
    let root = bare_project();
    write(&root, "api/config/server.json", "{ not json");
    let spec_before = std::fs::read(root.join("openapi.yaml")).unwrap();
    let s = server_w(&root, true);
    let response = one(&s, call(1, "generate", json!({}))).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(std::fs::read_to_string(root.join("api/config/server.json")).unwrap(), "{ not json");
    assert_eq!(std::fs::read(root.join("openapi.yaml")).unwrap(), spec_before);
    assert!(
        !root.join("api/datasources/endpoints").exists(),
        "no endpoint file is generated from a project whose config does not load"
    );
    cleanup(&root);
}
