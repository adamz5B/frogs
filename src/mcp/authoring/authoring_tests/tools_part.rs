//! The five tools themselves, driven through the same in-process transport (see the parent module for the harness).

use super::*;

// ---- project_describe / secrets

#[tokio::test]
async fn project_describe_returns_names_and_drivers_only_never_connection_settings() {
    let root = project_with(
        SERVER_JSON,
        r#"{ "db": { "driver": "postgres", "host": "internal-host.example", "database": "vehicles", "user": "svc-user", "passwordEnv": "SECRET_ENV_NAME" } }"#,
    );
    write(&root, "api/security/schemes.json", r#"{ "apiKeyAuth": { "verifier": "k.json" } }"#);
    write(
        &root,
        "api/security/verifiers/k.json",
        r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [ { "name": "k", "from": "header.Authorization" } ], "validIf": "row.active = true" }"#,
    );
    write(&root, "api/datasources/sql/db/verify.sql", "SELECT 1 AS active;");
    let s = server(&root, false);
    let response = one(&s, call(1, "project_describe", json!({}))).await;
    let text = response["result"]["content"][0]["text"].as_str().unwrap().to_string();
    let value = tool_text(&response);
    assert_eq!(value["connections"], json!([{ "name": "db", "driver": "postgres" }]));
    assert_eq!(value["schemes"], json!(["apiKeyAuth"]));
    assert_eq!(value["roles"], json!({ "api": true, "web": false }));
    for secret in ["internal-host.example", "svc-user", "SECRET_ENV_NAME", "passwordEnv"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    let endpoints = value["endpoints"].as_array().unwrap();
    let get = endpoints.iter().find(|e| e["path"] == "/cars/{vin}").expect("the GET endpoint is listed");
    assert_eq!(get["hasTestFile"], true);
    assert_eq!(get["hasReferenceFile"], true);
    let post = endpoints.iter().find(|e| e["path"] == "/cars").unwrap();
    assert_eq!(post["hasReferenceFile"], false);
    assert_eq!(value["spec"]["loaded"], true);
    assert_eq!(value["spec"]["operationCount"], 2);
    cleanup(&root);
}

#[tokio::test]
async fn project_describe_of_a_web_only_project_reports_the_role_and_no_api_fields() {
    let root = tempdir();
    write(&root, "index.html", "<html></html>");
    write(&root, "webserve.json", r#"{ "startPage": "index.html" }"#);
    let s = server(&root, false);
    let value = tool_text(&one(&s, call(1, "project_describe", json!({}))).await);
    assert_eq!(value["roles"], json!({ "api": false, "web": true }));
    assert!(value.get("connections").is_none());
    cleanup(&root);
}

// ---- endpoint_reference containment

#[tokio::test]
async fn endpoint_reference_returns_the_generated_reference_for_an_exact_path_and_method() {
    let root = project();
    let s = server(&root, false);
    let response = one(&s, call(1, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "get" }))).await;
    let value = tool_text(&response);
    assert!(response["result"].get("isError").is_none(), "{response}");
    assert_eq!(value["reference"], json!({ "marker": "REFERENCE-OF-GET-CAR" }));
    assert_eq!(value["path"], "/cars/{vin}");
    assert!(value["file"].as_str().unwrap().ends_with("endpoint.get.reference.json"));
    // method case is insensitive by default (caseSensitiveMethods unset)
    let upper = one(&s, call(2, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "GET" }))).await;
    assert!(upper["result"].get("isError").is_none(), "{upper}");
    cleanup(&root);
}

#[tokio::test]
async fn endpoint_reference_never_reads_outside_the_endpoint_tree_for_traversal_absolute_encoded_or_case_variant_paths() {
    let root = project();
    const MARKER: &str = "SENTINEL-MUST-NEVER-BE-READ";
    // sentinels placed where each traversal flavour would land if the argument were ever joined onto a path
    for relative in [
        "sentinel/endpoint.get.reference.json",
        "api/sentinel/endpoint.get.reference.json",
        "api/datasources/sentinel/endpoint.get.reference.json",
    ] {
        write(&root, relative, &format!(r#"{{ "secret": "{MARKER}" }}"#));
    }
    let outside = tempdir();
    write(&outside, "endpoint.get.reference.json", &format!(r#"{{ "secret": "{MARKER}" }}"#));
    let absolute_outside = outside.display().to_string();
    let absolute_ref = outside.join("endpoint.get.reference.json").display().to_string();

    let paths = vec![
        "../sentinel".to_string(),
        "/../sentinel".to_string(),
        "/cars/../../sentinel".to_string(),
        "/cars/{vin}/../../../../sentinel".to_string(),
        "../../../../sentinel".to_string(),
        "/..\\sentinel".to_string(),
        "..\\..\\sentinel".to_string(),
        "/%2e%2e/sentinel".to_string(),
        "/%2E%2E/%2E%2E/sentinel".to_string(),
        "/cars/%2e%2e/%2e%2e/sentinel".to_string(),
        "/cars/%2e%2e%2fsentinel".to_string(),
        "/..%2fsentinel".to_string(),
        "/sentinel".to_string(),
        "sentinel".to_string(),
        absolute_outside.clone(),
        absolute_ref.clone(),
        format!("{absolute_outside}/"),
        "/etc/passwd".to_string(),
        "C:\\Windows\\win.ini".to_string(),
        "\\\\server\\share".to_string(),
        "".to_string(),
        "/".to_string(),
        // case variants and near misses of a real route
        "/CARS/{vin}".to_string(),
        "/Cars/{vin}".to_string(),
        "/cars/{VIN}".to_string(),
        "/cars/{vin}/".to_string(),
        "/cars/{vin}/endpoint.get.reference.json".to_string(),
        "/cars/%7Bvin%7D".to_string(),
        "/cars/1HGCM82633A004352".to_string(),
        "cars/{vin}".to_string(),
        "/cars/{vin}\u{0}".to_string(),
    ];
    let s = server(&root, false);
    let mut lines = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        lines.push(call(i as i64 + 1, "endpoint_reference", json!({ "path": path, "method": "get" })));
    }
    let out = drive(&s, &lines).await;
    assert_eq!(out.len(), paths.len());
    for (i, path) in paths.iter().enumerate() {
        let response = answer(&out, i as i64 + 1);
        assert_eq!(response["result"]["isError"], true, "path {path:?} must not resolve: {response}");
        let error = tool_text(response);
        assert_eq!(error["error"]["kind"], "notFound", "path {path:?}: {response}");
        assert!(!response.to_string().contains(MARKER), "path {path:?} read the sentinel");
    }
    cleanup(&root);
    cleanup(&outside);
}

#[tokio::test]
async fn endpoint_reference_method_case_variants_are_not_found_when_methods_are_case_sensitive() {
    let root = project();
    write(
        &root,
        "api/config/server.json",
        r#"{ "caseSensitiveMethods": true, "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#,
    );
    let s = server(&root, false);
    let exact = one(&s, call(1, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "GET" }))).await;
    assert!(exact["result"].get("isError").is_none(), "{exact}");
    let variant = one(&s, call(2, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "get" }))).await;
    assert_eq!(variant["result"]["isError"], true, "{variant}");
    cleanup(&root);
}

#[tokio::test]
async fn endpoint_reference_with_a_method_that_would_spell_a_sibling_file_name_is_not_found() {
    let root = project();
    let s = server(&root, false);
    for method in ["get.reference", "get.test", "get.reference.json"] {
        let response = one(&s, call(1, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": method }))).await;
        assert_eq!(response["result"]["isError"], true, "{method}: {response}");
        assert_eq!(tool_text(&response)["error"]["kind"], "notFound", "{method}");
    }
    cleanup(&root);
}

#[tokio::test]
async fn endpoint_reference_for_a_missing_or_corrupt_or_oversized_reference_file_is_a_tool_error_not_a_crash() {
    let root = project();
    write(&root, "api/datasources/endpoints/cars/endpoint.post.reference.json", "{ broken");
    let s = server(&root, false);
    let missing_method = one(&s, call(1, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "delete" }))).await;
    assert_eq!(tool_text(&missing_method)["error"]["kind"], "notFound");
    assert!(tool_text(&missing_method)["error"]["message"].as_str().unwrap().contains("frogs generate"));
    let corrupt = one(&s, call(2, "endpoint_reference", json!({ "path": "/cars", "method": "post" }))).await;
    assert_eq!(corrupt["result"]["isError"], true);
    assert_eq!(tool_text(&corrupt)["error"]["kind"], "parse");
    let big = format!(r#"{{ "x": "{}" }}"#, "a".repeat(1024 * 1024 + 16));
    write(&root, "api/datasources/endpoints/cars/endpoint.post.reference.json", &big);
    let oversized = one(&s, call(3, "endpoint_reference", json!({ "path": "/cars", "method": "post" }))).await;
    assert_eq!(tool_text(&oversized)["error"]["kind"], "tooLarge");
    cleanup(&root);
}

// ---- errors_discovered / redaction

fn discovered_entry(status: u16, message: &str) -> String {
    format!(
        r#"{{ "_discovered": true, "httpStatus": {status}, "exposeDetail": false, "occurrences": 3, "firstSeen": "2026-07-16T10:03:00Z", "lastSeen": "2026-07-16T10:41:00Z", "sampleMessage": {} }}"#,
        serde_json::to_string(message).unwrap()
    )
}

#[tokio::test]
async fn errors_discovered_of_a_project_with_no_scratch_file_is_an_empty_list_and_writes_nothing() {
    let root = project();
    let s = server(&root, false);
    let value = tool_text(&one(&s, call(1, "errors_discovered", json!({}))).await);
    assert_eq!(value, json!({ "corrupt": false, "entries": [] }));
    assert!(!root.join("api/config/errors.discovered.json").exists());
    cleanup(&root);
}

#[tokio::test]
async fn errors_discovered_lists_entries_sorted_by_code_with_registry_membership() {
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
            r#"{{ "zzz.last": {}, "known.code": {}, "aaa.first": {} }}"#,
            discovered_entry(500, "z"),
            discovered_entry(400, "k"),
            discovered_entry(502, "a")
        ),
    );
    let s = server(&root, false);
    let value = tool_text(&one(&s, call(1, "errors_discovered", json!({}))).await);
    let entries = value["entries"].as_array().unwrap();
    let codes: Vec<&str> = entries.iter().map(|e| e["code"].as_str().unwrap()).collect();
    assert_eq!(codes, ["aaa.first", "known.code", "zzz.last"]);
    assert_eq!(entries[1]["alreadyInRegistry"], true);
    assert_eq!(entries[0]["alreadyInRegistry"], false);
    assert_eq!(entries[0]["occurrences"], 3);
    cleanup(&root);
}

#[tokio::test]
async fn a_corrupt_discovered_file_is_reported_as_corrupt_without_being_repaired_or_replaced() {
    let root = project();
    write(&root, "api/config/errors.discovered.json", "{ not json at all");
    let s = server(&root, false);
    let value = tool_text(&one(&s, call(1, "errors_discovered", json!({}))).await);
    assert_eq!(value["corrupt"], true);
    assert!(value["message"].as_str().unwrap().contains("line"));
    assert_eq!(std::fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap(), "{ not json at all");
    cleanup(&root);
}

#[tokio::test]
async fn a_long_sample_message_is_truncated_and_a_url_password_in_it_is_redacted() {
    let root = project();
    let message = format!("connect failed postgres://svc:hunter2-pw@db.internal:5432/x password=topsecret1 {}", "x".repeat(5000));
    write(
        &root,
        "api/config/errors.discovered.json",
        &format!(r#"{{ "db.fail": {} }}"#, discovered_entry(500, &message)),
    );
    let s = server(&root, false);
    let response = one(&s, call(1, "errors_discovered", json!({}))).await;
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains("hunter2-pw"), "{text}");
    assert!(!text.contains("topsecret1"), "{text}");
    assert!(text.contains("svc:***@db.internal"), "{text}");
    let sample = tool_text(&response)["entries"][0]["sampleMessage"].as_str().unwrap().to_string();
    assert!(sample.chars().count() <= 500, "sampleMessage is {} chars", sample.chars().count());
    cleanup(&root);
}

#[test]
fn redact_masks_url_userinfo_passwords_and_password_parameters_but_leaves_other_text_alone() {
    use crate::mcp::authoring::redact::redact;
    assert_eq!(redact("postgres://user:secret@host:5432/db"), "postgres://user:***@host:5432/db");
    assert_eq!(
        redact("https://u:p%40ss@h/x?y=1 and https://other:pw@h2/"),
        "https://u:***@h/x?y=1 and https://other:***@h2/"
    );
    assert_eq!(
        redact("Server=db;User Id=sa;Password=hunter2;Database=x"),
        "Server=db;User Id=sa;Password=***;Database=x"
    );
    assert_eq!(redact("pwd=abc&other=1"), "pwd=***&other=1");
    assert_eq!(redact("ftp://anonymous@host/file"), "ftp://anonymous@host/file");
    assert_eq!(redact("nothing sensitive here"), "nothing sensitive here");
    assert_eq!(redact("mypassword is fine"), "mypassword is fine");
    assert_eq!(redact("日本語 postgres://ü:pä@h/d 終わり"), "日本語 postgres://ü:***@h/d 終わり");
}

#[test]
fn redact_masks_a_password_value_even_when_spaces_surround_the_equals_sign() {
    use crate::mcp::authoring::redact::redact;
    let out = redact("login failed: PASSWORD = spacedsecret end");
    assert!(!out.contains("spacedsecret"), "the value after `= ` leaked: {out}");
}

// ---- validate

#[tokio::test]
async fn validate_without_allow_connections_skips_sql_leaves_an_absent_sqlite_file_absent_and_reports_one_note() {
    let root = project();
    let db = root.join("never-created.sqlite");
    let s = server(&root, false);
    let value = tool_text(&one(&s, call(1, "validate", json!({}))).await);
    assert_eq!(value["connections"], "skipped");
    assert!(!db.exists(), "a read-only validate must not create the sqlite file");
    let notes: Vec<&Value> = value["findings"].as_array().unwrap().iter().filter(|f| f["severity"] == "note").collect();
    assert_eq!(notes.len(), 1, "skipping is exactly one note finding: {value}");
    assert!(value["problemCount"].is_number());
    cleanup(&root);
}

#[tokio::test]
async fn validate_with_allow_connections_but_without_the_argument_still_skips_connections() {
    let root = project();
    let db = root.join("never-created.sqlite");
    let s = server(&root, true);
    let value = tool_text(&one(&s, call(1, "validate", json!({}))).await);
    assert_eq!(value["connections"], "skipped");
    assert!(!db.exists());
    let explicit_false = tool_text(&one(&s, call(2, "validate", json!({ "checkConnections": false }))).await);
    assert_eq!(explicit_false["connections"], "skipped");
    assert!(!db.exists());
    cleanup(&root);
}

#[tokio::test]
async fn validate_with_check_connections_true_reports_connections_as_checked() {
    let root = project_with(SERVER_JSON, r#"{ "db": { "driver": "nosuchdriver" } }"#);
    let s = server(&root, true);
    let value = tool_text(&one(&s, call(1, "validate", json!({ "checkConnections": true }))).await);
    assert_eq!(value["connections"], "checked");
    assert_eq!(value["ok"], false);
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["problem"] == true && f["message"].as_str().unwrap().contains("nosuchdriver")),
        "{value}"
    );
    cleanup(&root);
}

#[tokio::test]
async fn validate_and_test_run_make_no_outbound_http_request_even_when_sources_point_at_a_live_local_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = project();
    write(
        &root,
        "api/datasources/http/upstream.json",
        &format!(r#"{{ "method": "GET", "url": "http://127.0.0.1:{port}/probe" }}"#),
    );
    let s = server(&root, false);
    let validated = one(&s, call(1, "validate", json!({}))).await;
    assert!(validated.get("error").is_none(), "{validated}");
    let tested = one(&s, call(2, "test_run", json!({}))).await;
    assert!(tested.get("error").is_none(), "{tested}");
    std::thread::sleep(Duration::from_millis(300));
    match listener.accept() {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("a read-only tool dialled the local listener"),
        Err(e) => panic!("unexpected accept error: {e}"),
    }
    cleanup(&root);
}

// ---- test_run

async fn test_run(root: &Path, arguments: Value) -> Value {
    let s = server(root, false);
    let response = one(&s, call(1, "test_run", arguments)).await;
    assert!(response.get("error").is_none(), "{response}");
    assert!(response["result"].get("isError").is_none(), "{response}");
    tool_text(&response)
}

fn entry_for<'a>(value: &'a Value, case: &str) -> &'a Value {
    value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["case"] == case)
        .unwrap_or_else(|| panic!("no entry for case {case}: {}", value["entries"]))
}

#[tokio::test]
async fn test_run_reports_pass_and_fail_verdicts_for_driven_cases() {
    let root = project();
    let value = test_run(&root, json!({})).await;
    assert_eq!(entry_for(&value, "passes")["verdict"], "pass", "{value}");
    assert_eq!(entry_for(&value, "fails")["verdict"], "fail", "{value}");
    assert!(value["summary"]["passed"].as_u64().unwrap() >= 1);
    assert!(value["summary"]["failed"].as_u64().unwrap() >= 1);
    assert_eq!(value["ok"], false, "a failing case makes the run not ok");
    cleanup(&root);
}

#[tokio::test]
async fn test_run_lists_a_case_with_no_value_for_a_path_parameter_as_undrivable_with_a_reason() {
    let root = project();
    let value = test_run(&root, json!({})).await;
    let undrivable = value["undrivable"].as_array().unwrap();
    assert_eq!(undrivable.len(), 1, "{value}");
    assert_eq!(undrivable[0]["case"], "no path value");
    assert!(undrivable[0]["reason"].as_str().unwrap().contains("vin"));
    assert_eq!(value["summary"]["undrivable"], 1);
    cleanup(&root);
}

#[tokio::test]
async fn test_run_flags_a_case_that_the_selector_serves_from_a_sibling_as_selected_other() {
    let root = project();
    let value = test_run(&root, json!({})).await;
    let other = value["selectedOther"].as_array().unwrap();
    assert_eq!(other.len(), 1, "{value}");
    assert_eq!(other[0]["case"], "dupB");
    assert_eq!(other[0]["selectedOther"]["name"], "dupA");
    assert_eq!(value["summary"]["selectedOther"], 1);
    cleanup(&root);
}

#[tokio::test]
async fn test_run_carries_saved_memory_from_an_earlier_route_into_a_later_cases_path() {
    let root = project();
    let value = test_run(&root, json!({})).await;
    assert_eq!(entry_for(&value, "create")["verdict"], "pass", "{value}");
    assert_eq!(
        entry_for(&value, "read back")["verdict"],
        "pass",
        "memory.vin saved by the POST must reach the GET: {value}"
    );
    cleanup(&root);
}

#[tokio::test]
async fn test_run_sends_the_scenario_header_only_for_scenario_tagged_cases() {
    let root = project();
    let value = test_run(&root, json!({})).await;
    assert_eq!(
        entry_for(&value, "premium")["verdict"],
        "pass",
        "the premium mock is only served when X-Frogs-Scenario is sent: {value}"
    );
    assert_eq!(
        entry_for(&value, "baseline")["verdict"],
        "pass",
        "an untagged case must not be served by the scenario case: {value}"
    );
    cleanup(&root);
}

#[tokio::test]
async fn test_run_filters_are_exact_and_an_unknown_scenario_is_a_tool_error() {
    let root = project();
    let only_premium = test_run(&root, json!({ "scenario": "premium" })).await;
    assert_eq!(only_premium["entries"].as_array().unwrap().len(), 1, "{only_premium}");
    let only_post = test_run(&root, json!({ "path": "/cars", "method": "post" })).await;
    assert_eq!(only_post["entries"].as_array().unwrap().len(), 1);
    assert_eq!(entry_for(&only_post, "create")["verdict"], "pass");
    let wrong_path = test_run(&root, json!({ "path": "/car" })).await;
    assert_eq!(wrong_path["entries"].as_array().unwrap().len(), 0);
    let s = server(&root, false);
    let unknown = one(&s, call(1, "test_run", json!({ "scenario": "does-not-exist" }))).await;
    assert_eq!(unknown["result"]["isError"], true, "{unknown}");
    cleanup(&root);
}

#[tokio::test]
async fn test_run_never_dials_real_infrastructure_for_an_unmocked_source_and_reports_not_mocked() {
    let root = project();
    write(
        &root,
        "api/datasources/endpoints/cars/{vin}/endpoint.get.test.json",
        r#"{ "cases": [ { "name": "unmocked", "request": { "path": { "vin": "U1" } }, "expect": { "status": 200 } } ] }"#,
    );
    let value = test_run(&root, json!({ "path": "/cars/{vin}" })).await;
    assert_eq!(value["summary"]["notMocked"], 1, "{value}");
    assert!(!value.to_string().contains("REAL"));
    assert!(!root.join("never-created.sqlite").exists());
    cleanup(&root);
}

#[tokio::test]
async fn test_run_under_debug_mode_returns_unregistered_codes_but_never_writes_the_discovered_file_or_a_pidfile() {
    let root = project();
    write(&root, "api/config/server.json", DEBUG_SERVER_JSON);
    write(
        &root,
        "api/datasources/endpoints/cars/{vin}/endpoint.get.test.json",
        r#"{ "cases": [ { "name": "weird failure", "request": { "path": { "vin": "W1" } }, "mocks": { "car": { "fail": "custom.never_registered_code" } }, "expect": { "status": 500 } } ] }"#,
    );
    let value = test_run(&root, json!({ "path": "/cars/{vin}" })).await;
    let codes: Vec<&str> = value["discoveredCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert!(!codes.is_empty(), "the unregistered code is reported in the result: {value}");
    assert!(!root.join("api/config/errors.discovered.json").exists(), "the scratch file must stay absent");
    assert!(!root.join(".frogs/run.json").exists(), "no pidfile");
    cleanup(&root);
}

#[tokio::test]
async fn the_read_only_tools_leave_the_whole_project_tree_byte_identical_even_under_debug_mode() {
    fn snapshot(dir: &Path, out: &mut Vec<(String, Vec<u8>)>, root: &Path) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                out.push((format!("{}/", path.strip_prefix(root).unwrap().display()), Vec::new()));
                snapshot(&path, out, root);
            } else {
                out.push((path.strip_prefix(root).unwrap().display().to_string(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let root = project();
    write(&root, "api/config/server.json", DEBUG_SERVER_JSON);
    let mut before = Vec::new();
    snapshot(&root, &mut before, &root);
    let s = server(&root, false);
    let _ = drive(
        &s,
        &[
            call(1, "project_describe", json!({})),
            call(2, "validate", json!({})),
            call(3, "test_run", json!({})),
            call(4, "errors_discovered", json!({})),
            call(5, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "get" })),
        ],
    )
    .await;
    let mut after = Vec::new();
    snapshot(&root, &mut after, &root);
    assert_eq!(before, after, "the read-only tools must not change any project file or create any folder");
    cleanup(&root);
}

#[tokio::test]
async fn test_run_of_a_malformed_test_file_is_a_tool_error_with_a_nonzero_exit_code() {
    let root = project();
    write(&root, "api/datasources/endpoints/cars/{vin}/endpoint.get.test.json", "{ not json");
    let s = server(&root, false);
    let response = one(&s, call(1, "test_run", json!({}))).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(tool_text(&response)["error"]["exitCode"].as_i64().unwrap() != 0);
    cleanup(&root);
}
