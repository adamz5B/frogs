//! Path-item-level `parameters` are merged into every operation of the path (MCP plan, Step 1).

use super::*;
use std::path::PathBuf;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-openapi-pathparams-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn load_spec(components: &str, paths: &str) -> OpenApiDocument {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(
        &file,
        format!("openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\ncomponents:\n{components}paths:\n{paths}"),
    )
    .unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    doc
}

fn op<'a>(doc: &'a OpenApiDocument, path: &str, method: &str) -> &'a Operation {
    doc.operations
        .iter()
        .find(|o| o.path == path && o.method == method)
        .unwrap_or_else(|| panic!("no operation {method} {path}"))
}

fn names(op: &Operation) -> Vec<(&str, &str)> {
    op.parameters.iter().map(|p| (p.name.as_str(), p.location.as_str())).collect()
}

const OK: &str = "responses: { '200': { description: ok } }";

#[test]
fn a_path_level_parameter_reaches_every_operation_of_the_path() {
    let doc = load_spec(
        "",
        &format!(
            "  /cars/{{vin}}:\n    parameters:\n      - {{ name: vin, in: path, required: true, schema: {{ type: string }} }}\n    get:\n      operationId: g\n      {OK}\n    delete:\n      operationId: d\n      {OK}\n"
        ),
    );
    for method in ["get", "delete"] {
        let o = op(&doc, "/cars/{vin}", method);
        assert_eq!(names(o), [("vin", "path")], "{method}");
        assert!(o.parameters[0].required);
        assert_eq!(o.parameters[0].schema_type.as_deref(), Some("string"));
    }
}

#[test]
fn an_operation_level_parameter_replaces_the_path_level_one_with_the_same_name_and_location() {
    let doc = load_spec(
        "",
        &format!(
            "  /x:\n    parameters:\n      - {{ name: q, in: query, required: true, schema: {{ type: string }} }}\n      - {{ name: keep, in: query, schema: {{ type: string }} }}\n    get:\n      operationId: g\n      parameters:\n        - {{ name: q, in: query, required: false, schema: {{ type: integer }} }}\n      {OK}\n    post:\n      operationId: p\n      {OK}\n"
        ),
    );
    let g = op(&doc, "/x", "get");
    let q = g.parameters.iter().find(|p| p.name == "q").unwrap();
    assert!(!q.required, "the operation-level declaration wins");
    assert_eq!(q.schema_type.as_deref(), Some("integer"));
    assert_eq!(g.parameters.iter().filter(|p| p.name == "q").count(), 1, "replaced, not duplicated");
    assert!(g.parameters.iter().any(|p| p.name == "keep"));
    let p = op(&doc, "/x", "post");
    assert!(
        p.parameters.iter().find(|p| p.name == "q").unwrap().required,
        "a sibling operation keeps the path-level one"
    );
}

#[test]
fn the_same_name_in_a_different_location_is_not_an_override() {
    let doc = load_spec(
        "",
        &format!(
            "  /x:\n    parameters:\n      - {{ name: id, in: query, schema: {{ type: string }} }}\n    get:\n      operationId: g\n      parameters:\n        - {{ name: id, in: header, schema: {{ type: string }} }}\n      {OK}\n"
        ),
    );
    let mut got = names(op(&doc, "/x", "get"));
    got.sort();
    assert_eq!(got, [("id", "header"), ("id", "query")]);
}

#[test]
fn header_parameters_override_case_insensitively_but_query_names_stay_case_sensitive() {
    let doc = load_spec(
        "",
        &format!(
            "  /x:\n    parameters:\n      - {{ name: X-Trace, in: header, required: true, schema: {{ type: string }} }}\n      - {{ name: Q, in: query, schema: {{ type: string }} }}\n    get:\n      operationId: g\n      parameters:\n        - {{ name: x-trace, in: header, schema: {{ type: string }} }}\n        - {{ name: q, in: query, schema: {{ type: string }} }}\n      {OK}\n"
        ),
    );
    let got = names(op(&doc, "/x", "get"));
    assert_eq!(got.iter().filter(|(_, loc)| *loc == "header").count(), 1, "{got:?}");
    assert_eq!(got.iter().filter(|(_, loc)| *loc == "query").count(), 2, "{got:?}");
}

#[test]
fn a_path_level_parameter_ref_is_resolved_and_a_ref_d_path_item_carries_its_own_parameters() {
    let doc = load_spec(
        "  parameters:\n    Vin: { name: vin, in: path, required: true, schema: { type: string } }\n  pathItems:\n    CarItem:\n      parameters:\n        - $ref: '#/components/parameters/Vin'\n      get:\n        operationId: viaRef\n        responses: { '200': { description: ok } }\n",
        "  /cars/{vin}:\n    $ref: '#/components/pathItems/CarItem'\n",
    );
    let o = op(&doc, "/cars/{vin}", "get");
    assert_eq!(names(o), [("vin", "path")]);
    assert!(o.unresolved_parameter_refs.is_empty());
}

#[test]
fn additional_operations_get_the_path_level_parameters_too() {
    let doc = load_spec(
        "",
        &format!(
            "  /x:\n    parameters:\n      - {{ name: q, in: query, schema: {{ type: string }} }}\n    additionalOperations:\n      PURGE:\n        operationId: purge\n        {OK}\n"
        ),
    );
    let purge = doc.operations.iter().find(|o| o.operation_id == "purge").unwrap();
    assert_eq!(names(purge), [("q", "query")]);
}

#[test]
fn an_unresolved_path_level_ref_is_one_issue_recorded_on_every_operation_at_the_path() {
    let doc = load_spec(
        "",
        &format!(
            "  /x:\n    parameters:\n      - $ref: '#/components/parameters/Gone'\n    get:\n      operationId: g\n      {OK}\n    post:\n      operationId: p\n      {OK}\n    delete:\n      operationId: d\n      {OK}\n"
        ),
    );
    let issues: Vec<_> = doc.issues.iter().filter(|i| i.kind == IssueKind::ParameterRefUnresolved).collect();
    assert_eq!(issues.len(), 1, "reported once per path, not once per operation: {issues:?}");
    assert!(issues[0].message.contains("path '/x'"), "{}", issues[0].message);
    for method in ["get", "post", "delete"] {
        assert_eq!(
            op(&doc, "/x", method).unresolved_parameter_refs,
            ["#/components/parameters/Gone".to_string()],
            "{method}"
        );
    }
}

#[test]
fn an_operation_without_any_parameters_of_its_own_and_a_path_without_any_are_unchanged() {
    let doc = load_spec("", &format!("  /x:\n    get:\n      operationId: g\n      {OK}\n"));
    assert!(op(&doc, "/x", "get").parameters.is_empty());
    assert!(op(&doc, "/x", "get").unresolved_parameter_refs.is_empty());
}

#[test]
fn a_content_declared_parameter_keeps_its_schema_and_is_flagged_so_mcp_can_degrade_it() {
    let doc = load_spec(
        "",
        &format!(
            "  /x:\n    get:\n      operationId: g\n      parameters:\n        - {{ name: f, in: query, content: {{ application/json: {{ schema: {{ type: object }} }} }} }}\n      {OK}\n"
        ),
    );
    let p = &op(&doc, "/x", "get").parameters[0];
    assert!(p.from_content);
    assert_eq!(p.schema, Some(serde_json::json!({ "type": "object" })));
}

#[test]
fn summary_description_and_info_are_captured() {
    let doc = load_spec(
        "",
        &format!("  /x:\n    get:\n      operationId: g\n      summary: S\n      description: D\n      {OK}\n"),
    );
    let o = op(&doc, "/x", "get");
    assert_eq!(o.summary.as_deref(), Some("S"));
    assert_eq!(o.description.as_deref(), Some("D"));
    assert_eq!(doc.info_title.as_deref(), Some("t"));
    assert_eq!(doc.info_version.as_deref(), Some("1"));
}

#[test]
fn a_numeric_info_version_is_stringified_and_a_missing_one_is_none() {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(&file, "openapi: 3.2.0\ninfo: { title: t, version: 2.5 }\npaths: {}\n").unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    assert_eq!(doc.info_version.as_deref(), Some("2.5"));
    std::fs::write(&file, "openapi: 3.2.0\ninfo: { title: t }\npaths: {}\n").unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    assert_eq!(doc.info_version, None);
    let _ = std::fs::remove_dir_all(&dir);
}
