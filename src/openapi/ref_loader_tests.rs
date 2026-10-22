//! Loader behaviour for `$ref`s in parameters, request bodies, responses and path items, plus
//! RFC 6901 escapes in every existing local-ref site.

use super::*;
use std::path::PathBuf;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-openapi-refs-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\n";
const SECURITY_SCHEMES: &str = "  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\n    b: { type: apiKey, in: header, name: kb }\n";

/// `components` is the indented body under `components:` (without the securitySchemes block).
fn load_spec(components: &str, paths: &str) -> OpenApiDocument {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(&file, format!("{HEAD}components:\n{SECURITY_SCHEMES}{components}paths:\n{paths}")).unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    doc
}

fn load_spec_result(components: &str, paths: &str) -> Result<OpenApiDocument, OpenApiError> {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(&file, format!("{HEAD}components:\n{SECURITY_SCHEMES}{components}paths:\n{paths}")).unwrap();
    let doc = load(&file, LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    doc
}

fn kinds(doc: &OpenApiDocument) -> Vec<IssueKind> {
    doc.issues.iter().map(|i| i.kind).collect()
}

fn count(doc: &OpenApiDocument, kind: IssueKind) -> usize {
    doc.issues.iter().filter(|i| i.kind == kind).count()
}

fn op<'a>(doc: &'a OpenApiDocument, path: &str, method: &str) -> &'a Operation {
    doc.operations.iter().find(|o| o.path == path && o.method == method).unwrap_or_else(|| {
        panic!(
            "no operation {method} {path}: {:?}",
            doc.operations.iter().map(|o| (&o.path, &o.method)).collect::<Vec<_>>()
        )
    })
}

fn get_with(extra: &str) -> String {
    format!("  /x:\n    get:\n      operationId: getX\n{extra}      responses: {{ '200': {{ description: ok }} }}\n")
}

// ------------------------------------------------------------------- T-6 parameters

#[test]
fn a_parameter_ref_contributes_name_location_required_and_type_like_an_inline_parameter() {
    let doc = load_spec(
        "  parameters:\n    Limit: { name: limit, in: query, required: true, schema: { type: integer } }\n",
        &get_with("      parameters:\n        - $ref: '#/components/parameters/Limit'\n"),
    );
    let inline = load_spec(
        "",
        &get_with("      parameters:\n        - { name: limit, in: query, required: true, schema: { type: integer } }\n"),
    );
    assert_eq!(op(&doc, "/x", "get").parameters, op(&inline, "/x", "get").parameters);
    assert_eq!(
        op(&doc, "/x", "get").parameters,
        vec![ParameterInfo {
            name: "limit".into(),
            location: "query".into(),
            required: true,
            schema_type: Some("integer".into())
        }]
    );
    assert!(op(&doc, "/x", "get").unresolved_parameter_refs.is_empty());
    assert!(doc.issues.is_empty(), "{:?}", doc.issues);
}

#[test]
fn a_chained_parameter_ref_resolves_through_every_hop() {
    let doc = load_spec(
        "  parameters:\n    A: { $ref: '#/components/parameters/B' }\n    B: { name: id, in: path, required: true, schema: { type: string } }\n",
        &get_with("      parameters:\n        - $ref: '#/components/parameters/A'\n"),
    );
    assert_eq!(op(&doc, "/x", "get").parameters[0].name, "id");
    assert!(doc.issues.is_empty(), "{:?}", doc.issues);
}

#[test]
fn a_parameter_ref_whose_target_takes_its_type_from_a_content_media_type_ref() {
    let doc = load_spec(
        "  mediaTypes:\n    Num: { schema: { type: integer } }\n  parameters:\n    P: { name: n, in: query, content: { application/json: { $ref: '#/components/mediaTypes/Num' } } }\n",
        &get_with("      parameters:\n        - $ref: '#/components/parameters/P'\n"),
    );
    assert_eq!(op(&doc, "/x", "get").parameters[0].schema_type.as_deref(), Some("integer"));
}

// ------------------------------------------------------------------- T-7 unresolved parameters

#[test]
fn an_unknown_parameter_ref_raises_one_issue_leaves_the_parameter_out_and_records_the_raw_ref() {
    let doc = load_spec("", &get_with("      parameters:\n        - $ref: '#/components/parameters/Missing'\n"));
    assert_eq!(count(&doc, IssueKind::ParameterRefUnresolved), 1);
    let issue = doc.issues.iter().find(|i| i.kind == IssueKind::ParameterRefUnresolved).unwrap();
    assert_eq!(issue.severity, Severity::Error);
    assert!(issue.message.contains("#/components/parameters/Missing"), "{}", issue.message);
    assert!(issue.message.contains("unknown parameter 'Missing'"), "{}", issue.message);
    assert!(issue.message.contains("the parameter is unknown"), "{}", issue.message);
    let o = op(&doc, "/x", "get");
    assert!(o.parameters.is_empty());
    assert_eq!(o.unresolved_parameter_refs, vec!["#/components/parameters/Missing".to_string()]);
}

#[test]
fn a_parameter_ref_to_an_object_with_no_name_or_in_is_unresolved_while_an_inline_one_stays_silently_skipped() {
    let doc = load_spec(
        "  parameters:\n    Bad: { description: no name }\n",
        &get_with("      parameters:\n        - $ref: '#/components/parameters/Bad'\n"),
    );
    assert_eq!(count(&doc, IssueKind::ParameterRefUnresolved), 1);
    assert!(doc.issues[0].message.contains("target is not a Parameter Object"), "{}", doc.issues[0].message);
    assert_eq!(op(&doc, "/x", "get").unresolved_parameter_refs.len(), 1);

    let inline = load_spec("", &get_with("      parameters:\n        - { description: no name }\n"));
    assert!(inline.issues.is_empty(), "{:?}", inline.issues);
    assert!(op(&inline, "/x", "get").unresolved_parameter_refs.is_empty());
}

#[test]
fn cyclic_wrong_kind_and_external_parameter_refs_are_each_unresolved_but_neighbours_still_load() {
    let doc = load_spec(
        "  parameters:\n    Loop: { $ref: '#/components/parameters/Loop' }\n    Good: { name: g, in: query }\n",
        &get_with(
            "      parameters:\n        - $ref: '#/components/parameters/Loop'\n        - $ref: '#/components/schemas/Car'\n        - $ref: 'other.yaml#/components/parameters/P'\n        - $ref: '#/components/parameters/Good'\n",
        ),
    );
    assert_eq!(count(&doc, IssueKind::ParameterRefUnresolved), 3);
    let o = op(&doc, "/x", "get");
    assert_eq!(o.parameters.len(), 1);
    assert_eq!(o.parameters[0].name, "g");
    assert_eq!(o.unresolved_parameter_refs.len(), 3);
}

#[test]
fn unresolved_parameter_refs_are_stored_raw_but_the_issue_message_escapes_control_characters() {
    let doc = load_spec("", &get_with("      parameters:\n        - $ref: \"#/components/parameters/a\\x1bb\"\n"));
    let o = op(&doc, "/x", "get");
    assert!(o.unresolved_parameter_refs[0].contains('\u{1b}'), "stored raw");
    let issue = doc.issues.iter().find(|i| i.kind == IssueKind::ParameterRefUnresolved).unwrap();
    assert!(!issue.message.chars().any(|c| c.is_control()), "{:?}", issue.message);
}

// ------------------------------------------------------------------- T-8 siblings

#[test]
fn summary_and_description_next_to_a_ref_are_silent_and_other_siblings_warn_once() {
    let ok = load_spec(
        "  parameters:\n    P: { name: p, in: query }\n",
        &get_with("      parameters:\n        - { $ref: '#/components/parameters/P', summary: s, description: d }\n"),
    );
    assert!(ok.issues.is_empty(), "{:?}", ok.issues);

    let doc = load_spec(
        "  parameters:\n    P: { name: p, in: query }\n",
        &get_with("      parameters:\n        - { $ref: '#/components/parameters/P', required: true, schema: { type: integer } }\n"),
    );
    assert_eq!(count(&doc, IssueKind::RefSiblingIgnored), 1);
    let issue = &doc.issues[0];
    assert_eq!(issue.severity, Severity::Warning);
    assert!(issue.message.contains("required") && issue.message.contains("schema"), "{}", issue.message);
    // 3.1 semantics: siblings are ignored, so the target's values win.
    assert!(!op(&doc, "/x", "get").parameters[0].required);
}

#[test]
fn many_ignored_siblings_are_listed_up_to_five_then_an_ellipsis_and_are_escaped() {
    let doc = load_spec(
        "  parameters:\n    P: { name: p, in: query }\n",
        &get_with("      parameters:\n        - { $ref: '#/components/parameters/P', k1: 1, k2: 2, k3: 3, k4: 4, k5: 5, k6: 6, \"bad\\x1bkey\": 7 }\n"),
    );
    let issue = doc.issues.iter().find(|i| i.kind == IssueKind::RefSiblingIgnored).unwrap();
    assert!(issue.message.contains('…'), "{}", issue.message);
    assert!(!issue.message.contains("k6"), "only the first five are named: {}", issue.message);
    assert!(!issue.message.chars().any(|c| c.is_control()));
}

#[test]
fn siblings_on_a_request_body_response_and_media_type_ref_each_warn() {
    let doc = load_spec(
        "  requestBodies:\n    B: { content: { application/json: { schema: { type: object } } } }\n  responses:\n    R: { description: r }\n  mediaTypes:\n    M: { schema: { type: object } }\n",
        "  /x:\n    post:\n      operationId: pX\n      requestBody: { $ref: '#/components/requestBodies/B', required: true }\n      responses:\n        '200': { $ref: '#/components/responses/R', headers: {} }\n        '201': { description: x, content: { application/json: { $ref: '#/components/mediaTypes/M', example: 1 } } }\n",
    );
    assert_eq!(count(&doc, IssueKind::RefSiblingIgnored), 3, "{:?}", doc.issues);
}

// ------------------------------------------------------------------- T-9 request bodies

#[test]
fn a_request_body_ref_is_processed_exactly_like_an_inline_body() {
    let via_ref = load_spec(
        "  requestBodies:\n    B: { required: true, content: { application/json: { schema: { type: object, required: [a] } } } }\n",
        "  /x:\n    post:\n      operationId: pX\n      requestBody: { $ref: '#/components/requestBodies/B' }\n      responses: { '200': { description: ok } }\n",
    );
    let inline = load_spec(
        "",
        "  /x:\n    post:\n      operationId: pX\n      requestBody: { required: true, content: { application/json: { schema: { type: object, required: [a] } } } }\n      responses: { '200': { description: ok } }\n",
    );
    assert_eq!(op(&via_ref, "/x", "post").request_body, op(&inline, "/x", "post").request_body);
    assert!(op(&via_ref, "/x", "post").request_body.as_ref().unwrap().required);
    assert!(via_ref.issues.is_empty());
}

#[test]
fn a_chained_request_body_ref_with_a_media_type_ref_inside_resolves() {
    let doc = load_spec(
        "  mediaTypes:\n    M: { schema: { type: string } }\n  requestBodies:\n    A: { $ref: '#/components/requestBodies/B' }\n    B: { required: true, content: { application/json: { $ref: '#/components/mediaTypes/M' } } }\n",
        "  /x:\n    post:\n      operationId: pX\n      requestBody: { $ref: '#/components/requestBodies/A' }\n      responses: { '200': { description: ok } }\n",
    );
    let body = op(&doc, "/x", "post").request_body.clone().unwrap();
    assert!(body.required);
    assert_eq!(body.schema, serde_json::json!({ "type": "string" }));
}

#[test]
fn an_unresolved_request_body_ref_fails_closed_as_a_required_body_of_unknown_shape() {
    let doc = load_spec(
        "",
        "  /x:\n    post:\n      operationId: pX\n      requestBody: { $ref: '#/components/requestBodies/Gone' }\n      responses: { '200': { description: ok } }\n",
    );
    assert_eq!(count(&doc, IssueKind::RequestBodyRefUnresolved), 1);
    let o = op(&doc, "/x", "post");
    let body = o.request_body.clone().unwrap();
    assert!(body.required);
    assert_eq!(body.schema, serde_json::json!({}));
    assert!(o.request_body_unresolved.as_deref().unwrap().contains("unknown request body 'Gone'"));
}

// ------------------------------------------------------------------- T-10 responses

#[test]
fn a_response_ref_supplies_the_response_schema_exactly_as_an_inline_response_does() {
    let via_ref = load_spec(
        "  responses:\n    Ok: { description: ok, content: { application/json: { schema: { type: object, properties: { id: { type: integer } } } } } }\n",
        "  /x:\n    get:\n      operationId: getX\n      responses: { '200': { $ref: '#/components/responses/Ok' } }\n",
    );
    let inline = load_spec(
        "",
        "  /x:\n    get:\n      operationId: getX\n      responses: { '200': { description: ok, content: { application/json: { schema: { type: object, properties: { id: { type: integer } } } } } } }\n",
    );
    assert!(op(&via_ref, "/x", "get").response_schema.is_some());
    assert_eq!(op(&via_ref, "/x", "get").response_schema, op(&inline, "/x", "get").response_schema);
    assert_eq!(op(&via_ref, "/x", "get").response_status_codes, vec![200]);
    assert!(via_ref.issues.is_empty());
}

#[test]
fn an_unresolved_200_is_reported_once_and_the_next_2xx_is_still_used() {
    let doc = load_spec(
        "  responses:\n    Created: { description: c, content: { application/json: { schema: { type: string } } } }\n",
        "  /x:\n    get:\n      operationId: getX\n      responses:\n        '200': { $ref: '#/components/responses/Gone' }\n        '201': { $ref: '#/components/responses/Created' }\n",
    );
    assert_eq!(count(&doc, IssueKind::ResponseRefUnresolved), 1, "{:?}", doc.issues);
    assert_eq!(op(&doc, "/x", "get").response_schema, Some(serde_json::json!({ "type": "string" })));
    assert_eq!(op(&doc, "/x", "get").response_status_codes, vec![200, 201]);
}

#[test]
fn a_broken_non_2xx_response_ref_is_never_dereferenced_or_reported() {
    let doc = load_spec(
        "",
        "  /x:\n    get:\n      operationId: getX\n      responses:\n        '200': { description: ok }\n        '404': { $ref: '#/components/responses/Gone' }\n        default: { $ref: 'other.yaml#/x' }\n",
    );
    assert!(doc.issues.is_empty(), "{:?}", doc.issues);
}

#[test]
fn a_streaming_response_reached_through_a_response_ref_is_detected() {
    let doc = load_spec(
        "  responses:\n    S: { description: s, content: { text/event-stream: { itemSchema: { type: object } } } }\n",
        "  /x:\n    get:\n      operationId: getX\n      responses: { '200': { $ref: '#/components/responses/S' } }\n",
    );
    assert!(
        matches!(op(&doc, "/x", "get").response_mode, ResponseMode::Stream(_)),
        "{:?}",
        op(&doc, "/x", "get").response_mode
    );
    assert!(kinds(&doc).contains(&IssueKind::StreamingDeclared));
}

// ------------------------------------------------------------------- T-11..T-16 path items

const PATH_ITEM_COMPONENT: &str = "  pathItems:\n    Shared:\n      get:\n        operationId: sharedGet\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n      post:\n        operationId: sharedPost\n        security: []\n        responses: { '200': { description: ok } }\n";

#[test]
fn a_path_item_ref_to_a_component_yields_its_operations_with_their_own_security() {
    let doc = load_spec(PATH_ITEM_COMPONENT, "  /x:\n    $ref: '#/components/pathItems/Shared'\n");
    assert_eq!(doc.operations.len(), 2, "{:?}", doc.issues);
    assert_eq!(op(&doc, "/x", "get").security.as_deref(), Some("a"));
    assert_eq!(op(&doc, "/x", "get").security_alternatives, vec![vec!["a".to_string()]]);
    assert_eq!(op(&doc, "/x", "post").security, None);
    assert!(op(&doc, "/x", "post").security_alternatives.is_empty());
    assert!(doc.issues.is_empty(), "{:?}", doc.issues);
}

#[test]
fn document_default_security_is_inherited_by_operations_behind_a_path_item_ref() {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(
        &file,
        format!("{HEAD}security: [ {{ b: [] }} ]\ncomponents:\n{SECURITY_SCHEMES}  pathItems:\n    P:\n      get:\n        operationId: g\n        responses: {{ '200': {{ description: ok }} }}\npaths:\n  /x:\n    $ref: '#/components/pathItems/P'\n"),
    )
    .unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let o = op(&doc, "/x", "get");
    assert!(o.security_inherited);
    assert_eq!(o.security.as_deref(), Some("b"));
}

#[test]
fn the_same_component_used_by_two_paths_gives_two_independent_operations() {
    let doc = load_spec(
        PATH_ITEM_COMPONENT,
        "  /x:\n    $ref: '#/components/pathItems/Shared'\n  /y:\n    $ref: '#/components/pathItems/Shared'\n",
    );
    assert_eq!(doc.operations.len(), 4);
    assert_eq!(op(&doc, "/x", "get").operation_id, op(&doc, "/y", "get").operation_id);
    assert!(doc.issues.is_empty(), "duplicate operationIds from reuse are not an error: {:?}", doc.issues);
}

#[test]
fn an_unsafe_referencing_key_is_skipped_but_the_ref_d_operations_are_recorded_with_real_methods_and_security() {
    let doc = load_spec(PATH_ITEM_COMPONENT, "  '/a/../b':\n    $ref: '#/components/pathItems/Shared'\n");
    assert!(doc.skipped_paths.contains("/a/../b"));
    assert!(doc.operations.is_empty());
    let get = doc.skipped_operations.iter().find(|s| s.method_wire == "GET").expect("GET recorded");
    assert_eq!(get.raw_path, "/a/../b");
    assert_eq!(get.security_alternatives, vec![vec!["a".to_string()]]);
    assert!(!get.any_method);
    assert!(doc.skipped_operations.iter().any(|s| s.method_wire == "POST"));
    assert!(doc.skipped_operations.iter().all(|s| !s.any_method));
}

#[test]
fn a_case_twin_of_an_inline_path_and_a_ref_d_path_are_ambiguous() {
    let doc = load_spec(
        PATH_ITEM_COMPONENT,
        "  /Cars:\n    $ref: '#/components/pathItems/Shared'\n  /cars:\n    get:\n      operationId: inl\n      responses: { '200': { description: ok } }\n",
    );
    assert!(kinds(&doc).contains(&IssueKind::CaseOnlyPathCollision), "{:?}", doc.issues);
    assert_eq!(doc.ambiguous.len(), 2);
    assert!(doc.operations.is_empty());
    assert!(!doc.ambiguous_operations.is_empty());
}

#[test]
fn a_trailing_slash_twin_through_a_ref_collides_like_an_inline_one() {
    let doc = load_spec(
        PATH_ITEM_COMPONENT,
        "  /x:\n    $ref: '#/components/pathItems/Shared'\n  /x/:\n    get:\n      operationId: inl\n      responses: { '200': { description: ok } }\n",
    );
    assert!(kinds(&doc).contains(&IssueKind::TrailingSlashCollision), "{:?}", doc.issues);
    assert!(doc.skipped_paths.contains("/x/"));
}

#[test]
fn route_template_conflicts_are_still_detected_for_ref_d_paths() {
    let doc = load_spec(
        PATH_ITEM_COMPONENT,
        "  /items/{id}:\n    $ref: '#/components/pathItems/Shared'\n  /items/{itemId}:\n    $ref: '#/components/pathItems/Shared'\n",
    );
    assert!(kinds(&doc).contains(&IssueKind::RouteTemplateConflict), "{:?}", doc.issues);
}

#[test]
fn a_path_item_ref_to_another_paths_entry_copies_content_but_routes_under_the_referencing_key() {
    let doc = load_spec(
        "",
        "  /real:\n    get:\n      operationId: real\n      responses: { '200': { description: ok } }\n  /alias:\n    $ref: '#/paths/~1real'\n",
    );
    assert_eq!(op(&doc, "/real", "get").operation_id, "real");
    assert_eq!(op(&doc, "/alias", "get").operation_id, "real");
    assert_eq!(doc.operations.len(), 2);
}

#[test]
fn a_path_item_ref_to_a_skipped_unsafe_key_still_serves_under_the_safe_referencing_path() {
    let doc = load_spec(
        "",
        "  '/a/../b':\n    get:\n      operationId: unsafeOne\n      responses: { '200': { description: ok } }\n  /safe:\n    $ref: '#/paths/~1a~1..~1b'\n",
    );
    assert!(doc.skipped_paths.contains("/a/../b"));
    assert_eq!(op(&doc, "/safe", "get").operation_id, "unsafeOne");
}

#[test]
fn a_missing_operation_id_inside_a_component_path_item_is_the_same_error_as_inline() {
    let result = load_spec_result(
        "  pathItems:\n    NoId:\n      get:\n        responses: { '200': { description: ok } }\n",
        "  /x:\n    $ref: '#/components/pathItems/NoId'\n",
    );
    assert!(matches!(result, Err(OpenApiError::MissingOperationId { .. })), "{result:?}");
}

#[test]
fn additional_operations_inside_a_component_path_item_go_through_the_same_checks() {
    let doc = load_spec(
        "  pathItems:\n    Extra:\n      additionalOperations:\n        PURGE:\n          operationId: purgeIt\n          responses: { '200': { description: ok } }\n        'bad method':\n          operationId: bad\n          responses: { '200': { description: ok } }\n",
        "  /x:\n    $ref: '#/components/pathItems/Extra'\n",
    );
    assert!(doc.operations.iter().any(|o| o.http_method == "PURGE"), "{:?}", doc.issues);
    assert!(kinds(&doc).contains(&IssueKind::InvalidAdditionalOperation), "{:?}", doc.issues);
}

#[test]
fn local_siblings_next_to_a_path_item_ref_merge_without_conflict() {
    let doc = load_spec(
        PATH_ITEM_COMPONENT,
        "  /x:\n    $ref: '#/components/pathItems/Shared'\n    delete:\n      operationId: del\n      responses: { '200': { description: ok } }\n",
    );
    assert_eq!(doc.operations.len(), 3, "{:?}", doc.issues);
}

// ------------------------------------------------------------------- T-15 unresolved path items

fn assert_synthetic_skip(doc: &OpenApiDocument, path: &str) {
    let skips: Vec<&SkippedOperation> = doc.skipped_operations.iter().filter(|s| s.any_method).collect();
    assert_eq!(skips.len(), 1, "{:?}", doc.skipped_operations);
    let skip = skips[0];
    assert_eq!(skip.raw_path, path);
    assert!(skip.method_wire.is_empty());
    assert!(skip.operation_id.is_empty());
    assert!(skip.security_unparseable);
    assert!(!skip.security_inherited);
    assert!(skip.security_alternatives.is_empty());
    assert!(skip.reason.starts_with("path item $ref unresolved"), "{}", skip.reason);
}

#[test]
fn an_unknown_path_item_ref_is_one_error_issue_zero_operations_and_a_synthetic_any_method_skip() {
    let doc = load_spec("", "  /x:\n    $ref: '#/components/pathItems/Nope'\n");
    assert_eq!(count(&doc, IssueKind::PathItemRefUnresolved), 1, "{:?}", doc.issues);
    assert_eq!(
        doc.issues.iter().find(|i| i.kind == IssueKind::PathItemRefUnresolved).unwrap().severity,
        Severity::Error
    );
    assert!(doc.operations.is_empty());
    assert!(doc.unresolved_path_items.contains("/x"));
    assert!(!doc.skipped_paths.contains("/x"), "an otherwise-acceptable key stays accepted");
    assert_synthetic_skip(&doc, "/x");
}

#[test]
fn an_unresolved_item_at_a_trailing_slash_key_uses_the_normalised_path_everywhere() {
    let doc = load_spec("", "  /x/:\n    $ref: '#/components/pathItems/Nope'\n");
    assert!(doc.unresolved_path_items.contains("/x"));
    assert_synthetic_skip(&doc, "/x");
}

#[test]
fn an_unresolved_item_at_an_unsafe_key_is_skipped_and_still_gets_the_synthetic_entry_at_the_raw_key() {
    let doc = load_spec("", "  '/a/../b':\n    $ref: '#/components/pathItems/Nope'\n");
    assert!(doc.skipped_paths.contains("/a/../b"));
    assert!(doc.unresolved_path_items.is_empty());
    assert_synthetic_skip(&doc, "/a/../b");
}

#[test]
fn a_path_item_merge_conflict_is_its_own_issue_kind_and_also_unresolved() {
    let doc = load_spec(
        PATH_ITEM_COMPONENT,
        "  /x:\n    $ref: '#/components/pathItems/Shared'\n    get:\n      operationId: mine\n      responses: { '200': { description: ok } }\n",
    );
    assert_eq!(count(&doc, IssueKind::PathItemRefConflict), 1, "{:?}", doc.issues);
    assert_eq!(count(&doc, IssueKind::PathItemRefUnresolved), 0);
    assert!(doc.operations.is_empty());
    assert!(doc.unresolved_path_items.contains("/x"));
    assert_synthetic_skip(&doc, "/x");
}

#[test]
fn cyclic_external_and_wrong_kind_path_item_refs_are_unresolved() {
    for reference in [
        "'#/paths/~1x'",
        "'other.yaml#/paths/~1y'",
        "'https://example.com/spec.yaml#/paths/~1y'",
        "'#/components/parameters/P'",
        "'#/paths/~1y/get'",
    ] {
        let doc = load_spec("", &format!("  /x:\n    $ref: {reference}\n"));
        assert_eq!(count(&doc, IssueKind::PathItemRefUnresolved), 1, "{reference}: {:?}", doc.issues);
        assert!(doc.operations.is_empty());
        assert!(doc.unresolved_path_items.contains("/x"), "{reference}");
    }
}

#[test]
fn an_unresolved_path_item_message_escapes_control_characters_in_the_key_and_the_ref() {
    let doc = load_spec("", "  \"/a\\x1bb\":\n    $ref: \"#/components/pathItems/c\\x07d\"\n");
    for issue in &doc.issues {
        assert!(!issue.message.chars().any(|c| c.is_control()), "{:?}", issue.message);
    }
    for skip in &doc.skipped_operations {
        assert!(!skip.reason.chars().any(|c| c.is_control()), "{:?}", skip.reason);
    }
}

#[test]
fn a_path_item_expansion_past_the_node_ceiling_becomes_unresolved_not_a_memory_blowup() {
    // Each referencing path adds a local sibling, forcing a copy of the ~2000-node component.
    let big: String = (0..1999).map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    let components = format!("  pathItems:\n    Big:\n      x-big: [{big}]\n      get:\n        operationId: g\n        responses: {{ '200': {{ description: ok }} }}\n");
    let mut paths = String::new();
    for i in 0..150 {
        paths.push_str(&format!(
            "  /p{i}:\n    $ref: '#/components/pathItems/Big'\n    post:\n      operationId: post{i}\n      responses: {{ '200': {{ description: ok }} }}\n"
        ));
    }
    let doc = load_spec(&components, &paths);
    let unresolved = count(&doc, IssueKind::PathItemRefUnresolved);
    assert!(unresolved > 0, "the shared ceiling must trip: {} ops", doc.operations.len());
    assert!(
        doc.issues.iter().any(|i| i.message.contains("limit")),
        "{:?}",
        doc.issues.iter().map(|i| &i.message).take(3).collect::<Vec<_>>()
    );
    assert!(doc.operations.len() < 300);
}

// ------------------------------------------------------------------- T-17 escapes

#[test]
fn a_schema_ref_with_an_escaped_slash_resolves_to_the_component_named_with_a_slash_in_every_walker() {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(
        &file,
        format!(
            "{HEAD}components:\n  schemas:\n    a/b: {{ type: object, properties: {{ id: {{ type: integer }} }} }}\n    a~1b: {{ type: string }}\npaths:\n  /x:\n    get:\n      operationId: g\n      responses: {{ '200': {{ description: ok, content: {{ application/json: {{ schema: {{ $ref: '#/components/schemas/a~1b' }} }} }} }} }}\n"
        ),
    )
    .unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    // The slash-named component is unwritable as a cache file name, which is the documented outcome.
    assert!(doc.unwritable_components.contains("a/b"), "{:?}", doc.unwritable_components);
    let components = doc.resolve_components();
    let desc = walk_response_schema(op(&doc, "/x", "get").response_schema.as_ref().unwrap(), &components);
    assert!(desc.to_string().contains("integer"), "the ref must reach the object a/b, got {desc}");
}

#[test]
fn a_literal_tilde_one_schema_name_must_be_referenced_with_tilde_zero_one() {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(
        &file,
        format!(
            "{HEAD}components:\n  schemas:\n    a~1b: {{ type: integer }}\npaths:\n  /x:\n    get:\n      operationId: g\n      responses: {{ '200': {{ description: ok, content: {{ application/json: {{ schema: {{ $ref: '#/components/schemas/a~01b' }} }} }} }} }}\n  /y:\n    get:\n      operationId: h\n      responses: {{ '200': {{ description: ok, content: {{ application/json: {{ schema: {{ $ref: '#/components/schemas/a~1b' }} }} }} }} }}\n"
        ),
    )
    .unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let components = doc.resolve_components();
    let x = walk_response_schema(op(&doc, "/x", "get").response_schema.as_ref().unwrap(), &components);
    assert_eq!(x.to_string(), serde_json::json!("integer").to_string(), "{x}");
    let y = walk_response_schema(op(&doc, "/y", "get").response_schema.as_ref().unwrap(), &components);
    assert!(
        y.to_string().contains("unsupported") || y.to_string().contains("unknown"),
        "no fallback to the raw name: {y}"
    );
}

#[test]
fn media_type_and_security_scheme_refs_decode_escapes() {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(
        &file,
        format!(
            "{HEAD}components:\n  securitySchemes:\n    s/k: {{ type: apiKey, in: header, name: k }}\n  mediaTypes:\n    m/t: {{ schema: {{ type: integer }} }}\npaths:\n  /x:\n    get:\n      operationId: g\n      security: [ {{ '#/components/securitySchemes/s~1k': [] }} ]\n      parameters:\n        - name: n\n          in: query\n          content: {{ application/json: {{ $ref: '#/components/mediaTypes/m~1t' }} }}\n      responses: {{ '200': {{ description: ok }} }}\n"
        ),
    )
    .unwrap();
    let doc = load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!kinds(&doc).contains(&IssueKind::MediaTypeRefUnresolved), "{:?}", doc.issues);
    assert_eq!(op(&doc, "/x", "get").parameters[0].schema_type.as_deref(), Some("integer"));
}

#[test]
fn a_bad_escape_in_a_media_type_ref_is_the_existing_media_type_unresolved_issue() {
    let doc = load_spec(
        "  mediaTypes:\n    M: { schema: { type: integer } }\n",
        "  /x:\n    get:\n      operationId: g\n      parameters:\n        - name: n\n          in: query\n          content: { application/json: { $ref: '#/components/mediaTypes/M~9' } }\n      responses: { '200': { description: ok } }\n",
    );
    assert_eq!(count(&doc, IssueKind::MediaTypeRefUnresolved), 1, "{:?}", doc.issues);
}

#[test]
fn a_default_mapping_target_with_an_escape_is_found_when_collecting_referenced_components() {
    let schema = serde_json::json!({ "oneOf": [{ "$ref": "#/components/schemas/p~1q" }], "discriminator": { "propertyName": "t", "defaultMapping": "#/components/schemas/d~1e" } });
    let names = referenced_component_names(&schema);
    assert!(names.contains("p/q"), "{names:?}");
    assert!(names.contains("d/e"), "{names:?}");
}

// ------------------------------------------------------------------- T-18 strictness

#[test]
fn every_new_issue_kind_is_a_strict_error() {
    for kind in [
        IssueKind::ParameterRefUnresolved,
        IssueKind::RequestBodyRefUnresolved,
        IssueKind::ResponseRefUnresolved,
        IssueKind::PathItemRefUnresolved,
        IssueKind::PathItemRefConflict,
        IssueKind::RefSiblingIgnored,
        IssueKind::MediaTypeRefUnresolved,
    ] {
        assert!(kind.is_strict_error(), "{kind:?}");
    }
}

#[test]
fn the_new_unresolved_kinds_are_error_severity_and_the_sibling_note_is_a_warning() {
    let doc = load_spec(
        "",
        "  /x:\n    post:\n      operationId: p\n      parameters: [ { $ref: '#/components/parameters/N' } ]\n      requestBody: { $ref: '#/components/requestBodies/N' }\n      responses: { '200': { $ref: '#/components/responses/N' } }\n  /y:\n    $ref: '#/components/pathItems/N'\n",
    );
    for kind in [
        IssueKind::ParameterRefUnresolved,
        IssueKind::RequestBodyRefUnresolved,
        IssueKind::ResponseRefUnresolved,
        IssueKind::PathItemRefUnresolved,
    ] {
        let issue = doc
            .issues
            .iter()
            .find(|i| i.kind == kind)
            .unwrap_or_else(|| panic!("{kind:?} missing: {:?}", doc.issues));
        assert_eq!(issue.severity, Severity::Error, "{kind:?}");
    }
}
