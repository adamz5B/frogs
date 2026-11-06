//! What the loader keeps about paths and operations it sets aside, and the route
//! warnings it raises, so the routing/security checks can still see them.

use super::*;
use std::path::PathBuf;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-openapi-routes-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const PRE: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\n";
const COMPONENTS: &str = "components:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\n    b: { type: apiKey, in: header, name: kb }\n";
const OK: &str = "responses: { '200': { description: ok } }";

fn load_text(top: &str, paths: &str, options: LoadOptions) -> OpenApiDocument {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    let text = format!(
        "{PRE}{top}{COMPONENTS}paths:
{paths}"
    );
    std::fs::write(&file, text).unwrap();
    let doc = load(&file, options).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    doc
}

fn kinds(doc: &OpenApiDocument) -> Vec<IssueKind> {
    doc.issues.iter().map(|i| i.kind).collect()
}

// ------------------------------------------------------------------- T1.5

#[test]
fn a_colon_path_is_skipped_and_recorded_and_its_neighbours_still_load() {
    let doc = load_text(
        "",
        &format!("  /a:b:\n    get:\n      operationId: colon\n      {OK}\n  /ok:\n    get:\n      operationId: ok\n      {OK}\n"),
        LoadOptions::default(),
    );
    assert!(doc.skipped_paths.contains("/a:b"));
    assert_eq!(doc.operations.len(), 1);
    assert!(kinds(&doc).contains(&IssueKind::UnsafePath));
    assert!(doc.issues.iter().any(|i| i.kind == IssueKind::UnsafePath && i.severity == Severity::Error));
}

#[test]
fn two_paths_whose_parameter_names_differ_at_one_position_raise_a_route_template_conflict_and_both_stay() {
    let doc = load_text(
        "",
        &format!("  /x/{{a}}:\n    get:\n      operationId: one\n      {OK}\n  /x/{{b}}:\n    get:\n      operationId: two\n      {OK}\n"),
        LoadOptions::default(),
    );
    let conflicts: Vec<_> = doc.issues.iter().filter(|i| i.kind == IssueKind::RouteTemplateConflict).collect();
    assert_eq!(conflicts.len(), 1, "{:?}", doc.issues);
    assert_eq!(conflicts[0].severity, Severity::Warning);
    assert!(IssueKind::RouteTemplateConflict.is_strict_error());
    assert_eq!(doc.operations.len(), 2, "both paths are kept");
}

#[test]
fn compatible_templates_raise_no_route_template_conflict() {
    let doc = load_text(
        "",
        &format!("  /cars/new:\n    get:\n      operationId: one\n      {OK}\n  /cars/{{id}}:\n    get:\n      operationId: two\n      {OK}\n"),
        LoadOptions::default(),
    );
    assert!(!kinds(&doc).contains(&IssueKind::RouteTemplateConflict));
}

// ------------------------------------------------------------------- T3.7

#[test]
fn a_skipped_path_keeps_each_operations_own_security_and_marks_document_default_inheritance() {
    let paths = format!(
        "  /v1/{{id}}:cancel:\n    post:\n      operationId: own\n      security: [ {{ b: [] }} ]\n      {OK}\n    put:\n      operationId: inherited\n      {OK}\n    additionalOperations:\n      LINK:\n        operationId: link\n        security: [ {{ a: [] }}, {{ b: [] }} ]\n        {OK}\n"
    );
    let doc = load_text("security: [ { a: [] } ]\n", &paths, LoadOptions::default());
    let skipped = &doc.skipped_operations;
    assert_eq!(skipped.len(), 3, "{skipped:?}");
    let by_wire = |wire: &str| skipped.iter().find(|s| s.method_wire == wire).unwrap_or_else(|| panic!("{wire}: {skipped:?}"));
    let own = by_wire("POST");
    assert_eq!(own.raw_path, "/v1/{id}:cancel");
    assert_eq!(own.security_alternatives, vec![vec!["b".to_string()]]);
    assert!(!own.security_inherited && !own.security_unparseable);
    assert_eq!(own.operation_id, "own");
    let inherited = by_wire("PUT");
    assert_eq!(inherited.security_alternatives, vec![vec!["a".to_string()]]);
    assert!(inherited.security_inherited);
    let link = by_wire("LINK");
    assert_eq!(link.security_alternatives, vec![vec!["a".to_string()], vec!["b".to_string()]]);
    assert!(doc.operations.is_empty());
}

#[test]
fn a_skipped_path_without_any_security_records_an_unsecured_operation() {
    let doc = load_text("", &format!("  /a:b:\n    get:\n      operationId: x\n      {OK}\n"), LoadOptions::default());
    assert_eq!(doc.skipped_operations.len(), 1);
    assert!(doc.skipped_operations[0].security_alternatives.is_empty());
    assert!(!doc.skipped_operations[0].security_unparseable);
}

#[test]
fn a_skipped_path_is_recorded_even_without_an_operation_id_and_a_non_object_path_item_records_nothing() {
    let doc = load_text(
        "",
        &format!("  /a:b:\n    get:\n      security: [ {{ a: [] }} ]\n      {OK}\n  /c:d: just-a-string\n"),
        LoadOptions::default(),
    );
    assert_eq!(doc.skipped_operations.len(), 1, "{:?}", doc.skipped_operations);
    assert_eq!(doc.skipped_operations[0].operation_id, "");
    assert!(doc.skipped_paths.contains("/c:d"));
}

#[test]
fn every_kind_of_skipped_path_is_recorded_with_its_reason() {
    let sec = "      security: [ { a: [] } ]\n";
    let paths = format!(
        "  /dots/../x:\n    get:\n      operationId: dots\n{sec}      {OK}\n  /dbl//x:\n    get:\n      operationId: dbl\n{sec}      {OK}\n  /x/:\n    get:\n      operationId: slash\n{sec}      {OK}\n  /x:\n    get:\n      operationId: plain\n      {OK}\n"
    );
    let doc = load_text("", &paths, LoadOptions::default());
    let raw: BTreeSet<&str> = doc.skipped_operations.iter().map(|s| s.raw_path.as_str()).collect();
    assert!(raw.contains("/dots/../x") && raw.contains("/dbl//x") && raw.contains("/x/"), "{raw:?}");
    assert!(doc.skipped_operations.iter().all(|s| !s.reason.is_empty()));
    assert!(doc.skipped_operations.iter().all(|s| !s.reason.chars().any(char::is_control)));
}

#[test]
fn dropped_additional_operations_keep_their_security_or_inherit_the_document_default() {
    let paths = format!(
        "  /x:\n    additionalOperations:\n      get:\n        operationId: lower\n        security: [ {{ b: [] }} ]\n        {OK}\n      LINK:\n        security: [ {{ a: [] }} ]\n        {OK}\n      UNLINK:\n        {OK}\n      BAD: oops\n"
    );
    let doc = load_text("security: [ { a: [] } ]\n", &paths, LoadOptions::default());
    let dropped = &doc.dropped_operations;
    let find = |key: &str| dropped.iter().find(|d| d.key == key).unwrap_or_else(|| panic!("{key}: {dropped:?}"));
    assert_eq!(find("get").security_alternatives, vec![vec!["b".to_string()]]);
    assert!(!find("get").security_inherited);
    assert_eq!(find("get").wire, "GET");
    assert_eq!(find("LINK").security_alternatives, vec![vec!["a".to_string()]]);
    assert!(!find("LINK").security_inherited);
    assert!(find("UNLINK").security_inherited, "no own security: the document default applies");
    assert_eq!(find("UNLINK").security_alternatives, vec![vec!["a".to_string()]]);
    assert!(find("BAD").security_inherited, "a non-object entry inherits the default too");
}

#[test]
fn a_dropped_or_skipped_entry_with_malformed_security_is_flagged_unparseable() {
    let doc = load_text(
        "",
        &format!(
            "  /x:\n    additionalOperations:\n      LINK:\n        security: oops\n        {OK}\n  /a:b:\n    get:\n      operationId: s\n      security: oops\n      {OK}\n"
        ),
        LoadOptions::default(),
    );
    assert!(doc.dropped_operations.iter().all(|d| d.security_unparseable), "{:?}", doc.dropped_operations);
    assert!(doc.skipped_operations.iter().all(|s| s.security_unparseable), "{:?}", doc.skipped_operations);
    assert!(!doc.dropped_operations.is_empty() && !doc.skipped_operations.is_empty());
}

#[test]
fn reading_security_for_dropped_and_skipped_entries_emits_no_load_issues_of_its_own() {
    let paths = format!("  /a:b:\n    get:\n      operationId: s\n      security: [ {{ nosuchscheme: [] }} ]\n      {OK}\n");
    let doc = load_text("", &paths, LoadOptions::default());
    assert_eq!(doc.issues.len(), 1, "only the UnsafePath issue: {:?}", doc.issues);
    assert_eq!(doc.issues[0].kind, IssueKind::UnsafePath);
}

#[test]
fn in_exact_mode_dropped_and_skipped_wires_keep_the_key_bytes() {
    let paths = format!(
        "  /x:\n    additionalOperations:\n      purge:\n        security: [ {{ a: [] }} ]\n        {OK}\n  /a:b:\n    additionalOperations:\n      purge:\n        security: [ {{ a: [] }} ]\n        {OK}\n"
    );
    let exact = load_text("", &paths, LoadOptions { case_sensitive_methods: true });
    assert_eq!(exact.dropped_operations[0].wire, "purge");
    assert_eq!(exact.skipped_operations[0].method_wire, "purge");
    let default = load_text("", &paths, LoadOptions::default());
    assert_eq!(default.dropped_operations[0].wire, "PURGE");
    assert_eq!(default.skipped_operations[0].method_wire, "PURGE");
}

#[test]
fn an_operation_inheriting_the_document_default_is_marked_and_one_with_its_own_security_is_not() {
    let paths = format!(
        "  /own:\n    get:\n      operationId: own\n      security: [ {{ b: [] }} ]\n      {OK}\n  /inherit:\n    get:\n      operationId: inherit\n      {OK}\n  /open:\n    get:\n      operationId: open\n      security: []\n      {OK}\n"
    );
    let doc = load_text("security: [ { a: [] } ]\n", &paths, LoadOptions::default());
    let find = |id: &str| doc.operations.iter().find(|o| o.operation_id == id).unwrap();
    assert!(!find("own").security_inherited);
    assert!(find("inherit").security_inherited);
    assert!(!find("open").security_inherited, "an explicit empty list is an own decision");
    let without_default = load_text("", &paths, LoadOptions::default());
    assert!(without_default.operations.iter().all(|o| !o.security_inherited));
}
