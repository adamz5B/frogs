//! Spec -> file security checks when operations reach the spec through `$ref`s: a secured
//! operation behind a path item `$ref` is seen like an inline one, and an unresolvable path item
//! is treated as secured for every method (fail closed).

use super::*;

struct Proj {
    root: PathBuf,
}

impl Drop for Proj {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Analysis {
    check: SecurityCheck,
    doc: crate::openapi::OpenApiDocument,
}

const SHARED: &str =
    "  pathItems:\n    Secured:\n      get:\n        operationId: securedGet\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n";

fn spec(top: &str, components: &str, paths: &str) -> String {
    format!(
        "openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\n{top}components:\n  securitySchemes:\n    a: {{ type: apiKey, in: header, name: ka }}\n{components}paths:\n{paths}"
    )
}

fn open_get(path: &str, id: &str) -> String {
    format!("  '{path}':\n    get:\n      operationId: {id}\n      responses: {{ '200': {{ description: ok }} }}\n")
}

fn reference(path: &str, target: &str) -> String {
    format!("  '{path}':\n    $ref: '{target}'\n")
}

fn file_json(security: Option<&str>) -> String {
    match security {
        Some(s) => format!(r#"{{ "operationId": "x", "security": "{s}", "sources": {{}}, "response": {{}} }}"#),
        None => r#"{ "operationId": "x", "sources": {}, "response": {} }"#.to_string(),
    }
}

fn analyse(spec_yaml: &str, files: &[(&str, &str, Option<&str>)], ctx: &RouteContext) -> (Analysis, Proj) {
    let root = temp_root("refsec");
    std::fs::write(root.join("openapi.yaml"), spec_yaml).unwrap();
    for (folder, token, security) in files {
        write_endpoint(&root, folder, token, &file_json(*security));
    }
    let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions { case_sensitive_methods: false }).unwrap();
    let tree = tree_for_tests(&root.join("datasources/endpoints"));
    let plan = RoutePlan::build(&tree, doc.method_case, ctx);
    let check = security_check_with_routes(&tree, &doc, &plan);
    (Analysis { check, doc }, Proj { root })
}

fn refusals(a: &Analysis) -> usize {
    a.check.mismatches.len()
        + a.check.shadowed.len()
        + a.check.stale_variants.len()
        + a.check.template_instances.len()
        + a.check.unverifiable.len()
        + a.check.builtin_refusals.len()
}

fn builtin_ctx() -> RouteContext {
    RouteContext {
        metrics: true,
        readyz: true,
        docs: true,
        docs_path: "docs".to_string(),
        ..api_ctx()
    }
}

const SHARED_REF: &str = "#/components/pathItems/Secured";
const NOWHERE_REF: &str = "#/components/pathItems/Nowhere";

// ------------------------------------------------------------------- T-22

#[test]
fn a_secured_get_behind_a_path_item_ref_requires_its_endpoint_file_to_declare_the_scheme() {
    let yaml = spec("", SHARED, &reference("/x", SHARED_REF));
    let (open, _p) = analyse(&yaml, &[("x", "get", None)], &endpoints_only());
    assert_eq!(open.check.mismatches.len(), 1, "the ref'd operation's security must be compared with the file");
    let (good, _p) = analyse(&yaml, &[("x", "get", Some("a"))], &endpoints_only());
    assert_eq!(refusals(&good), 0);
    assert!(good.check.unmatched.is_empty());
}

#[test]
fn a_secured_operation_behind_a_path_item_ref_is_shadowed_by_an_open_sibling_parameter_route() {
    let yaml = spec("", SHARED, &(reference("/cars/admin", SHARED_REF) + &open_get("/cars/{id}", "byId")));
    let (a, _p) = analyse(&yaml, &[("cars/{id}", "get", None)], &endpoints_only());
    assert_eq!(a.check.shadowed.len(), 1);
    assert_eq!(a.check.shadowed[0].op_path, "/cars/admin");
    assert!(!a.check.shadowed[0].any_method);
}

// ------------------------------------------------------------------- T-24

#[test]
fn an_unresolved_path_item_is_a_fail_closed_shadow_for_every_method_when_a_parameter_route_answers_it() {
    let yaml = spec("", "", &(reference("/cars/search", NOWHERE_REF) + &open_get("/cars/{vin}", "byVin")));
    let (a, _p) = analyse(&yaml, &[("cars/{vin}", "get", None)], &endpoints_only());
    assert!(a.doc.unresolved_path_items.contains("/cars/search"));
    assert_eq!(a.check.shadowed.len(), 1, "{:?}", a.check.shadowed.iter().map(|s| s.message()).collect::<Vec<_>>());
    let shadow = &a.check.shadowed[0];
    assert!(shadow.any_method);
    let message = shadow.message();
    assert!(message.contains("every method"), "{message}");
    assert!(message.contains("/cars/search"), "{message}");
    assert!(!message.contains(" * "), "the internal wildcard must never be printed: {message}");
}

#[test]
fn an_unresolved_path_item_shadows_every_method_file_of_the_answering_route_once_each() {
    let yaml = spec("", "", &(reference("/cars/search", NOWHERE_REF) + &open_get("/cars/{vin}", "byVin")));
    let (a, _p) = analyse(&yaml, &[("cars/{vin}", "get", None), ("cars/{vin}", "put", None)], &endpoints_only());
    assert_eq!(
        a.check.shadowed.len(),
        2,
        "one finding per file: {:?}",
        a.check.shadowed.iter().map(|s| s.message()).collect::<Vec<_>>()
    );
}

#[test]
fn a_file_at_an_unresolved_path_refuses_even_when_it_declares_a_valid_looking_scheme() {
    let yaml = spec("", "", &reference("/cars/search", NOWHERE_REF));
    for security in [None, Some("a")] {
        let (a, _p) = analyse(&yaml, &[("cars/search", "get", security)], &endpoints_only());
        assert_eq!(a.check.shadowed.len(), 1, "security {security:?}");
        assert!(a.check.shadowed[0].any_method);
        assert!(a.check.shadowed[0].message().contains("every method"));
    }
}

#[test]
fn a_file_at_an_unresolved_path_refuses_whatever_its_method_token() {
    let yaml = spec("", "", &reference("/cars/search", NOWHERE_REF));
    for token in ["get", "post", "delete", "PURGE"] {
        let (a, _p) = analyse(&yaml, &[("cars/search", token, None)], &endpoints_only());
        assert_eq!(a.check.shadowed.len(), 1, "{token}");
    }
}

#[test]
fn an_unresolved_item_at_a_trailing_slash_key_still_refuses_a_file_at_the_normalised_path() {
    let yaml = spec("", "", &reference("/cars/search/", NOWHERE_REF));
    let (a, _p) = analyse(&yaml, &[("cars/search", "get", None)], &endpoints_only());
    assert_eq!(a.check.shadowed.len(), 1, "normalised path must be the synthetic view's path");
    assert_eq!(a.check.shadowed[0].op_path, "/cars/search");
}

#[test]
fn an_unresolved_path_item_nothing_routes_to_is_only_a_load_issue() {
    let yaml = spec("", "", &(reference("/nothing/here", NOWHERE_REF) + &open_get("/other", "other")));
    let (a, _p) = analyse(&yaml, &[("other", "get", None)], &endpoints_only());
    assert_eq!(refusals(&a), 0);
    assert!(a.doc.issues.iter().any(|i| i.kind == crate::openapi::IssueKind::PathItemRefUnresolved));
}

#[test]
fn an_unresolved_path_item_that_cannot_be_probed_is_reported_as_unverifiable_for_every_method() {
    let yaml = spec("", "", &reference("/a/../b", NOWHERE_REF));
    let (a, _p) = analyse(&yaml, &[("other", "get", None)], &endpoints_only());
    assert_eq!(
        a.check.unverifiable.len(),
        1,
        "{:?}",
        a.check.unverifiable.iter().map(|u| u.message()).collect::<Vec<_>>()
    );
    assert!(a.check.unverifiable[0].any_method);
    assert!(a.check.unverifiable[0].message().contains("every method"));
}

#[test]
fn an_external_path_item_ref_refuses_when_a_file_exists_at_that_path() {
    let yaml = spec("", "", &reference("/ext", "other.yaml#/paths/~1ext"));
    let (a, _p) = analyse(&yaml, &[("ext", "get", None)], &endpoints_only());
    assert_eq!(refusals(&a), 1);
    let (none, _p) = analyse(&yaml, &[], &endpoints_only());
    assert_eq!(refusals(&none), 0);
}

#[test]
fn a_merge_conflict_path_item_is_fail_closed_like_an_unresolvable_one() {
    let yaml = spec(
        "",
        SHARED,
        "  /x:\n    $ref: '#/components/pathItems/Secured'\n    get:\n      operationId: mine\n      responses: { '200': { description: ok } }\n",
    );
    let (a, _p) = analyse(&yaml, &[("x", "get", Some("a"))], &endpoints_only());
    assert_eq!(a.check.shadowed.len(), 1);
    assert!(a.check.shadowed[0].any_method);
}

// ------------------------------------------------------------------- T-25

#[test]
fn an_unresolved_path_item_at_healthz_refuses_because_the_builtin_would_answer_it_unauthenticated() {
    let yaml = spec("", "", &reference("/healthz", NOWHERE_REF));
    let (a, _p) = analyse(&yaml, &[], &api_ctx());
    assert_eq!(a.check.builtin_refusals.len(), 1);
    assert!(a.check.builtin_refusals[0].any_method);
    assert!(a.check.builtin_refusals[0].message().contains("every method"));
}

#[test]
fn an_unresolved_item_at_a_path_with_no_builtin_and_no_file_has_no_builtin_refusal() {
    let yaml = spec("", "", &reference("/not-builtin", NOWHERE_REF));
    let (a, _p) = analyse(&yaml, &[], &builtin_ctx());
    assert!(a.check.builtin_refusals.is_empty());
}

#[test]
fn a_ref_d_secured_operation_at_metrics_is_refused_like_an_inline_one() {
    let components = "  pathItems:\n    M:\n      get:\n        operationId: m\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n";
    let yaml = spec("", components, &reference("/metrics", "#/components/pathItems/M"));
    let (a, _p) = analyse(&yaml, &[], &builtin_ctx());
    assert_eq!(a.check.builtin_refusals.len(), 1);
    assert!(!a.check.builtin_refusals[0].any_method);
}

// ------------------------------------------------------------------- amendment B

#[test]
fn a_real_star_method_is_not_confused_with_the_every_method_marker() {
    let yaml = spec(
        "",
        "",
        &(reference("/u", NOWHERE_REF)
            + "  /x:\n    additionalOperations:\n      '*':\n        operationId: star\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n"),
    );
    let (a, _p) = analyse(&yaml, &[("x", "get", None), ("u", "get", None)], &endpoints_only());
    // The file at /u is refused for the unresolved item; the GET file at /x is no shadow, stale variant or instance of the `*` operation.
    assert_eq!(a.check.shadowed.len(), 1, "{:?}", a.check.shadowed.iter().map(|t| t.message()).collect::<Vec<_>>());
    assert_eq!(a.check.shadowed[0].op_path, "/u");
    assert!(a.check.shadowed[0].any_method);
    assert!(a.check.template_instances.is_empty());
    assert!(a.check.stale_variants.is_empty());
}
