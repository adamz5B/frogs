//! Spec -> file security checks that consume the route plan: shadowed secured
//! operations, built-in routes answering them, and unmatched files that stand
//! in for a secured operation.

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
    plan: RoutePlan,
}

const SEC_A: &str = "[ { a: [] } ]";

fn spec(top: &str, paths: &str) -> String {
    format!(
        "openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\n{top}components:\n  securitySchemes:\n    a: {{ type: apiKey, in: header, name: ka }}\n    b: {{ type: apiKey, in: header, name: kb }}\npaths:\n{paths}"
    )
}

/// A fixed-method operation under `path`; `sec` is a YAML flow value, empty for none.
fn fixed(path: &str, method: &str, id: &str, sec: &str) -> String {
    let security = if sec.is_empty() { String::new() } else { format!("      security: {sec}\n") };
    // YAML limits implicit keys to 1024 characters; a longer path needs the explicit `? key` form.
    let head = if path.len() > 900 {
        format!("  ? '{path}'\n  : {method}:\n")
    } else {
        format!("  '{path}':\n    {method}:\n")
    };
    format!("{head}      operationId: {id}\n{security}      responses: {{ '200': {{ description: ok }} }}\n")
}

/// One `additionalOperations` entry; `id` and `sec` optional.
fn extra(path: &str, key: &str, id: Option<&str>, sec: &str) -> String {
    let id = id.map(|i| format!("        operationId: {i}\n")).unwrap_or_default();
    let security = if sec.is_empty() { String::new() } else { format!("        security: {sec}\n") };
    format!("  '{path}':\n    additionalOperations:\n      {key}:\n{id}{security}        responses: {{ '200': {{ description: ok }} }}\n")
}

fn endpoint_json(security: Option<&str>) -> String {
    match security {
        Some(s) => format!(r#"{{ "operationId": "x", "security": "{s}", "sources": {{}}, "response": {{}} }}"#),
        None => r#"{ "operationId": "x", "sources": {}, "response": {} }"#.to_string(),
    }
}

/// `files` is `(folder, file token, security scheme or None)`.
fn proj(spec_yaml: &str, files: &[(&str, &str, Option<&str>)]) -> Proj {
    let root = temp_root("sec");
    std::fs::write(root.join("openapi.yaml"), spec_yaml).unwrap();
    for (folder, token, security) in files {
        write_endpoint(&root, folder, token, &endpoint_json(*security));
    }
    Proj { root }
}

fn analyse_with(project: &Proj, case_sensitive: bool, ctx: &RouteContext) -> Analysis {
    let doc = crate::openapi::load(
        &project.root.join("openapi.yaml"),
        crate::openapi::LoadOptions {
            case_sensitive_methods: case_sensitive,
        },
    )
    .unwrap();
    let tree = tree_for_tests(&project.root.join("datasources/endpoints"));
    let plan = RoutePlan::build(&tree, doc.method_case, ctx);
    let check = security_check_with_routes(&tree, &doc, &plan);
    Analysis { check, doc, plan }
}

fn analyse(spec_yaml: &str, files: &[(&str, &str, Option<&str>)]) -> Analysis {
    analyse_with(&proj(spec_yaml, files), false, &endpoints_only())
}

fn analyse_exact(spec_yaml: &str, files: &[(&str, &str, Option<&str>)]) -> Analysis {
    analyse_with(&proj(spec_yaml, files), true, &endpoints_only())
}

fn analyse_ctx(spec_yaml: &str, files: &[(&str, &str, Option<&str>)], ctx: &RouteContext) -> Analysis {
    analyse_with(&proj(spec_yaml, files), false, ctx)
}

/// (shadowed, stale variants, template instances, unverifiable, builtin refusals)
fn counts(a: &Analysis) -> (usize, usize, usize, usize, usize) {
    (
        a.check.shadowed.len(),
        a.check.stale_variants.len(),
        a.check.template_instances.len(),
        a.check.unverifiable.len(),
        a.check.builtin_refusals.len(),
    )
}

fn shadow_messages(a: &Analysis) -> Vec<String> {
    a.check.shadowed.iter().map(|s| s.message()).collect()
}

// -------------------------------------------------------------- T2.1 .. T2.6

#[test]
fn a_secured_operation_with_no_file_that_an_open_parameter_route_answers_is_a_shadow() {
    let spec = spec("", &(fixed("/cars/admin", "get", "adm", SEC_A) + &fixed("/cars/{id}", "get", "byId", "")));
    let a = analyse(&spec, &[("cars/{id}", "get", None)]);
    assert_eq!(a.check.shadowed.len(), 1);
    let shadow = &a.check.shadowed[0];
    assert_eq!(shadow.served_route, "/cars/:id");
    assert_eq!(shadow.origin, ShadowOrigin::Served);
    assert_eq!(shadow.file_security, None);
    assert_eq!(shadow.acceptable, vec!["a".to_string()]);
    let message = shadow.message();
    assert!(
        message.contains("GET /cars/admin") && message.contains("operationId adm") && message.contains("run frogs generate"),
        "{message}"
    );
    assert!(a.check.mismatches.is_empty());
}

#[test]
fn a_shadowing_route_that_declares_an_acceptable_scheme_is_fine() {
    let spec = spec("", &(fixed("/cars/admin", "get", "adm", SEC_A) + &fixed("/cars/{id}", "get", "byId", SEC_A)));
    let a = analyse(&spec, &[("cars/{id}", "get", Some("a"))]);
    assert_eq!(counts(&a), (0, 0, 0, 0, 0));
}

#[test]
fn a_shadowing_route_declaring_the_wrong_scheme_is_still_a_shadow() {
    let spec = spec("", &(fixed("/cars/admin", "get", "adm", SEC_A) + &fixed("/cars/{id}", "get", "byId", "")));
    let a = analyse(&spec, &[("cars/{id}", "get", Some("b"))]);
    assert_eq!(a.check.shadowed.len(), 1);
    assert_eq!(a.check.shadowed[0].file_security.as_deref(), Some("b"));
}

#[test]
fn a_secured_operation_nothing_routes_to_is_not_reported() {
    let spec = spec("", &fixed("/cars/admin", "get", "adm", SEC_A));
    let a = analyse(&spec, &[("other", "get", None)]);
    assert_eq!(counts(&a), (0, 0, 0, 0, 0));
}

#[test]
fn a_shadowing_route_that_only_serves_another_method_is_a_405_not_a_shadow() {
    let spec = spec("", &(fixed("/cars/admin", "get", "adm", SEC_A) + &fixed("/cars/{id}", "post", "byId", "")));
    let a = analyse(&spec, &[("cars/{id}", "post", None)]);
    assert_eq!(counts(&a), (0, 0, 0, 0, 0));
}

#[test]
fn a_literal_route_holding_only_another_method_wins_over_the_open_parameter_route_so_there_is_no_shadow() {
    let spec = spec(
        "",
        "  /cars/admin:\n    get:\n      operationId: adm\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n    post:\n      operationId: adm2\n      responses: { '200': { description: ok } }\n",
    );
    let a = analyse(&spec, &[("cars/admin", "post", None), ("cars/{id}", "get", None)]);
    assert_eq!(a.check.shadowed.len(), 0, "{:?}", shadow_messages(&a));
}

#[test]
fn backtracking_from_a_literal_with_deeper_children_still_reaches_the_open_parameter_route() {
    let spec = spec("", &fixed("/cars/admin", "get", "adm", SEC_A));
    let a = analyse(&spec, &[("cars/admin/keys", "get", None), ("cars/{id}", "get", None)]);
    assert_eq!(a.check.shadowed.len(), 1);
    assert_eq!(a.check.shadowed[0].served_route, "/cars/:id");
}

#[test]
fn an_operation_with_its_own_file_is_never_its_own_shadow() {
    let spec = spec("", &fixed("/cars/{id}", "get", "byId", SEC_A));
    let a = analyse(&spec, &[("cars/{id}", "get", Some("a"))]);
    assert_eq!(counts(&a), (0, 0, 0, 0, 0));
    assert!(a.check.mismatches.is_empty());
}

// -------------------------------------------------------------------- T2.8

#[test]
fn an_open_file_that_instantiates_a_secured_template_is_a_template_instance_refusal() {
    let spec = spec("", &fixed("/cars/{id}", "get", "byId", SEC_A));
    let a = analyse(&spec, &[("cars/new", "get", None)]);
    assert_eq!(a.check.template_instances.len(), 1);
    assert!(a.check.unmatched.is_empty());
    let message = a.check.template_instances[0].message();
    assert!(
        message.contains("GET /cars/new") && message.contains("'a'") && message.contains("GET /cars/{id}"),
        "{message}"
    );
}

#[test]
fn an_explicit_open_spec_operation_for_the_instance_path_governs_the_file_instead() {
    let spec = spec("", &(fixed("/cars/{id}", "get", "byId", SEC_A) + &fixed("/cars/new", "get", "new", "")));
    let a = analyse(&spec, &[("cars/new", "get", None)]);
    assert_eq!(a.check.template_instances.len(), 0);
    assert!(a.check.unmatched.is_empty() && a.check.mismatches.is_empty());
}

#[test]
fn a_deeper_template_instance_needs_an_acceptable_scheme_and_with_one_it_is_only_unmatched() {
    let spec = spec("", &fixed("/a/{x}/c", "get", "deep", SEC_A));
    let refused = analyse(&spec, &[("a/b/c", "get", None)]);
    assert_eq!(refused.check.template_instances.len(), 1);
    let acceptable = analyse(&spec, &[("a/b/c", "get", Some("a"))]);
    assert_eq!(acceptable.check.template_instances.len(), 0);
    assert_eq!(acceptable.check.unmatched.len(), 1);
}

#[test]
fn a_file_with_a_different_method_or_segment_count_is_not_an_instance() {
    let spec = spec("", &fixed("/cars/{id}", "get", "byId", SEC_A));
    assert_eq!(analyse(&spec, &[("cars/new", "post", None)]).check.template_instances.len(), 0);
    assert_eq!(analyse(&spec, &[("cars/new/extra", "get", None)]).check.template_instances.len(), 0);
    assert_eq!(analyse(&spec, &[("trucks/new", "get", None)]).check.template_instances.len(), 0);
}

// --------------------------------------------------------- T2.9 / T2.10

#[test]
fn a_secured_head_operation_is_shadowed_by_an_open_get_file_which_also_serves_head() {
    let spec = spec("", &fixed("/cars", "head", "h", SEC_A));
    let a = analyse(&spec, &[("cars", "get", None)]);
    assert_eq!(a.check.shadowed.len(), 1);
    assert_eq!(a.check.shadowed[0].op_method, "HEAD");
}

#[test]
fn a_secured_template_with_a_differently_named_file_is_one_mismatch_and_no_shadow() {
    let spec = spec("", &fixed("/cars/{vin}", "get", "byVin", SEC_A));
    let a = analyse(&spec, &[("cars/{id}", "get", Some("b"))]);
    assert_eq!(a.check.mismatches.len(), 1);
    assert_eq!(counts(&a), (0, 0, 0, 0, 0));
}

#[test]
fn case_only_duplicate_paths_yield_one_finding_for_the_path_a_route_actually_answers() {
    let spec = spec("", &(fixed("/Cars/admin", "get", "up", SEC_A) + &fixed("/cars/admin", "get", "low", SEC_A)));
    let a = analyse(&spec, &[("cars/{id}", "get", None)]);
    assert_eq!(a.check.shadowed.len(), 1, "{:?}", shadow_messages(&a));
    assert_eq!(a.check.shadowed[0].op_path, "/cars/admin");
}

// ------------------------------------------------------------------- T2.11

#[test]
fn exact_mode_a_secured_lowercase_extension_is_shadowed_only_by_the_file_with_the_same_exact_method() {
    let spec = spec("", &extra("/x/admin", "purge", Some("p"), SEC_A));
    let tilde = analyse_exact(&spec, &[("x/{id}", "~purge", None)]);
    assert_eq!(tilde.check.shadowed.len(), 1, "{:?}", shadow_messages(&tilde));
    assert_eq!(tilde.check.shadowed[0].op_method, "purge");
    let upper = analyse_exact(&spec, &[("x/{id}", "PURGE", None)]);
    assert_eq!(counts(&upper), (0, 0, 0, 0, 0));
}

#[test]
fn default_mode_a_secured_purge_is_shadowed_by_an_open_purge_file_on_a_parameter_route() {
    let spec = spec("", &extra("/x/admin", "PURGE", Some("p"), SEC_A));
    let a = analyse(&spec, &[("x/{id}", "PURGE", None)]);
    assert_eq!(a.check.shadowed.len(), 1);
    assert_eq!(a.check.shadowed[0].op_method, "PURGE");
}

// ------------------------------------------------------------------- T2.12 / FR-8d / FR-9

fn builtin_ctx() -> RouteContext {
    RouteContext {
        metrics: true,
        readyz: true,
        docs: true,
        docs_path: "docs".to_string(),
        ..api_ctx()
    }
}

#[test]
fn an_operation_level_secured_metrics_operation_is_refused_when_the_metrics_builtin_answers_it() {
    let spec = spec("", &fixed("/metrics", "get", "m", SEC_A));
    let a = analyse_ctx(&spec, &[], &builtin_ctx());
    assert_eq!(a.check.builtin_refusals.len(), 1);
    let message = a.check.builtin_refusals[0].message();
    assert!(
        message.contains("/metrics") && message.contains("features.metrics") && message.contains("without authentication"),
        "{message}"
    );
    assert!(a.check.builtin_warnings.is_empty());
    let off = analyse_ctx(&spec, &[], &api_ctx());
    assert_eq!(counts(&off), (0, 0, 0, 0, 0));
    assert!(off.check.builtin_warnings.is_empty());
}

#[test]
fn a_document_default_secured_healthz_or_readyz_is_only_a_warning_that_mentions_security_empty() {
    let spec = spec("security: [ { a: [] } ]\n", &(fixed("/healthz", "get", "h", "") + &fixed("/readyz", "get", "r", "")));
    let a = analyse_ctx(&spec, &[], &builtin_ctx());
    assert!(
        a.check.builtin_refusals.is_empty(),
        "{:?}",
        a.check.builtin_refusals.iter().map(|b| b.message()).collect::<Vec<_>>()
    );
    assert_eq!(a.check.builtin_warnings.len(), 2);
    for warning in &a.check.builtin_warnings {
        assert!(warning.contains("security: []"), "{warning}");
    }
}

#[test]
fn an_operation_level_secured_healthz_is_refused_even_though_the_inherited_form_only_warns() {
    let spec = spec("", &fixed("/healthz", "get", "h", SEC_A));
    let a = analyse_ctx(&spec, &[], &builtin_ctx());
    assert_eq!(a.check.builtin_refusals.len(), 1);
    assert!(a.check.builtin_warnings.is_empty());
}

#[test]
fn inheriting_the_document_default_does_not_excuse_metrics_or_docs_routes() {
    let spec = spec(
        "security: [ { a: [] } ]\n",
        &(fixed("/metrics", "get", "m", "") + &fixed("/docs", "get", "d", "") + &fixed("/docs/operations.json", "get", "o", "")),
    );
    let a = analyse_ctx(&spec, &[], &builtin_ctx());
    assert_eq!(
        a.check.builtin_refusals.len(),
        3,
        "{:?}",
        a.check.builtin_refusals.iter().map(|b| b.message()).collect::<Vec<_>>()
    );
    assert!(a.check.builtin_warnings.is_empty());
    for refusal in &a.check.builtin_refusals {
        assert!(refusal.message().contains("security: []"), "{}", refusal.message());
    }
}

#[test]
fn an_explicit_empty_security_on_a_builtin_documented_operation_is_neither_refused_nor_warned() {
    let spec = spec("security: [ { a: [] } ]\n", &fixed("/metrics", "get", "m", "[]"));
    let a = analyse_ctx(&spec, &[], &builtin_ctx());
    assert!(a.check.builtin_refusals.is_empty() && a.check.builtin_warnings.is_empty());
}

#[test]
fn a_secured_op_at_a_deep_docs_path_is_found_even_when_every_endpoint_file_is_shallow() {
    let spec = spec("", &fixed("/a/b/c/operations.json", "get", "ops", SEC_A));
    let ctx = RouteContext {
        docs: true,
        docs_path: "a/b/c".to_string(),
        ..api_ctx()
    };
    let a = analyse_ctx(&spec, &[("x", "get", None)], &ctx);
    assert_eq!(a.check.builtin_refusals.len(), 1);
    assert!(a.check.builtin_refusals[0].message().contains("docs UI operations.json"));
}

#[test]
fn a_builtin_does_not_answer_a_secured_operation_for_a_method_it_does_not_serve() {
    let spec = spec("", &fixed("/healthz", "post", "h", SEC_A));
    let a = analyse_ctx(&spec, &[], &builtin_ctx());
    assert_eq!(counts(&a), (0, 0, 0, 0, 0));
}

// ------------------------------------------------------- T2.15 .. T2.18

#[test]
fn a_secured_operation_on_a_skipped_colon_path_is_shadowed_by_the_open_parameter_route() {
    let spec = spec("", &fixed("/v1/{id}:cancel", "post", "cancel", SEC_A));
    let a = analyse(&spec, &[("v1/{id}", "post", None)]);
    assert!(a.doc.skipped_paths.contains("/v1/{id}:cancel"));
    assert_eq!(a.check.shadowed.len(), 1);
    assert!(matches!(a.check.shadowed[0].origin, ShadowOrigin::Skipped(_)));
    let acceptable = analyse(&spec, &[("v1/{id}", "post", Some("a"))]);
    assert_eq!(counts(&acceptable), (0, 0, 0, 0, 0));
}

#[test]
fn a_secured_operation_on_a_path_that_cannot_be_probed_refuses_but_an_unsecured_one_does_not() {
    let long = (0..10).map(|_| "a".repeat(250)).collect::<Vec<_>>().join("/");
    for path in ["/a/../b", "/a//b", &format!("/{long}")] {
        let secured = analyse(&spec("", &fixed(path, "get", "x", SEC_A)), &[("other", "get", None)]);
        assert_eq!(secured.check.unverifiable.len(), 1, "{path}");
        let message = secured.check.unverifiable[0].message();
        assert!(
            message.contains("can't determine which route would serve it") && message.contains("fix the path in openapi.yaml"),
            "{message}"
        );
        let open = analyse(&spec("", &fixed(path, "get", "x", "")), &[("other", "get", None)]);
        assert_eq!(counts(&open), (0, 0, 0, 0, 0), "{path}");
    }
}

#[tokio::test]
async fn a_trailing_slash_collision_probe_agrees_with_a_real_router() {
    let spec = spec("", &(fixed("/x/", "get", "slash", SEC_A) + &fixed("/x", "get", "plain", "")));
    let project = proj(&spec, &[("x", "get", None), ("x/{id}", "get", None)]);
    let a = analyse_with(&project, false, &endpoints_only());
    assert!(a.doc.skipped_paths.contains("/x/"), "{:?}", a.doc.skipped_paths);
    let mut real = Router::new();
    for route in &a.plan.routes {
        let label = route.path.clone();
        real = real.route(&route.path, axum::routing::any(move || async move { label }));
    }
    let (status, body) = call(&real, "GET", "/x/").await;
    match a.plan.resolve("/x/").map(|r| r.path.clone()) {
        Some(path) => assert_eq!((status, body), (200, path)),
        None => assert_eq!(status, 404),
    }
}

#[test]
fn a_secured_operation_on_a_windows_portability_skipped_path_is_shadowed_by_the_open_parameter_route() {
    let project = proj(&spec("", &fixed("/a?", "get", "q", SEC_A)), &[("{p}", "get", None)]);
    let doc = crate::openapi::load_with_policy(
        &project.root.join("openapi.yaml"),
        crate::openapi::PortabilityPolicy::Skip,
        crate::openapi::LoadOptions::default(),
    )
    .unwrap();
    assert!(doc.skipped_paths.contains("/a?"), "{:?}", doc.skipped_paths);
    let tree = tree_for_tests(&project.root.join("datasources/endpoints"));
    let plan = RoutePlan::build(&tree, doc.method_case, &endpoints_only());
    let check = security_check_with_routes(&tree, &doc, &plan);
    assert_eq!(check.shadowed.len(), 1, "{:?}", check.shadowed.iter().map(|s| s.message()).collect::<Vec<_>>());
    assert!(matches!(check.shadowed[0].origin, ShadowOrigin::Skipped(_)));
}

#[test]
fn a_dropped_secured_operation_without_an_operation_id_is_shadowed_like_a_served_one() {
    let spec = spec("", &extra("/x/admin", "PURGE", None, SEC_A));
    let a = analyse(&spec, &[("x/{id}", "PURGE", None)]);
    assert_eq!(a.doc.dropped_operations.len(), 1);
    assert_eq!(a.check.shadowed.len(), 1);
    assert_eq!(a.check.shadowed[0].origin, ShadowOrigin::Dropped);
}

#[test]
fn a_secured_purge_dropped_by_a_case_collision_is_one_dropped_shadow_not_two() {
    let paths = "  /x/admin:\n    additionalOperations:\n      PURGE:\n        operationId: up\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n      purge:\n        operationId: low\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n";
    let a = analyse(&spec("", paths), &[("x/{id}", "PURGE", None)]);
    assert_eq!(a.check.shadowed.len(), 1, "{:?}", shadow_messages(&a));
}

// ---------------------------------------------------- malformed security

#[test]
fn malformed_security_on_a_dropped_entry_fails_closed_as_secured_with_no_acceptable_scheme() {
    let spec = spec("", &extra("/x/admin", "PURGE", None, "oops"));
    let a = analyse(&spec, &[("x/{id}", "PURGE", Some("a"))]);
    assert_eq!(a.check.shadowed.len(), 1, "even a declared scheme can't satisfy a malformed requirement");
    assert!(a.check.shadowed[0].unknown);
    assert!(a.check.shadowed[0].message().contains("malformed"));
}

#[test]
fn malformed_security_on_a_skipped_entry_fails_closed() {
    let spec = spec("", &fixed("/v1/{id}:cancel", "post", "cancel", "oops"));
    let a = analyse(&spec, &[("v1/{id}", "post", None)]);
    assert_eq!(a.check.shadowed.len(), 1);
    assert!(a.check.shadowed[0].unknown);
}

#[test]
fn a_malformed_document_default_inherited_by_a_dropped_or_skipped_entry_fails_closed() {
    let dropped = spec("security: oops\n", &extra("/x/admin", "PURGE", None, ""));
    let a = analyse(&dropped, &[("x/{id}", "PURGE", None)]);
    assert_eq!(a.check.shadowed.len(), 1);
    assert!(a.check.shadowed[0].unknown);
    let skipped = spec("security: oops\n", &fixed("/v1/{id}:cancel", "post", "cancel", ""));
    let b = analyse(&skipped, &[("v1/{id}", "post", None)]);
    assert_eq!(b.check.shadowed.len(), 1);
    assert!(b.check.shadowed[0].unknown);
}

// ------------------------------------------------------------ T3 / FR-11

#[test]
fn exact_mode_a_secured_lowercase_extension_is_stale_when_an_open_uppercase_file_remains() {
    let spec = spec("", &extra("/x", "purge", Some("p"), SEC_A));
    let a = analyse_exact(&spec, &[("x", "PURGE", None)]);
    assert_eq!(a.check.stale_variants.len(), 1);
    assert!(a.check.unmatched.is_empty());
    let ok = analyse_exact(&spec, &[("x", "PURGE", Some("a"))]);
    assert_eq!(ok.check.stale_variants.len(), 0);
    assert_eq!(ok.check.unmatched.len(), 1, "an acceptable scheme leaves it a plain unmatched file");
}

#[test]
fn exact_mode_a_secured_uppercase_extension_is_stale_next_to_an_open_tilde_file() {
    let spec = spec("", &extra("/x", "PURGE", Some("p"), SEC_A));
    let a = analyse_exact(&spec, &[("x", "~purge", None)]);
    assert_eq!(a.check.stale_variants.len(), 1);
}

#[test]
fn a_secured_lowercase_get_dropped_in_default_mode_makes_an_open_get_file_a_stale_variant() {
    let spec = spec("", &extra("/x", "get", Some("g"), SEC_A));
    let a = analyse(&spec, &[("x", "get", None)]);
    assert_eq!(a.check.stale_variants.len(), 1);
}

#[test]
fn a_secured_uppercase_get_in_additional_operations_makes_an_open_get_file_a_stale_variant() {
    let spec = spec("", &extra("/x", "GET", Some("g"), SEC_A));
    let a = analyse(&spec, &[("x", "get", None)]);
    assert_eq!(a.check.stale_variants.len(), 1);
}

#[test]
fn a_secured_extension_without_an_operation_id_makes_an_open_file_for_it_a_stale_variant() {
    let spec = spec("", &extra("/x", "LINK", None, SEC_A));
    let a = analyse(&spec, &[("x", "LINK", None)]);
    assert_eq!(a.check.stale_variants.len(), 1);
    assert!(a.check.unmatched.is_empty());
}

#[test]
fn a_dropped_entry_inheriting_the_document_default_secures_its_open_file_but_an_unsecured_spec_does_not() {
    let secured = spec("security: [ { a: [] } ]\n", &extra("/x", "LINK", None, ""));
    assert_eq!(analyse(&secured, &[("x", "LINK", None)]).check.stale_variants.len(), 1);
    let non_object = spec("security: [ { a: [] } ]\n", "  /x:\n    additionalOperations:\n      LINK: oops\n");
    assert_eq!(analyse(&non_object, &[("x", "LINK", None)]).check.stale_variants.len(), 1);
    let no_default = spec("", "  /x:\n    additionalOperations:\n      LINK: oops\n");
    let plain = analyse(&no_default, &[("x", "LINK", None)]);
    assert_eq!(plain.check.stale_variants.len(), 0);
    assert_eq!(plain.check.unmatched.len(), 1);
}

#[test]
fn exact_mode_a_parameter_renamed_and_case_different_path_still_makes_the_stale_variant_refusal_via_match_key() {
    let spec = spec("", &extra("/X/{vin}", "purge", Some("p"), SEC_A));
    let a = analyse_exact(&spec, &[("x/{id}", "PURGE", None)]);
    assert_eq!(a.check.stale_variants.len(), 1);
}

#[test]
fn a_dropped_secured_template_operation_makes_an_open_instance_file_a_template_instance_refusal() {
    let spec = spec("", &extra("/x/{id}", "PURGE", None, SEC_A));
    let a = analyse(&spec, &[("x/abc", "PURGE", None)]);
    assert_eq!(a.check.template_instances.len(), 1);
}

#[test]
fn a_probeable_skipped_secured_template_operation_makes_an_open_instance_file_a_template_instance_refusal() {
    let spec = spec("", &fixed("/x/{id}:go", "post", "go", SEC_A));
    let a = analyse(&spec, &[("x/abc", "post", None)]);
    assert_eq!(a.check.template_instances.len(), 1);
}

#[test]
fn a_plain_unmatched_file_stays_unmatched_and_the_existing_ambiguous_refusal_is_unchanged() {
    let plain = analyse(&spec("", &fixed("/other", "get", "o", "")), &[("x", "get", None)]);
    assert_eq!(plain.check.unmatched.len(), 1);
    assert_eq!(counts(&plain), (0, 0, 0, 0, 0));
    let ambiguous = "  /x:\n    additionalOperations:\n      LINK:\n        operationId: one\n        responses: { '200': { description: ok } }\n      link:\n        operationId: two\n        responses: { '200': { description: ok } }\n";
    let a = analyse(&spec("", ambiguous), &[("x", "LINK", None)]);
    assert_eq!(a.check.ambiguous.len(), 1);
    assert_eq!(a.check.stale_variants.len(), 0);
}

// ------------------------------------------------------------------- T3.11

#[test]
fn every_new_security_message_escapes_control_characters_from_operation_ids_keys_and_paths() {
    let esc = r"\e[2J";

    let shadow_spec = spec("", &fixed("/cars/admin", "get", &format!("\"adm{esc}\""), SEC_A));
    let shadow = analyse(&shadow_spec, &[("cars/{id}", "get", None)]);
    assert_eq!(shadow.check.shadowed.len(), 1);
    assert!(no_control_chars(&shadow.check.shadowed[0].message()), "{:?}", shadow.check.shadowed[0].message());

    let stale_spec = spec("", &extra("/x", "purge", Some(&format!("\"p{esc}\"")), SEC_A));
    let stale = analyse_exact(&stale_spec, &[("x", "PURGE", None)]);
    assert_eq!(stale.check.stale_variants.len(), 1);
    assert!(no_control_chars(&stale.check.stale_variants[0].message()));

    let instance_spec = spec("", &fixed("/cars/{id}", "get", &format!("\"i{esc}\""), SEC_A));
    let instance = analyse(&instance_spec, &[("cars/new", "get", None)]);
    assert_eq!(instance.check.template_instances.len(), 1);
    assert!(no_control_chars(&instance.check.template_instances[0].message()));

    let builtin_spec = spec("", &fixed("/metrics", "get", &format!("\"m{esc}\""), SEC_A));
    let builtin = analyse_ctx(&builtin_spec, &[], &builtin_ctx());
    assert_eq!(builtin.check.builtin_refusals.len(), 1);
    assert!(no_control_chars(&builtin.check.builtin_refusals[0].message()));

    let hostile_path = "  \"/a/\\e[2J/..\":\n    get:\n      operationId: u\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n";
    let unverifiable = analyse(&spec("", hostile_path), &[("other", "get", None)]);
    assert!(
        !unverifiable.check.unverifiable.is_empty(),
        "{:?}",
        unverifiable.doc.issues.iter().map(|i| i.message.clone()).collect::<Vec<_>>()
    );
    for message in unverifiable.check.unverifiable.iter().map(|u| u.message()) {
        assert!(no_control_chars(&message), "{message:?}");
    }
}
