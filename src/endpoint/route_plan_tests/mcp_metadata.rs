//! The RFC 9728 metadata route as a root built-in: it claims every method at its absolute path.

use super::*;

const FOLDER: &str = ".well-known/oauth-protected-resource/mcp";
const PATH: &str = "/.well-known/oauth-protected-resource/mcp";

fn with_metadata(api_root: &str) -> RouteContext {
    let mcp_path = if api_root.is_empty() { "/mcp".to_string() } else { format!("{api_root}/mcp") };
    RouteContext {
        api_root: api_root.to_string(),
        mcp: true,
        mcp_metadata_path: Some(format!("/.well-known/oauth-protected-resource{mcp_path}")),
        ..api_ctx()
    }
}

#[test]
fn an_endpoint_folder_at_the_metadata_path_is_a_method_overlap_for_every_method() {
    let ctx = with_metadata("");
    for token in ["get", "post", "put", "patch", "delete", "query", "purge", "PROPFIND"] {
        let plan = RoutePlan::from_inventory(&inv(&[(FOLDER, token)]), &ctx);
        assert!(has_kind(&plan, RouteProblemKind::MethodOverlap), "{token}: {:?}", plan.problems);
        assert!(plan.is_excluded(PATH), "{token}");
    }
}

#[test]
fn the_overlap_message_names_the_config_key_that_mounts_the_route() {
    let plan = RoutePlan::from_inventory(&inv(&[(FOLDER, "get")]), &with_metadata(""));
    let message = &plan.problems.iter().find(|p| p.kind == RouteProblemKind::MethodOverlap).unwrap().message;
    assert!(message.contains("mcp.protectedResource"), "{message}");
    assert!(message.contains(PATH), "{message}");
}

#[test]
fn without_a_configured_protected_resource_the_same_folder_is_fine() {
    let ctx = RouteContext {
        mcp: true,
        mcp_metadata_path: None,
        ..api_ctx()
    };
    let plan = RoutePlan::from_inventory(&inv(&[(FOLDER, "get")]), &ctx);
    assert!(!has_kind(&plan, RouteProblemKind::MethodOverlap), "{:?}", plan.problems);
}

#[test]
fn with_an_api_root_an_endpoint_folder_cannot_reach_the_origin_root_path() {
    let ctx = with_metadata("/api");
    let plan = RoutePlan::from_inventory(&inv(&[(".well-known/oauth-protected-resource/api/mcp", "get")]), &ctx);
    assert!(
        !has_kind(&plan, RouteProblemKind::MethodOverlap),
        "that folder is served at /api/.well-known/..., not at the origin root: {:?}",
        plan.problems
    );
}

#[test]
fn the_unsuffixed_well_known_path_is_not_claimed() {
    let plan = RoutePlan::from_inventory(&inv(&[(".well-known/oauth-protected-resource", "get")]), &with_metadata(""));
    assert!(!has_kind(&plan, RouteProblemKind::MethodOverlap), "{:?}", plan.problems);
}

#[test]
fn the_mcp_path_and_the_metadata_path_are_two_separate_claims() {
    let ctx = with_metadata("");
    let mcp = RoutePlan::from_inventory(&inv(&[("mcp", "post")]), &ctx);
    assert!(has_kind(&mcp, RouteProblemKind::MethodOverlap), "{:?}", mcp.problems);
    let message = &mcp.problems.iter().find(|p| p.kind == RouteProblemKind::MethodOverlap).unwrap().message;
    assert!(!message.contains("protected-resource"), "{message}");
}
