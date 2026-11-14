//! `verifierCacheMaxEntries` and the lenient MCP-off storage of the Milestone 2 `mcp` keys.

use super::*;

fn parse(json: &str) -> ServerConfig {
    serde_json::from_str(json).unwrap()
}

fn effective(json: &str) -> u64 {
    parse(json).effective_verifier_cache_max_entries()
}

#[test]
fn an_absent_verifier_cache_bound_is_the_default_of_ten_thousand() {
    assert_eq!(effective("{}"), 10_000);
    assert_eq!(ServerConfig::default().effective_verifier_cache_max_entries(), DEFAULT_VERIFIER_CACHE_MAX_ENTRIES);
    assert_eq!(DEFAULT_VERIFIER_CACHE_MAX_ENTRIES, 10_000);
}

#[test]
fn the_verifier_cache_bound_is_read_from_the_camel_case_key() {
    assert_eq!(parse(r#"{ "verifierCacheMaxEntries": 500 }"#).verifier_cache_max_entries, Some(500));
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 500 }"#), 500);
}

#[test]
fn a_bound_below_the_minimum_or_above_the_ceiling_is_clamped_never_refused() {
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 0 }"#), 100);
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 99 }"#), 100);
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 100 }"#), 100);
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 1000000 }"#), 1_000_000);
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 1000001 }"#), 1_000_000);
    assert_eq!(effective(r#"{ "verifierCacheMaxEntries": 18446744073709551615 }"#), 1_000_000);
    assert_eq!((MIN_VERIFIER_CACHE_MAX_ENTRIES, MAX_VERIFIER_CACHE_MAX_ENTRIES), (100, 1_000_000));
}

#[test]
fn a_default_or_unset_server_config_never_serialises_the_verifier_cache_key() {
    let text = serde_json::to_string(&ServerConfig::default()).unwrap();
    assert!(!text.contains("verifierCacheMaxEntries"), "{text}");
    let set = serde_json::to_string(&parse(r#"{ "verifierCacheMaxEntries": 500 }"#)).unwrap();
    assert!(set.contains("\"verifierCacheMaxEntries\":500"), "{set}");
}

#[test]
fn garbage_in_the_two_milestone_two_mcp_keys_still_loads_so_an_mcp_off_server_json_never_fails() {
    let config = parse(r#"{ "mcp": { "accessScheme": 5, "protectedResource": "garbage" } }"#);
    assert!(!config.features.mcp);
    let settings = config.mcp_settings();
    assert_eq!(settings.access_scheme, Some(serde_json::json!(5)));
    assert_eq!(settings.protected_resource, Some(serde_json::json!("garbage")));
    let nested = parse(r#"{ "mcp": { "protectedResource": { "anything": [1, 2, { "x": null }] } } }"#);
    assert!(nested.mcp_settings().protected_resource.is_some());
}
