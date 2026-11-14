//! `features.mcp` and the `mcp` block of `config/server.json`.

use super::*;

fn parse(json: &str) -> Result<ServerConfig, serde_json::Error> {
    serde_json::from_str(json)
}

#[test]
fn mcp_is_off_by_default_everywhere_a_default_can_come_from() {
    assert!(!ServerConfig::default().features.mcp);
    assert!(!parse("{}").unwrap().features.mcp);
    assert!(
        !parse(r#"{ "features": { "cors": true } }"#).unwrap().features.mcp,
        "other feature keys don't switch it on"
    );
}

#[test]
fn features_mcp_true_parses_and_the_mcp_block_defaults_when_absent() {
    let config = parse(r#"{ "features": { "mcp": true } }"#).unwrap();
    assert!(config.features.mcp);
    assert!(config.mcp.is_none());
    let settings = config.mcp_settings();
    assert!(settings.allowed_hosts.is_empty() && settings.allowed_origins.is_empty());
    assert_eq!(settings.server_name, None);
    assert_eq!(settings.list_ttl_ms, None);
    assert!(settings.access_scheme.is_none() && settings.protected_resource.is_none());
}

#[test]
fn the_mcp_block_uses_camel_case_keys() {
    let config = parse(
        r#"{ "mcp": { "allowedOrigins": ["https://a.example"], "allowedHosts": ["h.example"], "serverName": "N", "listTtlMs": 5, "accessScheme": "x", "protectedResource": { "k": 1 } } }"#,
    )
    .unwrap();
    let mcp = config.mcp.unwrap();
    assert_eq!(mcp.allowed_origins, ["https://a.example"]);
    assert_eq!(mcp.allowed_hosts, ["h.example"]);
    assert_eq!(mcp.server_name.as_deref(), Some("N"));
    assert_eq!(mcp.list_ttl_ms, Some(5));
    assert!(mcp.access_scheme.is_some() && mcp.protected_resource.is_some());
}

#[test]
fn snake_case_keys_and_unknown_keys_inside_the_mcp_block_are_rejected() {
    for bad in [
        r#"{ "mcp": { "allowed_hosts": [] } }"#,
        r#"{ "mcp": { "allowedHost": [] } }"#,
        r#"{ "mcp": { "bogus": 1 } }"#,
    ] {
        let err = parse(bad).expect_err(bad);
        assert!(err.to_string().contains("unknown field"), "{bad}: {err}");
    }
}

#[test]
fn the_mcp_block_is_omitted_from_serialised_output_when_unset_and_features_mcp_is_written_out() {
    let text = serde_json::to_string(&ServerConfig::default()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(value.get("mcp").is_none(), "{text}");
    assert_eq!(value["features"]["mcp"], false);
    let with_block = parse(r#"{ "mcp": { "serverName": "S" } }"#).unwrap();
    let value: serde_json::Value = serde_json::to_value(&with_block).unwrap();
    assert_eq!(value["mcp"]["serverName"], "S");
    assert!(value["mcp"].get("listTtlMs").is_none() && value["mcp"].get("accessScheme").is_none());
}

#[test]
fn an_older_style_server_json_without_any_mcp_keys_still_parses_unchanged() {
    let config = parse(r#"{ "port": 8080, "debugMode": true, "features": { "requestValidation": false } }"#).unwrap();
    assert!(!config.features.mcp && config.mcp.is_none());
}

#[test]
fn the_list_ttl_constants_are_five_minutes_and_one_day() {
    assert_eq!(DEFAULT_MCP_LIST_TTL_MS, 300_000);
    assert_eq!(MAX_MCP_LIST_TTL_MS, 86_400_000);
}
