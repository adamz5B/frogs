use super::*;

fn tls(json: &str) -> TlsConfig {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} should parse: {e}"))
}

fn manual_with(client_auth: &str) -> TlsConfig {
    tls(&format!(
        r#"{{ "mode": "manual", "manual": {{ "certPath": "c.pem", "keyPath": "k.pem" }}, "clientAuth": {client_auth} }}"#
    ))
}

#[test]
fn a_client_auth_block_without_a_mode_fails_to_parse() {
    let err = serde_json::from_str::<TlsConfig>(r#"{ "mode": "manual", "clientAuth": { "caPath": "ca.pem" } }"#).expect_err("mode has no default");
    assert!(err.to_string().contains("mode"), "{err}");
}

#[test]
fn an_empty_client_auth_block_fails_to_parse() {
    assert!(serde_json::from_str::<TlsConfig>(r#"{ "clientAuth": {} }"#).is_err());
}

#[test]
fn an_unknown_client_auth_mode_fails_to_parse() {
    for bad in ["mandatory", "Required", "on", "true", ""] {
        let json = format!(r#"{{ "clientAuth": {{ "mode": "{bad}" }} }}"#);
        assert!(serde_json::from_str::<TlsConfig>(&json).is_err(), "{bad:?} must not be accepted");
    }
}

#[test]
fn all_three_modes_parse() {
    for (name, mode) in [
        ("off", ClientAuthMode::Off),
        ("optional", ClientAuthMode::Optional),
        ("required", ClientAuthMode::Required),
    ] {
        let parsed = tls(&format!(r#"{{ "clientAuth": {{ "mode": "{name}" }} }}"#));
        assert_eq!(parsed.client_auth.unwrap().mode, mode);
    }
}

#[test]
fn an_unknown_crl_policy_fails_to_parse() {
    assert!(serde_json::from_str::<TlsConfig>(r#"{ "clientAuth": { "mode": "required", "crlPolicy": "failOpen" } }"#).is_err());
    assert!(serde_json::from_str::<TlsConfig>(r#"{ "clientAuth": { "mode": "required", "crlPolicy": "failclosed" } }"#).is_err());
}

#[test]
fn both_crl_policies_parse_in_camel_case() {
    for (name, policy) in [("failClosed", CrlPolicy::FailClosed), ("bestEffort", CrlPolicy::BestEffort)] {
        let parsed = manual_with(&format!(
            r#"{{ "mode": "required", "caPath": "ca.pem", "crlPaths": ["a.crl"], "crlPolicy": "{name}" }}"#
        ));
        assert_eq!(parsed.client_auth.unwrap().crl_policy, Some(policy));
    }
}

#[test]
fn an_unknown_field_inside_client_auth_fails_to_parse() {
    let err = serde_json::from_str::<TlsConfig>(r#"{ "clientAuth": { "mode": "required", "caPaht": "ca.pem" } }"#).expect_err("typos must not be silently ignored");
    assert!(err.to_string().contains("caPaht"), "{err}");
}

#[test]
fn defaults_apply_when_optional_fields_are_absent() {
    let parsed = manual_with(r#"{ "mode": "required", "caPath": "ca.pem" }"#);
    let ca = parsed.client_auth.unwrap();
    assert!(ca.crl_paths.is_empty());
    assert_eq!(ca.crl_policy, None);
    assert_eq!(ca.effective_crl_policy(), CrlPolicy::FailClosed);
    assert_eq!(ca.require_client_auth_eku, None);
    assert!(ca.effective_require_client_auth_eku(), "requireClientAuthEku defaults to true");
}

#[test]
fn explicit_values_override_the_defaults() {
    let parsed = manual_with(r#"{ "mode": "optional", "caPath": "ca.pem", "crlPaths": ["a.crl", "b.crl"], "crlPolicy": "bestEffort", "requireClientAuthEku": false }"#);
    let ca = parsed.client_auth.unwrap();
    assert_eq!(ca.crl_paths, vec!["a.crl", "b.crl"]);
    assert_eq!(ca.effective_crl_policy(), CrlPolicy::BestEffort);
    assert!(!ca.effective_require_client_auth_eku());
}

#[test]
fn the_default_config_serializes_without_any_client_auth_key() {
    let json = serde_json::to_string(&ServerConfig::default()).unwrap();
    assert!(!json.contains("clientAuth"), "{json}");
    let tls_only = serde_json::to_string(&TlsConfig::default()).unwrap();
    assert!(!tls_only.contains("clientAuth"), "{tls_only}");
}

#[test]
fn a_client_auth_block_round_trips_and_omits_unset_optionals() {
    let parsed = manual_with(r#"{ "mode": "required", "caPath": "ca.pem" }"#);
    let json = serde_json::to_string(&parsed).unwrap();
    assert!(json.contains(r#""clientAuth":{"mode":"required","caPath":"ca.pem"}"#), "{json}");
    assert_eq!(serde_json::from_str::<TlsConfig>(&json).unwrap(), parsed);
}

#[test]
fn client_identity_is_enabled_only_for_manual_tls_with_a_non_off_mode() {
    assert!(!TlsConfig::default().client_identity_enabled());
    assert!(!tls(r#"{ "mode": "manual", "manual": { "certPath": "c", "keyPath": "k" } }"#).client_identity_enabled());
    assert!(!manual_with(r#"{ "mode": "off" }"#).client_identity_enabled());
    assert!(manual_with(r#"{ "mode": "optional", "caPath": "ca.pem" }"#).client_identity_enabled());
    assert!(manual_with(r#"{ "mode": "required", "caPath": "ca.pem" }"#).client_identity_enabled());
    // clientAuth over plain HTTP never yields an identity (and is a startup error elsewhere).
    assert!(!tls(r#"{ "mode": "off", "clientAuth": { "mode": "required", "caPath": "ca.pem" } }"#).client_identity_enabled());
}

#[test]
fn validate_structure_accepts_an_absent_block_a_bare_off_and_a_complete_enabled_block() {
    assert!(TlsConfig::default().validate_structure().is_ok());
    assert!(manual_with(r#"{ "mode": "off" }"#).validate_structure().is_ok());
    assert!(manual_with(r#"{ "mode": "required", "caPath": "ca.pem" }"#).validate_structure().is_ok());
    assert!(
        manual_with(r#"{ "mode": "optional", "caPath": "ca.pem", "crlPaths": ["a.crl"], "crlPolicy": "bestEffort" }"#)
            .validate_structure()
            .is_ok()
    );
}

#[test]
fn validate_structure_rejects_each_stray_field_under_mode_off_naming_it() {
    for (block, field) in [
        (r#"{ "mode": "off", "caPath": "ca.pem" }"#, "caPath"),
        (r#"{ "mode": "off", "crlPaths": ["a.crl"] }"#, "crlPaths"),
        (r#"{ "mode": "off", "crlPolicy": "failClosed" }"#, "crlPolicy"),
        (r#"{ "mode": "off", "requireClientAuthEku": false }"#, "requireClientAuthEku"),
        (r#"{ "mode": "off", "requireClientAuthEku": true }"#, "requireClientAuthEku"),
    ] {
        let err = manual_with(block).validate_structure().expect_err("a field alongside mode off is contradictory");
        assert!(err.contains(field), "{err} should name {field}");
    }
}

#[test]
fn validate_structure_rejects_client_auth_when_tls_is_not_manual() {
    let err = tls(r#"{ "mode": "off", "clientAuth": { "mode": "required", "caPath": "ca.pem" } }"#)
        .validate_structure()
        .expect_err("clientAuth needs TLS");
    assert!(err.contains("manual"), "{err}");
}

#[test]
fn validate_structure_requires_a_non_blank_ca_path_unless_off() {
    for block in [
        r#"{ "mode": "required" }"#,
        r#"{ "mode": "optional", "caPath": "" }"#,
        r#"{ "mode": "required", "caPath": "   " }"#,
    ] {
        let err = manual_with(block).validate_structure().expect_err("caPath is required");
        assert!(err.contains("caPath"), "{err}");
    }
}

#[test]
fn validate_structure_rejects_a_crl_policy_without_crl_paths() {
    let err = manual_with(r#"{ "mode": "required", "caPath": "ca.pem", "crlPolicy": "bestEffort" }"#)
        .validate_structure()
        .expect_err("a policy with nothing to apply to");
    assert!(err.contains("crlPolicy") && err.contains("crlPaths"), "{err}");
}

#[test]
fn webserve_json_shares_the_same_tls_client_auth_shape() {
    let parsed: crate::webserve::WebServeConfig = serde_json::from_str(
        r#"{ "startPage": "index.html", "tls": { "mode": "manual", "manual": { "certPath": "c", "keyPath": "k" }, "clientAuth": { "mode": "optional", "caPath": "ca.pem" } } }"#,
    )
    .unwrap();
    assert_eq!(parsed.tls.client_auth.unwrap().mode, ClientAuthMode::Optional);
}
