use super::*;
use crate::server::test_pki::temp_dir;

/// Writes `security/schemes.json` (one scheme, `certAuth`) plus the given
/// verifier file and loads the lot.
fn load_with(verifier_json: &str) -> Result<SecurityConfig, SecurityLoadError> {
    let dir = temp_dir("sec-load");
    std::fs::create_dir_all(dir.join("verifiers")).unwrap();
    std::fs::write(dir.join("schemes.json"), r#"{ "certAuth": { "verifier": "cert.json" } }"#).unwrap();
    std::fs::write(dir.join("verifiers/cert.json"), verifier_json).unwrap();
    SecurityConfig::load(&dir)
}

fn load_error(verifier_json: &str) -> String {
    match load_with(verifier_json) {
        Ok(_) => panic!("{verifier_json} should have failed to load"),
        Err(e) => e.to_string(),
    }
}

fn sql_with_param(from: &str) -> String {
    format!(r#"{{ "type": "sql", "connection": "db", "script": "v.sql", "parameters": [{{ "name": "p", "from": "{from}" }}], "validIf": "row.active = true" }}"#)
}

#[test]
fn a_valid_mtls_verifier_loads_with_a_compiled_condition() {
    let config = load_with(r#"{ "type": "mtls", "validIf": "cert.san.dns = orders.internal.example.com" }"#).unwrap();
    let verifier = &config.verifiers["certAuth"];
    assert!(verifier.mtls.is_some());
    assert!(verifier.requires_client_cert());
    assert_eq!(verifier.def.cache_ttl_seconds(), None);
    assert!(verifier.def.parameters().is_empty());
}

#[test]
fn every_documented_mtls_field_loads() {
    for expr in [
        "cert.cn = a",
        "cert.subject = CN=a",
        "cert.issuer = CN=ca",
        "cert.serial = 0a:0B",
        "cert.fingerprint = ab",
        "cert.notAfter = 2030-01-01T00:00:00Z",
        "cert.san.dns = a.example",
        "cert.san.uri = spiffe://x/y",
        "cert.san.email = a@b.example",
        "cert.san.dns = xn--caf-dma.example",
    ] {
        load_with(&format!(r#"{{ "type": "mtls", "validIf": "{expr}" }}"#)).unwrap_or_else(|e| panic!("{expr}: {e}"));
    }
}

#[test]
fn an_mtls_verifier_with_the_wrong_label_is_rejected() {
    let message = load_error(r#"{ "type": "mtls", "validIf": "row.cn = a" }"#);
    assert!(message.contains("cert"), "{message}");
}

#[test]
fn an_mtls_verifier_naming_an_unknown_field_is_rejected() {
    let message = load_error(r#"{ "type": "mtls", "validIf": "cert.foo = a" }"#);
    assert!(message.contains("foo"), "{message}");
}

#[test]
fn an_mtls_verifier_with_an_empty_right_hand_side_is_rejected() {
    assert!(load_with(r#"{ "type": "mtls", "validIf": "cert.cn = " }"#).is_err());
    assert!(load_with(r#"{ "type": "mtls", "validIf": "cert.cn = \"\"" }"#).is_err());
}

#[test]
fn an_mtls_verifier_with_a_non_ascii_san_dns_is_rejected_but_an_a_label_is_fine() {
    assert!(load_with("{ \"type\": \"mtls\", \"validIf\": \"cert.san.dns = caf\u{e9}.example\" }").is_err());
    assert!(load_with(r#"{ "type": "mtls", "validIf": "cert.san.dns = xn--caf-dma.example" }"#).is_ok());
}

#[test]
fn an_mtls_verifier_with_a_malformed_email_is_rejected() {
    for expr in ["cert.san.email = noat", "cert.san.email = @b.example", "cert.san.email = a@"] {
        assert!(load_with(&format!(r#"{{ "type": "mtls", "validIf": "{expr}" }}"#)).is_err(), "{expr}");
    }
}

#[test]
fn an_mtls_verifier_with_malformed_hex_is_rejected() {
    for expr in ["cert.serial = zz", "cert.fingerprint = 12 34"] {
        assert!(load_with(&format!(r#"{{ "type": "mtls", "validIf": "{expr}" }}"#)).is_err(), "{expr}");
    }
}

#[test]
fn an_mtls_verifier_rejects_each_sql_http_only_field_naming_it() {
    for (field, value) in [
        ("connection", r#""db""#),
        ("script", r#""v.sql""#),
        ("request", r#""r.json""#),
        ("parameters", r#"[{ "name": "p", "from": "cert.cn" }]"#),
        ("cacheTtlSeconds", "60"),
    ] {
        let message = load_error(&format!(r#"{{ "type": "mtls", "validIf": "cert.cn = a", "{field}": {value} }}"#));
        assert!(message.contains(field), "{field}: {message}");
    }
}

#[test]
fn an_mtls_verifier_reports_every_forbidden_field_it_sets() {
    let message = load_error(r#"{ "type": "mtls", "validIf": "cert.cn = a", "connection": "db", "cacheTtlSeconds": 5 }"#);
    assert!(message.contains("connection") && message.contains("cacheTtlSeconds"), "{message}");
}

#[test]
fn a_sql_verifier_binding_a_san_field_is_rejected_with_a_pointer_to_the_alternatives() {
    for from in ["cert.san.dns", "cert.san.uri", "cert.san.email"] {
        let message = load_error(&sql_with_param(from));
        assert!(message.contains("cert.fingerprint"), "{from}: {message}");
        assert!(message.contains("mtls"), "{from}: {message}");
        assert!(message.contains(from), "{from}: {message}");
    }
}

#[test]
fn a_verifier_binding_an_unknown_cert_field_is_rejected() {
    let message = load_error(&sql_with_param("cert.foo"));
    assert!(message.contains("cert.foo"), "{message}");
}

#[test]
fn every_bindable_cert_field_loads_in_a_sql_verifier_and_marks_it_cert_dependent() {
    for from in ["cert.cn", "cert.subject", "cert.issuer", "cert.serial", "cert.fingerprint", "cert.notAfter"] {
        let config = load_with(&sql_with_param(from)).unwrap_or_else(|e| panic!("{from}: {e}"));
        assert!(config.verifiers["certAuth"].requires_client_cert(), "{from}");
        assert!(config.verifiers["certAuth"].mtls.is_none(), "a sql verifier is not an mtls verifier");
    }
}

#[test]
fn a_cert_parameter_is_also_checked_on_http_verifiers() {
    let message = load_error(r#"{ "type": "http", "request": "r.json", "parameters": [{ "name": "p", "from": "cert.san.dns" }], "validIf": "response.ok = true" }"#);
    assert!(message.contains("cert.san.dns"), "{message}");
    let ok =
        load_with(r#"{ "type": "http", "request": "r.json", "parameters": [{ "name": "p", "from": "cert.fingerprint" }], "validIf": "response.ok = true" }"#).unwrap();
    assert!(ok.verifiers["certAuth"].requires_client_cert());
}

#[test]
fn a_header_only_verifier_does_not_require_a_client_cert() {
    let config = load_with(&sql_with_param("header.X-Api-Key")).unwrap();
    assert!(!config.verifiers["certAuth"].requires_client_cert());
}

#[test]
fn a_mixed_header_and_cert_verifier_requires_a_client_cert() {
    let json = r#"{ "type": "sql", "connection": "db", "script": "v.sql", "parameters": [{ "name": "k", "from": "header.X-Api-Key" }, { "name": "f", "from": "cert.fingerprint" }], "validIf": "row.active = true" }"#;
    assert!(load_with(json).unwrap().verifiers["certAuth"].requires_client_cert());
}

#[test]
fn the_invalid_client_cert_config_error_names_scheme_and_file() {
    let message = load_error(r#"{ "type": "mtls", "validIf": "cert.foo = a" }"#);
    assert!(message.contains("certAuth") && message.contains("cert.json"), "{message}");
}
