use super::*;
use crate::security::{SchemeConfig, SecurityConfig};
use crate::server::test_pki::temp_dir;

const MTLS_SPEC: &str = "openapi: 3.1.0\ninfo: { title: t, version: '1' }\n\
paths:\n  /orders:\n    get:\n      operationId: getOrders\n      security: [{ certAuth: [] }]\n      responses: { '200': { description: ok, content: { application/json: { schema: { type: object, properties: { id: { type: string } } } } } } }\n  \
/invoices:\n    get:\n      operationId: getInvoices\n      security: [{ certAuth: [] }]\n      responses: { '200': { description: ok, content: { application/json: { schema: { type: object, properties: { id: { type: string } } } } } } }\n\
components:\n  securitySchemes:\n    certAuth: { type: mutualTLS }\n    unusedCert: { type: mutualTLS }\n    keyAuth: { type: apiKey, in: header, name: X-Key }\n";

fn load_spec(yaml: &str) -> crate::openapi::OpenApiDocument {
    let dir = temp_dir("generate-spec");
    let path = dir.join("openapi.yaml");
    std::fs::write(&path, yaml).unwrap();
    crate::openapi::load(&path).unwrap()
}

fn security_defining(name: &str) -> SecurityConfig {
    SecurityConfig {
        schemes: HashMap::from([(name.to_string(), SchemeConfig { verifier: "x.json".to_string() })]),
        verifiers: HashMap::new(),
    }
}

#[test]
fn security_scheme_types_are_read_for_every_declared_scheme() {
    let doc = load_spec(MTLS_SPEC);
    assert_eq!(doc.security_scheme_types.get("certAuth").map(String::as_str), Some("mutualTLS"));
    assert_eq!(doc.security_scheme_types.get("keyAuth").map(String::as_str), Some("apiKey"));
    assert_eq!(doc.security_scheme_types.len(), 3);
}

#[test]
fn security_scheme_types_are_read_from_a_3_0_document_too_and_default_to_empty() {
    let doc = load_spec(
        "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\ncomponents:\n  securitySchemes:\n    m: { type: mutualTLS }\n    noType: { description: nothing }\n",
    );
    assert_eq!(doc.security_scheme_types.get("m").map(String::as_str), Some("mutualTLS"));
    assert!(!doc.security_scheme_types.contains_key("noType"));
    assert!(
        load_spec("openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n")
            .security_scheme_types
            .is_empty()
    );
}

#[test]
fn a_used_mutual_tls_scheme_missing_from_schemes_json_produces_one_ready_to_paste_hint() {
    let doc = load_spec(MTLS_SPEC);
    let hints = mutual_tls_hints(&doc, &SecurityConfig::default());
    assert_eq!(hints.len(), 1, "two operations share certAuth, and the unused scheme is not mentioned: {hints:?}");
    let hint = &hints[0];
    for needle in [
        "certAuth",
        "security/schemes.json",
        "\"type\": \"mtls\"",
        "cert.fingerprint",
        "clientAuth",
        "nothing has been written",
    ] {
        assert!(hint.contains(needle), "missing {needle:?} in:\n{hint}");
    }
    assert!(!hint.contains("unusedCert") && !hint.contains("keyAuth"));
}

#[test]
fn no_hint_is_printed_once_the_scheme_is_defined() {
    let doc = load_spec(MTLS_SPEC);
    assert!(mutual_tls_hints(&doc, &security_defining("certAuth")).is_empty());
}

#[test]
fn no_hint_is_printed_for_non_mutual_tls_schemes() {
    let doc = load_spec(
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\n\
         paths:\n  /x:\n    get:\n      operationId: x\n      security: [{ keyAuth: [] }]\n      responses: { '200': { description: ok } }\n\
         components:\n  securitySchemes:\n    keyAuth: { type: apiKey, in: header, name: X-Key }\n",
    );
    assert!(mutual_tls_hints(&doc, &SecurityConfig::default()).is_empty());
}

#[test]
fn hints_are_sorted_by_scheme_name_and_deduplicated() {
    let doc = load_spec(
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\n\
         paths:\n  /b:\n    get:\n      operationId: b\n      security: [{ zeta: [] }]\n      responses: { '200': { description: ok } }\n  \
         /a:\n    get:\n      operationId: a\n      security: [{ alpha: [] }]\n      responses: { '200': { description: ok } }\n  \
         /c:\n    get:\n      operationId: c\n      security: [{ alpha: [] }]\n      responses: { '200': { description: ok } }\n\
         components:\n  securitySchemes:\n    zeta: { type: mutualTLS }\n    alpha: { type: mutualTLS }\n",
    );
    let hints = mutual_tls_hints(&doc, &SecurityConfig::default());
    assert_eq!(hints.len(), 2);
    assert!(hints[0].contains("'alpha'") && hints[1].contains("'zeta'"), "{hints:?}");
}

#[test]
fn generate_prints_the_hint_but_never_modifies_schemes_json_or_writes_a_verifier() {
    let root = temp_dir("generate-run");
    std::fs::write(root.join("openapi.yaml"), MTLS_SPEC).unwrap();
    let schemes = root.join("api/security/schemes.json");
    std::fs::create_dir_all(schemes.parent().unwrap()).unwrap();
    let original = "{\n  \"someOtherScheme\": { \"verifier\": \"other.json\" }\n}\n";
    std::fs::write(&schemes, original).unwrap();
    std::fs::create_dir_all(root.join("api/security/verifiers")).unwrap();
    std::fs::write(root.join("api/security/verifiers/other.json"), r#"{ "type": "mtls", "validIf": "cert.cn = x" }"#).unwrap();

    generate_api(&root).expect("generate should succeed");

    assert_eq!(std::fs::read_to_string(&schemes).unwrap(), original, "schemes.json must be left byte-for-byte alone");
    let verifiers: Vec<_> = std::fs::read_dir(root.join("api/security/verifiers"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(verifiers, vec![std::ffi::OsString::from("other.json")], "no verifier file may be written");
    // The stub still bakes the operation's security scheme in, as before.
    let stub: Value = serde_json::from_str(&std::fs::read_to_string(root.join("api/datasources/endpoints/orders/endpoint.get.json")).unwrap()).unwrap();
    assert_eq!(stub["security"], "certAuth");
}

#[test]
fn the_default_core_errors_define_both_client_cert_codes_as_exposed_401s() {
    let errors = default_core_errors();
    for code in ["auth.client_cert_missing", "auth.client_cert_expired"] {
        assert_eq!(errors[code]["httpStatus"], 401, "{code}");
        assert_eq!(errors[code]["exposeDetail"], true, "{code}");
    }
}

#[test]
fn a_freshly_scaffolded_core_json_contains_both_client_cert_codes_and_loads() {
    let root = temp_dir("generate-scaffold");
    scaffold_config(&root.join("api")).unwrap();
    let registry = crate::errors::ErrorRegistry::load(&root.join("api/config/errors")).unwrap();
    assert_eq!(registry.get("auth.client_cert_missing").map(|d| d.http_status), Some(401));
    assert_eq!(registry.get("auth.client_cert_expired").map(|d| d.http_status), Some(401));
}
