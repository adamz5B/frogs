//! MCP Milestone 2 and `frogs generate`: `securityScopes` is baked into newly created stubs (and listed
//! in reference files), existing stubs are never edited, and a migration preserves the field.

use super::*;

fn spec(security: &str, schema_extra: &str) -> String {
    format!(
        "openapi: 3.2.0
info: {{ title: t, version: '1' }}
components:
  securitySchemes:
    oauth:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: 'https://auth.example.com/token'
          scopes: {{ cars.read: r, cars.write: w, admin: a }}
paths:
  /x:
    get:
      operationId: getX
{security}      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {{ type: object, properties: {{ id: {{ type: integer }}{schema_extra} }} }}
"
    )
}

const SCOPED: &str = "      security: [ { oauth: [cars.read, cars.write] } ]\n";
const UNSCOPED: &str = "      security: [ { oauth: [] } ]\n";
const NONE: &str = "";

#[test]
fn a_new_stub_bakes_the_first_requirements_scopes_next_to_its_scheme_and_the_reference_file_lists_them() {
    let fx = Fx::new(&spec(SCOPED, ""));
    assert!(fx.generate().errors.is_empty());
    let stub = fx.json("x/endpoint.get.json");
    assert_eq!(stub["security"], "oauth");
    assert_eq!(stub["securityScopes"], serde_json::json!(["cars.read", "cars.write"]));
    assert_eq!(
        fx.json("x/endpoint.get.reference.json")["securityScopes"],
        serde_json::json!(["cars.read", "cars.write"])
    );
}

#[test]
fn an_operation_with_a_scheme_but_no_scopes_gets_no_security_scopes_key_anywhere() {
    let fx = Fx::new(&spec(UNSCOPED, ""));
    assert!(fx.generate().errors.is_empty());
    let stub = fx.json("x/endpoint.get.json");
    assert_eq!(stub["security"], "oauth");
    assert!(stub.get("securityScopes").is_none(), "{stub}");
    assert!(fx.json("x/endpoint.get.reference.json").get("securityScopes").is_none());
}

#[test]
fn an_unsecured_operation_gets_neither_key() {
    let fx = Fx::new(&spec(NONE, ""));
    assert!(fx.generate().errors.is_empty());
    let stub = fx.json("x/endpoint.get.json");
    assert!(stub.get("security").is_none() && stub.get("securityScopes").is_none(), "{stub}");
    assert!(fx.json("x/endpoint.get.reference.json").get("securityScopes").is_none());
}

#[test]
fn an_existing_stub_is_never_edited_when_the_spec_gains_scopes_only_the_reference_file_is_refreshed() {
    let fx = Fx::new(&spec(UNSCOPED, ""));
    fx.generate();
    let stub_before = std::fs::read_to_string(fx.path("x/endpoint.get.json")).unwrap();
    assert!(fx.json("x/endpoint.get.reference.json").get("securityScopes").is_none());

    fx.set_spec(&spec(SCOPED, ""));
    fx.generate();
    assert_eq!(
        std::fs::read_to_string(fx.path("x/endpoint.get.json")).unwrap(),
        stub_before,
        "hand-edited stubs are never rewritten"
    );
    assert!(
        !fx.path("x/_backups").exists() && !fx.path("_backups").exists(),
        "a reference-only refresh makes no backup"
    );
    assert_eq!(
        fx.json("x/endpoint.get.reference.json")["securityScopes"],
        serde_json::json!(["cars.read", "cars.write"]),
        "the reference file tells the operator what to add"
    );
}

#[test]
fn migrating_a_changed_stub_preserves_its_security_scopes_and_security() {
    let fx = Fx::new(&spec(SCOPED, ""));
    fx.generate();
    let mut stub = fx.json("x/endpoint.get.json");
    stub["securityScopes"] = serde_json::json!(["cars.read", "cars.write", "admin"]);
    std::fs::write(fx.path("x/endpoint.get.json"), serde_json::to_string_pretty(&stub).unwrap()).unwrap();

    fx.set_spec(&spec(SCOPED, ", name: { type: string }"));
    fx.generate();

    let migrated = fx.json("x/endpoint.get.json");
    assert!(migrated["response"].to_string().contains("name"), "the migration really ran: {migrated}");
    assert_eq!(migrated["security"], "oauth");
    assert_eq!(
        migrated["securityScopes"],
        serde_json::json!(["cars.read", "cars.write", "admin"]),
        "the hand edit survived the migration"
    );
}

#[test]
fn a_stub_the_operator_never_gave_scopes_stays_without_them_through_a_migration() {
    let fx = Fx::new(&spec(UNSCOPED, ""));
    fx.generate();
    fx.set_spec(&spec(UNSCOPED, ", name: { type: string }"));
    fx.generate();
    let migrated = fx.json("x/endpoint.get.json");
    assert!(migrated["response"].to_string().contains("name"), "{migrated}");
    assert!(migrated.get("securityScopes").is_none(), "{migrated}");
}

#[test]
fn generate_reports_a_stub_that_does_not_cover_the_specs_scopes_as_an_error_only_when_the_verifier_enforces_scopes() {
    let fx = Fx::new(&spec(SCOPED, ""));
    fx.generate();
    let mut stub = fx.json("x/endpoint.get.json");
    stub.as_object_mut().unwrap().remove("securityScopes");
    std::fs::write(fx.path("x/endpoint.get.json"), serde_json::to_string_pretty(&stub).unwrap()).unwrap();

    let security = fx.root.join("api/security");
    std::fs::create_dir_all(security.join("verifiers")).unwrap();
    std::fs::write(security.join("schemes.json"), r#"{ "oauth": { "verifier": "v.json" } }"#).unwrap();
    let verifier = |extra: &str| format!(r#"{{ "type": "sql", "connection": "db", "script": "v.sql", "parameters": [], "validIf": "row.active = true"{extra} }}"#);
    std::fs::write(security.join("verifiers/v.json"), verifier("")).unwrap();
    let warned = fx.generate();
    assert!(warned.errors.is_empty(), "no scopesFrom: only a warning, got {:?}", warned.errors);

    std::fs::write(security.join("verifiers/v.json"), verifier(r#", "scopesFrom": "row.scope""#)).unwrap();
    let refused = fx.generate();
    assert!(
        refused.errors.iter().any(|e| e.contains("cars.read") && e.contains("securityScopes")),
        "{:?}",
        refused.errors
    );
}
