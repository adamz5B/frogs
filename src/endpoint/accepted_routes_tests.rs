//! `accept_routes` / `servability_problems`: the shared decision both the router and the MCP tool
//! table are built from, so a tool can never exist for a route that is not served.

use std::path::PathBuf;

use super::*;
use crate::config::Config;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-accepted-routes-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
}

impl Fx {
    fn new(schemes: &str, verifiers: &[(&str, &str)]) -> Fx {
        let root = tempdir();
        let api = root.join("api");
        for dir in ["config/errors", "security/verifiers", "datasources/endpoints"] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(api.join("config/server.json"), "{}").unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api.join("config/connections.json"), r#"{ "db": { "driver": "sqlite", "database": ":memory:" } }"#).unwrap();
        std::fs::write(api.join("security/schemes.json"), schemes).unwrap();
        for (name, body) in verifiers {
            std::fs::write(api.join("security/verifiers").join(name), body).unwrap();
        }
        Fx { root }
    }

    fn endpoint(&self, folder: &str, token: &str, body: &str) {
        let dir = self.root.join("api/datasources/endpoints").join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("endpoint.{token}.json")), body).unwrap();
    }

    fn decisions(&self, client_identity_available: bool) -> Vec<RouteDecision> {
        let config = Config::load(&self.root.join("api")).unwrap();
        let tree = crate::commands::run::scan_endpoint_tree(&self.root, &config.server);
        accept_routes(&tree, MethodCase::Default, &config.security, &config.connections, client_identity_available)
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn label(decision: &RouteDecision) -> String {
    match decision {
        RouteDecision::Accepted { entry, .. } => format!("accepted {}", entry.url_path),
        RouteDecision::Unavailable { entry, reason, endpoint } => format!("unavailable {} ({reason}) parsed={}", entry.url_path, endpoint.is_some()),
        RouteDecision::Skipped { message, .. } => format!("skipped ({message})"),
    }
}

const PLAIN: &str = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;

fn only<'a>(decisions: &'a [RouteDecision], path: &str) -> &'a RouteDecision {
    decisions
        .iter()
        .find(|d| match d {
            RouteDecision::Accepted { entry, .. } | RouteDecision::Unavailable { entry, .. } => entry.url_path == path,
            RouteDecision::Skipped { .. } => false,
        })
        .unwrap_or_else(|| panic!("no decision for {path}: {:?}", decisions.iter().map(label).collect::<Vec<_>>()))
}

#[test]
fn a_plain_endpoint_is_accepted_with_its_parsed_file_and_raw_contents() {
    let fx = Fx::new("{}", &[]);
    fx.endpoint("ok", "get", PLAIN);
    let decisions = fx.decisions(false);
    let RouteDecision::Accepted { endpoint, contents, entry } = only(&decisions, "/ok") else {
        panic!("{:?}", decisions.iter().map(label).collect::<Vec<_>>());
    };
    assert_eq!(endpoint.operation_id, "x");
    assert_eq!(contents, PLAIN);
    assert_eq!(entry.wire, "GET");
}

#[test]
fn an_endpoint_naming_an_unknown_security_scheme_is_unavailable_but_keeps_its_parsed_file() {
    let fx = Fx::new("{}", &[]);
    fx.endpoint("locked", "get", r#"{ "operationId": "x", "security": "nope", "sources": {}, "response": {} }"#);
    let decisions = fx.decisions(true);
    let RouteDecision::Unavailable { reason, endpoint, .. } = only(&decisions, "/locked") else {
        panic!("expected unavailable")
    };
    assert!(reason.contains("'nope'") && reason.contains("schemes.json"), "{reason}");
    assert!(endpoint.is_some());
}

#[test]
fn a_certificate_dependent_scheme_is_unavailable_without_client_identity_and_accepted_with_it() {
    let fx = Fx::new(
        r#"{ "m": { "verifier": "m.json" } }"#,
        &[("m.json", r#"{ "type": "mtls", "validIf": "cert.san.dns = orders.internal.example.com" }"#)],
    );
    fx.endpoint("orders", "get", r#"{ "operationId": "x", "security": "m", "sources": {}, "response": {} }"#);
    let without = fx.decisions(false);
    let RouteDecision::Unavailable { reason, .. } = only(&without, "/orders") else {
        panic!("expected unavailable")
    };
    assert!(reason.contains("needs a client certificate"), "{reason}");
    let with = fx.decisions(true);
    assert!(matches!(only(&with, "/orders"), RouteDecision::Accepted { .. }));
}

#[test]
fn an_invalid_nested_many_declaration_is_unavailable() {
    let fx = Fx::new("{}", &[]);
    fx.endpoint(
        "n",
        "get",
        r#"{ "operationId": "x", "response": {}, "sources": {
            "rows": { "type": "sql", "connection": "db", "script": "a.sql", "cardinality": "many" },
            "per": { "type": "sql", "connection": "db", "script": "b.sql", "cardinality": "one", "allowNestedMany": true,
                     "parameters": [ { "name": "v", "from": "sources.rows[].v" } ] } } }"#,
    );
    let decisions = fx.decisions(false);
    assert!(
        matches!(only(&decisions, "/n"), RouteDecision::Unavailable { endpoint: Some(_), .. }),
        "{:?}",
        decisions.iter().map(label).collect::<Vec<_>>()
    );
}

#[test]
fn a_call_timeout_together_with_allow_nested_many_is_unavailable() {
    let fx = Fx::new("{}", &[]);
    fx.endpoint(
        "t",
        "get",
        r#"{ "operationId": "x", "response": {}, "sources": {
            "rows": { "type": "sql", "connection": "db", "script": "a.sql", "cardinality": "many" },
            "per": { "type": "sql", "connection": "db", "script": "b.sql", "cardinality": "one", "allowNestedMany": true, "maxConcurrency": 1, "maxRows": 5, "rowTimeoutMs": 100,
                     "callTimeoutMs": 50, "parameters": [ { "name": "v", "from": "sources.rows[].v" } ] } } }"#,
    );
    let decisions = fx.decisions(false);
    let RouteDecision::Unavailable { reason, .. } = only(&decisions, "/t") else {
        panic!("expected unavailable")
    };
    assert!(reason.contains("callTimeoutMs"), "{reason}");
}

#[test]
fn an_unparseable_file_is_unavailable_with_no_parsed_endpoint() {
    let fx = Fx::new("{}", &[]);
    fx.endpoint("broken", "get", "{ not json");
    let decisions = fx.decisions(false);
    let RouteDecision::Unavailable { endpoint, reason, .. } = only(&decisions, "/broken") else {
        panic!("expected unavailable")
    };
    assert!(endpoint.is_none());
    assert!(reason.contains("invalid JSON"), "{reason}");
}

#[test]
fn servability_problems_is_empty_for_a_plain_endpoint_and_lists_every_problem_for_a_bad_one() {
    let fx = Fx::new("{}", &[]);
    let config = Config::load(&fx.root.join("api")).unwrap();
    let plain: EndpointFile = serde_json::from_str(PLAIN).unwrap();
    assert!(servability_problems(&plain, &config.security, &config.connections, false).is_empty());
    let bad: EndpointFile = serde_json::from_str(
        r#"{ "operationId": "x", "security": "nope", "response": {}, "sources": {
            "rows": { "type": "sql", "connection": "db", "script": "a.sql", "cardinality": "many" },
            "per": { "type": "sql", "connection": "db", "script": "b.sql", "cardinality": "one", "allowNestedMany": true, "callTimeoutMs": 5,
                     "parameters": [ { "name": "v", "from": "sources.rows[].v" } ] } } }"#,
    )
    .unwrap();
    let problems = servability_problems(&bad, &config.security, &config.connections, false);
    assert!(problems.len() >= 2, "{problems:?}");
    assert!(problems[0].contains("'nope'"), "the scheme problem comes first: {problems:?}");
}
