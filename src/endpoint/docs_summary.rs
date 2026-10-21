use serde_json::{Value, json};

use super::schema::{ArrayResponse, Cardinality, DetailedField, Parameter, ParameterType, ResponseField, ResponseShape, SourceDef};
use super::{EndpointFile, discover_endpoint_files};
use crate::openapi::endpoint_tree::EndpointTree;
use crate::openapi::method_token::MethodCase;

/// A sanitized, allowlisted summary of every discovered endpoint file's own
/// `sources`/`response` mapping — Point 4 of the docs-UI build
/// (`docs/frogs-quick-wins.md`), feeding `/docs/endpoints.json`. Built
/// field-by-field through an explicit allowlist (`endpoint_summary_json`
/// and friends below) rather than a raw dump of the parsed file: a new
/// field added to `EndpointFile`/`SourceDef` later defaults to *absent*
/// from this payload until someone deliberately adds it here, not exposed
/// by accident. Safe by construction regardless — nothing in this schema
/// ever stores a real secret *value*, only structural config (`Parameter`'s
/// `from` is a dot-path like `header.X-Api-Key`, never a header's actual
/// value; a SQL source's `script` is query text, not a credential) — but
/// the allowlist is defense in depth on top of that, not instead of it.
///
/// An HTTP source's own `datasources/http/<file>.json` is deliberately
/// *not* resolved and inlined here — only its filename (`request`) is
/// shown — keeping this pass's file I/O to exactly the endpoint files
/// themselves, the same scope `discover_endpoint_files` already has. A file
/// that fails to read or parse is silently skipped (same graceful-
/// degradation posture `build_router` itself uses for the exact same
/// failure) rather than failing the whole summary over one bad file.
pub(crate) fn endpoint_summaries(tree: &EndpointTree, mode: MethodCase) -> Vec<Value> {
    discover_endpoint_files(tree, mode)
        .into_iter()
        .filter_map(|(url_path, method, file_path)| {
            let contents = std::fs::read_to_string(&file_path).ok()?;
            let endpoint: EndpointFile = serde_json::from_str(&contents).ok()?;
            Some(endpoint_summary_json(&url_path, &method, &endpoint))
        })
        .collect()
}

fn endpoint_summary_json(url_path: &str, method: &str, endpoint: &EndpointFile) -> Value {
    let sources: Value = Value::Object(endpoint.sources.iter().map(|(name, def)| (name.clone(), source_def_json(def))).collect());

    json!({
        "method": crate::openapi::method_token::display_token(method),
        // Matches `openapi::Operation::path`'s own `{name}` convention (not
        // `discover_endpoint_files`'s axum-style `:name`) so the console
        // can line this entry up with its `/docs/operations.json`
        // counterpart by method+path.
        "path": openapi_style_path(url_path),
        "operationId": endpoint.operation_id,
        "generated": endpoint.generated,
        "sources": sources,
        "response": response_shape_json(&endpoint.response),
    })
}

fn openapi_style_path(url_path: &str) -> String {
    url_path
        .split('/')
        .map(|segment| match segment.strip_prefix(':') {
            Some(name) => format!("{{{name}}}"),
            None => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn source_def_json(def: &SourceDef) -> Value {
    match def {
        SourceDef::Sql {
            connection,
            script,
            cardinality,
            on_error,
            optional,
            parameters,
            ..
        } => json!({
            "type": "sql",
            "connection": connection,
            "script": script,
            "cardinality": cardinality_str(*cardinality),
            "onError": on_error,
            "optional": optional,
            "parameters": parameters.iter().map(parameter_json).collect::<Vec<_>>(),
        }),
        SourceDef::Http {
            request,
            cardinality,
            on_error,
            optional,
            parameters,
            ..
        } => json!({
            "type": "http",
            "request": request,
            "cardinality": cardinality_str(*cardinality),
            "onError": on_error,
            "optional": optional,
            "parameters": parameters.iter().map(parameter_json).collect::<Vec<_>>(),
        }),
    }
}

fn cardinality_str(c: Cardinality) -> &'static str {
    match c {
        Cardinality::One => "one",
        Cardinality::Many => "many",
    }
}

fn parameter_json(p: &Parameter) -> Value {
    json!({
        "name": p.name,
        "from": p.from,
        "type": match p.param_type {
            ParameterType::Scalar => "scalar",
            ParameterType::Array => "array",
        },
        "default": p.default,
        "min": p.min,
        "max": p.max,
    })
}

fn response_shape_json(shape: &ResponseShape) -> Value {
    match shape {
        ResponseShape::Array(arr) => array_response_json(arr),
        ResponseShape::Fields(fields) => json!({
            "kind": "fields",
            "fields": Value::Object(fields.iter().map(|(name, field)| (name.clone(), response_field_json(field))).collect()),
        }),
        // Same "unmapped, no schema at all" stub `resolve::build_response`
        // treats as an empty object — rendered the same as an empty
        // `Fields` map so the console doesn't need a fourth case to handle.
        ResponseShape::Null => json!({ "kind": "fields", "fields": {} }),
    }
}

fn array_response_json(arr: &ArrayResponse) -> Value {
    json!({
        "kind": "array",
        "source": arr.source,
        "items": Value::Object(arr.items.iter().map(|(name, field)| (name.clone(), response_field_json(field))).collect()),
    })
}

fn response_field_json(field: &ResponseField) -> Value {
    match field {
        ResponseField::Plain(path) => json!({ "from": path }),
        ResponseField::Detailed(d) => detailed_field_json(d),
        ResponseField::Array(arr) => array_response_json(arr),
        ResponseField::Null => json!({ "from": Value::Null }),
    }
}

fn detailed_field_json(d: &DetailedField) -> Value {
    json!({
        "from": d.from,
        "format": d.format,
        "precision": d.precision,
        "sourceFormat": d.source_format,
        "trim": d.trim,
        "uppercase": d.uppercase,
        "lowercase": d.lowercase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::endpoint_tree::tree_for_tests;

    fn temp_endpoints_root() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-docs-summary-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn summarizes_a_sql_source_and_a_plain_response_field() {
        let root = temp_endpoints_root();
        let dir = root.join("cars").join("{id}");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{
                "operationId": "getCar",
                "sources": {
                    "car": {
                        "type": "sql",
                        "connection": "vehicles_db",
                        "script": "SELECT * FROM cars WHERE id = :id",
                        "parameters": [{ "name": "id", "from": "path.id" }]
                    }
                },
                "response": { "vin": "sources.car.vin" }
            }"#,
        )
        .unwrap();

        let summaries = endpoint_summaries(&tree_for_tests(&root), MethodCase::Default);
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s["method"], "GET");
        assert_eq!(
            s["path"], "/cars/{id}",
            "the axum-style :id folder name must be normalized back to OpenAPI-style {{id}}"
        );
        assert_eq!(s["operationId"], "getCar");
        assert_eq!(s["generated"], false);
        assert_eq!(s["sources"]["car"]["type"], "sql");
        assert_eq!(s["sources"]["car"]["connection"], "vehicles_db");
        assert_eq!(s["sources"]["car"]["script"], "SELECT * FROM cars WHERE id = :id");
        assert_eq!(s["sources"]["car"]["parameters"][0]["from"], "path.id");
        assert_eq!(s["response"]["kind"], "fields");
        assert_eq!(s["response"]["fields"]["vin"]["from"], "sources.car.vin");
    }

    #[test]
    fn a_generated_stub_with_a_null_response_field_is_summarized_not_skipped() {
        let root = temp_endpoints_root();
        let dir = root.join("ping");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{ "operationId": "ping", "_generated": true, "sources": {}, "response": null }"#,
        )
        .unwrap();

        let summaries = endpoint_summaries(&tree_for_tests(&root), MethodCase::Default);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0]["generated"], true);
        assert_eq!(summaries[0]["response"]["kind"], "fields");
        assert!(summaries[0]["response"]["fields"].as_object().unwrap().is_empty());
    }

    #[test]
    fn an_http_source_never_exposes_its_own_request_files_body_or_auth() {
        let root = temp_endpoints_root();
        let dir = root.join("pricing");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{
                "operationId": "getPricing",
                "sources": { "price": { "type": "http", "request": "pricing_lookup.json" } },
                "response": {}
            }"#,
        )
        .unwrap();

        let summaries = endpoint_summaries(&tree_for_tests(&root), MethodCase::Default);
        let src = &summaries[0]["sources"]["price"];
        assert_eq!(src["type"], "http");
        assert_eq!(src["request"], "pricing_lookup.json");
        assert!(src.get("url").is_none(), "the referenced HTTP request file must never be resolved/inlined here");
        assert!(src.get("body").is_none());
        assert!(src.get("auth").is_none());
    }

    #[test]
    fn an_unparsable_endpoint_file_is_skipped_not_fatal_to_the_whole_summary() {
        let root = temp_endpoints_root();
        let good = root.join("ping");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(good.join("endpoint.get.json"), r#"{ "operationId": "ping", "sources": {}, "response": {} }"#).unwrap();

        let bad = root.join("broken");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("endpoint.get.json"), "not valid json").unwrap();

        let summaries = endpoint_summaries(&tree_for_tests(&root), MethodCase::Default);
        assert_eq!(summaries.len(), 1, "the malformed file must be skipped, not fail the whole summary");
        assert_eq!(summaries[0]["operationId"], "ping");
    }

    #[test]
    fn an_array_response_reports_its_source_and_item_fields() {
        let root = temp_endpoints_root();
        let dir = root.join("cars");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{
                "operationId": "listCars",
                "sources": { "cars": { "type": "sql", "connection": "db", "script": "SELECT * FROM cars", "cardinality": "many" } },
                "response": { "type": "array", "source": "sources.cars", "items": { "vin": "vin" } }
            }"#,
        )
        .unwrap();

        let summaries = endpoint_summaries(&tree_for_tests(&root), MethodCase::Default);
        let response = &summaries[0]["response"];
        assert_eq!(response["kind"], "array");
        assert_eq!(response["source"], "sources.cars");
        assert_eq!(response["items"]["vin"]["from"], "vin");
        assert_eq!(summaries[0]["sources"]["cars"]["cardinality"], "many");
    }
}

#[cfg(test)]
mod m4_docs_tests {
    use super::*;
    use crate::openapi::endpoint_tree::tree_for_tests;

    fn temp_root() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-docs-m4-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    const STUB: &str = r#"{ "operationId": "o", "sources": {}, "response": {} }"#;

    fn write(root: &std::path::Path, dir: &str, token: &str) {
        let d = root.join("datasources/endpoints").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("endpoint.{token}.json")), STUB).unwrap();
    }

    fn methods(summaries: &[Value]) -> Vec<String> {
        let mut m: Vec<String> = summaries.iter().map(|s| s["method"].as_str().unwrap().to_string()).collect();
        m.sort();
        m
    }

    #[test]
    fn summaries_show_the_wire_method_for_each_token_kind() {
        let root = temp_root();
        write(&root, "a", "~purge");
        write(&root, "b", "PURGE");
        write(&root, "c", "query");
        write(&root, "d", "~_50urge");
        write(&root, "e", "~_58_2e_59");
        let found = endpoint_summaries(&tree_for_tests(&root.join("datasources/endpoints")), MethodCase::Exact);
        assert_eq!(methods(&found), ["PURGE", "Purge", "QUERY", "X.Y", "purge"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn default_mode_summaries_omit_a_wrong_mode_file() {
        let root = temp_root();
        write(&root, "a", "~purge");
        write(&root, "b", "PURGE");
        let found = endpoint_summaries(&tree_for_tests(&root.join("datasources/endpoints")), MethodCase::Default);
        assert_eq!(methods(&found), ["PURGE"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn operations_json_and_endpoints_json_join_on_the_wire_method_and_path_for_case_distinct_methods() {
        let root = temp_root();
        write(&root, "things", "~purge");
        write(&root, "things", "PURGE");
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    additionalOperations:\n      purge:\n        operationId: lower\n        responses: { '200': { description: ok } }\n      PURGE:\n        operationId: upper\n        responses: { '200': { description: ok } }\n";
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions { case_sensitive_methods: true }).unwrap();
        let summaries = endpoint_summaries(&tree_for_tests(&root.join("datasources/endpoints")), MethodCase::Exact);
        let router = crate::server::docs_ui_router(
            crate::config::DocsUiMode::Public,
            "docs",
            Some(std::sync::Arc::new(doc)),
            std::sync::Arc::new(crate::security::SecurityConfig::default()),
            summaries,
        );
        let addr = crate::server::spawn_served(router, true).await;
        let operations: Value = reqwest::get(format!("http://{addr}/docs/operations.json")).await.unwrap().json().await.unwrap();
        let endpoints: Value = reqwest::get(format!("http://{addr}/docs/endpoints.json")).await.unwrap().json().await.unwrap();
        let ops = operations["operations"].as_array().unwrap();
        let eps = endpoints.as_array().cloned().or_else(|| endpoints["endpoints"].as_array().cloned()).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(eps.len(), 2);
        for op in ops {
            let joined: Vec<&Value> = eps.iter().filter(|e| e["method"] == op["method"] && e["path"] == op["path"]).collect();
            assert_eq!(joined.len(), 1, "operation {op} must line up with exactly one endpoint summary");
            assert_eq!(joined[0]["operationId"], "o");
        }
        let mut op_methods: Vec<&str> = ops.iter().map(|o| o["method"].as_str().unwrap()).collect();
        op_methods.sort_unstable();
        assert_eq!(op_methods, ["PURGE", "purge"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn operations_json_serialises_a_hostile_looking_method_as_data_not_markup() {
        // A wire method is a validated RFC 9110 token, but '<' style characters can't occur; `&`, `'` and `|` can.
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    additionalOperations:\n      'A&B':\n        operationId: amp\n        responses: { '200': { description: ok } }\n";
        let root = temp_root();
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        let router = crate::server::docs_ui_router(
            crate::config::DocsUiMode::Public,
            "docs",
            Some(std::sync::Arc::new(doc)),
            std::sync::Arc::new(crate::security::SecurityConfig::default()),
            vec![],
        );
        let addr = crate::server::spawn_served(router, false).await;
        let body: Value = reqwest::get(format!("http://{addr}/docs/operations.json")).await.unwrap().json().await.unwrap();
        assert_eq!(body["operations"][0]["method"], "A&B");
        let page = reqwest::get(format!("http://{addr}/docs")).await.unwrap().text().await.unwrap();
        assert!(page.contains("escapeHtml(op.method)"), "the page must HTML-escape the method before inserting it");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn the_shipped_try_it_guard_still_blocks_unsendable_methods_and_gets_the_right_method_input_for_case_distinct_get() {
        let root = temp_root();
        write(&root, "x", "get");
        write(&root, "x", "~get");
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    get:\n      operationId: upper\n      responses: { '200': { description: ok } }\n    additionalOperations:\n      get:\n        operationId: lower\n        responses: { '200': { description: ok } }\n";
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions { case_sensitive_methods: true }).unwrap();
        let summaries = endpoint_summaries(&tree_for_tests(&root.join("datasources/endpoints")), MethodCase::Exact);
        let router = crate::server::docs_ui_router(
            crate::config::DocsUiMode::Public,
            "docs",
            Some(std::sync::Arc::new(doc)),
            std::sync::Arc::new(crate::security::SecurityConfig::default()),
            summaries,
        );
        let addr = crate::server::spawn_served(router, true).await;

        // operations.json: the fixed operation says GET, the exact-mode one says get - the guard compares these strings.
        let operations: Value = reqwest::get(format!("http://{addr}/docs/operations.json")).await.unwrap().json().await.unwrap();
        let by_id = |id: &str| operations["operations"].as_array().unwrap().iter().find(|o| o["operationId"] == id).unwrap().clone();
        assert_eq!(by_id("upper")["method"], "GET");
        assert_eq!(by_id("lower")["method"], "get");

        // The page's guard: CONNECT/TRACE/TRACK can never be sent, and the six fetch-normalised names can only be sent
        // when the method is already exactly upper case (m !== u disables the lowercase spelling).
        let page = reqwest::get(format!("http://{addr}/docs")).await.unwrap().text().await.unwrap();
        assert!(page.contains(r#"["CONNECT", "TRACE", "TRACK"].indexOf(u) >= 0"#));
        assert!(page.contains(r#"["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"].indexOf(u) >= 0 && m !== u"#));
        assert!(page.contains("var cannotSend ="));
        assert!(page.contains("tryButton.disabled = true"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
