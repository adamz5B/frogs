//! Tool mapping (`plan_tools`) and argument splitting (`split_arguments`) of `mcp::tools`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::value::RawValue;
use serde_json::{Value, json};

use super::protocol::{INVALID_PARAMS, ProtoError};
use super::tools::*;
use crate::config::McpConfig;
use crate::endpoint::EndpointFile;
use crate::openapi::{LoadOptions, OpenApiDocument};

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-mcp-tools-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\n";

fn load_doc(components: &str, paths: &str) -> OpenApiDocument {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(&file, format!("{HEAD}components:\n  schemas: {{}}\n{components}paths:\n{paths}")).unwrap();
    let doc = crate::openapi::load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    doc
}

fn endpoint(extra: &str) -> EndpointFile {
    let tail = if extra.is_empty() { String::new() } else { format!(", {extra}") };
    serde_json::from_str(&format!(r#"{{ "operationId": "x", "sources": {{}}, "response": {{}}{tail} }}"#)).unwrap()
}

fn expose() -> EndpointFile {
    endpoint(r#""mcp": { "expose": true }"#)
}

struct Cand {
    url_path: &'static str,
    token: &'static str,
    file: PathBuf,
    endpoint: EndpointFile,
}

fn cand(url_path: &'static str, token: &'static str, endpoint: EndpointFile) -> Cand {
    Cand {
        url_path,
        token,
        file: Path::new("endpoints")
            .join(url_path.trim_start_matches('/').replace(':', "_"))
            .join(format!("endpoint.{token}.json")),
        endpoint,
    }
}

fn plan_with(cands: &[Cand], doc: Option<&OpenApiDocument>, settings: &McpConfig) -> Planned {
    let candidates: Vec<Candidate> = cands
        .iter()
        .map(|c| Candidate {
            url_path: c.url_path,
            token: c.token,
            file: &c.file,
            endpoint: &c.endpoint,
        })
        .collect();
    plan_tools(&candidates, doc, settings, &crate::mcp::AuthSettings::default())
}

fn plan(cands: &[Cand], doc: &OpenApiDocument) -> Planned {
    plan_with(cands, Some(doc), &McpConfig::default())
}

fn tools_of(planned: &Planned) -> Vec<Value> {
    let list: Value = serde_json::from_str(planned.plan.as_ref().expect("a plan").list_legacy.get()).unwrap();
    list["tools"].as_array().unwrap().clone()
}

fn tool(planned: &Planned, name: &str) -> Value {
    tools_of(planned).into_iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("no tool {name}"))
}

fn errors(planned: &Planned) -> String {
    assert!(planned.plan.is_none(), "expected the plan to be refused");
    planned.errors.join("\n")
}

const GET_ONE: &str = "  /cars/{vin}:\n    get:\n      operationId: getCar\n      summary: Fetch a car\n      parameters:\n        - { name: vin, in: path, required: true, schema: { type: string } }\n      responses: { '200': { description: ok } }\n";

// ------------------------------------------------------------------ mcp block

#[test]
fn only_an_endpoint_with_expose_true_becomes_a_tool() {
    let doc = load_doc("", GET_ONE);
    let hidden = endpoint(r#""mcp": { "expose": false }"#);
    let none = endpoint("");
    for e in [hidden, none] {
        let planned = plan(&[cand("/cars/:vin", "get", e)], &doc);
        assert!(planned.errors.is_empty());
        assert!(tools_of(&planned).is_empty());
    }
    let planned = plan(&[cand("/cars/:vin", "get", expose())], &doc);
    assert_eq!(tools_of(&planned).len(), 1);
}

#[test]
fn a_malformed_mcp_block_is_a_problem_naming_the_file_not_a_silent_skip() {
    let doc = load_doc("", GET_ONE);
    for block in [
        r#""mcp": true"#,
        r#""mcp": []"#,
        r#""mcp": {}"#,
        r#""mcp": { "expose": "yes" }"#,
        r#""mcp": { "expose": true, "exposed": true }"#,
        r#""mcp": { "expose": true, "name": 5 }"#,
        r#""mcp": { "expose": true, "description": [] }"#,
    ] {
        let planned = plan(&[cand("/cars/:vin", "get", endpoint(block))], &doc);
        let text = errors(&planned);
        assert!(text.contains("endpoint.get.json") && text.contains("mcp"), "{block}: {text}");
    }
}

#[test]
fn a_malformed_mcp_block_does_not_make_the_endpoint_file_unparseable() {
    for block in [r#""mcp": 5"#, r#""mcp": "x""#, r#""mcp": [1,2]"#, r#""mcp": null"#] {
        let parsed: Result<EndpointFile, _> = serde_json::from_str(&format!(r#"{{ "operationId": "x", "sources": {{}}, "response": {{}}, {block} }}"#));
        assert!(parsed.is_ok(), "{block}");
    }
}

// ------------------------------------------------------------------ names

#[test]
fn the_tool_name_defaults_to_the_operation_id_and_mcp_name_overrides_it() {
    let doc = load_doc("", GET_ONE);
    let planned = plan(&[cand("/cars/:vin", "get", expose())], &doc);
    assert_eq!(tools_of(&planned)[0]["name"], "getCar");
    let named = endpoint(r#""mcp": { "expose": true, "name": "find.car-1_x" }"#);
    let planned = plan(&[cand("/cars/:vin", "get", named)], &doc);
    assert_eq!(tools_of(&planned)[0]["name"], "find.car-1_x");
}

#[test]
fn an_empty_or_whitespace_operation_id_without_mcp_name_is_refused_and_mcp_name_rescues_it() {
    for id in ["''", "'   '"] {
        let doc = load_doc("", &GET_ONE.replace("getCar", id));
        let text = errors(&plan(&[cand("/cars/:vin", "get", expose())], &doc));
        assert!(text.contains("empty operationId") && text.contains("mcp.name"), "{id}: {text}");
        let named = endpoint(r#""mcp": { "expose": true, "name": "ok" }"#);
        assert_eq!(tools_of(&plan(&[cand("/cars/:vin", "get", named)], &doc))[0]["name"], "ok");
    }
}

#[test]
fn names_outside_the_allowed_character_set_or_over_128_bytes_are_refused() {
    let doc = load_doc("", GET_ONE);
    let too_long = "a".repeat(129);
    for bad in ["has space", "slash/name", "caf\u{e9}", "a:b", "", too_long.as_str()] {
        let block = format!(r#""mcp": {{ "expose": true, "name": {} }}"#, serde_json::to_string(bad).unwrap());
        let planned = plan(&[cand("/cars/:vin", "get", endpoint(&block))], &doc);
        let text = errors(&planned);
        assert!(text.contains("not valid"), "{bad:?}: {text}");
    }
    let at_cap = "a".repeat(128);
    let block = format!(r#""mcp": {{ "expose": true, "name": "{at_cap}" }}"#);
    assert!(plan(&[cand("/cars/:vin", "get", endpoint(&block))], &doc).plan.is_some());
}

#[test]
fn two_tools_with_one_name_are_refused_naming_both_files() {
    let paths = format!(
        "{GET_ONE}  /other/{{vin}}:\n    get:\n      operationId: getOther\n      parameters:\n        - {{ name: vin, in: path, required: true, schema: {{ type: string }} }}\n      responses: {{ '200': {{ description: ok }} }}\n"
    );
    let doc = load_doc("", &paths);
    let clash = endpoint(r#""mcp": { "expose": true, "name": "getCar" }"#);
    let text = errors(&plan(&[cand("/cars/:vin", "get", expose()), cand("/other/:vin", "get", clash)], &doc));
    assert!(text.contains("already used by") && text.contains("cars") && text.contains("other"), "{text}");
}

#[test]
fn tools_are_listed_sorted_by_name_whatever_the_candidate_order() {
    let paths = "  /b:\n    get: { operationId: zeta, responses: { '200': { description: ok } } }\n  /a:\n    get: { operationId: alpha, responses: { '200': { description: ok } } }\n  /c:\n    get: { operationId: Mid, responses: { '200': { description: ok } } }\n";
    let doc = load_doc("", paths);
    let planned = plan(&[cand("/b", "get", expose()), cand("/a", "get", expose()), cand("/c", "get", expose())], &doc);
    let names: Vec<String> = tools_of(&planned).iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["Mid", "alpha", "zeta"]);
}

// ------------------------------------------------------------------ operation matching

#[test]
fn an_exposed_endpoint_with_no_loaded_spec_is_refused() {
    let text = errors(&plan_with(&[cand("/cars/:vin", "get", expose())], None, &McpConfig::default()));
    assert!(text.contains("could not be loaded"), "{text}");
}

#[test]
fn an_exposed_endpoint_with_no_spec_operation_is_refused() {
    let doc = load_doc("", GET_ONE);
    let text = errors(&plan(&[cand("/nothing", "get", expose())], &doc));
    assert!(text.contains("no operation for this path and method"), "{text}");
    let wrong_method = errors(&plan(&[cand("/cars/:vin", "post", expose())], &doc));
    assert!(wrong_method.contains("no operation"), "{wrong_method}");
}

#[test]
fn a_folder_that_only_matches_through_the_parameter_name_fallback_is_refused_with_the_rename() {
    let doc = load_doc("", GET_ONE);
    let text = errors(&plan(&[cand("/cars/:id", "get", expose())], &doc));
    assert!(text.contains("rename the folder to '/cars/{vin}'"), "{text}");
}

#[test]
fn a_route_template_parameter_the_spec_does_not_declare_as_a_path_parameter_is_refused() {
    let paths = "  /cars/{vin}:\n    get:\n      operationId: getCar\n      responses: { '200': { description: ok } }\n";
    let doc = load_doc("", paths);
    let text = errors(&plan(&[cand("/cars/:vin", "get", expose())], &doc));
    assert!(text.contains("route template parameter 'vin'"), "{text}");
}

#[test]
fn a_parameter_named_body_next_to_a_request_body_and_a_path_query_name_clash_are_refused() {
    let with_body = "  /x:\n    post:\n      operationId: p\n      parameters:\n        - { name: body, in: query, schema: { type: string } }\n      requestBody: { content: { application/json: { schema: { type: object } } } }\n      responses: { '200': { description: ok } }\n";
    let text = errors(&plan(&[cand("/x", "post", expose())], &load_doc("", with_body)));
    assert!(text.contains("named 'body'"), "{text}");

    let clash = "  /x/{id}:\n    get:\n      operationId: g\n      parameters:\n        - { name: id, in: path, required: true, schema: { type: string } }\n        - { name: id, in: query, schema: { type: string } }\n      responses: { '200': { description: ok } }\n";
    let text = errors(&plan(&[cand("/x/:id", "get", expose())], &load_doc("", clash)));
    assert!(text.contains("share the name 'id'"), "{text}");
}

#[test]
fn a_parameter_named_body_is_fine_when_the_operation_has_no_request_body() {
    let spec = "  /x:\n    get:\n      operationId: g\n      parameters:\n        - { name: body, in: query, schema: { type: string } }\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "get", expose())], &load_doc("", spec));
    assert!(planned.errors.is_empty(), "{:?}", planned.errors);
}

// ------------------------------------------------------------------ input schema

#[test]
fn a_path_level_parameter_shows_up_in_the_input_schema_as_required_with_its_description() {
    let spec = "  /cars/{vin}:\n    parameters:\n      - { name: vin, in: path, required: true, description: The vehicle id, schema: { type: string } }\n      - { name: fields, in: query, schema: { type: string } }\n    get:\n      operationId: getCar\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/cars/:vin", "get", expose())], &load_doc("", spec));
    let t = tool(&planned, "getCar");
    let schema = &t["inputSchema"];
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["vin"], json!({ "type": "string", "description": "The vehicle id" }));
    assert_eq!(schema["properties"]["fields"], json!({ "type": "string" }));
    assert_eq!(schema["required"], json!(["vin"]));
}

#[test]
fn a_path_parameter_is_required_even_when_the_spec_forgot_required_true() {
    let spec = GET_ONE.replace("required: true, ", "");
    let planned = plan(&[cand("/cars/:vin", "get", expose())], &load_doc("", &spec));
    assert_eq!(tool(&planned, "getCar")["inputSchema"]["required"], json!(["vin"]));
}

#[test]
fn query_parameters_are_required_only_when_the_spec_says_so() {
    let spec = "  /x:\n    get:\n      operationId: g\n      parameters:\n        - { name: a, in: query, required: true, schema: { type: integer } }\n        - { name: b, in: query, schema: { type: integer } }\n        - { name: h, in: header, required: true, schema: { type: string } }\n        - { name: c, in: cookie, schema: { type: string } }\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "get", expose())], &load_doc("", spec));
    let schema = &tool(&planned, "g")["inputSchema"];
    assert_eq!(schema["required"], json!(["a"]));
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("a") && props.contains_key("b"));
    assert!(
        !props.contains_key("h") && !props.contains_key("c"),
        "header and cookie parameters are never arguments"
    );
}

#[test]
fn an_operation_level_parameter_overrides_the_path_level_one_with_the_same_name_and_location() {
    let spec = "  /x:\n    parameters:\n      - { name: q, in: query, required: true, schema: { type: string } }\n    get:\n      operationId: g\n      parameters:\n        - { name: q, in: query, required: false, schema: { type: integer } }\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "get", expose())], &load_doc("", spec));
    let schema = &tool(&planned, "g")["inputSchema"];
    assert_eq!(schema["properties"]["q"], json!({ "type": "integer" }));
    assert!(schema.get("required").is_none(), "the override made it optional: {schema}");
}

#[test]
fn array_object_and_content_declared_parameters_are_advertised_as_strings_with_a_verbatim_note() {
    let spec = "  /x:\n    get:\n      operationId: g\n      parameters:\n        - { name: tags, in: query, description: Tag list, schema: { type: array, items: { type: string } } }\n        - { name: filter, in: query, schema: { type: object } }\n        - { name: raw, in: query, content: { application/json: { schema: { type: object } } } }\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "get", expose())], &load_doc("", spec));
    let props = tool(&planned, "g")["inputSchema"]["properties"].clone();
    for name in ["tags", "filter", "raw"] {
        assert_eq!(props[name]["type"], "string", "{name}");
        assert!(
            props[name]["description"].as_str().unwrap().contains("passed through verbatim"),
            "{name}: {}",
            props[name]
        );
        assert!(props[name].get("items").is_none());
    }
    assert!(props["tags"]["description"].as_str().unwrap().starts_with("Tag list"));
}

#[test]
fn the_request_body_schema_is_inlined_with_its_refs_and_a_cycle_collapses_to_anything() {
    let components = "  schemas:\n    Node: { type: object, properties: { next: { $ref: '#/components/schemas/Node' }, label: { type: string } } }\n    Car: { type: object, properties: { vin: { type: string }, owner: { $ref: '#/components/schemas/Owner' } } }\n    Owner: { type: object, properties: { name: { type: string } } }\n";
    let spec = "  /cars:\n    post:\n      operationId: create\n      requestBody:\n        required: true\n        content: { application/json: { schema: { $ref: '#/components/schemas/Car' } } }\n      responses: { '200': { description: ok } }\n  /nodes:\n    post:\n      operationId: node\n      requestBody:\n        content: { application/json: { schema: { $ref: '#/components/schemas/Node' } } }\n      responses: { '200': { description: ok } }\n";
    let doc = load_doc_with_schemas(components, spec);
    let planned = plan(&[cand("/cars", "post", expose()), cand("/nodes", "post", expose())], &doc);
    let create = tool(&planned, "create");
    let body = &create["inputSchema"]["properties"]["body"];
    assert_eq!(body["properties"]["owner"]["properties"]["name"]["type"], "string", "{body}");
    assert!(!create.to_string().contains("$ref"), "{create}");
    assert_eq!(create["inputSchema"]["required"], json!(["body"]));

    let node = tool(&planned, "node");
    assert_eq!(node["inputSchema"]["properties"]["body"]["properties"]["next"], json!({}), "the cycle becomes {{}}");
    assert!(node["inputSchema"].get("required").is_none(), "an optional body is not required");
}

/// `load_doc` always writes an empty `schemas`, so a spec with real components writes its own header.
fn load_doc_with_schemas(components: &str, paths: &str) -> OpenApiDocument {
    let dir = tempdir();
    let file = dir.join("openapi.yaml");
    std::fs::write(&file, format!("{HEAD}components:\n{components}paths:\n{paths}")).unwrap();
    let doc = crate::openapi::load(&file, LoadOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    doc
}

#[test]
fn nullable_in_a_body_schema_becomes_a_json_schema_type_array() {
    let spec = "  /x:\n    post:\n      operationId: p\n      requestBody:\n        content: { application/json: { schema: { type: object, properties: { n: { type: string, nullable: true } } } } }\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "post", expose())], &load_doc("", spec));
    assert_eq!(
        tool(&planned, "p")["inputSchema"]["properties"]["body"]["properties"]["n"],
        json!({ "type": ["string", "null"] })
    );
}

#[test]
fn a_number_typed_body_appends_the_double_precision_note_but_an_integer_one_does_not() {
    let number = "  /x:\n    post:\n      operationId: p\n      summary: Make it\n      requestBody:\n        content: { application/json: { schema: { type: object, properties: { price: { type: number } } } } }\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "post", expose())], &load_doc("", number));
    assert_eq!(tool(&planned, "p")["description"], "Make it Numbers in `body` are processed as IEEE-754 doubles.");
    let integer = number.replace("type: number", "type: integer");
    let planned = plan(&[cand("/x", "post", expose())], &load_doc("", &integer));
    assert_eq!(tool(&planned, "p")["description"], "Make it");
}

#[test]
fn title_and_description_fall_back_in_order_with_mcp_description_winning() {
    let spec =
        "  /x:\n    get:\n      operationId: g\n      summary: The summary\n      description: The long description\n      responses: { '200': { description: ok } }\n";
    let doc = load_doc("", spec);
    let t = tool(&plan(&[cand("/x", "get", expose())], &doc), "g");
    assert_eq!(t["title"], "The summary");
    assert_eq!(t["description"], "The summary");
    let no_summary = spec.replace("      summary: The summary\n", "");
    let t = tool(&plan(&[cand("/x", "get", expose())], &load_doc("", &no_summary)), "g");
    assert!(t.get("title").is_none());
    assert_eq!(t["description"], "The long description");
    let own = endpoint(r#""mcp": { "expose": true, "description": "Mine" }"#);
    assert_eq!(tool(&plan(&[cand("/x", "get", own)], &doc), "g")["description"], "Mine");
}

#[test]
fn annotations_are_explicit_per_method() {
    let methods = [
        ("get", "GET", json!({ "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false })),
        (
            "delete",
            "DELETE",
            json!({ "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false }),
        ),
        ("put", "PUT", json!({ "readOnlyHint": false, "idempotentHint": true, "openWorldHint": false })),
        ("post", "POST", json!({ "readOnlyHint": false, "openWorldHint": false })),
        ("patch", "PATCH", json!({ "readOnlyHint": false, "openWorldHint": false })),
    ];
    for (token, _wire, expected) in methods {
        let spec = format!("  /x:\n    {token}:\n      operationId: op_{token}\n      responses: {{ '200': {{ description: ok }} }}\n");
        let planned = plan(&[cand("/x", Box::leak(token.to_string().into_boxed_str()), expose())], &load_doc("", &spec));
        assert_eq!(tool(&planned, &format!("op_{token}"))["annotations"], expected, "{token}");
    }
}

#[test]
fn the_query_method_is_annotated_like_get() {
    let spec = "  /x:\n    query:\n      operationId: q\n      responses: { '200': { description: ok } }\n";
    let planned = plan(&[cand("/x", "query", expose())], &load_doc("", spec));
    assert_eq!(
        tool(&planned, "q")["annotations"],
        json!({ "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false })
    );
}

#[test]
fn no_tool_ever_declares_an_output_schema() {
    let planned = plan(&[cand("/cars/:vin", "get", expose())], &load_doc("", GET_ONE));
    assert!(tool(&planned, "getCar").get("outputSchema").is_none());
}

// ------------------------------------------------------------------ list results and caps

#[test]
fn the_modern_list_carries_ttl_scope_and_result_type_and_the_legacy_list_does_not() {
    let doc = load_doc("", GET_ONE);
    let planned = plan(&[cand("/cars/:vin", "get", expose())], &doc);
    let plan_ref = planned.plan.as_ref().unwrap();
    let modern: Value = serde_json::from_str(plan_ref.list_modern.get()).unwrap();
    assert_eq!(modern["ttlMs"], 300_000);
    assert_eq!(modern["cacheScope"], "public");
    assert_eq!(modern["resultType"], "complete");
    assert!(modern.get("nextCursor").is_none());
    let legacy: Value = serde_json::from_str(plan_ref.list_legacy.get()).unwrap();
    assert_eq!(legacy.as_object().unwrap().keys().collect::<Vec<_>>(), ["tools"]);
    assert_eq!(modern["tools"], legacy["tools"]);
}

#[test]
fn a_configured_list_ttl_is_used_in_the_modern_list() {
    let doc = load_doc("", GET_ONE);
    let settings: McpConfig = serde_json::from_str(r#"{ "listTtlMs": 1234 }"#).unwrap();
    let planned = plan_with(&[cand("/cars/:vin", "get", expose())], Some(&doc), &settings);
    let modern: Value = serde_json::from_str(planned.plan.as_ref().unwrap().list_modern.get()).unwrap();
    assert_eq!(modern["ttlMs"], 1234);
}

#[test]
fn a_tools_list_over_one_mebibyte_is_refused_naming_the_largest_tool() {
    let huge = "d".repeat(1_100_000);
    let spec = format!("  /big:\n    get:\n      operationId: bigTool\n      description: {huge}\n      responses: {{ '200': {{ description: ok }} }}\n");
    let text = errors(&plan(&[cand("/big", "get", expose())], &load_doc("", &spec)));
    assert!(
        text.contains("over the 1048576-byte limit") && text.contains("bigTool"),
        "{}",
        &text[..text.len().min(400)]
    );
}

#[test]
fn a_body_schema_over_the_node_budget_refuses_that_tool() {
    let props: Vec<String> = (0..21_000).map(|i| format!("p{i}: {{ type: string }}")).collect();
    let spec = format!(
        "  /x:\n    post:\n      operationId: p\n      requestBody:\n        content: {{ application/json: {{ schema: {{ type: object, properties: {{ {} }} }} }} }}\n      responses: {{ '200': {{ description: ok }} }}\n",
        props.join(", ")
    );
    let text = errors(&plan(&[cand("/x", "post", expose())], &load_doc("", &spec)));
    assert!(text.contains("schema size budget"), "{text}");
}

// ------------------------------------------------------------------ warnings

#[test]
fn an_exposed_generated_stub_and_an_exposed_secured_endpoint_each_warn() {
    let doc = load_doc("", GET_ONE);
    let stub = endpoint(r#""_generated": true, "mcp": { "expose": true }"#);
    let planned = plan(&[cand("/cars/:vin", "get", stub)], &doc);
    assert!(planned.warnings.iter().any(|w| w.contains("generated stub")), "{:?}", planned.warnings);
    let secured = endpoint(r#""security": "bearer", "mcp": { "expose": true }"#);
    let planned = plan(&[cand("/cars/:vin", "get", secured)], &doc);
    assert!(
        planned.warnings.iter().any(|w| w.contains("not authenticated") && w.contains("bearer")),
        "{:?}",
        planned.warnings
    );
}

// ------------------------------------------------------------------ split_arguments

fn arg_map(entries: &[(&str, ArgLoc)]) -> HashMap<String, ArgLoc> {
    entries.iter().map(|(name, loc)| (name.to_string(), *loc)).collect()
}

fn raw(json: &str) -> Box<RawValue> {
    RawValue::from_string(json.to_string()).unwrap()
}

fn split(args: &HashMap<String, ArgLoc>, path_params: &[&str], arguments: Option<&str>) -> Result<SplitArgs, ProtoError> {
    let path_params: Vec<String> = path_params.iter().map(|s| s.to_string()).collect();
    let raw = arguments.map(raw);
    split_arguments(args, &path_params, raw.as_deref())
}

#[test]
fn strings_numbers_and_booleans_become_their_http_text_form_with_numbers_kept_verbatim() {
    let args = arg_map(&[
        ("vin", ArgLoc::Path),
        ("price", ArgLoc::Query),
        ("big", ArgLoc::Query),
        ("flag", ArgLoc::Query),
        ("off", ArgLoc::Query),
    ]);
    let split = split(
        &args,
        &["vin"],
        Some(r#"{"vin":"A\"B\u00e9","price":12345678901234567.89,"big":1e3,"flag":true,"off":false}"#),
    )
    .unwrap();
    assert_eq!(split.path["vin"], "A\"B\u{e9}");
    assert_eq!(split.query["price"], "12345678901234567.89");
    assert_eq!(split.query["big"], "1e3");
    assert_eq!(split.query["flag"], "true");
    assert_eq!(split.query["off"], "false");
    assert_eq!(split.body, Value::Null);
}

#[test]
fn a_null_argument_means_absent() {
    let args = arg_map(&[("a", ArgLoc::Query), ("body", ArgLoc::Body)]);
    let s = split(&args, &[], Some(r#"{"a":null}"#)).unwrap();
    assert!(s.query.is_empty());
    let s = split(&args, &[], Some(r#"{"body":null}"#)).unwrap();
    assert_eq!(s.body, Value::Null);
}

#[test]
fn an_array_or_object_for_a_path_or_query_parameter_is_invalid_params() {
    let args = arg_map(&[("a", ArgLoc::Query), ("p", ArgLoc::Path)]);
    for bad in [r#"{"a":[1]}"#, r#"{"a":{"x":1}}"#, r#"{"p":[1],"a":"x"}"#] {
        assert_eq!(split(&args, &[], Some(bad)).err().unwrap().code, INVALID_PARAMS, "{bad}");
    }
}

#[test]
fn an_unknown_argument_name_is_invalid_params() {
    let args = arg_map(&[("a", ArgLoc::Query)]);
    assert_eq!(split(&args, &[], Some(r#"{"a":"1","zzz":"2"}"#)).err().unwrap().code, INVALID_PARAMS);
}

#[test]
fn arguments_must_be_an_object_when_present_and_may_be_absent() {
    let args = arg_map(&[("a", ArgLoc::Query)]);
    for bad in ["[]", "5", "\"x\"", "null", "true"] {
        assert_eq!(split(&args, &[], Some(bad)).err().unwrap().code, INVALID_PARAMS, "{bad}");
    }
    assert!(split(&args, &[], None).is_ok());
    assert!(split(&args, &[], Some("{}")).is_ok());
}

#[test]
fn every_template_path_parameter_must_be_present_and_non_empty() {
    let args = arg_map(&[("vin", ArgLoc::Path), ("q", ArgLoc::Query)]);
    assert_eq!(split(&args, &["vin"], Some("{}")).err().unwrap().code, INVALID_PARAMS);
    assert_eq!(split(&args, &["vin"], None).err().unwrap().code, INVALID_PARAMS);
    assert_eq!(split(&args, &["vin"], Some(r#"{"vin":""}"#)).err().unwrap().code, INVALID_PARAMS);
    assert_eq!(split(&args, &["vin"], Some(r#"{"vin":null}"#)).err().unwrap().code, INVALID_PARAMS);
    assert_eq!(split(&args, &["vin"], Some(r#"{"q":"x"}"#)).err().unwrap().code, INVALID_PARAMS);
    assert!(split(&args, &["vin"], Some(r#"{"vin":"7"}"#)).is_ok());
}

#[test]
fn a_body_argument_is_parsed_as_json_of_any_shape() {
    let args = arg_map(&[("body", ArgLoc::Body)]);
    for (text, expected) in [
        (r#"{"body":{"a":[1,2,{"b":null}]}}"#, json!({ "a": [1, 2, { "b": null }] })),
        (r#"{"body":"text"}"#, json!("text")),
        (r#"{"body":7}"#, json!(7)),
    ] {
        assert_eq!(split(&args, &[], Some(text)).unwrap().body, expected, "{text}");
    }
}

#[test]
fn a_body_whose_number_cannot_be_represented_is_invalid_params_not_a_silent_null() {
    let args = arg_map(&[("body", ArgLoc::Body)]);
    for text in [r#"{"body":1e400}"#, r#"{"body":{"x":1e999}}"#] {
        assert_eq!(split(&args, &[], Some(text)).err().unwrap().code, INVALID_PARAMS, "{text}");
    }
}

#[test]
fn path_traversal_looking_values_are_carried_as_plain_strings_never_joined_into_anything() {
    let args = arg_map(&[("vin", ArgLoc::Path)]);
    for value in ["a/../b", "%2e%2e", "..", "../../etc/passwd", "a\\..\\b"] {
        let s = split(&args, &["vin"], Some(&format!(r#"{{"vin":{}}}"#, serde_json::to_string(value).unwrap()))).unwrap();
        assert_eq!(s.path["vin"], value);
    }
}

// ------------------------------------------------------------------ Milestone 2: gate, scopes and protected resource

fn plan_auth(cands: &[Cand], doc: &OpenApiDocument, auth: &crate::mcp::AuthSettings) -> Planned {
    let candidates: Vec<Candidate> = cands
        .iter()
        .map(|c| Candidate {
            url_path: c.url_path,
            token: c.token,
            file: &c.file,
            endpoint: &c.endpoint,
        })
        .collect();
    plan_tools(&candidates, Some(doc), &McpConfig::default(), auth)
}

fn protected(scopes: &[&str]) -> crate::mcp::AuthSettings {
    crate::mcp::AuthSettings {
        access_scheme: None,
        protected: Some(super::settings::ProtectedResource {
            resource: "https://api.example.com/mcp".to_string(),
            metadata_path: "/.well-known/oauth-protected-resource/mcp".to_string(),
            metadata_url: "https://api.example.com/.well-known/oauth-protected-resource/mcp".to_string(),
            authorization_servers: vec!["https://auth.example.com".to_string()],
            scopes_supported: scopes.iter().map(|s| s.to_string()).collect(),
            host: "api.example.com".to_string(),
        }),
    }
}

fn secured(extra: &str) -> EndpointFile {
    endpoint(&format!(r#""mcp": {{ "expose": true }}, "security": "oauth"{extra}"#))
}

#[test]
fn a_gated_server_lists_tools_with_a_private_cache_scope_and_an_ungated_one_publicly() {
    let doc = load_doc("", GET_ONE);
    let cands = [cand("/cars/:vin", "get", expose())];
    let gated = crate::mcp::AuthSettings {
        access_scheme: Some("oauth".to_string()),
        protected: None,
    };
    let planned = plan_auth(&cands, &doc, &gated);
    let modern: Value = serde_json::from_str(planned.plan.as_ref().unwrap().list_modern.get()).unwrap();
    assert_eq!(modern["cacheScope"], "private");
    let open: Value = serde_json::from_str(plan_auth(&cands, &doc, &crate::mcp::AuthSettings::default()).plan.as_ref().unwrap().list_modern.get()).unwrap();
    assert_eq!(open["cacheScope"], "public");
}

#[test]
fn the_anonymous_listing_warning_for_a_secured_tool_disappears_when_an_access_scheme_gates_the_list() {
    let doc = load_doc("", GET_ONE);
    let cands = [cand("/cars/:vin", "get", secured(""))];
    let ungated = plan_auth(&cands, &doc, &crate::mcp::AuthSettings::default());
    assert!(ungated.warnings.iter().any(|w| w.contains("listed to anyone")), "{:?}", ungated.warnings);
    let gated = plan_auth(
        &cands,
        &doc,
        &crate::mcp::AuthSettings {
            access_scheme: Some("oauth".to_string()),
            protected: None,
        },
    );
    assert!(gated.warnings.iter().all(|w| !w.contains("listed to anyone")), "{:?}", gated.warnings);
}

#[test]
fn a_tools_security_scopes_are_carried_on_its_plan_entry() {
    let doc = load_doc("", GET_ONE);
    let planned = plan_auth(
        &[cand("/cars/:vin", "get", secured(r#", "securityScopes": ["cars.read", "cars.write"]"#))],
        &doc,
        &protected(&["cars.read", "cars.write"]),
    );
    let tools = &planned.plan.as_ref().unwrap().tools;
    assert_eq!(tools[0].security_scopes, ["cars.read", "cars.write"]);
    assert!(planned.warnings.iter().all(|w| !w.contains("not listed")), "{:?}", planned.warnings);
}

#[test]
fn a_tool_scope_missing_from_scopes_supported_is_warned_naming_the_scope() {
    let doc = load_doc("", GET_ONE);
    let planned = plan_auth(
        &[cand("/cars/:vin", "get", secured(r#", "securityScopes": ["cars.read", "admin"]"#))],
        &doc,
        &protected(&["cars.read"]),
    );
    let warning = planned
        .warnings
        .iter()
        .find(|w| w.contains("not listed in mcp.protectedResource.scopesSupported"))
        .expect("a warning");
    assert!(warning.contains("admin") && !warning.contains("cars.read,"), "{warning}");
    assert!(planned.plan.is_some(), "only a warning, never a refusal");
}

#[test]
fn an_empty_scopes_supported_with_exposed_tools_is_warned_once_and_not_without_tools() {
    let doc = load_doc("", GET_ONE);
    let with_tool = plan_auth(&[cand("/cars/:vin", "get", expose())], &doc, &protected(&[]));
    assert_eq!(
        with_tool.warnings.iter().filter(|w| w.contains("scopesSupported is empty")).count(),
        1,
        "{:?}",
        with_tool.warnings
    );
    let none = plan_auth(&[], &doc, &protected(&[]));
    assert!(none.warnings.iter().all(|w| !w.contains("scopesSupported is empty")), "{:?}", none.warnings);
}
