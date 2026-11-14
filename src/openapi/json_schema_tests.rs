//! The JSON-Schema-preserving `$ref` inliner used for MCP tool input schemas.

use serde_json::{Map, Value, json};

use super::json_schema::*;

fn components(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn inline(schema: Value, components: &Map<String, Value>) -> Result<Value, InlineError> {
    inline_component_refs(&schema, components, &mut InlineBudget::new())
}

#[test]
fn a_component_ref_is_replaced_by_the_component_schema_recursively() {
    let comps = components(json!({
        "Car": { "type": "object", "properties": { "owner": { "$ref": "#/components/schemas/Owner" } } },
        "Owner": { "type": "object", "properties": { "address": { "$ref": "#/components/schemas/Address" } } },
        "Address": { "type": "string" }
    }));
    let out = inline(json!({ "$ref": "#/components/schemas/Car" }), &comps).unwrap();
    assert_eq!(out["properties"]["owner"]["properties"]["address"], json!({ "type": "string" }));
    assert!(!out.to_string().contains("$ref"));
}

#[test]
fn refs_inside_arrays_and_combinators_are_inlined_too() {
    let comps = components(json!({ "A": { "type": "integer" }, "B": { "type": "boolean" } }));
    let out = inline(
        json!({ "oneOf": [ { "$ref": "#/components/schemas/A" }, { "$ref": "#/components/schemas/B" } ], "items": { "$ref": "#/components/schemas/A" } }),
        &comps,
    )
    .unwrap();
    assert_eq!(
        out,
        json!({ "oneOf": [ { "type": "integer" }, { "type": "boolean" } ], "items": { "type": "integer" } })
    );
}

#[test]
fn escaped_component_names_are_decoded_per_rfc_6901() {
    let comps = components(json!({ "a/b": { "type": "string" }, "a~b": { "type": "integer" } }));
    assert_eq!(inline(json!({ "$ref": "#/components/schemas/a~1b" }), &comps).unwrap(), json!({ "type": "string" }));
    assert_eq!(inline(json!({ "$ref": "#/components/schemas/a~0b" }), &comps).unwrap(), json!({ "type": "integer" }));
}

#[test]
fn a_self_referencing_component_collapses_the_back_edge_to_an_empty_schema() {
    let comps = components(json!({ "Node": { "type": "object", "properties": { "next": { "$ref": "#/components/schemas/Node" } } } }));
    let out = inline(json!({ "$ref": "#/components/schemas/Node" }), &comps).unwrap();
    assert_eq!(out["properties"]["next"], json!({}));
}

#[test]
fn a_mutual_cycle_is_cut_at_the_first_repeat_and_does_not_overflow() {
    let comps = components(json!({
        "A": { "type": "object", "properties": { "b": { "$ref": "#/components/schemas/B" } } },
        "B": { "type": "object", "properties": { "a": { "$ref": "#/components/schemas/A" } } }
    }));
    let out = inline(json!({ "$ref": "#/components/schemas/A" }), &comps).unwrap();
    assert_eq!(out["properties"]["b"]["properties"]["a"], json!({}));
}

#[test]
fn the_same_component_used_twice_side_by_side_is_inlined_both_times_not_mistaken_for_a_cycle() {
    let comps = components(json!({ "S": { "type": "string" } }));
    let out = inline(
        json!({ "properties": { "x": { "$ref": "#/components/schemas/S" }, "y": { "$ref": "#/components/schemas/S" } } }),
        &comps,
    )
    .unwrap();
    assert_eq!(out["properties"]["x"], json!({ "type": "string" }));
    assert_eq!(out["properties"]["y"], json!({ "type": "string" }));
}

#[test]
fn external_non_component_and_unknown_refs_become_the_empty_schema() {
    let comps = components(json!({ "A": { "type": "string" } }));
    for reference in [
        "https://example.com/s.json",
        "other.yaml#/A",
        "#/components/parameters/p",
        "#/components/schemas/Missing",
        "#/components/schemas/A/properties/x",
        "#/components/schemas/%zz",
    ] {
        assert_eq!(inline(json!({ "$ref": reference }), &comps).unwrap(), json!({}), "{reference}");
    }
}

#[test]
fn siblings_next_to_a_ref_are_kept_and_win_over_the_component() {
    let comps = components(json!({ "A": { "type": "string", "description": "from component" } }));
    let out = inline(json!({ "$ref": "#/components/schemas/A", "description": "local" }), &comps).unwrap();
    assert_eq!(out, json!({ "type": "string", "description": "local" }));
}

#[test]
fn nullable_true_next_to_a_string_type_becomes_a_type_array() {
    let out = inline(json!({ "type": "string", "nullable": true }), &Map::new()).unwrap();
    assert_eq!(out, json!({ "type": ["string", "null"] }));
}

#[test]
fn nullable_false_or_without_a_type_and_non_nullable_schemas_pass_through_verbatim() {
    let comps = Map::new();
    for schema in [
        json!({ "type": "string", "nullable": false }),
        json!({ "nullable": true }),
        json!({ "type": ["string", "null"], "nullable": true }),
        json!({ "type": "integer", "minimum": 1, "x-custom": [1, 2, { "k": null }], "format": "int64" }),
    ] {
        assert_eq!(inline(schema.clone(), &comps).unwrap(), schema);
    }
}

#[test]
fn nullable_inside_an_inlined_component_is_rewritten_too() {
    let comps = components(json!({ "N": { "type": "integer", "nullable": true } }));
    assert_eq!(
        inline(json!({ "$ref": "#/components/schemas/N" }), &comps).unwrap(),
        json!({ "type": ["integer", "null"] })
    );
}

#[test]
fn nesting_deeper_than_the_depth_cap_is_too_large() {
    let mut schema = json!({ "type": "string" });
    for _ in 0..80 {
        schema = json!({ "items": schema });
    }
    assert_eq!(inline(schema, &Map::new()), Err(InlineError::TooLarge));
    let mut shallow = json!({ "type": "string" });
    for _ in 0..30 {
        shallow = json!({ "items": shallow });
    }
    assert!(inline(shallow, &Map::new()).is_ok());
}

#[test]
fn a_schema_with_more_than_twenty_thousand_nodes_is_too_large_and_the_budget_is_shared_across_calls() {
    let wide: Map<String, Value> = (0..20_100).map(|i| (format!("p{i}"), json!("x"))).collect();
    assert_eq!(inline(Value::Object(wide), &Map::new()), Err(InlineError::TooLarge));

    let half: Map<String, Value> = (0..12_000).map(|i| (format!("p{i}"), json!("x"))).collect();
    let mut budget = InlineBudget::new();
    assert!(inline_component_refs(&Value::Object(half.clone()), &Map::new(), &mut budget).is_ok());
    assert_eq!(
        inline_component_refs(&Value::Object(half), &Map::new(), &mut budget),
        Err(InlineError::TooLarge),
        "one tool's parameters and body share one budget"
    );
}

#[test]
fn a_ref_expansion_blow_up_is_stopped_by_the_node_budget() {
    // Each level references the next one twice: 2^n expanded nodes from a tiny document.
    let mut comps = Map::new();
    for i in 0..30 {
        comps.insert(
            format!("L{i}"),
            json!({ "allOf": [ { "$ref": format!("#/components/schemas/L{}", i + 1) }, { "$ref": format!("#/components/schemas/L{}", i + 1) } ] }),
        );
    }
    comps.insert("L30".to_string(), json!({ "type": "string" }));
    assert_eq!(inline(json!({ "$ref": "#/components/schemas/L0" }), &comps), Err(InlineError::TooLarge));
}

#[test]
fn number_detection_sees_type_number_alone_in_arrays_and_nested_but_not_integer() {
    assert!(contains_number_type(&json!({ "type": "number" })));
    assert!(contains_number_type(&json!({ "type": ["number", "null"] })));
    assert!(contains_number_type(&json!({ "properties": { "a": { "items": { "type": "number" } } } })));
    assert!(contains_number_type(&json!({ "oneOf": [ { "type": "string" }, { "type": "number" } ] })));
    assert!(!contains_number_type(&json!({ "type": "integer", "format": "int64" })));
    assert!(!contains_number_type(&json!({ "description": "type: number" })));
}
