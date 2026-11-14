//! A JSON-Schema-preserving `$ref` inliner for MCP tool input schemas. `SchemaWalker` emits frogs's
//! own type descriptors, not JSON Schema, so it can't be used here.

use serde_json::{Map, Value};

use super::local_ref::decode_token;

const MAX_NODES: usize = 20_000;
const MAX_DEPTH: usize = 64;
const COMPONENT_PREFIX: &str = "#/components/schemas/";

pub(crate) struct InlineBudget {
    nodes: usize,
}

impl InlineBudget {
    pub(crate) fn new() -> Self {
        InlineBudget { nodes: 0 }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InlineError {
    TooLarge,
}

/// Replaces every `#/components/schemas/<name>` reference with the component's own schema. A
/// cycle back to a component already being expanded, an unknown component and any external or
/// non-component reference become `{}` (accept anything). OpenAPI 3.0 `nullable: true` next to a
/// string `type` becomes a `[type, "null"]` array; everything else passes through verbatim.
pub(crate) fn inline_component_refs(schema: &Value, components: &Map<String, Value>, budget: &mut InlineBudget) -> Result<Value, InlineError> {
    walk(schema, components, budget, 0, &mut Vec::new())
}

fn walk(value: &Value, components: &Map<String, Value>, budget: &mut InlineBudget, depth: usize, stack: &mut Vec<String>) -> Result<Value, InlineError> {
    if depth > MAX_DEPTH {
        return Err(InlineError::TooLarge);
    }
    budget.nodes += 1;
    if budget.nodes > MAX_NODES {
        return Err(InlineError::TooLarge);
    }
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| walk(item, components, budget, depth + 1, stack))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            if let Some(Value::String(reference)) = map.get("$ref") {
                let mut target = resolve(reference, components, budget, depth, stack)?;
                if let Value::Object(target_map) = &mut target {
                    for (key, sibling) in map.iter().filter(|(key, _)| key.as_str() != "$ref") {
                        target_map.insert(key.clone(), walk(sibling, components, budget, depth + 1, stack)?);
                    }
                }
                return Ok(target);
            }
            let mut out = Map::new();
            for (key, child) in map {
                out.insert(key.clone(), walk(child, components, budget, depth + 1, stack)?);
            }
            if out.get("nullable") == Some(&Value::Bool(true))
                && let Some(Value::String(type_name)) = out.get("type").cloned()
            {
                out.remove("nullable");
                out.insert("type".to_string(), Value::Array(vec![Value::String(type_name), Value::String("null".to_string())]));
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn resolve(reference: &str, components: &Map<String, Value>, budget: &mut InlineBudget, depth: usize, stack: &mut Vec<String>) -> Result<Value, InlineError> {
    let Some(token) = reference.strip_prefix(COMPONENT_PREFIX) else {
        return Ok(Value::Object(Map::new()));
    };
    if token.contains('/') {
        return Ok(Value::Object(Map::new()));
    }
    let Ok(name) = decode_token(token) else {
        return Ok(Value::Object(Map::new()));
    };
    let name = name.into_owned();
    let Some(component) = components.get(&name) else {
        return Ok(Value::Object(Map::new()));
    };
    if stack.contains(&name) {
        return Ok(Value::Object(Map::new()));
    }
    stack.push(name);
    let inlined = walk(component, components, budget, depth + 1, stack);
    stack.pop();
    inlined
}

/// Whether any schema node declares `type: number` (alone or inside a `type` array).
pub(crate) fn contains_number_type(schema: &Value) -> bool {
    match schema {
        Value::Object(map) => {
            let own = match map.get("type") {
                Some(Value::String(type_name)) => type_name == "number",
                Some(Value::Array(names)) => names.iter().any(|name| name.as_str() == Some("number")),
                _ => false,
            };
            own || map.values().any(contains_number_type)
        }
        Value::Array(items) => items.iter().any(contains_number_type),
        _ => false,
    }
}
