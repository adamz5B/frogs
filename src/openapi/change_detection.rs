use std::collections::HashSet;

use serde_json::Value;

/// A stable, non-cryptographic content fingerprint (FNV-1a) — used purely
/// to detect "did this JSON value change since the last `generate` run,"
/// not for anything security-sensitive. Deliberately not `std`'s
/// `DefaultHasher` (its exact algorithm isn't part of any cross-version
/// stability guarantee) or a crypto crate (overkill for a low-stakes cache
/// key) — FNV-1a is simple enough to implement directly and stable by
/// construction.
pub fn content_hash(value: &Value) -> String {
    let json = serde_json::to_string(value).unwrap_or_default();
    format!("{:016x}", fnv1a(json.as_bytes()))
}

fn fnv1a(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Recursively collects every named component a *raw* (unresolved) schema
/// references via `$ref`. Deliberately cheap — gathering names, not
/// building descriptors — so an endpoint can know which components it
/// transitively depends on without paying for a full schema walk just to
/// find out whether it needs one.
pub fn referenced_component_names(schema: &Value) -> HashSet<String> {
    let mut names = HashSet::new();
    collect_refs(schema, &mut names);
    names
}

fn collect_refs(schema: &Value, names: &mut HashSet<String>) {
    let Some(obj) = schema.as_object() else {
        return;
    };

    if let Some(ref_str) = obj.get("$ref").and_then(Value::as_str) {
        if let Some(name) = ref_str.strip_prefix("#/components/schemas/") {
            names.insert(name.to_string());
        }
        return;
    }

    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for prop_schema in props.values() {
            collect_refs(prop_schema, names);
        }
    }
    if let Some(items) = obj.get("items") {
        collect_refs(items, names);
    }
    for key in ["allOf", "oneOf", "anyOf"] {
        if let Some(variants) = obj.get(key).and_then(Value::as_array) {
            for variant in variants {
                collect_refs(variant, names);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_produces_the_same_hash() {
        let a = serde_json::json!({ "vin": "string", "year": "integer" });
        let b = serde_json::json!({ "vin": "string", "year": "integer" });
        assert_eq!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn a_changed_value_produces_a_different_hash() {
        let a = serde_json::json!({ "vin": "string", "year": "integer" });
        let b = serde_json::json!({ "vin": "string", "year": "string" });
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn finds_a_direct_ref() {
        let schema = serde_json::json!({ "$ref": "#/components/schemas/Owner" });
        assert_eq!(referenced_component_names(&schema), HashSet::from(["Owner".to_string()]));
    }

    #[test]
    fn finds_refs_nested_in_properties_arrays_and_composition_keywords() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "owner": { "$ref": "#/components/schemas/Owner" },
                "tags": { "type": "array", "items": { "$ref": "#/components/schemas/Tag" } }
            },
            "allOf": [{ "$ref": "#/components/schemas/Base" }]
        });
        assert_eq!(
            referenced_component_names(&schema),
            HashSet::from(["Owner".to_string(), "Tag".to_string(), "Base".to_string()])
        );
    }

    #[test]
    fn no_refs_is_an_empty_set() {
        let schema = serde_json::json!({ "type": "string" });
        assert!(referenced_component_names(&schema).is_empty());
    }
}
