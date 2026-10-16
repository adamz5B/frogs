use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

/// A configurable ceiling protects against pathological or adversarial
/// schemas — past this many nested levels, the walk stops and marks that
/// subtree rather than guessing or recursing forever.
const MAX_DEPTH: usize = 10;

/// Descriptor keys the walker adds itself, as opposed to real schema
/// properties — an explicit list (never "starts with `$`") so a spec property
/// that happens to be named e.g. `$type` is never mistaken for metadata.
const METADATA_KEYS: &[&str] = &["$component", "$oneOf"];

/// Component names are matched by a hand-written check, not a regex.
pub(crate) fn is_name_shaped(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) enum DefaultMapping<'a> {
    Absent,
    Target(&'a str),
    Unresolved(&'static str),
}

/// What a `oneOf`/`anyOf` schema's `discriminator.defaultMapping` points at.
/// Only a local component name or `#/components/schemas/<Name>` is ever
/// accepted; nothing is fetched.
pub(crate) fn default_mapping_target<'a>(obj: &'a Map<String, Value>, is_component: impl Fn(&str) -> bool) -> DefaultMapping<'a> {
    let has_variants = obj.get("oneOf").is_some_and(Value::is_array) || obj.get("anyOf").is_some_and(Value::is_array);
    if !has_variants {
        return DefaultMapping::Absent;
    }
    let Some(value) = obj.get("discriminator").and_then(|d| d.get("defaultMapping")) else {
        return DefaultMapping::Absent;
    };
    let Some(text) = value.as_str() else {
        return DefaultMapping::Unresolved("is not a string");
    };
    if is_component(text) {
        return DefaultMapping::Target(text);
    }
    if let Some(name) = text.strip_prefix("#/components/schemas/") {
        return if is_component(name) {
            DefaultMapping::Target(name)
        } else {
            DefaultMapping::Unresolved("names no component in components/schemas")
        };
    }
    if is_name_shaped(text) {
        DefaultMapping::Unresolved("names no component in components/schemas")
    } else {
        DefaultMapping::Unresolved("is not a component name or #/components/schemas/<Name> reference (external references are never fetched)")
    }
}

fn annotate_default(name: &str, rendered: String, target_fields: Map<String, Value>) -> Value {
    let mut out = Map::new();
    out.insert("$component".to_string(), Value::String(name.to_string()));
    out.insert("$oneOf".to_string(), Value::String(rendered));
    out.extend(target_fields.into_iter().filter(|(key, _)| !METADATA_KEYS.contains(&key.as_str())));
    Value::Object(out)
}

/// Walks `components/schemas` (and, later, an endpoint's own response
/// schema — same algorithm either way) producing one JSON *type descriptor*
/// per schema node: nested objects become nested descriptors, a `$ref` to a
/// named component becomes a `$component` marker plus that component's own
/// resolved shape inlined, and anything the walk can't resolve confidently
/// (a cycle, an unknown ref, too much nesting) becomes a `"<...>"` marker
/// string rather than an error — the same "say so, don't guess or hang"
/// posture as everywhere else `datasources/` config gets generated.
pub struct SchemaWalker<'a> {
    components: &'a Map<String, Value>,
}

impl<'a> SchemaWalker<'a> {
    pub fn new(components: &'a Map<String, Value>) -> Self {
        Self { components }
    }

    /// Resolves every named component into one descriptor each. Cycle
    /// detection is scoped *per component*: a fresh "in progress" set for
    /// each top-level name, so `Car` referencing `Owner` twice (not a
    /// cycle) doesn't get flagged, but `Car` → `Owner` → `Car` (a genuine
    /// cycle) does — caught once per component, not once per endpoint that
    /// happens to use it.
    pub fn resolve_components(&self) -> HashMap<String, Value> {
        self.components.keys().map(|name| (name.clone(), self.resolve_named(name))).collect()
    }

    fn resolve_named(&self, name: &str) -> Value {
        let mut in_progress = HashSet::new();
        self.walk_named(name, &mut in_progress, 0)
    }

    fn walk_named(&self, name: &str, in_progress: &mut HashSet<String>, depth: usize) -> Value {
        if in_progress.contains(name) {
            return Value::String(format!("<circular reference: {name}>"));
        }
        let Some(schema) = self.components.get(name) else {
            return Value::String(format!("<unknown component: {name}>"));
        };

        in_progress.insert(name.to_string());
        let result = self.walk(schema, in_progress, depth);
        in_progress.remove(name);
        result
    }

    /// The core recursive walk, in the order cases are resolved: `$ref`,
    /// `allOf`, `oneOf`/`anyOf`, object-with-properties, free-form map,
    /// array, primitive.
    fn walk(&self, schema: &Value, in_progress: &mut HashSet<String>, depth: usize) -> Value {
        if depth > MAX_DEPTH {
            return Value::String("<max depth exceeded>".to_string());
        }
        let Some(obj) = schema.as_object() else {
            return Value::Null;
        };

        if let Some(ref_str) = obj.get("$ref").and_then(Value::as_str) {
            return self.walk_ref(ref_str, in_progress, depth);
        }

        if let Some(variants) = obj.get("allOf").and_then(Value::as_array) {
            return self.walk_all_of(variants, in_progress, depth);
        }

        if let Some(variants) = obj.get("oneOf").or_else(|| obj.get("anyOf")).and_then(Value::as_array) {
            return self.walk_one_of(obj, variants, in_progress, depth);
        }

        if let Some(props) = obj.get("properties").and_then(Value::as_object) {
            let fields = props.iter().map(|(key, prop_schema)| (key.clone(), self.walk(prop_schema, in_progress, depth + 1)));
            return Value::Object(fields.collect());
        }

        if obj.get("type").and_then(Value::as_str) == Some("object") {
            // No `properties` to enumerate — a free-form map means mapping
            // a source at the *whole* object, not per-key.
            return Value::String("map".to_string());
        }

        if obj.get("type").and_then(Value::as_str) == Some("array") {
            let items = obj.get("items").map_or(Value::Null, |items| self.walk(items, in_progress, depth + 1));
            return serde_json::json!({ "type": "array", "items": items });
        }

        if let Some(ty) = obj.get("type").and_then(Value::as_str) {
            return match obj.get("format").and_then(Value::as_str) {
                Some(format) => Value::String(format!("{ty} ({format})")),
                None => Value::String(ty.to_string()),
            };
        }

        Value::Null
    }

    fn walk_ref(&self, ref_str: &str, in_progress: &mut HashSet<String>, depth: usize) -> Value {
        let Some(name) = ref_str.strip_prefix("#/components/schemas/") else {
            return Value::String(format!("<unsupported $ref: {ref_str}>"));
        };

        let resolved = self.walk_named(name, in_progress, depth + 1);
        with_component_marker(name, resolved)
    }

    /// `allOf` is the tractable composition case: structurally it's just
    /// "all of these fields together," so sub-schemas' `properties` are
    /// merged into one flat object.
    fn walk_all_of(&self, variants: &[Value], in_progress: &mut HashSet<String>, depth: usize) -> Value {
        let mut merged = Map::new();
        for variant in variants {
            if let Value::Object(fields) = self.walk(variant, in_progress, depth + 1) {
                merged.extend(fields);
            }
        }
        Value::Object(merged)
    }

    /// `oneOf`/`anyOf` are genuinely ambiguous — not flattened. Each
    /// variant's own descriptor is rendered compactly into one
    /// `"oneOf<A, B>"` string; picking a stub value from the first variant
    /// is the stub-generation milestone's job, not this one's.
    ///
    /// The one exception: a `discriminator.defaultMapping` naming a component
    /// resolves to that component's shape (annotated with `$component`/
    /// `$oneOf`), since the spec itself says which variant to assume.
    fn walk_one_of(&self, obj: &Map<String, Value>, variants: &[Value], in_progress: &mut HashSet<String>, depth: usize) -> Value {
        let rendered: Vec<String> = variants.iter().map(|variant| render_compact(&self.walk(variant, in_progress, depth + 1))).collect();
        let rendered = format!("oneOf<{}>", rendered.join(", "));
        if let DefaultMapping::Target(name) = default_mapping_target(obj, |n| self.components.contains_key(n))
            && let Value::Object(fields) = self.walk_named(name, in_progress, depth + 1)
        {
            return annotate_default(name, rendered, fields);
        }
        Value::String(rendered)
    }
}

/// Wraps a resolved component's descriptor with metadata recording which
/// component it came from — used both when Phase 0 resolves a `$ref` while
/// building the cache, and when Phase 1 looks one up from it. Metadata
/// only: it doesn't change the shape itself, since two endpoints returning
/// the same component may still map it completely differently (a SQL join
/// vs. a cached HTTP call vs. a partial-fields view). A cycle/unknown-ref
/// marker stays a plain string, not wrapped in an object.
fn with_component_marker(name: &str, resolved: Value) -> Value {
    match resolved {
        Value::Object(mut fields) => {
            let mut with_marker = Map::new();
            with_marker.insert("$component".to_string(), Value::String(name.to_string()));
            with_marker.append(&mut fields);
            Value::Object(with_marker)
        }
        other => other,
    }
}

/// Walks an endpoint's own schema (e.g. a response schema) — the same
/// recursive cases as `SchemaWalker`'s component walk, except a `$ref` to a
/// named component is looked up in `cache` (already resolved by
/// `resolve_components`) instead of being re-walked from scratch: cheap
/// regardless of how many endpoints share that component, and no cycle
/// tracking is needed here since Phase 0 already handled that when it
/// built the cache. A separate function rather than a generalized version
/// of `SchemaWalker::walk` — the two `$ref` strategies (resolve fresh vs.
/// look up) are different enough, and each case here short enough, that
/// duplicating the handful of branches reads more clearly than threading a
/// strategy parameter through the shared one would.
pub fn walk_response_schema(schema: &Value, cache: &HashMap<String, Value>) -> Value {
    walk_response_schema_at(schema, cache, 0)
}

fn walk_response_schema_at(schema: &Value, cache: &HashMap<String, Value>, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::String("<max depth exceeded>".to_string());
    }
    let Some(obj) = schema.as_object() else {
        return Value::Null;
    };

    if let Some(ref_str) = obj.get("$ref").and_then(Value::as_str) {
        let Some(name) = ref_str.strip_prefix("#/components/schemas/") else {
            return Value::String(format!("<unsupported $ref: {ref_str}>"));
        };
        return match cache.get(name) {
            Some(resolved) => with_component_marker(name, resolved.clone()),
            None => Value::String(format!("<unknown component: {name}>")),
        };
    }

    if let Some(variants) = obj.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for variant in variants {
            if let Value::Object(fields) = walk_response_schema_at(variant, cache, depth + 1) {
                merged.extend(fields);
            }
        }
        return Value::Object(merged);
    }

    if let Some(variants) = obj.get("oneOf").or_else(|| obj.get("anyOf")).and_then(Value::as_array) {
        let rendered: Vec<String> = variants
            .iter()
            .map(|variant| render_compact(&walk_response_schema_at(variant, cache, depth + 1)))
            .collect();
        let rendered = format!("oneOf<{}>", rendered.join(", "));
        if let DefaultMapping::Target(name) = default_mapping_target(obj, |n| cache.contains_key(n))
            && let Some(Value::Object(fields)) = cache.get(name)
        {
            return annotate_default(name, rendered, fields.clone());
        }
        return Value::String(rendered);
    }

    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        let fields = props
            .iter()
            .map(|(key, prop_schema)| (key.clone(), walk_response_schema_at(prop_schema, cache, depth + 1)));
        return Value::Object(fields.collect());
    }

    if obj.get("type").and_then(Value::as_str) == Some("object") {
        return Value::String("map".to_string());
    }

    if obj.get("type").and_then(Value::as_str) == Some("array") {
        let items = obj.get("items").map_or(Value::Null, |items| walk_response_schema_at(items, cache, depth + 1));
        return serde_json::json!({ "type": "array", "items": items });
    }

    if let Some(ty) = obj.get("type").and_then(Value::as_str) {
        return match obj.get("format").and_then(Value::as_str) {
            Some(format) => Value::String(format!("{ty} ({format})")),
            None => Value::String(ty.to_string()),
        };
    }

    Value::Null
}

/// Derives a generated stub's response shape from an already-resolved
/// descriptor (the same one written to a `.reference.json` file) — a
/// separate, mechanical transform rather than threading a second (descriptor,
/// stub) value through the walk itself, since every case but one is a pure
/// function of the descriptor alone:
/// - primitive / `"map"` / marker string (cycle, unknown ref, depth guard) → `null`
/// - object (optionally `$component`/`$oneOf`-annotated) → nested stub, metadata keys dropped
/// - `{"type":"array","items":...}` → `{"type":"array","source":null,"items":null}`
///   (the design doc's own array-stub example never recurses into `items`
///   for the stub, only the reference keeps the item shape)
///
/// The one deliberate simplification: `oneOf`/`anyOf` collapses to a plain
/// string (`"oneOf<A, B>"`) in the descriptor, which loses which variant was
/// "first" — the design doc's stub for that case is meant to be the first
/// variant's own shape, but reconstructing that here would mean re-walking
/// the original schema, not just the descriptor. Since a `oneOf` whose first
/// variant is itself a primitive already produces the same `null` either
/// way (the doc's own worked example is exactly this case), the gap only
/// matters when the first variant is an object — worth a `_todo` note when
/// that happens, not worth a bigger refactor for yet. The exception is a
/// `oneOf` with a resolvable `discriminator.defaultMapping`: its descriptor is
/// the default component's object shape, so the stub becomes that nested object.
pub fn stub_from_descriptor(descriptor: &Value) -> Value {
    match descriptor {
        Value::Object(fields) => {
            if fields.get("type").and_then(Value::as_str) == Some("array") && fields.contains_key("items") {
                return serde_json::json!({ "type": "array", "source": null, "items": null });
            }
            let nested = fields
                .iter()
                .filter(|(key, _)| !METADATA_KEYS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), stub_from_descriptor(value)));
            Value::Object(nested.collect())
        }
        _ => Value::Null,
    }
}

/// Reconciles an existing (possibly hand-edited) stub's `response` tree
/// against a freshly-generated one — the design doc's structural-merge
/// step of schema-drift migration, field by field:
/// - same path, compatible shape in both → the old mapping is carried
///   forward unchanged
/// - path gone from the new schema → dropped (still recoverable from the
///   pre-migration backup)
/// - new path, not present in the old stub → `null`, same as first-time
///   generation
/// - same path, but the shape changed incompatibly (was a mapping, now a
///   nested object, or vice versa) → **not** carried forward, even though a
///   mapping exists — a stale mapping that happens to still parse is worse
///   than an obvious `null` flagged for review
pub fn merge_stub_response(old: &Value, fresh: &Value) -> Value {
    match fresh {
        Value::Object(fresh_fields) if fresh_fields.get("type").and_then(Value::as_str) == Some("array") => {
            // Array envelope: only the "source" mapping is ever
            // user-authored (`items` stays null in a stub either way), and
            // only if `old` was itself an array envelope.
            let old_source = old
                .as_object()
                .filter(|fields| fields.get("type").and_then(Value::as_str) == Some("array"))
                .and_then(|fields| fields.get("source"))
                .cloned()
                .unwrap_or(Value::Null);
            serde_json::json!({ "type": "array", "source": old_source, "items": Value::Null })
        }
        Value::Object(fresh_fields) => {
            // Structural nesting (an object-typed field). `old` is
            // compatible if it's the same kind of structural value (or
            // simply absent, i.e. `null`) — not a plain mapping the user
            // wrote in for what used to be a different shape here.
            if is_structural_object(old) {
                let old_fields = old.as_object();
                let merged = fresh_fields.iter().map(|(key, fresh_value)| {
                    let merged_value = match old_fields.and_then(|fields| fields.get(key)) {
                        Some(old_value) => merge_stub_response(old_value, fresh_value),
                        None => fresh_value.clone(),
                    };
                    (key.clone(), merged_value)
                });
                Value::Object(merged.collect())
            } else {
                fresh.clone()
            }
        }
        // `fresh` is `null` — a primitive/map/oneOf leaf. `old` carries
        // forward as long as it's a plain mapping (a dot-path string, or a
        // detailed `{"from": ...}` object) rather than leftover structural
        // nesting from a type that used to be an object/array here.
        Value::Null if is_mapping(old) => old.clone(),
        _ => Value::Null,
    }
}

fn is_mapping(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Object(fields) => fields.contains_key("from"),
        _ => false,
    }
}

// Metadata keys (`METADATA_KEYS`) never appear in a stub, so they need no special handling here.
fn is_structural_object(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => !fields.contains_key("from") && fields.get("type").and_then(Value::as_str) != Some("array"),
        _ => false,
    }
}

fn render_compact(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Object(fields) => {
            let parts: Vec<String> = fields
                .iter()
                .filter(|(k, _)| !METADATA_KEYS.contains(&k.as_str()))
                .map(|(k, v)| format!("{k}: {}", render_compact(v)))
                .collect();
            format!("object{{{}}}", parts.join(", "))
        }
        Value::Array(_) => "array".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components(json: &str) -> Map<String, Value> {
        let value: Value = serde_json::from_str(json).unwrap();
        value.as_object().unwrap().clone()
    }

    #[test]
    fn resolves_flat_primitive_properties() {
        let components = components(
            r##"{
                "Owner": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "since": { "type": "string", "format": "date-time" }
                    }
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(resolved["Owner"], serde_json::json!({ "name": "string", "since": "string (date-time)" }));
    }

    #[test]
    fn resolves_a_ref_to_another_component_with_a_component_marker() {
        let components = components(
            r##"{
                "Car": {
                    "type": "object",
                    "properties": {
                        "owner": { "$ref": "#/components/schemas/Owner" }
                    }
                },
                "Owner": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } }
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(resolved["Car"], serde_json::json!({ "owner": { "$component": "Owner", "name": "string" } }));
    }

    #[test]
    fn detects_a_genuine_cycle() {
        let components = components(
            r##"{
                "Car": {
                    "type": "object",
                    "properties": { "owner": { "$ref": "#/components/schemas/Owner" } }
                },
                "Owner": {
                    "type": "object",
                    "properties": { "car": { "$ref": "#/components/schemas/Car" } }
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(
            resolved["Car"],
            serde_json::json!({ "owner": { "$component": "Owner", "car": "<circular reference: Car>" } })
        );
    }

    #[test]
    fn a_component_referenced_twice_non_cyclically_is_not_flagged() {
        let components = components(
            r##"{
                "Car": {
                    "type": "object",
                    "properties": {
                        "primaryOwner": { "$ref": "#/components/schemas/Owner" },
                        "secondaryOwner": { "$ref": "#/components/schemas/Owner" }
                    }
                },
                "Owner": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } }
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(
            resolved["Car"],
            serde_json::json!({
                "primaryOwner": { "$component": "Owner", "name": "string" },
                "secondaryOwner": { "$component": "Owner", "name": "string" }
            })
        );
    }

    #[test]
    fn resolves_arrays_and_free_form_maps() {
        let components = components(
            r##"{
                "Car": {
                    "type": "object",
                    "properties": {
                        "features": { "type": "array", "items": { "type": "string" } },
                        "metadata": { "type": "object" }
                    }
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(
            resolved["Car"],
            serde_json::json!({
                "features": { "type": "array", "items": "string" },
                "metadata": "map"
            })
        );
    }

    #[test]
    fn all_of_merges_sub_schema_properties() {
        let components = components(
            r##"{
                "Car": {
                    "allOf": [
                        { "type": "object", "properties": { "vin": { "type": "string" } } },
                        { "type": "object", "properties": { "year": { "type": "integer" } } }
                    ]
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(resolved["Car"], serde_json::json!({ "vin": "string", "year": "integer" }));
    }

    #[test]
    fn one_of_is_flagged_not_flattened() {
        let components = components(
            r##"{
                "Price": {
                    "oneOf": [
                        { "type": "number" },
                        { "type": "object", "properties": { "min": { "type": "number" }, "max": { "type": "number" } } }
                    ]
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(resolved["Price"], serde_json::json!("oneOf<number, object{min: number, max: number}>"));
    }

    #[test]
    fn unknown_ref_is_a_marker_not_a_panic() {
        let components = components(
            r##"{
                "Car": {
                    "type": "object",
                    "properties": { "owner": { "$ref": "#/components/schemas/DoesNotExist" } }
                }
            }"##,
        );
        let resolved = SchemaWalker::new(&components).resolve_components();
        assert_eq!(resolved["Car"], serde_json::json!({ "owner": "<unknown component: DoesNotExist>" }));
    }

    #[test]
    fn depth_guard_stops_pathological_nesting() {
        // 15 levels of `{ "type": "object", "properties": { "next": ... } }`
        // -- past MAX_DEPTH (10), the walk should mark and stop rather than
        // recursing forever.
        let mut schema = serde_json::json!({ "type": "string" });
        for _ in 0..15 {
            schema = serde_json::json!({ "type": "object", "properties": { "next": schema } });
        }
        let mut components = Map::new();
        components.insert("Deep".to_string(), schema);

        let resolved = SchemaWalker::new(&components).resolve_components();
        let json = serde_json::to_string(&resolved["Deep"]).unwrap();
        assert!(json.contains("max depth exceeded"), "expected a depth-guard marker, got: {json}");
    }

    #[test]
    fn walk_response_schema_resolves_primitives_directly() {
        let schema: Value = serde_json::from_str(r##"{ "type": "integer" }"##).unwrap();
        let cache = HashMap::new();
        assert_eq!(walk_response_schema(&schema, &cache), serde_json::json!("integer"));
    }

    #[test]
    fn walk_response_schema_looks_up_a_ref_from_the_cache_instead_of_rewalking() {
        let schema: Value = serde_json::from_str(r##"{ "$ref": "#/components/schemas/CarWithPrice" }"##).unwrap();
        let mut cache = HashMap::new();
        cache.insert("CarWithPrice".to_string(), serde_json::json!({ "vin": "string", "year": "integer" }));

        assert_eq!(
            walk_response_schema(&schema, &cache),
            serde_json::json!({ "$component": "CarWithPrice", "vin": "string", "year": "integer" })
        );
    }

    #[test]
    fn walk_response_schema_marks_a_ref_not_in_the_cache() {
        let schema: Value = serde_json::from_str(r##"{ "$ref": "#/components/schemas/Missing" }"##).unwrap();
        let cache = HashMap::new();
        assert_eq!(walk_response_schema(&schema, &cache), serde_json::json!("<unknown component: Missing>"));
    }

    #[test]
    fn walk_response_schema_handles_arrays_of_a_cached_component() {
        let schema: Value = serde_json::from_str(r##"{ "type": "array", "items": { "$ref": "#/components/schemas/Owner" } }"##).unwrap();
        let mut cache = HashMap::new();
        cache.insert("Owner".to_string(), serde_json::json!({ "name": "string" }));

        assert_eq!(
            walk_response_schema(&schema, &cache),
            serde_json::json!({
                "type": "array",
                "items": { "$component": "Owner", "name": "string" }
            })
        );
    }

    #[test]
    fn walk_response_schema_handles_nested_objects_mixing_own_fields_and_a_cached_ref() {
        let schema: Value = serde_json::from_str(
            r##"{
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "owner": { "$ref": "#/components/schemas/Owner" }
                }
            }"##,
        )
        .unwrap();
        let mut cache = HashMap::new();
        cache.insert("Owner".to_string(), serde_json::json!({ "name": "string" }));

        assert_eq!(
            walk_response_schema(&schema, &cache),
            serde_json::json!({
                "id": "string",
                "owner": { "$component": "Owner", "name": "string" }
            })
        );
    }

    #[test]
    fn stub_nulls_out_primitives_and_maps_and_markers() {
        assert_eq!(stub_from_descriptor(&serde_json::json!("string")), Value::Null);
        assert_eq!(stub_from_descriptor(&serde_json::json!("string (date-time)")), Value::Null);
        assert_eq!(stub_from_descriptor(&serde_json::json!("map")), Value::Null);
        assert_eq!(stub_from_descriptor(&serde_json::json!("oneOf<number, object{min: number}>")), Value::Null);
        assert_eq!(stub_from_descriptor(&serde_json::json!("<circular reference: Car>")), Value::Null);
    }

    #[test]
    fn stub_recurses_into_objects_and_drops_the_component_marker() {
        let descriptor = serde_json::json!({
            "$component": "Owner",
            "name": "string",
            "since": "string (date-time)"
        });
        assert_eq!(stub_from_descriptor(&descriptor), serde_json::json!({ "name": null, "since": null }));
    }

    #[test]
    fn stub_for_an_array_never_recurses_into_items() {
        let descriptor = serde_json::json!({
            "type": "array",
            "items": { "id": "string", "owner": { "$component": "Owner", "name": "string" } }
        });
        assert_eq!(
            stub_from_descriptor(&descriptor),
            serde_json::json!({ "type": "array", "source": null, "items": null })
        );
    }

    #[test]
    fn stub_matches_the_design_docs_worked_example_exactly() {
        // Mirrors docs/datasource-schema-design.md's getCarDetails example.
        let descriptor = serde_json::json!({
            "vin": "string",
            "maker": "string",
            "owner": { "$component": "Owner", "name": "string", "since": "string (date-time)" },
            "features": { "type": "array", "items": "string" },
            "price": "oneOf<number, object{min: number, max: number}>"
        });
        assert_eq!(
            stub_from_descriptor(&descriptor),
            serde_json::json!({
                "vin": null,
                "maker": null,
                "owner": { "name": null, "since": null },
                "features": { "type": "array", "source": null, "items": null },
                "price": null
            })
        );
    }

    #[test]
    fn merge_carries_forward_a_matching_plain_mapping() {
        let old = serde_json::json!("sources.car.vin");
        let fresh = Value::Null;
        assert_eq!(merge_stub_response(&old, &fresh), serde_json::json!("sources.car.vin"));
    }

    #[test]
    fn merge_carries_forward_a_matching_detailed_mapping() {
        let old = serde_json::json!({ "from": "sources.car.year", "format": "integer" });
        let fresh = Value::Null;
        assert_eq!(merge_stub_response(&old, &fresh), old);
    }

    #[test]
    fn merge_drops_a_new_object_field_replacing_a_former_primitive_mapping() {
        // Field used to be a primitive (mapped to "sources.car.owner_name"),
        // the new schema turned it into a nested object -- incompatible.
        let old = serde_json::json!("sources.car.owner_name");
        let fresh = serde_json::json!({ "name": null, "since": null });
        assert_eq!(merge_stub_response(&old, &fresh), serde_json::json!({ "name": null, "since": null }));
    }

    #[test]
    fn merge_drops_a_mapping_that_used_to_be_a_nested_object() {
        // Field used to be a nested object with a mapping inside, the new
        // schema made it a plain primitive -- incompatible, becomes null.
        let old = serde_json::json!({ "name": "sources.car.owner_name" });
        let fresh = Value::Null;
        assert_eq!(merge_stub_response(&old, &fresh), Value::Null);
    }

    #[test]
    fn merge_recurses_into_matching_nested_objects() {
        let old = serde_json::json!({ "name": "sources.car.owner_name", "since": null });
        let fresh = serde_json::json!({ "name": null, "since": null, "email": null });
        assert_eq!(
            merge_stub_response(&old, &fresh),
            serde_json::json!({ "name": "sources.car.owner_name", "since": null, "email": null })
        );
    }

    #[test]
    fn merge_carries_forward_an_array_sources_mapping() {
        let old = serde_json::json!({ "type": "array", "source": "sources.cars", "items": { "vin": "sources.cars[].vin" } });
        let fresh = serde_json::json!({ "type": "array", "items": "string" });
        assert_eq!(
            merge_stub_response(&old, &fresh),
            serde_json::json!({ "type": "array", "source": "sources.cars", "items": null })
        );
    }

    #[test]
    fn merge_adds_a_brand_new_field_as_null() {
        let old = serde_json::json!({});
        let fresh = serde_json::json!({ "vin": null });
        assert_eq!(merge_stub_response(&old, &fresh), serde_json::json!({ "vin": null }));
    }
}

#[cfg(test)]
mod m2_default_mapping_tests {
    use super::*;

    fn components(json: &str) -> Map<String, Value> {
        serde_json::from_str::<Value>(json).unwrap().as_object().unwrap().clone()
    }

    const TWO_CARS: &str = r##"{
        "Car": { "type": "object", "properties": { "vin": { "type": "string" } } },
        "Truck": { "type": "object", "properties": { "axles": { "type": "integer" } } },
        "Vehicle": { "oneOf": [ { "$ref": "#/components/schemas/Car" }, { "$ref": "#/components/schemas/Truck" } ], "discriminator": { "propertyName": "kind", "defaultMapping": "DEFAULT" } }
    }"##;

    fn with_default(default: &str) -> Map<String, Value> {
        components(&TWO_CARS.replace("DEFAULT", default))
    }

    #[test]
    fn a_default_mapping_by_bare_name_annotates_with_component_then_one_of_then_target_fields_in_that_order() {
        let comps = with_default("Car");
        let resolved = SchemaWalker::new(&comps).resolve_components();
        let vehicle = resolved["Vehicle"].as_object().unwrap();
        let keys: Vec<&str> = vehicle.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["$component", "$oneOf", "vin"]);
        assert_eq!(vehicle["$component"], "Car");
        assert!(vehicle["$oneOf"].as_str().unwrap().starts_with("oneOf<"));
        assert_eq!(vehicle["vin"], "string");
    }

    #[test]
    fn a_default_mapping_by_schema_ref_form_resolves_the_same_as_the_bare_name() {
        let by_name = with_default("Truck");
        let by_ref = with_default("#/components/schemas/Truck");
        assert_eq!(
            SchemaWalker::new(&by_name).resolve_components()["Vehicle"],
            SchemaWalker::new(&by_ref).resolve_components()["Vehicle"]
        );
    }

    #[test]
    fn phase_one_walk_of_an_inline_one_of_with_default_mapping_annotates_identically() {
        let comps = with_default("Car");
        let cache = SchemaWalker::new(&comps).resolve_components();
        let inline = serde_json::json!({
            "oneOf": [ { "$ref": "#/components/schemas/Car" }, { "$ref": "#/components/schemas/Truck" } ],
            "discriminator": { "propertyName": "kind", "defaultMapping": "#/components/schemas/Car" }
        });
        let out = walk_response_schema(&inline, &cache);
        let keys: Vec<&str> = out.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys[0], "$component");
        assert_eq!(keys[1], "$oneOf");
        assert_eq!(out["$component"], "Car");
        assert_eq!(out["vin"], "string");
    }

    #[test]
    fn a_default_mapping_naming_an_unknown_component_keeps_the_plain_one_of_string() {
        let comps = with_default("Nope");
        let resolved = SchemaWalker::new(&comps).resolve_components();
        assert!(resolved["Vehicle"].is_string());
        assert!(resolved["Vehicle"].as_str().unwrap().starts_with("oneOf<"));
    }

    #[test]
    fn a_default_mapping_to_a_primitive_component_keeps_the_plain_one_of_string() {
        let comps = components(
            r##"{ "Name": { "type": "string" },
                  "U": { "oneOf": [ { "type": "string" }, { "type": "integer" } ], "discriminator": { "propertyName": "k", "defaultMapping": "Name" } } }"##,
        );
        let resolved = SchemaWalker::new(&comps).resolve_components();
        assert_eq!(resolved["U"], serde_json::json!("oneOf<string, integer>"));
    }

    #[test]
    fn a_default_mapping_that_points_back_at_its_own_component_terminates_with_the_plain_string() {
        let comps = components(r##"{ "Loop": { "oneOf": [ { "type": "string" } ], "discriminator": { "propertyName": "k", "defaultMapping": "Loop" } } }"##);
        let resolved = SchemaWalker::new(&comps).resolve_components();
        assert!(resolved["Loop"].is_string());
    }

    #[test]
    fn mutually_recursive_default_mappings_terminate() {
        let comps = components(
            r##"{
                "A": { "oneOf": [ { "type": "string" } ], "discriminator": { "propertyName": "k", "defaultMapping": "B" } },
                "B": { "oneOf": [ { "type": "string" } ], "discriminator": { "propertyName": "k", "defaultMapping": "A" } }
            }"##,
        );
        let resolved = SchemaWalker::new(&comps).resolve_components();
        assert!(resolved.contains_key("A") && resolved.contains_key("B"));
    }

    #[test]
    fn without_a_default_mapping_the_output_is_exactly_the_old_flagged_string() {
        let plain = TWO_CARS.replace(r#", "defaultMapping": "DEFAULT""#, "");
        let comps = components(&plain);
        let resolved = SchemaWalker::new(&comps).resolve_components();
        assert!(resolved["Vehicle"].is_string());
        assert!(!resolved["Vehicle"].as_str().unwrap().contains('$'));
    }

    #[test]
    fn a_default_mapping_on_a_schema_without_one_of_or_any_of_is_ignored() {
        let comps = components(
            r##"{ "Car": { "type": "object", "properties": { "vin": { "type": "string" } } },
                  "X": { "type": "object", "properties": { "a": { "type": "string" } }, "discriminator": { "propertyName": "k", "defaultMapping": "Car" } } }"##,
        );
        let resolved = SchemaWalker::new(&comps).resolve_components();
        assert_eq!(resolved["X"], serde_json::json!({ "a": "string" }));
    }

    #[test]
    fn stub_of_an_annotated_descriptor_is_a_nested_null_object_without_metadata_keys() {
        let comps = with_default("Car");
        let resolved = SchemaWalker::new(&comps).resolve_components();
        let stub = stub_from_descriptor(&resolved["Vehicle"]);
        assert_eq!(stub, serde_json::json!({ "vin": null }));
    }

    #[test]
    fn a_real_property_named_dollar_type_survives_stub_and_render() {
        let comps = components(r##"{ "W": { "type": "object", "properties": { "$type": { "type": "string" }, "x": { "type": "integer" } } } }"##);
        let resolved = SchemaWalker::new(&comps).resolve_components();
        let stub = stub_from_descriptor(&resolved["W"]);
        assert_eq!(stub, serde_json::json!({ "$type": null, "x": null }));
        assert_eq!(render_compact(&resolved["W"]), "object{$type: string, x: integer}");
    }

    #[test]
    fn render_compact_of_an_annotated_variant_omits_both_metadata_keys() {
        let annotated = serde_json::json!({ "$component": "Car", "$oneOf": "oneOf<a>", "vin": "string" });
        assert_eq!(render_compact(&annotated), "object{vin: string}");
    }

    #[test]
    fn default_mapping_target_classifies_each_form() {
        let is_c = |n: &str| n == "Car";
        let obj = |dm: Value| {
            serde_json::json!({ "oneOf": [], "discriminator": { "defaultMapping": dm } })
                .as_object()
                .unwrap()
                .clone()
        };
        assert!(matches!(default_mapping_target(&obj(serde_json::json!("Car")), is_c), DefaultMapping::Target("Car")));
        assert!(matches!(
            default_mapping_target(&obj(serde_json::json!("#/components/schemas/Car")), is_c),
            DefaultMapping::Target("Car")
        ));
        assert!(matches!(default_mapping_target(&obj(serde_json::json!("Nope")), is_c), DefaultMapping::Unresolved(_)));
        assert!(matches!(
            default_mapping_target(&obj(serde_json::json!("https://x/y")), is_c),
            DefaultMapping::Unresolved(_)
        ));
        assert!(matches!(
            default_mapping_target(&obj(serde_json::json!(5)), is_c),
            DefaultMapping::Unresolved("is not a string")
        ));
        let no_variants = serde_json::json!({ "discriminator": { "defaultMapping": "Car" } }).as_object().unwrap().clone();
        assert!(matches!(default_mapping_target(&no_variants, is_c), DefaultMapping::Absent));
    }
}
