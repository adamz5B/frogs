//! Unit tests for the shared local `$ref` machinery: RFC 6901 token decoding, the generalised
//! hop-capped resolver, Reference Object siblings and path item merging.

use super::local_ref::*;
use serde_json::{Map, Value, json};
use std::borrow::Cow;

struct Docs {
    media_types: Map<String, Value>,
    parameters: Map<String, Value>,
    request_bodies: Map<String, Value>,
    responses: Map<String, Value>,
    path_items: Map<String, Value>,
    paths: Map<String, Value>,
}

impl Docs {
    fn new() -> Docs {
        Docs {
            media_types: Map::new(),
            parameters: Map::new(),
            request_bodies: Map::new(),
            responses: Map::new(),
            path_items: Map::new(),
            paths: Map::new(),
        }
    }

    fn index(&self) -> RefIndex<'_> {
        RefIndex {
            media_types: &self.media_types,
            parameters: &self.parameters,
            request_bodies: &self.request_bodies,
            responses: &self.responses,
            path_items: &self.path_items,
            paths: &self.paths,
        }
    }

    fn components(&mut self, kind: RefKind) -> &mut Map<String, Value> {
        match kind {
            RefKind::MediaType => &mut self.media_types,
            RefKind::Parameter => &mut self.parameters,
            RefKind::RequestBody => &mut self.request_bodies,
            RefKind::Response => &mut self.responses,
            RefKind::PathItem => &mut self.path_items,
        }
    }
}

const ALL_KINDS: [RefKind; 5] = [RefKind::MediaType, RefKind::Parameter, RefKind::RequestBody, RefKind::Response, RefKind::PathItem];

fn ref_to(kind: RefKind, name: &str) -> Value {
    json!({ "$ref": format!("#/components/{}/{name}", kind.component_key()) })
}

// ------------------------------------------------------------------- T-1

#[test]
fn decode_token_turns_tilde_one_into_a_slash_and_tilde_zero_into_a_tilde() {
    assert_eq!(decode_token("a~1b").unwrap(), "a/b");
    assert_eq!(decode_token("a~0b").unwrap(), "a~b");
}

#[test]
fn decode_token_is_one_left_to_right_pass_so_tilde_zero_one_is_tilde_one_not_a_slash() {
    assert_eq!(decode_token("~01").unwrap(), "~1");
    assert_eq!(decode_token("~10").unwrap(), "/0");
    assert_eq!(decode_token("~0~1~0").unwrap(), "~/~");
}

#[test]
fn decode_token_rejects_an_unknown_escape_and_a_trailing_tilde() {
    assert_eq!(decode_token("a~2b"), Err(PointerError::BadEscape));
    assert_eq!(decode_token("abc~"), Err(PointerError::BadEscape));
    assert_eq!(decode_token("~"), Err(PointerError::BadEscape));
    assert_eq!(decode_token("~x"), Err(PointerError::BadEscape));
}

#[test]
fn decode_token_borrows_when_there_is_nothing_to_decode_and_does_not_percent_decode() {
    assert!(matches!(decode_token("plain").unwrap(), Cow::Borrowed("plain")));
    assert!(matches!(decode_token("").unwrap(), Cow::Borrowed("")));
    assert_eq!(decode_token("a%2Fb").unwrap(), "a%2Fb");
}

#[test]
fn decode_token_keeps_non_ascii_text_intact() {
    assert_eq!(decode_token("caf\u{e9}~1\u{1f438}").unwrap(), "caf\u{e9}/\u{1f438}");
}

// ------------------------------------------------------------------- T-2

#[test]
fn component_name_returns_the_decoded_single_token() {
    assert_eq!(component_name("#/components/schemas/Car", "schemas").unwrap().unwrap(), "Car");
    assert_eq!(component_name("#/components/schemas/a~1b", "schemas").unwrap().unwrap(), "a/b");
    assert_eq!(component_name("#/components/schemas/a~01b", "schemas").unwrap().unwrap(), "a~1b");
}

#[test]
fn component_name_rejects_a_pointer_that_goes_deeper_than_the_component() {
    assert_eq!(
        component_name("#/components/schemas/Car/properties/id", "schemas"),
        Some(Err(PointerError::DeepPointer))
    );
}

#[test]
fn component_name_is_none_for_a_different_kind_or_prefix() {
    assert!(component_name("#/components/parameters/Car", "schemas").is_none());
    assert!(component_name("#/definitions/Car", "schemas").is_none());
    assert!(component_name("other.yaml#/components/schemas/Car", "schemas").is_none());
    assert!(component_name("#/components/schemasX/Car", "schemas").is_none());
    assert!(component_name("#/components/schemas", "schemas").is_none());
}

#[test]
fn component_name_reports_a_bad_escape_in_the_name() {
    assert_eq!(component_name("#/components/schemas/a~2", "schemas"), Some(Err(PointerError::BadEscape)));
}

// ------------------------------------------------------------------- T-3

#[test]
fn every_kind_resolves_a_direct_reference_and_returns_inline_objects_as_they_are() {
    for kind in ALL_KINDS {
        let mut docs = Docs::new();
        docs.components(kind).insert("X".into(), json!({ "marker": kind.label() }));
        let entry = ref_to(kind, "X");
        let resolved = resolve_ref(&entry, kind, &docs.index()).unwrap().unwrap();
        assert_eq!(resolved.get("marker"), Some(&json!(kind.label())), "{kind:?}");

        let inline = json!({ "inline": true });
        let resolved = resolve_ref(&inline, kind, &docs.index()).unwrap().unwrap();
        assert_eq!(resolved.get("inline"), Some(&json!(true)));
    }
}

#[test]
fn every_kind_follows_a_two_hop_chain() {
    for kind in ALL_KINDS {
        let mut docs = Docs::new();
        docs.components(kind).insert("A".into(), ref_to(kind, "B"));
        docs.components(kind).insert("B".into(), json!({ "end": true }));
        let entry = ref_to(kind, "A");
        let resolved = resolve_ref(&entry, kind, &docs.index()).unwrap().unwrap();
        assert!(resolved.contains_key("end"), "{kind:?}");
    }
}

fn chain(docs: &mut Docs, kind: RefKind, links: usize) {
    for i in 0..links {
        docs.components(kind).insert(format!("n{i}"), ref_to(kind, &format!("n{}", i + 1)));
    }
    docs.components(kind).insert(format!("n{links}"), json!({ "end": true }));
}

#[test]
fn a_chain_of_exactly_eight_hops_resolves_and_nine_is_too_long() {
    for kind in ALL_KINDS {
        let mut docs = Docs::new();
        chain(&mut docs, kind, 7);
        // entry -> n0 (hop 1) ... n7 (hop 8, the object)
        let entry = ref_to(kind, "n0");
        assert!(resolve_ref(&entry, kind, &docs.index()).unwrap().unwrap().contains_key("end"), "{kind:?} 8 hops");

        let mut docs = Docs::new();
        chain(&mut docs, kind, 8);
        assert_eq!(resolve_ref(&entry, kind, &docs.index()), Err(RefError::TooLong), "{kind:?} 9 hops");
    }
    assert_eq!(MAX_REF_HOPS, 8);
}

#[test]
fn a_self_cycle_and_a_two_cycle_are_cycles_not_hangs() {
    for kind in ALL_KINDS {
        let mut docs = Docs::new();
        docs.components(kind).insert("A".into(), ref_to(kind, "A"));
        docs.components(kind).insert("P".into(), ref_to(kind, "Q"));
        docs.components(kind).insert("Q".into(), ref_to(kind, "P"));
        assert_eq!(resolve_ref(&ref_to(kind, "A"), kind, &docs.index()), Err(RefError::Cycle), "{kind:?} self");
        assert_eq!(resolve_ref(&ref_to(kind, "P"), kind, &docs.index()), Err(RefError::Cycle), "{kind:?} two");
    }
}

#[test]
fn an_unknown_name_names_it_and_the_kind_label() {
    for kind in ALL_KINDS {
        let docs = Docs::new();
        let err = resolve_ref(&ref_to(kind, "Nope"), kind, &docs.index()).unwrap_err();
        assert_eq!(
            err,
            RefError::UnknownName {
                label: kind.label(),
                name: "Nope".into()
            }
        );
        assert_eq!(err.to_string(), format!("unknown {} 'Nope'", kind.label()));
    }
}

#[test]
fn a_non_string_ref_is_reported_and_a_non_object_entry_is_ignored_at_hop_zero_but_an_error_after_a_hop() {
    for kind in ALL_KINDS {
        let mut docs = Docs::new();
        assert_eq!(resolve_ref(&json!({ "$ref": 5 }), kind, &docs.index()), Err(RefError::NonStringRef));
        assert_eq!(resolve_ref(&json!("text"), kind, &docs.index()), Ok(None));
        assert_eq!(resolve_ref(&json!(null), kind, &docs.index()), Ok(None));
        docs.components(kind).insert("S".into(), json!("not an object"));
        assert_eq!(resolve_ref(&ref_to(kind, "S"), kind, &docs.index()), Err(RefError::NotAnObject));
    }
}

#[test]
fn a_reference_into_another_known_component_kind_is_wrong_kind() {
    let docs = Docs::new();
    let err = resolve_ref(&json!({ "$ref": "#/components/schemas/Car" }), RefKind::Parameter, &docs.index()).unwrap_err();
    assert_eq!(
        err,
        RefError::WrongKind {
            found: "schemas".into(),
            expected: "parameter"
        }
    );
    let err = resolve_ref(&json!({ "$ref": "#/components/responses/R" }), RefKind::RequestBody, &docs.index()).unwrap_err();
    assert!(matches!(err, RefError::WrongKind { ref found, .. } if found == "responses"));
    let err = resolve_ref(&json!({ "$ref": "#/components/headers/H" }), RefKind::Response, &docs.index()).unwrap_err();
    assert!(matches!(err, RefError::WrongKind { ref found, .. } if found == "headers"));
}

#[test]
fn external_urls_info_pointers_and_unknown_component_kinds_are_unsupported_and_never_fetched() {
    let docs = Docs::new();
    for reference in [
        "https://example.com/x.yaml#/components/parameters/P",
        "other.yaml#/components/parameters/P",
        "#/info",
        "#/components/madeUp/P",
        "#/components/parameters",
        "",
    ] {
        let err = resolve_ref(&json!({ "$ref": reference }), RefKind::Parameter, &docs.index()).unwrap_err();
        assert!(matches!(err, RefError::Unsupported(_)), "{reference:?} -> {err:?}");
    }
}

#[test]
fn a_hash_paths_pointer_is_only_understood_for_path_items() {
    let mut docs = Docs::new();
    docs.paths.insert("/real".into(), json!({ "get": {} }));
    let entry = json!({ "$ref": "#/paths/~1real" });
    assert!(resolve_ref(&entry, RefKind::PathItem, &docs.index()).unwrap().unwrap().contains_key("get"));
    assert!(matches!(resolve_ref(&entry, RefKind::Parameter, &docs.index()), Err(RefError::Unsupported(_))));
}

#[test]
fn the_name_is_decoded_before_lookup_and_a_literal_tilde_one_name_needs_tilde_zero_one() {
    let mut docs = Docs::new();
    docs.parameters.insert("a/b".into(), json!({ "slash": true }));
    docs.parameters.insert("a~1b".into(), json!({ "literal": true }));
    let slash_entry = json!({ "$ref": "#/components/parameters/a~1b" });
    let slash = resolve_ref(&slash_entry, RefKind::Parameter, &docs.index()).unwrap().unwrap();
    assert!(slash.contains_key("slash"));
    let literal_entry = json!({ "$ref": "#/components/parameters/a~01b" });
    let literal = resolve_ref(&literal_entry, RefKind::Parameter, &docs.index()).unwrap().unwrap();
    assert!(literal.contains_key("literal"));
}

#[test]
fn a_bad_escape_or_deep_pointer_is_a_bad_pointer_error_naming_the_reference() {
    let docs = Docs::new();
    let err = resolve_ref(&json!({ "$ref": "#/components/parameters/a~2" }), RefKind::Parameter, &docs.index()).unwrap_err();
    assert!(matches!(
        err,
        RefError::BadPointer {
            error: PointerError::BadEscape,
            ..
        }
    ));
    assert!(err.to_string().contains("#/components/parameters/a~2"));
    let err = resolve_ref(&json!({ "$ref": "#/components/parameters/P/schema" }), RefKind::Parameter, &docs.index()).unwrap_err();
    assert!(matches!(
        err,
        RefError::BadPointer {
            error: PointerError::DeepPointer,
            ..
        }
    ));
}

#[test]
fn control_characters_in_a_reference_are_escaped_in_error_text() {
    let docs = Docs::new();
    let err = resolve_ref(&json!({ "$ref": "evil\u{1b}[31m\nline" }), RefKind::Parameter, &docs.index()).unwrap_err();
    let text = err.to_string();
    assert!(!text.chars().any(|c| c.is_control()), "{text:?}");
    let err = resolve_ref(&json!({ "$ref": "#/components/parameters/x\u{7}y" }), RefKind::Parameter, &docs.index()).unwrap_err();
    assert!(!err.to_string().chars().any(|c| c.is_control()));
}

// ------------------------------------------------------------------- T-4

#[test]
fn media_type_error_texts_are_byte_identical_to_the_pre_generalisation_ones() {
    assert_eq!(RefError::Cycle.to_string(), "cycle");
    assert_eq!(RefError::TooLong.to_string(), "chain longer than 8 hops");
    assert_eq!(
        RefError::UnknownName {
            label: RefKind::MediaType.label(),
            name: "x".into()
        }
        .to_string(),
        "unknown media type 'x'"
    );
    assert_eq!(
        RefError::WrongKind {
            found: "schemas".into(),
            expected: RefKind::MediaType.label()
        }
        .to_string(),
        "a #/components/schemas/ reference where a media type belongs"
    );
    assert_eq!(
        RefError::Unsupported("other.yaml#/x".into()).to_string(),
        "unsupported reference form 'other.yaml#/x' (external references are never fetched)"
    );
    assert_eq!(RefError::NonStringRef.to_string(), "$ref is not a string");
    assert_eq!(RefError::NotAnObject.to_string(), "reference target is not an object");
}

#[test]
fn a_schema_reference_in_a_media_type_slot_resolves_to_the_old_wrong_kind_text() {
    let docs = Docs::new();
    let err = resolve_ref(&json!({ "$ref": "#/components/schemas/Car" }), RefKind::MediaType, &docs.index()).unwrap_err();
    assert_eq!(err.to_string(), "a #/components/schemas/ reference where a media type belongs");
}

// ------------------------------------------------------------------- siblings

#[test]
fn ref_siblings_ignores_summary_and_description_and_lists_everything_else() {
    assert!(ref_siblings(&json!({ "$ref": "#/x", "summary": "s", "description": "d" })).is_empty());
    assert!(ref_siblings(&json!({ "name": "inline", "in": "query" })).is_empty());
    let many = json!({ "$ref": "#/x", "required": true, "summary": "s", "schema": {} });
    let mut siblings = ref_siblings(&many);
    siblings.sort();
    assert_eq!(siblings, vec!["required", "schema"]);
    assert!(ref_siblings(&json!("text")).is_empty());
}

// ------------------------------------------------------------------- T-5

fn resolve_item<'a>(item: &'a Value, docs: &'a Docs) -> Result<Option<Cow<'a, Map<String, Value>>>, PathItemError> {
    resolve_path_item(item, &docs.index(), &mut ExpansionBudget::default())
}

#[test]
fn a_path_item_without_a_ref_is_borrowed_unchanged_and_a_non_object_is_none() {
    let docs = Docs::new();
    let item = json!({ "get": { "operationId": "g" } });
    assert!(matches!(resolve_item(&item, &docs).unwrap().unwrap(), Cow::Borrowed(_)));
    assert!(resolve_item(&json!("x"), &docs).unwrap().is_none());
}

#[test]
fn a_bare_ref_to_a_component_path_item_is_borrowed_not_copied() {
    let mut docs = Docs::new();
    docs.path_items.insert("X".into(), json!({ "get": { "operationId": "g" } }));
    let item = json!({ "$ref": "#/components/pathItems/X" });
    let resolved = resolve_item(&item, &docs).unwrap().unwrap();
    assert!(matches!(resolved, Cow::Borrowed(_)));
    assert!(resolved.contains_key("get"));
}

#[test]
fn local_siblings_merge_with_the_target_when_they_do_not_overlap() {
    let mut docs = Docs::new();
    docs.path_items.insert("X".into(), json!({ "get": { "operationId": "g" } }));
    let item = json!({ "$ref": "#/components/pathItems/X", "post": { "operationId": "p" } });
    let resolved = resolve_item(&item, &docs).unwrap().unwrap();
    assert!(resolved.contains_key("get") && resolved.contains_key("post"));
    assert!(!resolved.contains_key("$ref"));
}

#[test]
fn the_same_operation_defined_locally_and_in_the_target_is_a_conflict() {
    let mut docs = Docs::new();
    docs.path_items.insert("X".into(), json!({ "get": { "operationId": "g" } }));
    let item = json!({ "$ref": "#/components/pathItems/X", "get": { "operationId": "other" } });
    let err = resolve_item(&item, &docs).unwrap_err();
    assert_eq!(err, PathItemError::Conflict("get".into()));
    assert!(err.is_conflict());
}

#[test]
fn parameters_and_additional_operations_defined_on_both_sides_conflict_too() {
    let mut docs = Docs::new();
    docs.path_items.insert("X".into(), json!({ "parameters": [], "additionalOperations": {} }));
    let a = json!({ "$ref": "#/components/pathItems/X", "parameters": [] });
    assert_eq!(resolve_item(&a, &docs).unwrap_err(), PathItemError::Conflict("parameters".into()));
    let b = json!({ "$ref": "#/components/pathItems/X", "additionalOperations": {} });
    assert_eq!(resolve_item(&b, &docs).unwrap_err(), PathItemError::Conflict("additionalOperations".into()));
}

#[test]
fn the_nearer_summary_description_servers_and_extension_win_without_conflict() {
    let mut docs = Docs::new();
    docs.path_items.insert(
        "X".into(),
        json!({ "summary": "far", "description": "far", "servers": [{"url": "far"}], "x-note": "far", "get": {} }),
    );
    let item = json!({ "$ref": "#/components/pathItems/X", "summary": "near", "description": "near", "servers": [{"url": "near"}], "x-note": "near" });
    let resolved = resolve_item(&item, &docs).unwrap().unwrap();
    assert_eq!(resolved["summary"], json!("near"));
    assert_eq!(resolved["description"], json!("near"));
    assert_eq!(resolved["servers"], json!([{"url": "near"}]));
    assert_eq!(resolved["x-note"], json!("near"));
    assert!(resolved.contains_key("get"));
}

#[test]
fn a_chain_through_component_path_items_ending_at_a_paths_entry_with_an_escaped_slash_resolves() {
    let mut docs = Docs::new();
    docs.path_items.insert("A".into(), json!({ "$ref": "#/components/pathItems/B" }));
    docs.path_items.insert("B".into(), json!({ "$ref": "#/paths/~1real" }));
    docs.paths.insert("/real".into(), json!({ "get": { "operationId": "real" } }));
    let item = json!({ "$ref": "#/components/pathItems/A" });
    let resolved = resolve_item(&item, &docs).unwrap().unwrap();
    assert_eq!(resolved["get"]["operationId"], json!("real"));
}

#[test]
fn a_path_item_ref_into_paths_uses_exact_bytes_and_unknown_keys_are_unresolved() {
    let mut docs = Docs::new();
    docs.paths.insert("/Real".into(), json!({ "get": {} }));
    let ok = json!({ "$ref": "#/paths/~1Real" });
    assert!(resolve_item(&ok, &docs).is_ok());
    let miss = json!({ "$ref": "#/paths/~1real" });
    assert!(matches!(resolve_item(&miss, &docs), Err(PathItemError::Ref(RefError::UnknownName { .. }))));
}

#[test]
fn two_paths_pointing_at_each_other_are_a_cycle() {
    let mut docs = Docs::new();
    docs.paths.insert("/a".into(), json!({ "$ref": "#/paths/~1b" }));
    docs.paths.insert("/b".into(), json!({ "$ref": "#/paths/~1a" }));
    let item = docs.paths["/a"].clone();
    assert_eq!(resolve_item(&item, &docs).unwrap_err(), PathItemError::Ref(RefError::Cycle));
}

#[test]
fn a_path_item_ref_to_itself_through_paths_is_a_cycle() {
    let mut docs = Docs::new();
    docs.paths.insert("/a".into(), json!({ "$ref": "#/paths/~1a" }));
    let item = docs.paths["/a"].clone();
    // /a -> /a (hop 1, target has $ref) -> /a again (visited): cycle.
    assert_eq!(resolve_item(&item, &docs).unwrap_err(), PathItemError::Ref(RefError::Cycle));
}

#[test]
fn path_item_chains_are_capped_at_eight_hops() {
    let mut docs = Docs::new();
    for i in 0..9 {
        docs.path_items
            .insert(format!("n{i}"), json!({ "$ref": format!("#/components/pathItems/n{}", i + 1) }));
    }
    docs.path_items.insert("n9".into(), json!({ "get": {} }));
    let too_long = json!({ "$ref": "#/components/pathItems/n0" });
    assert_eq!(resolve_item(&too_long, &docs).unwrap_err(), PathItemError::Ref(RefError::TooLong));
    let fits = json!({ "$ref": "#/components/pathItems/n2" });
    assert!(resolve_item(&fits, &docs).unwrap().unwrap().contains_key("get"));
}

#[test]
fn path_item_refs_that_are_external_wrong_kind_or_non_objects_are_errors() {
    let mut docs = Docs::new();
    docs.path_items.insert("S".into(), json!(5));
    assert!(matches!(
        resolve_item(&json!({ "$ref": "other.yaml#/paths/~1x" }), &docs),
        Err(PathItemError::Ref(RefError::Unsupported(_)))
    ));
    assert!(matches!(
        resolve_item(&json!({ "$ref": "#/components/parameters/P" }), &docs),
        Err(PathItemError::Ref(RefError::WrongKind { .. }))
    ));
    assert_eq!(
        resolve_item(&json!({ "$ref": "#/components/pathItems/S" }), &docs).unwrap_err(),
        PathItemError::Ref(RefError::NotAnObject)
    );
    assert_eq!(resolve_item(&json!({ "$ref": 1 }), &docs).unwrap_err(), PathItemError::Ref(RefError::NonStringRef));
}

#[test]
fn a_path_item_ref_to_a_deep_pointer_is_a_bad_pointer() {
    let docs = Docs::new();
    let err = resolve_item(&json!({ "$ref": "#/paths/~1a/get" }), &docs).unwrap_err();
    assert!(matches!(
        err,
        PathItemError::Ref(RefError::BadPointer {
            error: PointerError::DeepPointer,
            ..
        })
    ));
}

#[test]
fn merging_a_big_component_into_many_paths_hits_the_node_ceiling_and_fails_closed() {
    let mut docs = Docs::new();
    // ~1000 nodes per copy; a merge (local sibling forces a copy) charges the shared budget.
    let big: Vec<Value> = (0..999).map(|i| json!(i)).collect();
    docs.path_items.insert("Big".into(), json!({ "x-big": big, "get": {} }));
    let mut budget = ExpansionBudget::default();
    let item = json!({ "$ref": "#/components/pathItems/Big", "post": {} });
    let mut outcomes = Vec::new();
    for _ in 0..400 {
        outcomes.push(resolve_path_item(&item, &docs.index(), &mut budget));
    }
    let ok = outcomes.iter().filter(|r| r.is_ok()).count();
    assert!(
        ok > 100 && ok < 400,
        "some copies fit the {MAX_EXPANDED_PATH_ITEM_NODES}-node budget, later ones do not: {ok}"
    );
    assert!(outcomes.iter().any(|r| matches!(r, Err(PathItemError::TooLarge))));
    // once exhausted it stays exhausted
    assert!(matches!(outcomes.last().unwrap(), Err(PathItemError::TooLarge)));
}

#[test]
fn bare_refs_never_spend_the_expansion_budget_however_many_paths_use_them() {
    let mut docs = Docs::new();
    let big: Vec<Value> = (0..999).map(|i| json!(i)).collect();
    docs.path_items.insert("Big".into(), json!({ "x-big": big, "get": {} }));
    let mut budget = ExpansionBudget::default();
    let item = json!({ "$ref": "#/components/pathItems/Big" });
    for _ in 0..2000 {
        assert!(resolve_path_item(&item, &docs.index(), &mut budget).unwrap().is_some());
    }
}
