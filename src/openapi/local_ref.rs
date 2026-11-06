use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

use serde_json::{Map, Value};

use super::path_rules::untrusted;

/// Shared ceiling on one `$ref` chain, whatever the kind of object it points at.
pub(crate) const MAX_REF_HOPS: usize = 8;

/// Total size, counted in JSON nodes, of every path item that had to be copied while merging a
/// `$ref`'d path item with its siblings. A path item that is a bare `$ref` to a component is
/// borrowed rather than copied and never counts. Past this ceiling the offending item is
/// treated as unresolved (fail closed), so a spec cannot multiply one large component by
/// thousands of referencing paths.
pub(crate) const MAX_EXPANDED_PATH_ITEM_NODES: usize = 200_000;

const KNOWN_COMPONENT_KEYS: [&str; 11] = [
    "schemas",
    "responses",
    "parameters",
    "examples",
    "requestBodies",
    "headers",
    "securitySchemes",
    "links",
    "callbacks",
    "pathItems",
    "mediaTypes",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointerError {
    BadEscape,
    DeepPointer,
}

impl fmt::Display for PointerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PointerError::BadEscape => write!(f, "invalid '~' escape in JSON Pointer"),
            PointerError::DeepPointer => write!(f, "pointers into a component are not supported"),
        }
    }
}

/// RFC 6901 reference-token decoding in one left-to-right pass, so `~01` is `~1` and not `/`.
pub(crate) fn decode_token(raw: &str) -> Result<Cow<'_, str>, PointerError> {
    if !raw.contains('~') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            _ => return Err(PointerError::BadEscape),
        }
    }
    Ok(Cow::Owned(out))
}

/// The component name a `#/components/<kind>/<name>` reference points at, decoded. `None` when
/// the reference has a different prefix; a remainder that is more than one token is
/// `DeepPointer`.
pub(crate) fn component_name<'a>(reference: &'a str, kind: &str) -> Option<Result<Cow<'a, str>, PointerError>> {
    let rest = reference.strip_prefix("#/components/")?.strip_prefix(kind)?.strip_prefix('/')?;
    Some(single_token(rest))
}

fn single_token(raw: &str) -> Result<Cow<'_, str>, PointerError> {
    if raw.contains('/') {
        return Err(PointerError::DeepPointer);
    }
    decode_token(raw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefKind {
    MediaType,
    Parameter,
    RequestBody,
    Response,
    PathItem,
}

impl RefKind {
    pub(crate) fn component_key(self) -> &'static str {
        match self {
            RefKind::MediaType => "mediaTypes",
            RefKind::Parameter => "parameters",
            RefKind::RequestBody => "requestBodies",
            RefKind::Response => "responses",
            RefKind::PathItem => "pathItems",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            RefKind::MediaType => "media type",
            RefKind::Parameter => "parameter",
            RefKind::RequestBody => "request body",
            RefKind::Response => "response",
            RefKind::PathItem => "path item",
        }
    }
}

/// The parts of the document a local `$ref` may point into. Only ever borrows; nothing is fetched.
#[derive(Clone, Copy)]
pub(crate) struct RefIndex<'a> {
    pub media_types: &'a Map<String, Value>,
    pub parameters: &'a Map<String, Value>,
    pub request_bodies: &'a Map<String, Value>,
    pub responses: &'a Map<String, Value>,
    pub path_items: &'a Map<String, Value>,
    pub paths: &'a Map<String, Value>,
}

impl<'a> RefIndex<'a> {
    #[cfg(test)]
    pub(crate) fn empty(empty: &'a Map<String, Value>) -> Self {
        RefIndex {
            media_types: empty,
            parameters: empty,
            request_bodies: empty,
            responses: empty,
            path_items: empty,
            paths: empty,
        }
    }

    fn components_for(&self, kind: RefKind) -> &'a Map<String, Value> {
        match kind {
            RefKind::MediaType => self.media_types,
            RefKind::Parameter => self.parameters,
            RefKind::RequestBody => self.request_bodies,
            RefKind::Response => self.responses,
            RefKind::PathItem => self.path_items,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefError {
    Cycle,
    TooLong,
    UnknownName { label: &'static str, name: String },
    WrongKind { found: String, expected: &'static str },
    Unsupported(String),
    NonStringRef,
    NotAnObject,
    BadPointer { reference: String, error: PointerError },
}

impl fmt::Display for RefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefError::Cycle => write!(f, "cycle"),
            RefError::TooLong => write!(f, "chain longer than {MAX_REF_HOPS} hops"),
            RefError::UnknownName { label, name } => write!(f, "unknown {label} '{}'", untrusted(name)),
            RefError::WrongKind { found, expected } => write!(f, "a #/components/{found}/ reference where a {expected} belongs"),
            RefError::Unsupported(r) => write!(f, "unsupported reference form '{}' (external references are never fetched)", untrusted(r)),
            RefError::NonStringRef => write!(f, "$ref is not a string"),
            RefError::NotAnObject => write!(f, "reference target is not an object"),
            RefError::BadPointer { reference, error } => write!(f, "malformed reference '{}': {error}", untrusted(reference)),
        }
    }
}

struct Located<'a> {
    visited_key: String,
    map: &'a Map<String, Value>,
    name: Cow<'a, str>,
    label: &'static str,
}

fn locate<'a>(reference: &'a str, kind: RefKind, index: &RefIndex<'a>) -> Result<Located<'a>, RefError> {
    let bad_pointer = |error| RefError::BadPointer {
        reference: reference.to_string(),
        error,
    };
    if kind == RefKind::PathItem
        && let Some(rest) = reference.strip_prefix("#/paths/")
    {
        let name = single_token(rest).map_err(bad_pointer)?;
        return Ok(Located {
            visited_key: format!("paths/{name}"),
            map: index.paths,
            name,
            label: kind.label(),
        });
    }
    if let Some(found) = component_name(reference, kind.component_key()) {
        let name = found.map_err(bad_pointer)?;
        return Ok(Located {
            visited_key: format!("{}/{name}", kind.component_key()),
            map: index.components_for(kind),
            name,
            label: kind.label(),
        });
    }
    if let Some(rest) = reference.strip_prefix("#/components/")
        && let Some(found) = KNOWN_COMPONENT_KEYS
            .iter()
            .find(|key| rest.strip_prefix(**key).is_some_and(|tail| tail.starts_with('/')))
    {
        return Err(RefError::WrongKind {
            found: (*found).to_string(),
            expected: kind.label(),
        });
    }
    Err(RefError::Unsupported(reference.to_string()))
}

/// Follows a `$ref` chain through the document's own `components` (and, for path items, `paths`)
/// only. A non-object entry is `Ok(None)` (nothing to read, nothing to report). Each hop is
/// looked up by exact decoded name; cycles and chains over `MAX_REF_HOPS` are errors.
pub(crate) fn resolve_ref<'a>(entry: &'a Value, kind: RefKind, index: &RefIndex<'a>) -> Result<Option<&'a Map<String, Value>>, RefError> {
    let mut current = entry;
    let mut hops = 0usize;
    let mut visited: HashSet<String> = HashSet::new();
    loop {
        let Some(obj) = current.as_object() else {
            return if hops == 0 { Ok(None) } else { Err(RefError::NotAnObject) };
        };
        let Some(reference) = obj.get("$ref") else {
            return Ok(Some(obj));
        };
        let Some(reference) = reference.as_str() else {
            return Err(RefError::NonStringRef);
        };
        let located = locate(reference, kind, index)?;
        if !visited.insert(located.visited_key) {
            return Err(RefError::Cycle);
        }
        hops += 1;
        if hops > MAX_REF_HOPS {
            return Err(RefError::TooLong);
        }
        current = located.map.get(located.name.as_ref()).ok_or_else(|| RefError::UnknownName {
            label: located.label,
            name: located.name.to_string(),
        })?;
    }
}

/// Keys next to a `$ref` that a Reference Object ignores (`summary` and `description` are
/// allowed there and not reported). Empty when the entry has no `$ref`.
pub(crate) fn ref_siblings(entry: &Value) -> Vec<&str> {
    let Some(obj) = entry.as_object().filter(|obj| obj.contains_key("$ref")) else {
        return Vec::new();
    };
    obj.keys()
        .map(String::as_str)
        .filter(|key| !matches!(*key, "$ref" | "summary" | "description"))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PathItemError {
    Ref(RefError),
    Conflict(String),
    TooLarge,
}

impl PathItemError {
    pub(crate) fn is_conflict(&self) -> bool {
        matches!(self, PathItemError::Conflict(_))
    }
}

impl fmt::Display for PathItemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathItemError::Ref(e) => write!(f, "{e}"),
            PathItemError::Conflict(key) => write!(f, "the path item and its $ref target both define '{}'", untrusted(key)),
            PathItemError::TooLarge => write!(f, "expanded path items exceed the {MAX_EXPANDED_PATH_ITEM_NODES}-node limit"),
        }
    }
}

/// Running total of how much path-item content has been copied while merging.
#[derive(Default)]
pub(crate) struct ExpansionBudget {
    used: usize,
}

fn node_count(value: &Value, ceiling: usize) -> usize {
    let mut count = 0usize;
    let mut stack = vec![value];
    while let Some(next) = stack.pop() {
        count += 1;
        if count > ceiling {
            break;
        }
        match next {
            Value::Array(items) => stack.extend(items),
            Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    count
}

fn nearer_wins(key: &str) -> bool {
    matches!(key, "summary" | "description" | "servers") || key.starts_with("x-")
}

/// A path item with its `$ref` chain (to `#/components/pathItems/<name>` or `#/paths/<name>`)
/// merged in. The referencing `paths` key stays the only identity; the target's key is never
/// used. Local fields come first, then each target's: a key present on both sides is a conflict
/// unless it is `summary`/`description`/`servers`/`x-*`, where the nearer one wins. `Ok(None)`
/// is a non-object item. An item without `$ref`, or a bare `$ref` to a target without one,
/// is borrowed, not copied.
pub(crate) fn resolve_path_item<'a>(item: &'a Value, index: &RefIndex<'a>, budget: &mut ExpansionBudget) -> Result<Option<Cow<'a, Map<String, Value>>>, PathItemError> {
    let Some(obj) = item.as_object() else {
        return Ok(None);
    };
    if !obj.contains_key("$ref") {
        return Ok(Some(Cow::Borrowed(obj)));
    }

    let mut merged: Map<String, Value> = obj.iter().filter(|(key, _)| key.as_str() != "$ref").map(|(k, v)| (k.clone(), v.clone())).collect();
    let bare = merged.is_empty();
    let mut current = obj;
    let mut hops = 0usize;
    let mut visited: HashSet<String> = HashSet::new();
    while let Some(reference) = current.get("$ref") {
        let Some(reference) = reference.as_str() else {
            return Err(PathItemError::Ref(RefError::NonStringRef));
        };
        let located = locate(reference, RefKind::PathItem, index).map_err(PathItemError::Ref)?;
        if !visited.insert(located.visited_key) {
            return Err(PathItemError::Ref(RefError::Cycle));
        }
        hops += 1;
        if hops > MAX_REF_HOPS {
            return Err(PathItemError::Ref(RefError::TooLong));
        }
        let target = located.map.get(located.name.as_ref()).ok_or_else(|| {
            PathItemError::Ref(RefError::UnknownName {
                label: located.label,
                name: located.name.to_string(),
            })
        })?;
        let Some(target) = target.as_object() else {
            return Err(PathItemError::Ref(RefError::NotAnObject));
        };
        if bare && hops == 1 && !target.contains_key("$ref") {
            return Ok(Some(Cow::Borrowed(target)));
        }
        for (key, value) in target {
            if key == "$ref" {
                continue;
            }
            if merged.contains_key(key) {
                if nearer_wins(key) {
                    continue;
                }
                return Err(PathItemError::Conflict(key.clone()));
            }
            budget.used = budget.used.saturating_add(node_count(value, MAX_EXPANDED_PATH_ITEM_NODES));
            if budget.used > MAX_EXPANDED_PATH_ITEM_NODES {
                return Err(PathItemError::TooLarge);
            }
            merged.insert(key.clone(), value.clone());
        }
        current = target;
    }
    Ok(Some(Cow::Owned(merged)))
}
