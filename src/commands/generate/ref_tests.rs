//! `frogs generate` with `$ref`s in responses, parameters and path items: stubs, drift,
//! reference-only refreshes and orphan protection, plus a golden backward-compatibility check for
//! a spec that uses none of it.

use super::*;
use std::collections::BTreeMap;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-gen-refs-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fx {
    fn new(spec: &str) -> Fx {
        let root = tempdir();
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        Fx { root }
    }

    fn set_spec(&self, spec: &str) {
        std::fs::write(self.root.join("openapi.yaml"), spec).unwrap();
    }

    fn generate(&self) -> GenerateOutcome {
        generate_api_inner(&self.root).unwrap()
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join("api/datasources/endpoints").join(rel)
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn json(&self, rel: &str) -> Value {
        serde_json::from_str(&self.read(rel)).unwrap()
    }

    fn exists(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }
}

fn spec(components: &str, paths: &str) -> String {
    format!(
        "openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\ncomponents:\n  securitySchemes:\n    a: {{ type: apiKey, in: header, name: ka }}\n{components}paths:\n{paths}"
    )
}

const OK_RESPONSE: &str = "  responses:\n    Ok:\n      description: ok\n      content:\n        application/json:\n          schema: { type: object, properties: { id: { type: integer } } }\n";
const OK_RESPONSE_V2: &str = "  responses:\n    Ok:\n      description: ok\n      content:\n        application/json:\n          schema: { type: object, properties: { id: { type: integer }, name: { type: string } } }\n";
const REF_GET: &str = "  /x:\n    get:\n      operationId: getX\n      responses: { '200': { $ref: '#/components/responses/Ok' } }\n";
const INLINE_GET: &str = "  /x:\n    get:\n      operationId: getX\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: { type: object, properties: { id: { type: integer } } }\n";

// ------------------------------------------------------------------- T-28

#[test]
fn a_response_ref_generates_the_same_stub_and_reference_as_the_inlined_response() {
    let via_ref = Fx::new(&spec(OK_RESPONSE, REF_GET));
    let inline = Fx::new(&spec("", INLINE_GET));
    assert!(via_ref.generate().errors.is_empty());
    assert!(inline.generate().errors.is_empty());
    assert_eq!(via_ref.read("x/endpoint.get.json"), inline.read("x/endpoint.get.json"));
    assert_eq!(via_ref.read("x/endpoint.get.reference.json"), inline.read("x/endpoint.get.reference.json"));
    assert!(via_ref.read("x/endpoint.get.json").contains("\"id\""));
}

#[test]
fn editing_a_referenced_response_triggers_drift_backup_and_migration_keeping_sources_and_security() {
    let fx = Fx::new(&spec(OK_RESPONSE, REF_GET));
    fx.generate();
    let mut stub = fx.json("x/endpoint.get.json");
    stub["sources"] = serde_json::json!({ "db": { "type": "sql", "connection": "main", "query": "select 1" } });
    stub["security"] = serde_json::json!("a");
    std::fs::write(fx.path("x/endpoint.get.json"), serde_json::to_string_pretty(&stub).unwrap()).unwrap();
    let hash_before = fx.json("x/endpoint.get.reference.json")["_hash"].clone();

    fx.set_spec(&spec(OK_RESPONSE_V2, REF_GET));
    fx.generate();

    assert_ne!(
        fx.json("x/endpoint.get.reference.json")["_hash"],
        hash_before,
        "editing the component must change the drift hash"
    );
    assert!(fx.path("_backups").exists() || fx.path("x/_backups").exists(), "the old stub is backed up");
    let migrated = fx.json("x/endpoint.get.json");
    assert_eq!(migrated["sources"], stub["sources"], "sources are never touched by migration");
    assert_eq!(migrated["security"], serde_json::json!("a"));
    assert!(fx.read("x/endpoint.get.json").contains("\"name\""), "the new field appears in the migrated stub");
}

// ------------------------------------------------------------------- T-29

fn param_spec(name: &str) -> String {
    spec(
        &format!("  parameters:\n    Limit: {{ name: {name}, in: query, schema: {{ type: integer }} }}\n"),
        "  /x:\n    get:\n      operationId: getX\n      parameters:\n        - $ref: '#/components/parameters/Limit'\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: { type: string }\n",
    )
}

#[test]
fn a_parameter_ref_lands_in_the_reference_files_request_and_available_sources() {
    let fx = Fx::new(&param_spec("limit"));
    assert!(fx.generate().errors.is_empty());
    let reference = fx.json("x/endpoint.get.reference.json");
    assert_eq!(reference["request"]["query"], serde_json::json!(["limit"]));
    assert_eq!(reference["availableParameterSources"], serde_json::json!(["query.limit"]));
}

#[test]
fn editing_only_a_referenced_parameter_refreshes_the_reference_file_without_backup_or_stub_change() {
    let fx = Fx::new(&param_spec("limit"));
    fx.generate();
    let stub_before = fx.read("x/endpoint.get.json");

    fx.set_spec(&param_spec("max"));
    let outcome = fx.generate();
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);

    let reference = fx.json("x/endpoint.get.reference.json");
    assert_eq!(reference["request"]["query"], serde_json::json!(["max"]));
    assert_eq!(reference["availableParameterSources"], serde_json::json!(["query.max"]));
    assert_eq!(fx.read("x/endpoint.get.json"), stub_before, "stub bytes unchanged");
    assert!(!fx.path("x/_backups").exists(), "no backup for a reference-only refresh");
    assert!(!fx.exists("_backups"));
}

#[test]
fn write_endpoint_files_counts_a_reference_only_refresh_and_a_second_unchanged_run_skips() {
    let fx = Fx::new(&param_spec("limit"));
    fx.generate();
    fx.set_spec(&param_spec("max"));
    let doc = crate::openapi::load(&fx.root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
    let components = doc.resolve_components();
    let ctx = test_ctx(&fx.root);
    let run = |errors: &mut Vec<String>| {
        write_endpoint_files(
            &ctx,
            &fx.root.join("api"),
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            errors,
        )
        .unwrap()
    };
    let first = run(&mut Vec::new());
    assert_eq!(
        first,
        GenerateSummary {
            skipped: 0,
            created: 0,
            migrated: 0,
            drift_warned: 0,
            references_refreshed: 1
        }
    );
    let second = run(&mut Vec::new());
    assert_eq!(
        second,
        GenerateSummary {
            skipped: 1,
            created: 0,
            migrated: 0,
            drift_warned: 0,
            references_refreshed: 0
        }
    );
}

#[test]
fn a_reference_only_refresh_does_not_abort_generate_when_the_reference_cannot_be_rewritten() {
    let fx = Fx::new(&param_spec("limit"));
    fx.generate();
    fx.set_spec(&param_spec("max"));
    // A read-only reference file makes the rewrite fail; generate must warn and carry on.
    let reference_path = fx.path("x/endpoint.get.reference.json");
    let mut permissions = std::fs::metadata(&reference_path).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&reference_path, permissions.clone()).unwrap();
    let result = generate_api_inner(&fx.root);
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(&reference_path, permissions).unwrap();
    assert!(result.is_ok(), "{result:?}");
}

// ------------------------------------------------------------------- T-31 / T-32

const SHARED_ITEM: &str = "  pathItems:\n    X:\n      get:\n        operationId: getX\n        responses:\n          '200':\n            description: ok\n            content:\n              application/json:\n                schema: { type: string }\n";

#[test]
fn a_broken_path_item_ref_never_orphans_existing_files_and_exits_nonzero_until_fixed() {
    let good = spec(SHARED_ITEM, "  /x:\n    $ref: '#/components/pathItems/X'\n");
    let fx = Fx::new(&good);
    assert!(fx.generate().errors.is_empty());
    assert!(fx.exists("x/endpoint.get.json"));
    let stub_before = fx.read("x/endpoint.get.json");

    fx.set_spec(&spec(SHARED_ITEM, "  /x:\n    $ref: '#/components/pathItems/Typo'\n"));
    let broken = fx.generate();
    assert!(!broken.errors.is_empty(), "an unresolved path item must make generate exit 1");
    assert!(fx.exists("x/endpoint.get.json"), "the file must not be underscore-renamed");
    assert!(!fx.exists("x/_endpoint.get.json"));
    assert!(!fx.exists("x/_endpoint.get.reference.json"));
    assert_eq!(fx.read("x/endpoint.get.json"), stub_before);

    fx.set_spec(&good);
    let fixed = fx.generate();
    assert!(fixed.errors.is_empty(), "{:?}", fixed.errors);
    assert!(fx.exists("x/endpoint.get.json"));
    assert!(!fx.exists("x/_endpoint.get.json"));
}

#[test]
fn a_path_item_ref_into_another_path_generates_stubs_only_under_the_referencing_folder() {
    let fx = Fx::new(&spec(
        "",
        "  /real:\n    get:\n      operationId: real\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: { type: string }\n  /other:\n    $ref: '#/paths/~1real'\n",
    ));
    let outcome = fx.generate();
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(fx.exists("real/endpoint.get.json"));
    assert!(fx.exists("other/endpoint.get.json"));
    let entries: Vec<String> = std::fs::read_dir(fx.path(""))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(entries.iter().all(|e| e == "real" || e == "other"), "no folder named after the pointer: {entries:?}");
}

// ------------------------------------------------------------------- T-30 golden

/// Every file under `dir`, `/`-joined relative path -> text.
fn snapshot(dir: &Path) -> BTreeMap<String, String> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(rel, String::from_utf8(std::fs::read(&path).unwrap()).unwrap().replace("\r\n", "\n"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

mod golden_components;
mod golden_config;
mod golden_endpoints;
mod golden_spec;

use golden_spec::GOLDEN_SPEC;

#[test]
fn a_spec_with_no_new_style_refs_generates_byte_identical_output_to_the_pre_change_build() {
    let fx = Fx::new(GOLDEN_SPEC);
    let outcome = fx.generate();
    let mut got = snapshot(&fx.root);
    got.remove("openapi.yaml");
    let expected: BTreeMap<String, String> = golden_config::GOLDEN_CONFIG
        .iter()
        .chain(golden_components::GOLDEN_COMPONENTS)
        .chain(golden_endpoints::GOLDEN_ENDPOINTS)
        .map(|(name, content)| (name.to_string(), content.to_string()))
        .collect();
    // The fixture carries one unsafe secured path, so the pre-change build exited 1 with two problems too.
    assert_eq!(outcome.errors.len(), 2, "{:?}", outcome.errors);
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "the set of generated files changed"
    );
    for (name, content) in &expected {
        assert_eq!(&got[name], content, "{name} differs from the pre-change output");
    }
    // A second run over the golden output changes nothing.
    fx.generate();
    let mut again = snapshot(&fx.root);
    again.remove("openapi.yaml");
    assert_eq!(again, got);
}
