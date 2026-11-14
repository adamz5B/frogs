//! `frogs generate` and the MCP work: the `mcp` block is never written, survives migration, and
//! path-level parameters now flow into reference files with a reference-only refresh.

use super::*;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-gen-mcp-{}-{}-{n}",
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

    fn json(&self, rel: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))).unwrap()
    }
}

const SPEC_V1: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    get:\n      operationId: getX\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: { type: object, properties: { id: { type: integer } } }\n";
const SPEC_V2: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    get:\n      operationId: getX\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: { type: object, properties: { id: { type: integer }, name: { type: string } } }\n";

#[test]
fn a_freshly_generated_stub_never_contains_an_mcp_block() {
    let fx = Fx::new(SPEC_V1);
    assert!(fx.generate().errors.is_empty());
    assert!(fx.json("x/endpoint.get.json").get("mcp").is_none(), "exposure is always a deliberate human edit");
}

#[test]
fn migrating_a_changed_stub_keeps_a_hand_written_mcp_block_untouched() {
    let fx = Fx::new(SPEC_V1);
    fx.generate();
    let mut stub = fx.json("x/endpoint.get.json");
    stub["mcp"] = serde_json::json!({ "expose": true, "name": "get_x", "description": "Mine" });
    std::fs::write(fx.path("x/endpoint.get.json"), serde_json::to_string_pretty(&stub).unwrap()).unwrap();

    fx.set_spec(SPEC_V2);
    fx.generate();

    let migrated = fx.json("x/endpoint.get.json");
    assert_eq!(migrated["mcp"], serde_json::json!({ "expose": true, "name": "get_x", "description": "Mine" }));
    assert!(migrated["response"].to_string().contains("name"), "the migration really ran: {migrated}");
}

#[test]
fn a_path_level_parameter_appears_in_the_reference_file_and_a_change_to_it_refreshes_only_the_reference() {
    let with_param = |extra: &str| {
        format!(
            "openapi: 3.2.0
info: {{ title: t, version: '1' }}
paths:
  /x:
    parameters:
      - {{ name: tenant, in: query, schema: {{ type: integer }} }}
{extra}    get:
      operationId: getX
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {{ type: object, properties: {{ id: {{ type: integer }} }} }}
"
        )
    };
    let fx = Fx::new(&with_param(""));
    assert!(fx.generate().errors.is_empty());
    let reference = fx.json("x/endpoint.get.reference.json");
    assert!(
        reference.to_string().contains("tenant"),
        "path-level parameters are part of the reference file: {reference}"
    );

    let stub_before = std::fs::read_to_string(fx.path("x/endpoint.get.json")).unwrap();
    fx.set_spec(&with_param(
        "      - { name: region, in: query, schema: { type: string } }
",
    ));
    fx.generate();
    assert_eq!(
        std::fs::read_to_string(fx.path("x/endpoint.get.json")).unwrap(),
        stub_before,
        "the stub is not rewritten"
    );
    assert!(
        !fx.path("_backups").exists() && !fx.path("x/_backups").exists(),
        "no backup for a reference-only refresh"
    );
    let refreshed = fx.json("x/endpoint.get.reference.json");
    assert!(refreshed.to_string().contains("region"), "{refreshed}");
    assert_ne!(refreshed, reference, "the reference file now lists the second path-level parameter");
}

mod scopes_m2;
