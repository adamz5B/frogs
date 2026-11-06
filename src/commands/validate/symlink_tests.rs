//! `frogs validate`'s problem counts for links, per `endpointSymlinks` mode and `strictOpenApi`.

use super::*;
use crate::openapi::fs_os_tests::{link_dangling_dir, link_dir};
use std::fs;

const ENDPOINT: &str = r#"{ "operationId": "getThings", "sources": {}, "response": {} }"#;
const SPEC: &str = "openapi: 3.2.0
info: { title: t, version: '1' }
paths:
  /things:
    get:
      operationId: getThings
      responses:
        '200': { description: ok }
";
const LINKED_OPS: &str = "  /inlink/a:
    get:
      operationId: getInlink
      responses:
        '200': { description: ok }
  /outlink:
    get:
      operationId: getOutlink
      responses:
        '200': { description: ok }
";

fn tempdir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-validate-links-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
    outside: PathBuf,
    links: Vec<PathBuf>,
}

impl Fx {
    fn new(mode: &str, strict: bool) -> Fx {
        let root = tempdir("root");
        let outside = tempdir("outside");
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/datasources/endpoints/things")).unwrap();
        fs::write(
            root.join("api/config/server.json"),
            format!(r#"{{ "endpointSymlinks": "{mode}", "strictOpenApi": {strict} }}"#),
        )
        .unwrap();
        fs::write(root.join("api/datasources/endpoints/things/endpoint.get.json"), ENDPOINT).unwrap();
        fs::write(root.join(MANIFEST_FILE), SPEC).unwrap();
        Fx {
            root,
            outside,
            links: Vec::new(),
        }
    }

    fn link(&mut self, target: &Path, link: &Path) -> bool {
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        let ok = link_dir(target, link);
        if ok {
            self.links.push(link.to_path_buf());
        }
        ok
    }

    fn eps(&self) -> PathBuf {
        self.root.join("api/datasources/endpoints")
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        for link in &self.links {
            if fs::remove_dir(link).is_err() {
                let _ = fs::remove_file(link);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.outside);
    }
}

/// One in-project link, one outside link, each holding an endpoint file the spec doesn't mention (so the only
/// problems any run can report are about the links themselves).
fn with_links(mode: &str, strict: bool) -> Option<Fx> {
    let mut fx = Fx::new(mode, strict);
    fs::create_dir_all(fx.root.join("shared/a")).unwrap();
    fs::write(fx.root.join("shared/a/endpoint.get.json"), ENDPOINT).unwrap();
    fs::write(fx.outside.join("endpoint.get.json"), ENDPOINT).unwrap();
    let (shared, outside) = (fx.root.join("shared"), fx.outside.clone());
    let eps = fx.eps();
    if !fx.link(&shared, &eps.join("inlink")) || !fx.link(&outside, &eps.join("outlink")) {
        return None;
    }
    Some(fx)
}

#[tokio::test]
async fn a_project_without_links_has_zero_problems_in_every_mode_and_strictness() {
    for mode in ["contained", "refuse", "follow"] {
        for strict in [false, true] {
            let fx = Fx::new(mode, strict);
            assert_eq!(validate_api(&fx.root).await, 0, "{mode} strict={strict}");
        }
    }
}

#[tokio::test]
async fn contained_reports_an_escaping_link_as_a_warning_normally_and_one_problem_under_strict() {
    let Some(fx) = with_links("contained", false) else { return };
    assert_eq!(validate_api(&fx.root).await, 0);
    fs::write(
        fx.root.join("api/config/server.json"),
        r#"{ "endpointSymlinks": "contained", "strictOpenApi": true }"#,
    )
    .unwrap();
    // Under strictOpenApi an endpoint file matching no spec operation is itself a problem; declare the followed one.
    fs::write(
        fx.root.join(MANIFEST_FILE),
        format!("{SPEC}{}", &LINKED_OPS[..LINKED_OPS.find("  /outlink").unwrap()]),
    )
    .unwrap();
    assert_eq!(validate_api(&fx.root).await, 1, "exactly the one escaping link");
}

#[tokio::test]
async fn refuse_reports_every_link_as_a_problem_whether_or_not_strict_is_on() {
    for strict in [false, true] {
        let Some(fx) = with_links("refuse", strict) else { return };
        assert_eq!(validate_api(&fx.root).await, 2, "strict={strict}: one Refused finding per link");
    }
}

#[tokio::test]
async fn follow_reports_no_problem_for_an_outside_link_in_either_strictness() {
    for strict in [false, true] {
        let Some(fx) = with_links("follow", strict) else { return };
        // Strict adds one problem that is not about links: the outside file matches no spec operation
        // (declaring it would make `generate`'s write plan refuse the outside link).
        if strict {
            fs::write(
                fx.root.join(MANIFEST_FILE),
                format!("{SPEC}{}", &LINKED_OPS[..LINKED_OPS.find("  /outlink").unwrap()]),
            )
            .unwrap();
        }
        assert_eq!(validate_api(&fx.root).await, usize::from(strict), "strict={strict}");
    }
}

#[tokio::test]
async fn an_api_folder_link_outside_the_project_is_always_a_problem_in_every_mode() {
    for mode in ["contained", "refuse", "follow"] {
        let mut fx = Fx::new(mode, false);
        fs::create_dir_all(fx.outside.join("config")).unwrap();
        fs::write(fx.outside.join("config/server.json"), format!(r#"{{ "endpointSymlinks": "{mode}" }}"#)).unwrap();
        fs::create_dir_all(fx.outside.join("datasources/endpoints")).unwrap();
        fs::remove_dir_all(fx.root.join("api")).unwrap();
        let (outside, api) = (fx.outside.clone(), fx.root.join("api"));
        if !fx.link(&outside, &api) {
            return;
        }
        assert!(validate_api(&fx.root).await >= 1, "{mode}: boundary failures are always problems");
    }
}

#[tokio::test]
async fn a_dangling_components_link_is_always_a_problem_and_validate_creates_nothing() {
    for mode in ["contained", "refuse", "follow"] {
        let mut fx = Fx::new(mode, false);
        let (gone, link) = (fx.outside.join("gone"), fx.root.join("api/datasources/components"));
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        if !link_dangling_dir(&gone, &link) {
            return;
        }
        fx.links.push(link);
        assert!(validate_api(&fx.root).await >= 1, "{mode}");
        assert!(!gone.exists(), "validate is read-only");
    }
}

#[tokio::test]
async fn a_dangling_scaffold_file_link_is_always_a_problem() {
    let mut fx = Fx::new("contained", false);
    let victim = fx.outside.join("victim.json");
    fs::create_dir_all(fx.root.join("api/security")).unwrap();
    let link = fx.root.join("api/security/schemes.json");
    if !crate::openapi::fs_os_tests::link_dangling_file(&victim, &link) {
        return;
    }
    fx.links.push(link);
    assert!(validate_api(&fx.root).await >= 1);
    assert!(!victim.exists());
}

#[tokio::test]
async fn a_linked_endpoint_file_that_does_not_parse_counts_as_one_problem() {
    let mut fx = Fx::new("contained", false);
    fs::create_dir_all(fx.root.join("shared/a")).unwrap();
    fs::write(
        fx.root.join("shared/a/endpoint.get.json"),
        r#"{ "operationId": "x", "sources": "TOPSECRET-123", "response": {} }"#,
    )
    .unwrap();
    let (shared, link) = (fx.root.join("shared"), fx.eps().join("inlink"));
    if !fx.link(&shared, &link) {
        return;
    }
    assert_eq!(validate_api(&fx.root).await, 1);
}
