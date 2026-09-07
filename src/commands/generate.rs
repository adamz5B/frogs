use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::{Config, ServerConfig};
use crate::openapi::{OpenApiDocument, Operation, content_hash, merge_stub_response, stub_from_descriptor};
use crate::project::{MANIFEST_FILE, find_files_with_extensions, require_project_root};

/// Files `generate --role web` scans the project root for (non-recursive —
/// see `find_files_with_extensions`) to confirm there's a static project
/// here and pick a start page. Actual request-time serving (Point 2) does
/// its own direct filesystem lookup instead of relying on this list, so
/// nothing here needs to be exhaustive — this is purely `generate`'s own
/// "is this a web project, and what should the start page default to" check.
const WEB_ASSET_EXTENSIONS: &[&str] = &["html", "js", "css"];

/// Forces `generate` to produce config for only one side of a project that
/// has both an `openapi.yaml` and web asset file(s) — the default when both
/// are found and no `--role` is given is to generate *both* (see `run`'s
/// role-resolution below), so this is an override for staging one side
/// before the other's ready, not a required disambiguator like it used to
/// be. Has no effect (beyond a mismatch check) on a project that only has
/// one kind of marker to begin with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Role {
    Api,
    Web,
}

pub fn run(cwd: &Path, role: Option<Role>) -> io::Result<()> {
    let root = require_project_root(cwd);
    println!("project root: {}", root.display());

    let has_openapi = root.join(MANIFEST_FILE).is_file();
    let web_files = find_files_with_extensions(&root, WEB_ASSET_EXTENSIONS);
    let has_web = !web_files.is_empty();

    match (has_openapi, has_web) {
        (false, false) => {
            // Shouldn't be reachable — `require_project_root` already
            // guarantees at least one marker exists at `root` — but a clear
            // failure beats silently doing nothing if that invariant ever
            // breaks.
            eprintln!("error: no {MANIFEST_FILE} or web asset files found at {} — nothing to generate", root.display());
            std::process::exit(1);
        }
        (true, true) => match role {
            Some(Role::Api) => generate_api(&root),
            Some(Role::Web) => generate_web(&root, &web_files),
            // Both markers present and no override: generate both sides of
            // the project rather than forcing the user to pick, now that a
            // project can genuinely serve both at once (see `run_both` in
            // `commands::run`, Point 5).
            None => {
                generate_api(&root)?;
                generate_web(&root, &web_files)
            }
        },
        (true, false) => {
            if role == Some(Role::Web) {
                eprintln!("error: --role web was given, but no web asset files were found at {}", root.display());
                std::process::exit(1);
            }
            generate_api(&root)
        }
        (false, true) => {
            if role == Some(Role::Api) {
                eprintln!("error: --role api was given, but no {MANIFEST_FILE} was found at {}", root.display());
                std::process::exit(1);
            }
            generate_web(&root, &web_files)
        }
    }
}

fn generate_api(root: &Path) -> io::Result<()> {
    let api_root = crate::project::api_base(root);
    scaffold_config(&api_root)?;
    {
        let config = Config::load_or_exit(&api_root);
        println!(
            "loaded config — debugMode={}, {} connection(s), {} error code(s)",
            config.server.debug_mode,
            config.connections.len(),
            config.errors.len()
        );

        let doc = match crate::openapi::load(&root.join(MANIFEST_FILE)) {
            Ok(doc) => doc,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        };

        let (components, changed_components) = resolve_and_write_components(&api_root, &doc)?;
        if !components.is_empty() {
            let mut names: Vec<&String> = components.keys().collect();
            names.sort();
            println!(
                "resolved {} component(s) into datasources/components/: {}",
                names.len(),
                names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        if !changed_components.is_empty() {
            let mut names: Vec<&String> = changed_components.iter().collect();
            names.sort();
            println!(
                "component(s) changed since the last generate run: {}",
                names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ")
            );
        }

        println!("found {} operation(s) in {}:", doc.operations.len(), MANIFEST_FILE);
        for op in &doc.operations {
            println!("  {} {} -> {}", op.method.to_uppercase(), op.path, op.operation_id);
        }

        let restored = restore_orphaned_endpoints(&api_root, &doc)?;
        for (path, method) in &restored {
            println!(
                "  restoring {} {path} (was orphaned) — will run through the normal migration flow below",
                method.to_uppercase()
            );
        }

        let restored_set: HashSet<(String, String)> = restored.into_iter().collect();
        let summary = write_endpoint_files(&api_root, &doc, &components, &changed_components, &restored_set, config.server.auto_migrate_endpoints)?;
        println!(
            "endpoints: {} unchanged (skipped), {} newly generated, {} migrated, {} drifted but left alone \
             (autoMigrateEndpoints off)",
            summary.skipped, summary.created, summary.migrated, summary.drift_warned
        );

        let orphaned = mark_orphaned_endpoints(&api_root, &doc)?;
        for (path, method) in &orphaned {
            println!(
                "  {} {path} no longer in {MANIFEST_FILE} — prefixed with _ (never deleted; restores automatically \
                 if it comes back)",
                method.to_uppercase()
            );
        }

        let validation_errors = validate_success_statuses(&api_root, &doc);
        for error in &validation_errors {
            eprintln!("error: {error}");
        }
        if !validation_errors.is_empty() {
            eprintln!(
                "error: {} endpoint file(s) have an invalid successStatus — files were still written above, \
                 but this needs fixing by hand",
                validation_errors.len()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Writes every `api/`-rooted config file once, if it doesn't already exist
/// — never touched again afterward, same permanence rule as `webserve.json`.
/// `config/server.json` and `config/errors/core.json` get real, complete
/// defaults (nothing project-specific to invent — `core.json`'s codes are
/// ones frogs' own error classification produces regardless of project).
/// `config/connections.json` and `security/schemes.json` are written empty:
/// a real connection needs credentials and a real scheme needs verifier
/// logic only a human can supply, so there's nothing honest to scaffold
/// beyond "this file exists, here's where to add yours" — said in the
/// console output below rather than embedded in the JSON, which (unlike an
/// endpoint stub) has no natural place for a `_todo`-style marker without
/// changing the on-disk shape every existing project's `connections.json`
/// already uses.
fn scaffold_config(api_root: &Path) -> io::Result<()> {
    write_if_absent(
        &api_root.join("config/server.json"),
        &serde_json::to_string_pretty(&ServerConfig::default()).expect("always serializes"),
        "config/server.json",
    )?;
    write_if_absent(
        &api_root.join("config/errors/core.json"),
        &serde_json::to_string_pretty(&default_core_errors()).expect("always serializes"),
        "config/errors/core.json",
    )?;
    write_if_absent(
        &api_root.join("config/connections.json"),
        "{}",
        "config/connections.json (empty — add your SQL connections here)",
    )?;
    write_if_absent(
        &api_root.join("security/schemes.json"),
        "{}",
        "security/schemes.json (empty — add security schemes + verifiers here, or leave empty if this API needs none)",
    )?;
    Ok(())
}

fn write_if_absent(path: &Path, contents: &str, message: &str) -> io::Result<()> {
    if path.is_file() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    println!("wrote {message}");
    Ok(())
}

/// The error codes frogs' own classification logic (`endpoint::error`)
/// produces, mapped to a sensible HTTP status and exposure default — the
/// same boilerplate every project needs, so `generate` writes it in full
/// rather than leaving it for a human to look up and retype.
fn default_core_errors() -> Value {
    serde_json::json!({
        "datasource.sql.connection_failed":    { "httpStatus": 500, "exposeDetail": false },
        "datasource.sql.query_failed":         { "httpStatus": 500, "exposeDetail": false },
        "datasource.sql.constraint_violation": { "httpStatus": 409, "exposeDetail": true },
        "datasource.sql.not_found":            { "httpStatus": 404, "exposeDetail": true },
        "datasource.http.timeout":             { "httpStatus": 502, "exposeDetail": false },
        "datasource.http.not_found":           { "httpStatus": 404, "exposeDetail": true },
        "datasource.http.upstream_error":      { "httpStatus": 502, "exposeDetail": false },
        "auth.invalid_credentials":            { "httpStatus": 401, "exposeDetail": true },
        "auth.verifier_unavailable":           { "httpStatus": 500, "exposeDetail": false },
        "validation.missing_parameter":        { "httpStatus": 400, "exposeDetail": true },
        "validation.invalid_type":             { "httpStatus": 400, "exposeDetail": true },
        "unexpected.error": { "httpStatus": 500, "exposeDetail": false }
    })
}

/// Writes `webserve.json` once, if it doesn't already exist — never
/// overwritten afterward, same permanence rule as `connections.json` or a
/// hand-edited endpoint stub. `start_page` defaults to `index.html` if
/// present, else the first `.html` file found (alphabetically, for
/// determinism); `not_found_page` defaults to `404.html` if that exists,
/// else is left unset (a generic 404 is used at request time — Point 2).
fn generate_web(root: &Path, web_files: &[PathBuf]) -> io::Result<()> {
    let webserve_path = root.join("webserve.json");
    if webserve_path.is_file() {
        println!("webserve.json already exists at {} — left unchanged", webserve_path.display());
        return Ok(());
    }

    let mut names: Vec<String> = web_files
        .iter()
        .filter_map(|path| path.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .collect();
    names.sort();

    let Some(start_page) = names
        .iter()
        .find(|name| name.as_str() == "index.html")
        .or_else(|| names.iter().find(|name| name.ends_with(".html")))
        .cloned()
    else {
        // `has_web` only requires *some* web asset extension (html/js/css —
        // see `WEB_ASSET_EXTENSIONS`), so `.js`/`.css` alone (no `.html` at
        // all) can reach here when `--role web` was given explicitly
        // alongside an openapi.yaml. A static site needs a page to start
        // from, so this is a real, reportable error, not a silent default.
        eprintln!(
            "error: no .html file found at {} — a static-content project needs at least one to use as a start page",
            root.display()
        );
        std::process::exit(1);
    };

    let not_found_page = names.iter().find(|name| name.as_str() == "404.html").cloned();

    let config = crate::webserve::WebServeConfig {
        start_page,
        port: 8080,
        not_found_page,
        tls: Default::default(),
    };
    crate::webserve::save_to(&webserve_path, &config)?;

    println!(
        "found {} web asset file(s): {} — wrote webserve.json (startPage: {}, port: {}{})",
        names.len(),
        names.join(", "),
        config.start_page,
        config.port,
        config.not_found_page.as_ref().map(|p| format!(", notFoundPage: {p}")).unwrap_or_default()
    );
    Ok(())
}

/// Resolves every component (Phase 0 always fully re-resolves every run —
/// unavoidable, since it's the only way to know whether a component's
/// *resolved shape* changed, not just its raw spec text) and compares each
/// against the hash embedded in its existing cache file, if any. Returns
/// the fresh descriptor map (used as-is for endpoint resolution — no
/// `_hash` noise in the in-memory value) plus the set of component names
/// whose resolved shape changed since the last run.
fn resolve_and_write_components(root: &Path, doc: &OpenApiDocument) -> io::Result<(HashMap<String, Value>, HashSet<String>)> {
    let descriptors = doc.resolve_components();
    let dir = root.join("datasources/components");
    std::fs::create_dir_all(&dir)?;

    let mut changed = HashSet::new();
    for (name, descriptor) in &descriptors {
        let new_hash = content_hash(descriptor);
        let path = dir.join(format!("{name}.json"));

        let old_hash = read_json(&path).and_then(|value| value.get("_hash").and_then(Value::as_str).map(str::to_string));
        if old_hash.as_deref() != Some(new_hash.as_str()) {
            changed.insert(name.clone());
        }

        std::fs::write(&path, serde_json::to_string_pretty(&with_hash(&new_hash, descriptor)).expect("always serializes"))?;
    }

    Ok((descriptors, changed))
}

/// Wraps a descriptor with its `_hash`, merging into the top level when the
/// descriptor is itself an object (the common case) rather than nesting it
/// under a second key.
fn with_hash(hash: &str, descriptor: &Value) -> Value {
    match descriptor {
        Value::Object(fields) => {
            let mut wrapped = serde_json::Map::new();
            wrapped.insert("_hash".to_string(), Value::String(hash.to_string()));
            wrapped.extend(fields.clone());
            Value::Object(wrapped)
        }
        other => serde_json::json!({ "_hash": hash, "value": other }),
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Maps an OpenAPI path to its folder under `datasources/endpoints/` —
/// leading slash dropped, path-parameter braces (`{vin}`) kept literally as
/// written, per the design doc's file-naming decision. The root path `/`
/// (an empty relative path once the slash is stripped) maps to the
/// `endpoints/` folder itself, matching that same decision.
fn endpoint_dir(root: &Path, path: &str) -> PathBuf {
    root.join("datasources/endpoints").join(path.trim_start_matches('/'))
}

/// The reverse of `endpoint_dir`: given a folder under
/// `datasources/endpoints/`, what OpenAPI path does it represent. An empty
/// relative path (the `endpoints/` folder itself) maps back to `/`.
fn path_for_endpoint_dir(endpoints_root: &Path, dir: &Path) -> String {
    let relative = dir.strip_prefix(endpoints_root).unwrap_or(dir);
    if relative.as_os_str().is_empty() {
        return "/".to_string();
    }
    let segments: Vec<String> = relative.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    format!("/{}", segments.join("/"))
}

/// Finds every currently-*active* `endpoint.<method>.json` file under
/// `datasources/endpoints/` (skipping `_backups/` and anything already
/// underscore-prefixed), paired with the (path, method) it represents.
fn discover_active_endpoint_files(endpoints_root: &Path) -> Vec<(String, String, PathBuf)> {
    let mut found = Vec::new();
    walk_active_endpoint_files(endpoints_root, endpoints_root, &mut found);
    found
}

fn walk_active_endpoint_files(root: &Path, dir: &Path, out: &mut Vec<(String, String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("_backups") {
                continue;
            }
            walk_active_endpoint_files(root, &path, out);
        } else if let Some(method) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("endpoint."))
            .and_then(|n| n.strip_suffix(".json"))
        {
            // A real HTTP method (`get`, `post`, ...) never contains a dot —
            // this excludes `.reference.json` and `.test.json` siblings
            // (whose "method" segment would be `get.reference`/`get.test`
            // after stripping), which aren't stub files at all.
            if !method.contains('.') {
                out.push((path_for_endpoint_dir(root, dir), method.to_string(), path.clone()));
            }
        }
    }
}

/// If a previously-orphaned (`_`-prefixed) endpoint's path+method is back
/// in the current spec, strips the underscore from both its stub and
/// reference file. Deliberately does nothing else: the now-active stub
/// still carries its *old* hash-less state, so the normal
/// `write_endpoint_files` pass that runs right after this one will detect
/// it as drifted and run it through the ordinary backup-and-migrate flow —
/// exactly the design doc's "restoration is treated like an update, not a
/// fresh start."
fn restore_orphaned_endpoints(root: &Path, doc: &OpenApiDocument) -> io::Result<Vec<(String, String)>> {
    let mut restored = Vec::new();
    for op in &doc.operations {
        let dir = endpoint_dir(root, &op.path);
        let active_stub = dir.join(format!("endpoint.{}.json", op.method));
        let orphaned_stub = dir.join(format!("_endpoint.{}.json", op.method));
        if active_stub.is_file() || !orphaned_stub.is_file() {
            continue;
        }

        std::fs::rename(&orphaned_stub, &active_stub)?;
        let orphaned_reference = dir.join(format!("_endpoint.{}.reference.json", op.method));
        if orphaned_reference.is_file() {
            std::fs::rename(&orphaned_reference, dir.join(format!("endpoint.{}.reference.json", op.method)))?;
        }
        restored.push((op.path.clone(), op.method.clone()));
    }
    Ok(restored)
}

/// Prefixes any active endpoint file whose (path, method) no longer
/// matches an operation in the current spec with `_` — excluded from
/// routing from then on, but never deleted; `_backups/` history stays
/// exactly where it is.
fn mark_orphaned_endpoints(root: &Path, doc: &OpenApiDocument) -> io::Result<Vec<(String, String)>> {
    let endpoints_root = root.join("datasources/endpoints");
    let active: HashSet<(String, String)> = doc.operations.iter().map(|op| (op.path.clone(), op.method.clone())).collect();

    let mut orphaned = Vec::new();
    for (path, method, stub_path) in discover_active_endpoint_files(&endpoints_root) {
        if active.contains(&(path.clone(), method.clone())) {
            continue;
        }

        let dir = stub_path.parent().expect("a file always has a parent").to_path_buf();
        std::fs::rename(&stub_path, dir.join(format!("_endpoint.{method}.json")))?;

        let reference_path = dir.join(format!("endpoint.{method}.reference.json"));
        if reference_path.is_file() {
            std::fs::rename(&reference_path, dir.join(format!("_endpoint.{method}.reference.json")))?;
        }
        orphaned.push((path, method));
    }
    Ok(orphaned)
}

/// Checks every active endpoint file's `successStatus` (if it declares one
/// at all) against its operation's own declared response codes — run last,
/// against whatever's on disk after generation/migration/orphan-handling,
/// since it's validating the *user's* config, not producing it.
fn validate_success_statuses(root: &Path, doc: &OpenApiDocument) -> Vec<String> {
    let mut errors = Vec::new();
    for op in &doc.operations {
        let stub_path = endpoint_dir(root, &op.path).join(format!("endpoint.{}.json", op.method));
        let Some(endpoint_file) = read_json(&stub_path) else {
            continue;
        };
        if let Err(message) = op.validate_success_status(&endpoint_file) {
            errors.push(message);
        }
    }
    errors
}

fn build_reference_file(op: &Operation, hash: &str, response_descriptor: &Value) -> Value {
    serde_json::json!({
        "operationId": op.operation_id,
        "_hash": hash,
        "security": op.security,
        "request": op.request_sources(),
        "response": response_descriptor,
        "availableParameterSources": op.available_parameter_sources(),
    })
}

/// Only set here at *creation* time — an existing hand-edited stub's
/// `security` is never retroactively touched by a later `generate` run
/// even when it drifts from the spec (`write_endpoint_files` rewrites the
/// reference file whenever `security:` changes, but `migrate_stub` only
/// ever touches the stub's `response`, matching how it already leaves
/// `sources` alone). The reference file above is what stays authoritative
/// if the two ever disagree.
fn build_stub_file(op: &Operation, reference_file_name: &str, response_descriptor: &Value) -> Value {
    let mut stub = serde_json::json!({
        "operationId": op.operation_id,
        "_generated": true,
        "_todo": format!(
            "See {reference_file_name} for available request/response fields. \
             Fill in sources and map each response field to a source path."
        ),
        "sources": {},
        "response": stub_from_descriptor(response_descriptor),
    });
    if let Some(scheme) = &op.security {
        stub["security"] = Value::String(scheme.clone());
    }
    stub
}

#[derive(Debug, Default, PartialEq)]
struct GenerateSummary {
    /// Neither this endpoint's own schema nor any component it references
    /// changed since the last run — entirely untouched, no read or write.
    skipped: usize,
    /// No stub existed yet; both files written fresh.
    created: usize,
    /// A stub existed and drift was detected; backed up and structurally
    /// merged onto the new schema.
    migrated: usize,
    /// Drift was detected but `autoMigrateEndpoints` is off; only the
    /// reference file updated, the stub was left alone with a warning.
    drift_warned: usize,
}

/// Writes (or skips) every operation's reference and stub files, per the
/// design doc's hash-based drift detection: an endpoint is only touched at
/// all if its own response-schema hash changed, it references a component
/// that changed, or it was just restored from orphaned status — everything
/// else is left completely alone.
fn write_endpoint_files(
    root: &Path,
    doc: &OpenApiDocument,
    components: &HashMap<String, Value>,
    changed_components: &HashSet<String>,
    just_restored: &HashSet<(String, String)>,
    auto_migrate_endpoints: bool,
) -> io::Result<GenerateSummary> {
    let mut summary = GenerateSummary::default();

    for op in &doc.operations {
        let dir = endpoint_dir(root, &op.path);
        let reference_path = dir.join(format!("endpoint.{}.reference.json", op.method));
        let stub_path = dir.join(format!("endpoint.{}.json", op.method));

        let current_hash = op.response_schema_hash();
        let stored_reference = read_json(&reference_path);
        let stored_hash = stored_reference.as_ref().and_then(|v| v.get("_hash").and_then(Value::as_str).map(str::to_string));
        let stored_security = stored_reference.as_ref().and_then(|v| v.get("security").and_then(Value::as_str).map(str::to_string));
        let references_a_changed_component = op.referenced_components().iter().any(|name| changed_components.contains(name));
        // No stored hash at all (first-ever generation for this endpoint)
        // counts as drifted too — there's nothing to skip yet. A just-
        // restored endpoint is *always* treated as drifted too, even if its
        // schema happens to be byte-for-byte what it was before it was
        // orphaned — the design doc requires restoration to always take a
        // fresh backup and run through the migration flow, not just
        // whenever the hash-based check would have caught it anyway. A
        // changed `security:` counts too — otherwise an operation whose
        // response shape never changes would keep its reference file
        // silently stale forever, since nothing else here would ever
        // rewrite it (the always-carried-forward stub itself still isn't
        // touched by this — see `build_stub_file`/`migrate_stub`).
        let drifted = stored_hash.as_deref() != Some(current_hash.as_str())
            || references_a_changed_component
            || just_restored.contains(&(op.path.clone(), op.method.clone()))
            || stored_security != op.security;

        if !drifted && stub_path.is_file() && reference_path.is_file() {
            summary.skipped += 1;
            continue;
        }

        std::fs::create_dir_all(&dir)?;
        let response_descriptor = op.resolve_response(components).unwrap_or(Value::Null);
        let reference_file_name = format!("endpoint.{}.reference.json", op.method);

        let reference = build_reference_file(op, &current_hash, &response_descriptor);
        std::fs::write(&reference_path, serde_json::to_string_pretty(&reference).expect("always serializes"))?;

        if !stub_path.is_file() {
            let stub = build_stub_file(op, &reference_file_name, &response_descriptor);
            std::fs::write(&stub_path, serde_json::to_string_pretty(&stub).expect("always serializes"))?;
            summary.created += 1;
        } else if auto_migrate_endpoints {
            backup_stub(&dir, &op.method, &stub_path)?;
            migrate_stub(&stub_path, &response_descriptor)?;
            summary.migrated += 1;
        } else {
            eprintln!(
                "warning: {} has drifted from its updated schema but autoMigrateEndpoints is off — \
                 review it manually against {reference_file_name}",
                stub_path.display()
            );
            summary.drift_warned += 1;
        }
    }

    Ok(summary)
}

/// Copies the current stub into `_backups/` (inside the path's own folder,
/// alongside its other methods — never a shared directory) before
/// migration touches anything, so a bad automatic migration is always
/// trivially reversible by hand.
fn backup_stub(dir: &Path, method: &str, stub_path: &Path) -> io::Result<()> {
    let backups_dir = dir.join("_backups");
    std::fs::create_dir_all(&backups_dir)?;
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ");
    std::fs::copy(stub_path, backups_dir.join(format!("endpoint.{method}.{timestamp}.json")))?;
    Ok(())
}

/// Structurally merges the existing stub's `response` tree onto the fresh
/// one (see `merge_stub_response`); `operationId`/`_generated`/`_todo`/
/// `sources` are carried forward exactly as they were — migration never
/// touches `sources`, and doesn't invent or remove metadata fields the
/// endpoint file didn't already have.
fn migrate_stub(stub_path: &Path, response_descriptor: &Value) -> io::Result<()> {
    let mut stub = read_json(stub_path).unwrap_or_else(|| serde_json::json!({}));
    let fresh_response = stub_from_descriptor(response_descriptor);
    let old_response = stub.get("response").cloned().unwrap_or(Value::Null);
    let merged_response = merge_stub_response(&old_response, &fresh_response);

    if let Value::Object(fields) = &mut stub {
        fields.insert("response".to_string(), merged_response);
    }

    std::fs::write(stub_path, serde_json::to_string_pretty(&stub).expect("always serializes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_dir_strips_the_leading_slash_and_keeps_brace_segments_literal() {
        let root = Path::new("/proj");
        assert_eq!(endpoint_dir(root, "/cars"), root.join("datasources/endpoints/cars"));
        assert_eq!(endpoint_dir(root, "/cars/{vin}"), root.join("datasources/endpoints/cars/{vin}"));
    }

    #[test]
    fn endpoint_dir_maps_the_root_path_to_the_endpoints_folder_itself() {
        let root = Path::new("/proj");
        assert_eq!(endpoint_dir(root, "/"), root.join("datasources/endpoints"));
    }

    /// A per-process atomic counter, not just a nanosecond timestamp, is
    /// what actually guarantees uniqueness here: cargo runs these tests
    /// across many parallel threads, and a timestamp alone occasionally
    /// collided between two tests under load (Windows' effective clock
    /// resolution isn't always as fine as raw nanoseconds suggest) — two
    /// tests silently sharing one directory produced exactly the kind of
    /// flaky failure this was chasing down.
    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-generate-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Parses `yaml` through the real `openapi::load` (via a throwaway
    /// file) so these tests exercise the same code path `generate` does,
    /// not a hand-built shortcut.
    fn doc_from_yaml(yaml: &str) -> OpenApiDocument {
        let dir = temp_project();
        std::fs::write(dir.join("openapi.yaml"), yaml).unwrap();
        let doc = crate::openapi::load(&dir.join("openapi.yaml")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        doc
    }

    const PING_YAML: &str = "openapi: 3.0.3\n\
        info: { title: t, version: 0.1.0 }\n\
        paths:\n  \
          /ping:\n    \
            get:\n      \
              operationId: ping\n      \
              responses:\n        \
                '200':\n          \
                  description: ok\n          \
                  content:\n            \
                    application/json:\n              \
                      schema: { type: string }\n";

    #[test]
    fn writes_a_reference_and_stub_file_for_a_new_operation() {
        let root = temp_project();
        let doc = doc_from_yaml(PING_YAML);
        let components = HashMap::new();

        let summary = write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 1,
                migrated: 0,
                drift_warned: 0
            }
        );

        let dir = root.join("datasources/endpoints/ping");
        assert!(dir.join("endpoint.get.reference.json").is_file());
        let stub = read_json(&dir.join("endpoint.get.json")).unwrap();
        assert_eq!(stub["_generated"], true);
        assert_eq!(stub["operationId"], "ping");

        let _ = std::fs::remove_dir_all(&root);
    }

    const PROTECTED_PING_YAML: &str = "openapi: 3.0.3\n\
        info: { title: t, version: 0.1.0 }\n\
        paths:\n  \
          /ping:\n    \
            get:\n      \
              operationId: ping\n      \
              security:\n        \
                - apiKeyAuth: []\n      \
              responses:\n        \
                '200':\n          \
                  description: ok\n          \
                  content:\n            \
                    application/json:\n              \
                      schema: { type: string }\n";

    /// Proves Point 5's whole point end to end: a freshly generated stub
    /// for an operation with `security:` in the spec comes out of
    /// `write_endpoint_files` already carrying `"security": "apiKeyAuth"` —
    /// not something the user has to hand-add, unlike `sources`/`response`
    /// which are always left as a `_todo` stub for the user to fill in.
    #[test]
    fn a_protected_operation_gets_its_security_scheme_baked_into_the_new_stub() {
        let root = temp_project();
        let doc = doc_from_yaml(PROTECTED_PING_YAML);
        let components = HashMap::new();

        let summary = write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 1,
                migrated: 0,
                drift_warned: 0
            }
        );

        let dir = root.join("datasources/endpoints/ping");
        let stub = read_json(&dir.join("endpoint.get.json")).unwrap();
        assert_eq!(stub["security"], "apiKeyAuth");

        let reference = read_json(&dir.join("endpoint.get.reference.json")).unwrap();
        assert_eq!(reference["security"], "apiKeyAuth");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The mirror case: an operation with no `security:` at all in the spec
    /// gets a stub with no `security` key rather than `null` — so a plain
    /// public endpoint's hand-authored file stays exactly as clean as it
    /// was before this feature existed.
    #[test]
    fn an_unprotected_operation_gets_no_security_key_in_its_new_stub() {
        let root = temp_project();
        let doc = doc_from_yaml(PING_YAML);
        let components = HashMap::new();

        write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let stub = read_json(&root.join("datasources/endpoints/ping/endpoint.get.json")).unwrap();
        assert!(stub.get("security").is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An existing, already-migrated stub's `security` is never touched by
    /// a later run even if the spec's own `security:` for that operation
    /// changes — drift detection is entirely response-schema-based, and
    /// `security` isn't part of that hash, matching how `sources` is
    /// likewise left alone by migration. The reference file, which is
    /// always regenerated, is what actually stays in sync.
    #[test]
    fn an_existing_stubs_security_survives_a_response_schema_migration_untouched() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PROTECTED_PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc_v1, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(
            &stub_path,
            r#"{ "operationId": "ping", "security": "apiKeyAuth", "sources": {}, "response": "hand-edited" }"#,
        )
        .unwrap();

        // The response schema changes (string -> object), which does
        // trigger migration, but the spec's security scheme name doesn't.
        let changed_yaml = PROTECTED_PING_YAML.replace("schema: { type: string }", "schema: { type: object, properties: { value: { type: string } } }");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let summary = write_endpoint_files(&root, &doc_v2, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 1,
                drift_warned: 0
            }
        );

        let stub = read_json(&stub_path).unwrap();
        assert_eq!(stub["security"], "apiKeyAuth", "migration must not touch an existing stub's security field");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The fix for the gap the security-change drift signal above closes:
    /// without it, adding `security:` to an operation whose response shape
    /// never changes would leave its reference file silently stale forever,
    /// since nothing else would ever trigger a rewrite.
    #[test]
    fn a_security_only_change_still_refreshes_the_reference_file() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PING_YAML); // unprotected
        let components = HashMap::new();
        write_endpoint_files(&root, &doc_v1, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let reference_path = root.join("datasources/endpoints/ping/endpoint.get.reference.json");
        assert!(read_json(&reference_path).unwrap()["security"].is_null());

        // Same response schema as PING_YAML — only `security:` is new.
        let doc_v2 = doc_from_yaml(PROTECTED_PING_YAML);
        let summary = write_endpoint_files(&root, &doc_v2, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 1,
                drift_warned: 0
            }
        );

        assert_eq!(read_json(&reference_path).unwrap()["security"], "apiKeyAuth");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rerunning_with_no_schema_change_skips_the_endpoint_entirely() {
        let root = temp_project();
        let doc = doc_from_yaml(PING_YAML);
        let components = HashMap::new();

        write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        let modified_before = std::fs::metadata(&stub_path).unwrap().modified().unwrap();

        let summary = write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 1,
                created: 0,
                migrated: 0,
                drift_warned: 0
            }
        );
        assert_eq!(std::fs::metadata(&stub_path).unwrap().modified().unwrap(), modified_before);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_schema_change_backs_up_and_migrates_the_existing_stub() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc_v1, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(&stub_path, r#"{ "operationId": "ping", "sources": { "x": 1 }, "response": "sources.x.value" }"#).unwrap();

        // Response schema changes from a bare string to an object — the old
        // "sources.x.value" mapping is now incompatible and must be dropped.
        let changed_yaml = PING_YAML.replace("schema: { type: string }", "schema: { type: object, properties: { value: { type: string } } }");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let summary = write_endpoint_files(&root, &doc_v2, &components, &HashSet::new(), &HashSet::new(), true).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 1,
                drift_warned: 0
            }
        );

        let backups_dir = root.join("datasources/endpoints/ping/_backups");
        assert_eq!(std::fs::read_dir(&backups_dir).unwrap().count(), 1, "expected exactly one backup file");

        let migrated = read_json(&stub_path).unwrap();
        assert_eq!(migrated["sources"], serde_json::json!({ "x": 1 }), "sources must never be touched by migration");
        assert_eq!(migrated["response"], serde_json::json!({ "value": null }), "incompatible mapping must be dropped");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drift_with_auto_migrate_off_only_warns_and_leaves_the_stub_alone() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc_v1, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(&stub_path, r#"{ "operationId": "ping", "sources": {}, "response": "hand-edited" }"#).unwrap();

        let changed_yaml = PING_YAML.replace("type: string", "type: integer");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let summary = write_endpoint_files(&root, &doc_v2, &components, &HashSet::new(), &HashSet::new(), false).unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 0,
                drift_warned: 1
            }
        );

        let stub_contents = std::fs::read_to_string(&stub_path).unwrap();
        assert!(stub_contents.contains("hand-edited"), "autoMigrateEndpoints:false must leave the stub untouched");
        assert!(
            !root.join("datasources/endpoints/ping/_backups").exists(),
            "no backup should be made when migration doesn't run"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn path_for_endpoint_dir_is_the_reverse_of_endpoint_dir() {
        let root = Path::new("/proj");
        let endpoints_root = root.join("datasources/endpoints");
        for path in ["/cars", "/cars/{vin}", "/"] {
            let dir = endpoint_dir(root, path);
            assert_eq!(path_for_endpoint_dir(&endpoints_root, &dir), path);
        }
    }

    #[test]
    fn a_test_file_sibling_is_never_mistaken_for_an_orphaned_endpoint() {
        // Caught live against the real cars-demo fixture: `endpoint.get.
        // test.json` (the design doc's mock-test-file convention) has a
        // dotted "method" segment (`get.test`) once `endpoint.`/`.json` are
        // stripped, and was being flagged as an orphaned `get.test` method.
        let root = temp_project();
        let doc = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let dir = root.join("datasources/endpoints/ping");
        std::fs::write(dir.join("endpoint.get.test.json"), r#"{ "cases": [] }"#).unwrap();

        let orphaned = mark_orphaned_endpoints(&root, &doc).unwrap();
        assert!(orphaned.is_empty(), "a .test.json sibling must not be treated as its own endpoint file");
        assert!(dir.join("endpoint.get.test.json").is_file(), "the test file itself must be untouched");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_operation_removed_from_the_spec_gets_its_files_prefixed_not_deleted() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc_v1, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        // /ping no longer exists in the new spec.
        let doc_v2 = doc_from_yaml("openapi: 3.0.3\ninfo: { title: t, version: 0.1.0 }\npaths: {}\n");

        let orphaned = mark_orphaned_endpoints(&root, &doc_v2).unwrap();
        assert_eq!(orphaned, vec![("/ping".to_string(), "get".to_string())]);

        let dir = root.join("datasources/endpoints/ping");
        assert!(!dir.join("endpoint.get.json").exists(), "the active name must be gone");
        assert!(dir.join("_endpoint.get.json").is_file(), "content must survive under the _ name");
        assert!(dir.join("_endpoint.get.reference.json").is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_restored_operation_is_reactivated_and_then_migrated_not_treated_as_brand_new() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc_v1, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        // Hand-edit the stub before it gets orphaned, so we can prove the
        // mapping survives the whole orphan -> restore -> migrate round trip.
        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(&stub_path, r#"{ "operationId": "ping", "sources": { "x": 1 }, "response": "sources.x.value" }"#).unwrap();

        let empty_doc = doc_from_yaml("openapi: 3.0.3\ninfo: { title: t, version: 0.1.0 }\npaths: {}\n");
        mark_orphaned_endpoints(&root, &empty_doc).unwrap();
        assert!(!stub_path.exists());

        // /ping comes back, with a schema change (string -> object) at the
        // same time -- restoration must run through the same
        // backup-and-migrate flow as ordinary drift, not a fresh stub.
        let changed_yaml = PING_YAML.replace("schema: { type: string }", "schema: { type: object, properties: { value: { type: string } } }");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let restored = restore_orphaned_endpoints(&root, &doc_v2).unwrap();
        assert_eq!(restored, vec![("/ping".to_string(), "get".to_string())]);
        assert!(stub_path.is_file(), "the active name must be back");

        let restored_set: HashSet<(String, String)> = restored.into_iter().collect();
        let summary = write_endpoint_files(&root, &doc_v2, &components, &HashSet::new(), &restored_set, true).unwrap();
        assert_eq!(summary.migrated, 1, "restoration should be treated as drift, not first-time generation");

        let migrated = read_json(&stub_path).unwrap();
        assert_eq!(migrated["sources"], serde_json::json!({ "x": 1 }));
        assert_eq!(migrated["response"], serde_json::json!({ "value": null }), "incompatible mapping dropped");
        assert!(root.join("datasources/endpoints/ping/_backups").is_dir(), "restoration takes a fresh backup too");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restoration_forces_migration_even_with_no_schema_change_at_all() {
        // Caught live against a real fixture: if the schema is byte-for-byte
        // identical before and after the orphan period, hash-based drift
        // detection alone sees "nothing changed" and would otherwise skip
        // it -- but the design doc requires restoration to *always* take a
        // fresh backup and run through migration, regardless of whether the
        // schema itself moved.
        let root = temp_project();
        let doc = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(&root, &doc, &components, &HashSet::new(), &HashSet::new(), true).unwrap();

        let empty_doc = doc_from_yaml("openapi: 3.0.3\ninfo: { title: t, version: 0.1.0 }\npaths: {}\n");
        mark_orphaned_endpoints(&root, &empty_doc).unwrap();

        // Same `doc` as before -- nothing about /ping's schema changed.
        let restored = restore_orphaned_endpoints(&root, &doc).unwrap();
        let restored_set: HashSet<(String, String)> = restored.into_iter().collect();

        let summary = write_endpoint_files(&root, &doc, &components, &HashSet::new(), &restored_set, true).unwrap();
        assert_eq!(summary.migrated, 1, "restoration must force migration even when the hash didn't change");
        assert!(root.join("datasources/endpoints/ping/_backups").is_dir());

        let _ = std::fs::remove_dir_all(&root);
    }

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, "").unwrap();
        path
    }

    #[test]
    fn generate_web_prefers_index_html_as_the_start_page() {
        let root = temp_project();
        let files = vec![touch(&root, "about.html"), touch(&root, "index.html"), touch(&root, "style.css")];

        generate_web(&root, &files).unwrap();

        let config = crate::webserve::load(&root.join("webserve.json")).unwrap();
        assert_eq!(config.start_page, "index.html");
        assert_eq!(config.port, 8080);
        assert_eq!(config.not_found_page, None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn generate_web_falls_back_to_the_first_html_file_alphabetically_when_theres_no_index() {
        let root = temp_project();
        let files = vec![touch(&root, "zebra.html"), touch(&root, "about.html")];

        generate_web(&root, &files).unwrap();

        let config = crate::webserve::load(&root.join("webserve.json")).unwrap();
        assert_eq!(config.start_page, "about.html");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn generate_web_detects_a_404_html_as_the_not_found_page() {
        let root = temp_project();
        let files = vec![touch(&root, "index.html"), touch(&root, "404.html")];

        generate_web(&root, &files).unwrap();

        let config = crate::webserve::load(&root.join("webserve.json")).unwrap();
        assert_eq!(config.not_found_page, Some("404.html".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn generate_web_never_overwrites_an_existing_webserve_json() {
        let root = temp_project();
        let files = vec![touch(&root, "index.html")];
        std::fs::write(root.join("webserve.json"), r#"{ "startPage": "hand-edited.html", "port": 1234 }"#).unwrap();

        generate_web(&root, &files).unwrap();

        let config = crate::webserve::load(&root.join("webserve.json")).unwrap();
        assert_eq!(config.start_page, "hand-edited.html", "an existing webserve.json must be left untouched");
        assert_eq!(config.port, 1234);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end through `run` itself (not just `generate_web` directly),
    /// proving a project with only web asset files infers `Role::Web`
    /// without needing `--role` at all.
    #[test]
    fn run_infers_the_web_role_when_only_html_files_are_present() {
        let root = temp_project();
        touch(&root, "index.html");

        run(&root, None).unwrap();

        assert!(root.join("webserve.json").is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The core behavior change of Point 3: a project with both markers and
    /// no `--role` used to error, requiring the user to pick one. Now it
    /// generates both sides — a project can genuinely serve both at once
    /// (see `run_both` in `commands::run`, Point 5).
    #[test]
    fn run_generates_both_sides_when_both_markers_are_present_and_no_role_is_given() {
        let root = temp_project();
        std::fs::write(root.join(MANIFEST_FILE), PING_YAML).unwrap();
        touch(&root, "index.html");

        run(&root, None).unwrap();

        assert!(root.join("webserve.json").is_file(), "the web side must still be generated");
        assert!(root.join("api/config/server.json").is_file(), "the api side must still be generated");
        assert!(root.join("api/datasources/endpoints/ping/endpoint.get.json").is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_role_api_generates_only_the_api_side_even_when_both_markers_are_present() {
        let root = temp_project();
        std::fs::write(root.join(MANIFEST_FILE), PING_YAML).unwrap();
        touch(&root, "index.html");

        run(&root, Some(Role::Api)).unwrap();

        assert!(root.join("api/config/server.json").is_file());
        assert!(!root.join("webserve.json").is_file(), "--role api must not also generate the web side");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_role_web_generates_only_the_web_side_even_when_both_markers_are_present() {
        let root = temp_project();
        std::fs::write(root.join(MANIFEST_FILE), PING_YAML).unwrap();
        touch(&root, "index.html");

        run(&root, Some(Role::Web)).unwrap();

        assert!(root.join("webserve.json").is_file());
        assert!(!root.join("api").is_dir(), "--role web must not also generate the api side");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffold_config_writes_all_four_files_into_a_fresh_project() {
        let root = temp_project();
        let api_root = root.join("api");

        scaffold_config(&api_root).unwrap();

        assert!(api_root.join("config/server.json").is_file());
        assert!(api_root.join("config/errors/core.json").is_file());
        assert!(api_root.join("config/connections.json").is_file());
        assert!(api_root.join("security/schemes.json").is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffolded_server_json_round_trips_into_server_config_defaults() {
        let root = temp_project();
        let api_root = root.join("api");

        scaffold_config(&api_root).unwrap();

        let contents = std::fs::read_to_string(api_root.join("config/server.json")).unwrap();
        let config: ServerConfig = serde_json::from_str(&contents).unwrap();
        assert_eq!(config.api_root, "", "apiRoot must default to empty even in the scaffolded file");
        assert_eq!(config.port, 8080);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffolded_core_errors_load_through_the_real_error_registry() {
        let root = temp_project();
        let api_root = root.join("api");

        scaffold_config(&api_root).unwrap();

        let registry = crate::errors::ErrorRegistry::load(&api_root.join("config/errors")).unwrap();
        assert!(registry.get("datasource.sql.not_found").is_some());
        assert!(registry.get("auth.invalid_credentials").is_some());
        assert!(registry.get(crate::errors::UNEXPECTED_ERROR_CODE).is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffolded_connections_and_schemes_are_empty_but_valid() {
        let root = temp_project();
        let api_root = root.join("api");

        scaffold_config(&api_root).unwrap();

        let connections: HashMap<String, crate::config::ConnectionConfig> =
            serde_json::from_str(&std::fs::read_to_string(api_root.join("config/connections.json")).unwrap()).unwrap();
        assert!(connections.is_empty());

        let security = crate::security::SecurityConfig::load(&api_root.join("security")).unwrap();
        assert!(security.schemes.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffold_config_never_overwrites_existing_files() {
        let root = temp_project();
        let api_root = root.join("api");
        std::fs::create_dir_all(api_root.join("config")).unwrap();
        std::fs::write(api_root.join("config/server.json"), r#"{ "port": 1234 }"#).unwrap();

        scaffold_config(&api_root).unwrap();

        let contents = std::fs::read_to_string(api_root.join("config/server.json")).unwrap();
        let config: ServerConfig = serde_json::from_str(&contents).unwrap();
        assert_eq!(config.port, 1234, "an existing server.json must be left untouched");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end through `generate_api` itself, proving the scaffolding is
    /// actually wired into the real command, not just callable in isolation.
    #[test]
    fn generate_api_scaffolds_config_for_a_brand_new_project() {
        let root = temp_project();
        std::fs::write(root.join(MANIFEST_FILE), PING_YAML).unwrap();

        generate_api(&root).unwrap();

        assert!(root.join("api/config/server.json").is_file());
        assert!(root.join("api/config/errors/core.json").is_file());
        assert!(root.join("api/config/connections.json").is_file());
        assert!(root.join("api/security/schemes.json").is_file());

        let _ = std::fs::remove_dir_all(&root);
    }
}
