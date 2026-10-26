use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::EndpointSymlinks;
use crate::config::{Config, ServerConfig};
use crate::openapi::dir_index::{
    DirIndex, DirState, EndpointFsError, EntryKind, FileState, Lookup, check_file, check_file_with, copy_into_checked, create_dir_checked, create_dirs_checked,
    create_endpoint_dir, create_new_checked, create_new_file, fold, rename_checked_with, resolve_endpoint_dir, write_existing_file,
};
#[cfg(test)]
use crate::openapi::endpoint_tree::tree_for_tests;
use crate::openapi::endpoint_tree::{EndpointTree, LeafRule, LinkContext, LinkFindingKind, ProjectBoundary};
use crate::openapi::method_token::{self, MethodCase, TokenStatus};
use crate::openapi::path_rules::is_single_normal_component;
use crate::openapi::{
    LoadIssue, OpenApiDocument, Operation, ResponseMode, Severity, StreamSpec, content_hash, merge_stub_response, stub_from_descriptor, untrusted, walk_response_schema,
};
use crate::project::{MANIFEST_FILE, find_files_with_extensions, require_project_root};

#[cfg(test)]
fn test_ctx(root: &Path) -> LinkContext {
    LinkContext::new(root, EndpointSymlinks::Contained)
}

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
    let outcome = generate_api_inner(root)?;
    if outcome.strict_aborted || !outcome.errors.is_empty() {
        eprintln!("error: generate finished with {} problem(s) — see the messages above", outcome.errors.len().max(1));
        std::process::exit(1);
    }
    Ok(())
}

/// What `generate_api_inner` found wrong. Every entry was already printed
/// where it happened; `generate_api` only turns a non-empty outcome into the
/// process exit code.
#[derive(Debug, Default)]
pub(crate) struct GenerateOutcome {
    pub errors: Vec<String>,
    pub strict_aborted: bool,
}

pub(crate) fn print_issues(issues: &[LoadIssue]) {
    for issue in issues {
        match issue.severity {
            Severity::Warning => eprintln!("warning: {}", issue.message),
            Severity::Error => eprintln!("error: {}", issue.message),
        }
    }
}

pub(crate) fn generate_api_inner(root: &Path) -> io::Result<GenerateOutcome> {
    let api_root = crate::project::api_base(root);
    let mut outcome = GenerateOutcome::default();

    // Nothing is created, not even the scaffold, until every place generate
    // will write resolves inside the project — whatever `server.json` says.
    let boundary = ProjectBoundary::new(root);
    if let Err(e) = write_gate(&boundary, &api_root) {
        eprintln!("error: {e}");
        eprintln!("error: nothing was generated — fix the link or folder above and re-run");
        outcome.errors.push(e.to_string());
        return Ok(outcome);
    }
    scaffold_config(&boundary, &api_root)?;

    let config = Config::load_or_exit(&api_root);
    println!(
        "loaded config — debugMode={}, {} connection(s), {} error code(s), strictOpenApi={}, caseSensitiveMethods={}, endpointSymlinks={}",
        config.server.debug_mode,
        config.connections.len(),
        config.errors.len(),
        config.server.strict_open_api(),
        config.server.case_sensitive_methods(),
        config.server.endpoint_symlinks().as_str()
    );
    let ctx = LinkContext {
        boundary,
        policy: config.server.endpoint_symlinks(),
    };
    let endpoints_root = api_root.join("datasources/endpoints");

    let doc = match crate::openapi::load(&root.join(MANIFEST_FILE), config.server.openapi_load_options()) {
        Ok(doc) => doc,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };

    println!("found {} operation(s) in {}:", doc.operations.len(), MANIFEST_FILE);
    for op in &doc.operations {
        println!("  {} {} -> {}", op.http_method, op.path, op.operation_id);
    }
    print_issues(&doc.issues);

    let tree = EndpointTree::scan(&ctx, &endpoints_root);
    let plan = plan_endpoint_files(&api_root, &doc, &tree, &ctx);
    for error in &plan.errors {
        eprintln!("error: {}", error.message);
    }

    let links = link_report(&tree);
    for message in &links.errors {
        eprintln!("error: {message}");
    }
    for message in plan.invalid_tokens.iter().chain(&plan.wrong_mode).chain(&links.warnings) {
        eprintln!("warning: {message}");
    }

    let strict_findings = doc.issues.iter().filter(|i| i.kind.is_strict_error()).count()
        + plan.errors.iter().filter(|e| e.strict).count()
        + plan.invalid_tokens.len()
        + plan.wrong_mode.len()
        + links.errors.len()
        + links.warnings.len();
    if strict_findings > 0 {
        if config.server.strict_open_api() {
            eprintln!(
                "error: {strict_findings} openapi.yaml issue(s) found and \"strictOpenApi\" is true — nothing was generated; fix them (or set it to false) and re-run"
            );
            outcome.strict_aborted = true;
            outcome.errors.push(format!("{strict_findings} strict openapi issue(s)"));
            return Ok(outcome);
        }
        println!("note: {strict_findings} issue(s) would be errors with \"strictOpenApi\": true");
    }
    outcome
        .errors
        .extend(doc.issues.iter().filter(|i| i.severity == Severity::Error).map(|i| i.message.clone()));
    outcome.errors.extend(plan.errors.iter().map(|e| e.message.clone()));
    outcome.errors.extend(links.errors);

    let mut file_errors = Vec::new();
    let (components, changed_components) = resolve_and_write_components(&ctx.boundary, &api_root, &doc, &mut file_errors)?;
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

    let restored = restore_orphaned_endpoints(&ctx, &api_root, &doc, &plan.skip, &mut file_errors)?;
    for (path, method) in &restored {
        println!(
            "  restoring {} {} (was orphaned) — will run through the normal migration flow below",
            crate::openapi::method_token::display_token(method),
            untrusted(path)
        );
    }

    let restored_set: HashSet<(String, String)> = restored.into_iter().collect();
    let summary = write_endpoint_files(
        &ctx,
        &api_root,
        &doc,
        &components,
        &changed_components,
        &restored_set,
        config.server.auto_migrate_endpoints,
        &plan.skip,
        &mut file_errors,
    )?;
    println!(
        "endpoints: {} unchanged (skipped), {} newly generated, {} migrated, {} drifted but left alone \
         (autoMigrateEndpoints off)",
        summary.skipped, summary.created, summary.migrated, summary.drift_warned
    );
    if summary.references_refreshed > 0 {
        println!(
            "  {} reference file(s) refreshed (request parameters changed; stubs untouched)",
            summary.references_refreshed
        );
    }

    // What the write phase just created or renamed is on disk now; the orphan pass and the final checks read the fresh state.
    let tree = EndpointTree::scan(&ctx, &endpoints_root);
    let orphaned = mark_orphaned_endpoints(&ctx, &tree, &doc, &plan.rejected_paths, &plan.protected_files, &mut file_errors)?;
    for (path, method) in &orphaned {
        println!(
            "  {} {} no longer in {MANIFEST_FILE} — prefixed with _ (never deleted; restores automatically \
             if it comes back)",
            crate::openapi::method_token::display_token(method),
            untrusted(path)
        );
    }

    for hint in mutual_tls_hints(&doc, &config.security) {
        println!("{hint}");
    }

    for error in &file_errors {
        eprintln!("error: {error}");
    }
    outcome.errors.extend(file_errors);

    let validation_errors = validate_success_statuses(&tree, &doc);
    for error in &validation_errors {
        eprintln!("error: {error}");
    }
    if !validation_errors.is_empty() {
        eprintln!(
            "error: {} endpoint file(s) have an invalid successStatus — files were still written above, \
             but this needs fixing by hand",
            validation_errors.len()
        );
        outcome.errors.extend(validation_errors);
    }

    use crate::endpoint::route_plan::{RootExtras, RouteContext, RoutePlan};
    let strict = config.server.strict_open_api();
    let method_case = crate::openapi::method_token::MethodCase::from_case_sensitive(config.server.case_sensitive_methods());
    let route_ctx = RouteContext::for_server(&config.server).with_extras(RootExtras {
        web: root.join("webserve.json").is_file(),
        control_plane: false,
    });
    let route_plan = RoutePlan::build(&tree, method_case, &route_ctx);
    for problem in route_plan.warnings(strict) {
        eprintln!("warning: {}", problem.message());
    }
    for problem in route_plan.refusals(strict) {
        eprintln!("error: {}", problem.message());
        outcome.errors.push(problem.message().to_string());
    }
    let with_control_plane = RoutePlan::build(
        &tree,
        method_case,
        &route_ctx.clone().with_extras(RootExtras {
            web: route_ctx.extras.web,
            control_plane: true,
        }),
    );
    for problem in with_control_plane.refusals(strict) {
        if !route_plan.problems.contains(problem) {
            let message = format!("{} (frogs test would refuse to start)", problem.message());
            eprintln!("error: {message}");
            outcome.errors.push(message);
        }
    }

    let security = crate::endpoint::security_check_with_routes(&tree, &doc, &route_plan);
    let mut security_errors: Vec<String> = Vec::new();
    security_errors.extend(security.mismatches.iter().map(|m| m.message()));
    security_errors.extend(security.ambiguous.iter().map(|m| m.message()));
    security_errors.extend(security.stale_variants.iter().map(|m| m.message()));
    security_errors.extend(security.template_instances.iter().map(|m| m.message()));
    security_errors.extend(security.shadowed.iter().map(|m| m.message()));
    security_errors.extend(security.unverifiable.iter().map(|m| m.message()));
    security_errors.extend(security.builtin_refusals.iter().map(|m| m.message()));
    let known_builtin_refusals: std::collections::HashSet<String> = security.builtin_refusals.iter().map(|m| m.message()).collect();
    for message in crate::endpoint::security_check_with_routes(&tree, &doc, &with_control_plane)
        .builtin_refusals
        .iter()
        .map(|m| m.message())
        .filter(|m| !known_builtin_refusals.contains(m))
    {
        security_errors.push(format!("{message} (frogs test would refuse to start)"));
    }
    for message in security_errors {
        eprintln!("error: {message}");
        outcome.errors.push(message);
    }
    for message in &security.builtin_warnings {
        eprintln!("warning: {message}");
    }
    for file in &security.unmatched {
        let message = crate::endpoint::unmatched_security_message(file);
        if strict {
            eprintln!("error: {message} (\"strictOpenApi\" is true)");
            outcome.errors.push(message);
        } else {
            eprintln!("warning: {message}");
        }
    }
    if !security.mismatches.is_empty() || !security.unmatched.is_empty() {
        println!("note: generate never changes an existing endpoint file's \"security\" — edit it by hand");
    }

    Ok(outcome)
}

/// For each `mutualTLS` security scheme an operation uses that
/// `security/schemes.json` doesn't define yet, a ready-to-paste example.
/// Printed only — `generate` never writes `schemes.json` or a verifier file
/// (what a client certificate should be authorized *for* is a decision for
/// the project, not something to invent).
fn mutual_tls_hints(doc: &crate::openapi::OpenApiDocument, security: &crate::security::SecurityConfig) -> Vec<String> {
    let mut names: Vec<&String> = doc
        .operations
        .iter()
        .filter_map(|op| op.security.as_ref())
        .filter(|name| doc.security_scheme_types.get(*name).map(String::as_str) == Some("mutualTLS") && !security.schemes.contains_key(*name))
        .collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| {
            format!(
                "note: security scheme '{name}' is a mutualTLS scheme but security/schemes.json has no entry for it — nothing has been written. To enable it:\n\
                 \n\
                 \x20\x20security/schemes.json:\n\
                 \x20\x20\x20\x20\"{name}\": {{ \"verifier\": \"{name}.json\" }}\n\
                 \n\
                 \x20\x20security/verifiers/{name}.json (authorize one SAN; or use a sql/http verifier with a \"cert.fingerprint\" parameter for an allowlist):\n\
                 \x20\x20\x20\x20{{ \"type\": \"mtls\", \"validIf\": \"cert.san.dns = client.example.com\" }}\n\
                 \n\
                 \x20\x20config/server.json (the listener must request client certificates):\n\
                 \x20\x20\x20\x20\"tls\": {{ \"mode\": \"manual\", \"manual\": {{ ... }}, \"clientAuth\": {{ \"mode\": \"optional\", \"caPath\": \"security/client-ca.pem\" }} }}"
            )
        })
        .collect()
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
fn scaffold_config(boundary: &ProjectBoundary, api_root: &Path) -> io::Result<()> {
    write_if_absent(
        boundary,
        &api_root.join("config/server.json"),
        &serde_json::to_string_pretty(&ServerConfig::default()).expect("always serializes"),
        "config/server.json",
    )?;
    write_if_absent(
        boundary,
        &api_root.join("config/errors/core.json"),
        &serde_json::to_string_pretty(&default_core_errors()).expect("always serializes"),
        "config/errors/core.json",
    )?;
    write_if_absent(
        boundary,
        &api_root.join("config/connections.json"),
        "{}",
        "config/connections.json (empty — add your SQL connections here)",
    )?;
    write_if_absent(
        boundary,
        &api_root.join("security/schemes.json"),
        "{}",
        "security/schemes.json (empty — add security schemes + verifiers here, or leave empty if this API needs none)",
    )?;
    Ok(())
}

/// Every scaffold file, relative to `api/`.
const SCAFFOLD_FILES: [&str; 4] = ["config/server.json", "config/errors/core.json", "config/connections.json", "security/schemes.json"];

/// Read-only: confirms every folder and file `generate` is about to write
/// resolves inside the project (a dangling link counts as outside), so a
/// planted link can't redirect the scaffold, the endpoint folders or the
/// component cache. `frogs validate` reports the same failure.
pub(crate) fn write_gate(boundary: &ProjectBoundary, api_root: &Path) -> Result<(), EndpointFsError> {
    boundary.check_write_target(api_root, LeafRule::Dir)?;
    for dir in ["config", "config/errors", "security", "datasources/endpoints", "datasources/components"] {
        boundary.check_write_target(&api_root.join(dir), LeafRule::Dir)?;
    }
    for file in SCAFFOLD_FILES {
        boundary.check_write_target(&api_root.join(file), LeafRule::NoLink)?;
    }
    Ok(())
}

fn write_if_absent(boundary: &ProjectBoundary, path: &Path, contents: &str, message: &str) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(EndpointFsError::Symlink { at: path.to_path_buf() }.into()),
        Ok(meta) if meta.is_file() => return Ok(()),
        Ok(_) => return Err(EndpointFsError::NotARegularFile { at: path.to_path_buf() }.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        create_dirs_checked(boundary, parent)?;
    }
    let name = path.file_name().and_then(|n| n.to_str()).expect("scaffold paths always end in a file name");
    create_new_checked(boundary, path.parent().expect("a file always has a parent"), name, contents.as_bytes())?;
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
        "auth.client_cert_missing":            { "httpStatus": 401, "exposeDetail": true },
        "auth.client_cert_expired":            { "httpStatus": 401, "exposeDetail": true },
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
        .filter(|name| match crate::webserve::lexically_denied(root, name) {
            Some(reason) => {
                println!(
                    "note: {} is never served by frogs run ({}) — not considered for startPage/notFoundPage",
                    name,
                    reason.as_str()
                );
                false
            }
            None => true,
        })
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
/// whose resolved shape changed since the last run. A component whose name
/// can't safely be a file name, or whose cache file can't safely be written,
/// is never written and always counts as changed.
fn resolve_and_write_components(
    boundary: &ProjectBoundary,
    root: &Path,
    doc: &OpenApiDocument,
    errors: &mut Vec<String>,
) -> io::Result<(HashMap<String, Value>, HashSet<String>)> {
    let descriptors = doc.resolve_components();
    let dir = root.join("datasources/components");

    let dir_usable = match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            errors.push(format!(
                "{} is a symbolic link or junction — refusing to write component files through it",
                dir.display()
            ));
            false
        }
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            create_dirs_checked(boundary, &dir)?;
            true
        }
        Err(e) => return Err(e),
    };

    let mut changed = HashSet::new();
    for (name, descriptor) in &descriptors {
        if !dir_usable || doc.unwritable_components.contains(name) {
            changed.insert(name.clone());
            continue;
        }
        let new_hash = content_hash(descriptor);
        let file_name = format!("{name}.json");
        let path = dir.join(&file_name);

        // Component names are allowed to differ only by case (a non-goal to
        // police), so a case variant is treated as "absent" here rather than
        // the conflict `check_file` would report; `create_new` still refuses
        // to clobber it on a case-insensitive filesystem.
        let existing = match DirIndex::read(&dir)?.lookup(&file_name) {
            Lookup::Exact(EntryKind::File) => true,
            Lookup::Exact(EntryKind::Symlink) => {
                errors.push(format!("{} is a symbolic link or junction — refusing to follow it", path.display()));
                changed.insert(name.clone());
                continue;
            }
            Lookup::Exact(_) => {
                errors.push(format!("{} exists but is not a regular file", path.display()));
                changed.insert(name.clone());
                continue;
            }
            Lookup::CaseConflict { .. } | Lookup::Absent => false,
        };

        let old_hash = if existing {
            read_json(&path).and_then(|value| value.get("_hash").and_then(Value::as_str).map(str::to_string))
        } else {
            None
        };
        if old_hash.as_deref() != Some(new_hash.as_str()) {
            changed.insert(name.clone());
        }

        let contents = serde_json::to_string_pretty(&with_hash(&new_hash, descriptor)).expect("always serializes");
        let written = if existing {
            write_existing_file(boundary, &dir, &file_name, contents.as_bytes())
        } else {
            create_new_checked(boundary, &dir, &file_name, contents.as_bytes())
        };
        match written {
            Ok(()) => {}
            Err(EndpointFsError::AlreadyExists { .. }) if !existing => {
                errors.push(format!("{} already exists in a different letter case — refusing to overwrite it", path.display()));
                changed.insert(name.clone());
            }
            Err(e) if e.is_strict_error() => {
                errors.push(format!("{}: {e}", path.display()));
                changed.insert(name.clone());
            }
            Err(e) => return Err(e.into()),
        }
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

/// The path segments of an OpenAPI path, re-validated at the point of use
/// (the loader checks them too, but `generate` never trusts that alone):
/// `/` is zero segments, the leading slash is dropped, and braces stay
/// literal per the design doc's file-naming decision.
fn endpoint_segments(path: &str) -> Result<Vec<&str>, EndpointFsError> {
    if path == "/" {
        return Ok(Vec::new());
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    for seg in &segments {
        let bad = seg.is_empty()
            || *seg == "."
            || *seg == ".."
            || seg.contains('\\')
            || seg.contains('\0')
            || seg.chars().any(char::is_control)
            || !is_single_normal_component(seg);
        if bad {
            return Err(EndpointFsError::Containment(format!(
                "path '{}' has a segment that is not a plain folder name",
                untrusted(path)
            )));
        }
    }
    Ok(segments)
}

/// Maps an OpenAPI path to its folder under `endpoints_root` without
/// creating anything, refusing symlinks and case-variant folders on the way.
fn endpoint_dir(ctx: &LinkContext, endpoints_root: &Path, path: &str) -> Result<DirState, EndpointFsError> {
    let segments = endpoint_segments(path)?;
    let state = resolve_endpoint_dir(ctx, endpoints_root, &segments)?;
    if !state.path().starts_with(endpoints_root) {
        return Err(EndpointFsError::Containment(format!(
            "path '{}' resolves outside the endpoints folder",
            untrusted(path)
        )));
    }
    Ok(state)
}

fn create_endpoint_dir_for(ctx: &LinkContext, endpoints_root: &Path, path: &str) -> Result<PathBuf, EndpointFsError> {
    let segments = endpoint_segments(path)?;
    let dir = create_endpoint_dir(ctx, endpoints_root, &segments)?;
    if !dir.starts_with(endpoints_root) {
        return Err(EndpointFsError::Containment(format!(
            "path '{}' resolves outside the endpoints folder",
            untrusted(path)
        )));
    }
    Ok(dir)
}

/// The reverse of `endpoint_dir`: given a folder under
/// `datasources/endpoints/`, what OpenAPI path does it represent. An empty
/// relative path (the `endpoints/` folder itself) maps back to `/`.
#[cfg(test)]
fn path_for_endpoint_dir(endpoints_root: &Path, dir: &Path) -> String {
    let relative = dir.strip_prefix(endpoints_root).unwrap_or(dir);
    if relative.as_os_str().is_empty() {
        return "/".to_string();
    }
    let segments: Vec<String> = relative.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    format!("/{}", segments.join("/"))
}

/// One thing the read-only preflight found wrong; `strict` ones are what
/// `strictOpenApi` turns into a refusal.
#[derive(Debug, Clone)]
pub(crate) struct PlanError {
    pub strict: bool,
    pub message: String,
}

/// What `plan_endpoint_files` decided: which problems exist, and which
/// operations/paths the write phase must leave alone because of them.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub errors: Vec<PlanError>,
    pub skip: HashSet<(String, String)>,
    pub rejected_paths: BTreeSet<String>,
    /// Stub names that are not a canonical method token (`endpoint.GET.json`,
    /// `endpoint.purge.json`): never routed or renamed. A warning, and a problem
    /// only under `strictOpenApi`.
    pub invalid_tokens: Vec<String>,
    /// Stub files valid only under the other `caseSensitiveMethods` setting
    /// that no spec operation competes for: left alone, always a `validate` problem.
    pub wrong_mode: Vec<String>,
    /// `(folded path, token)` of files `generate` must never orphan: case-only
    /// mismatches with a spec operation, and methods the loader set aside.
    pub protected_files: HashSet<(String, String)>,
}

/// A read-only pass over everything `generate` would write to: finds case
/// conflicts, symlinks, containment failures and folder-claim collisions
/// before a single byte is written, so `strictOpenApi` can refuse cleanly
/// and `validate` can report the same problems without writing.
/// What the endpoint tree's link findings amount to: under `refuse` every
/// refusal is an error (as it always was), every other finding a warning —
/// all of them strict-class.
#[derive(Debug, Default)]
pub(crate) struct LinkReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub(crate) fn link_report(tree: &EndpointTree) -> LinkReport {
    let mut report = LinkReport::default();
    for finding in tree.findings() {
        let message = finding.message(tree.policy());
        if tree.policy() == EndpointSymlinks::Refuse && finding.kind == LinkFindingKind::Refused {
            report.errors.push(message);
        } else {
            report.warnings.push(message);
        }
    }
    report
}

pub(crate) fn plan_endpoint_files(api_root: &Path, doc: &OpenApiDocument, tree: &EndpointTree, ctx: &LinkContext) -> Plan {
    let endpoints_root = api_root.join("datasources/endpoints");
    let mut plan = Plan::default();
    let mut claimed: HashMap<String, String> = HashMap::new();
    let mut physical_claimed: HashMap<String, String> = HashMap::new();
    let mut handled: HashSet<&str> = HashSet::new();

    let mode = doc.method_case;
    let findings = crate::endpoint::method_file_findings(tree, mode);
    plan.invalid_tokens = findings
        .iter()
        .filter(|f| matches!(f.kind, crate::endpoint::MethodFileKind::NonCanonical { .. }))
        .map(|f| f.message(mode))
        .collect();
    let mut mismatch_files: HashSet<PathBuf> = HashSet::new();

    for (path, token) in doc.ambiguous_methods.keys() {
        plan.skip.insert((path.clone(), token.clone()));
        plan.protected_files.insert((fold(path), token.clone()));
    }
    // Only orphan protection: a genuine fixed operation with the same token is still written.
    for (path, token) in &doc.protected_methods {
        plan.protected_files.insert((fold(path), token.clone()));
    }

    // Two spec paths that reach one physical folder (one through a link) claim
    // it in this order: paths with no link on the way first, then the rest,
    // each in spec order — so a real folder always beats a link to it.
    let mut distinct_paths: Vec<&str> = Vec::new();
    for op in &doc.operations {
        if !distinct_paths.contains(&op.path.as_str()) {
            distinct_paths.push(op.path.as_str());
        }
    }
    let is_linked = |path: &str| match endpoint_segments(path) {
        Ok(segments) => {
            let mut full = endpoints_root.clone();
            full.extend(&segments);
            ctx.boundary.path_has_link(&full)
        }
        Err(_) => false,
    };
    let (linked_paths, plain_paths): (Vec<&str>, Vec<&str>) = distinct_paths.into_iter().partition(|path| is_linked(path));

    for path in plain_paths.into_iter().chain(linked_paths) {
        if !handled.insert(path) {
            continue;
        }
        let ops_here: Vec<&Operation> = doc.operations.iter().filter(|o| o.path == path).collect();
        let reject = |plan: &mut Plan, strict: bool, message: String| {
            plan.errors.push(PlanError { strict, message });
            plan.rejected_paths.insert(path.to_string());
            for o in &ops_here {
                plan.skip.insert((o.path.clone(), o.method.clone()));
            }
        };

        let segments = match endpoint_segments(path) {
            Ok(segments) => segments,
            Err(e) => {
                reject(&mut plan, e.is_strict_error(), format!("{} {}: {e}", describe_ops(&ops_here), untrusted(path)));
                continue;
            }
        };
        let key = fold(&segments.join("/"));
        if let Some(first) = claimed.get(&key) {
            if first != path {
                reject(
                    &mut plan,
                    true,
                    format!(
                        "path '{}' would share a folder with '{}' (they differ only by letter case) — skipped, its files are left alone",
                        untrusted(path),
                        untrusted(first)
                    ),
                );
                continue;
            }
        } else {
            claimed.insert(key, path.to_string());
        }

        let state = match endpoint_dir(ctx, &endpoints_root, path) {
            Ok(state) => state,
            Err(e) => {
                reject(&mut plan, e.is_strict_error(), format!("{} {}: {e}", describe_ops(&ops_here), untrusted(path)));
                continue;
            }
        };
        if let Some(key) = physical_claim_key(&state) {
            match physical_claimed.get(&key) {
                Some(first) if first != path => {
                    reject(
                        &mut plan,
                        true,
                        format!(
                            "path '{}' resolves to the same folder as '{}' (through a link) — skipped, its files are left alone",
                            untrusted(path),
                            untrusted(first)
                        ),
                    );
                    continue;
                }
                Some(_) => {}
                None => {
                    physical_claimed.insert(key, path.to_string());
                }
            }
        }
        let DirState::Exists(dir) = state else { continue };

        match DirIndex::read(&dir).map(|index| index.lookup("_backups")) {
            Ok(Lookup::Exact(EntryKind::Dir)) | Ok(Lookup::Absent) => {}
            Ok(Lookup::Exact(EntryKind::Symlink)) => reject(
                &mut plan,
                true,
                format!("{}: {}", untrusted(path), EndpointFsError::Symlink { at: dir.join("_backups") }),
            ),
            Ok(Lookup::Exact(_)) => reject(
                &mut plan,
                false,
                format!("{}: {}", untrusted(path), EndpointFsError::NotADirectory { at: dir.join("_backups") }),
            ),
            Ok(Lookup::CaseConflict { found }) => reject(
                &mut plan,
                true,
                format!(
                    "{}: {}",
                    untrusted(path),
                    EndpointFsError::CaseConflict {
                        wanted: "_backups".to_string(),
                        found: found.to_string_lossy().into_owned(),
                        at: dir.clone()
                    }
                ),
            ),
            Err(e) => reject(&mut plan, false, format!("{}: {e}", untrusted(path))),
        }
        if plan.rejected_paths.contains(path) {
            continue;
        }

        case_mismatch_pass(&dir, path, &ops_here, mode, &mut plan, &mut mismatch_files);

        for op in ops_here {
            let names = [
                format!("endpoint.{}.json", op.method),
                format!("endpoint.{}.reference.json", op.method),
                format!("_endpoint.{}.json", op.method),
                format!("_endpoint.{}.reference.json", op.method),
            ];
            for (position, name) in names.iter().enumerate() {
                // The stub names (0 and 2) may be links the read policy accepts; the reference files never.
                let checked = if position % 2 == 0 {
                    check_file_with(ctx, &dir, name)
                } else {
                    check_file(&dir, name)
                };
                if let Err(e) = checked {
                    plan.errors.push(PlanError {
                        strict: e.is_strict_error(),
                        message: format!("{} {}: {e}", op.http_method, untrusted(&op.path)),
                    });
                    plan.skip.insert((op.path.clone(), op.method.clone()));
                    break;
                }
            }
        }
    }
    plan.wrong_mode = findings
        .iter()
        .filter(|f| matches!(f.kind, crate::endpoint::MethodFileKind::WrongMode { .. }) && !mismatch_files.contains(&f.file))
        .map(|f| f.message(mode))
        .collect();
    plan
}

/// Identifies the physical folder a spec path lands in: the canonical form of
/// its deepest existing ancestor plus the (case-folded) names still to be
/// created. `None` when nothing can be resolved, which simply opts the path
/// out of the physical claim.
fn physical_claim_key(state: &DirState) -> Option<String> {
    let mut existing = state.path().to_path_buf();
    let mut remaining: Vec<String> = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        remaining.push(fold(&existing.file_name()?.to_string_lossy()));
        existing = existing.parent()?.to_path_buf();
    }
    remaining.reverse();
    Some(format!("{}\u{0}{}", std::fs::canonicalize(&existing).ok()?.display(), remaining.join("/")))
}

/// Compares, for one spec path, the operations in the spec with the stub files on
/// disk without regard to method case. A spec operation with no file of its own
/// whose method matches an unclaimed file only by case is a mismatch: nothing is
/// written, orphaned or renamed for it, and generate reports it as a strict error.
fn case_mismatch_pass(dir: &Path, path: &str, ops: &[&Operation], mode: MethodCase, plan: &mut Plan, mismatch_files: &mut HashSet<PathBuf>) {
    let Ok(index) = DirIndex::read(dir) else { return };
    struct OnDisk {
        file_name: String,
        token: String,
        wire: String,
        served: bool,
    }
    let mut files: Vec<OnDisk> = Vec::new();
    let mut names: HashSet<&str> = HashSet::new();
    for (name, kind) in index.entries() {
        if kind != EntryKind::File {
            continue;
        }
        names.insert(name);
        let Some(token) = method_token::stub_file_token(name) else { continue };
        match method_token::parse_file_token(token, mode) {
            TokenStatus::Valid(t) => files.push(OnDisk {
                file_name: name.to_string(),
                token: token.to_string(),
                wire: t.wire().into_owned(),
                served: true,
            }),
            TokenStatus::WrongMode { wire } => files.push(OnDisk {
                file_name: name.to_string(),
                token: token.to_string(),
                wire,
                served: false,
            }),
            TokenStatus::Invalid => {}
        }
    }
    let claimed = |file: &OnDisk| ops.iter().any(|o| o.method == file.token);
    for op in ops {
        if names.contains(format!("endpoint.{}.json", op.method).as_str()) {
            continue;
        }
        let candidates: Vec<&OnDisk> = files
            .iter()
            .filter(|f| !claimed(f) && f.wire.eq_ignore_ascii_case(&op.http_method) && f.wire != op.http_method)
            .collect();
        if candidates.is_empty() {
            continue;
        }
        let listed = candidates
            .iter()
            .map(|f| format!("{} (method '{}')", untrusted(&f.file_name), untrusted(&f.wire)))
            .collect::<Vec<_>>()
            .join(", ");
        let head = format!(
            "{listed} vs openapi.yaml's '{}' on {} under caseSensitiveMethods={}",
            untrusted(&op.http_method),
            untrusted(path),
            mode.case_sensitive()
        );
        let still_served: Vec<&&OnDisk> = candidates.iter().filter(|f| f.served).collect();
        let message = if still_served.is_empty() {
            format!("{head} — rename the file to endpoint.{}.json by hand to keep your mappings", op.method)
        } else {
            let old = still_served.iter().map(|f| untrusted(&f.wire)).collect::<Vec<_>>().join("/");
            format!(
                "{head} — the OLD route {old} {} is STILL BEING SERVED by `frogs run` from this file until you rename it; requests sending '{}' get 405. Rename it to endpoint.{}.json by hand to move your mappings.",
                untrusted(path),
                untrusted(&op.http_method),
                op.method
            )
        };
        plan.errors.push(PlanError { strict: true, message });
        plan.skip.insert((op.path.clone(), op.method.clone()));
        for file in candidates {
            plan.protected_files.insert((fold(path), file.token.clone()));
            mismatch_files.insert(dir.join(&file.file_name));
        }
    }
}

fn describe_ops(ops: &[&Operation]) -> String {
    ops.iter().map(|o| o.http_method.clone()).collect::<Vec<_>>().join("/")
}

/// One currently-active stub: the path and method it represents, where it
/// sits, and whether its folder may be written through.
struct ActiveStub {
    path: String,
    method: String,
    stub_path: PathBuf,
    dir_writable: bool,
}

/// Every currently-*active* `endpoint.<method>.json` file in `tree`, paired
/// with the (path, method) it represents. Only a canonical token valid in this
/// mode counts: that also excludes `.reference.json`/`.test.json` siblings,
/// underscore-prefixed orphans, and `WrongMode`/`Invalid` names, which are
/// never orphan candidates.
fn discover_active_endpoint_files(tree: &EndpointTree, mode: MethodCase) -> Vec<ActiveStub> {
    tree.files()
        .iter()
        .filter_map(|file| {
            let token_text = method_token::stub_file_token(&file.name)?;
            let TokenStatus::Valid(token) = method_token::parse_file_token(token_text, mode) else {
                return None;
            };
            let path = if file.rel_dir.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", file.rel_dir.join("/"))
            };
            Some(ActiveStub {
                path,
                method: token.file_token().into_owned(),
                stub_path: file.logical.clone(),
                dir_writable: file.dir_writable,
            })
        })
        .collect()
}

/// If a previously-orphaned (`_`-prefixed) endpoint's path+method is back
/// in the current spec, strips the underscore from both its stub and
/// reference file. Deliberately does nothing else: the now-active stub
/// still carries its *old* hash-less state, so the normal
/// `write_endpoint_files` pass that runs right after this one will detect
/// it as drifted and run it through the ordinary backup-and-migrate flow —
/// exactly the design doc's "restoration is treated like an update, not a
/// fresh start."
fn restore_orphaned_endpoints(
    ctx: &LinkContext,
    root: &Path,
    doc: &OpenApiDocument,
    skip: &HashSet<(String, String)>,
    errors: &mut Vec<String>,
) -> io::Result<Vec<(String, String)>> {
    let endpoints_root = root.join("datasources/endpoints");
    let mut restored = Vec::new();
    for op in &doc.operations {
        if skip.contains(&(op.path.clone(), op.method.clone())) {
            continue;
        }
        let dir = match endpoint_dir(ctx, &endpoints_root, &op.path) {
            Ok(DirState::Exists(dir)) => dir,
            Ok(DirState::WillCreate(_)) => continue,
            Err(e) => {
                errors.push(format!("{} {}: {e}", op.http_method, untrusted(&op.path)));
                continue;
            }
        };
        let active_stub = format!("endpoint.{}.json", op.method);
        let orphaned_stub = format!("_endpoint.{}.json", op.method);
        let outcome = (|| -> Result<bool, EndpointFsError> {
            if !matches!(check_file_with(ctx, &dir, &active_stub)?, FileState::Absent) || matches!(check_file_with(ctx, &dir, &orphaned_stub)?, FileState::Absent) {
                return Ok(false);
            }
            rename_checked_with(ctx, &dir, &orphaned_stub, &active_stub)?;
            let orphaned_reference = format!("_endpoint.{}.reference.json", op.method);
            if matches!(check_file(&dir, &orphaned_reference)?, FileState::Present(_)) {
                rename_checked_with(ctx, &dir, &orphaned_reference, &format!("endpoint.{}.reference.json", op.method))?;
            }
            Ok(true)
        })();
        match outcome {
            Ok(true) => restored.push((op.path.clone(), op.method.clone())),
            Ok(false) => {}
            Err(e) => errors.push(format!("{} {}: {e}", op.http_method, untrusted(&op.path))),
        }
    }
    Ok(restored)
}

/// Prefixes any active endpoint file whose (path, method) no longer
/// matches an operation in the current spec with `_` — excluded from
/// routing from then on, but never deleted; `_backups/` history stays
/// exactly where it is. Comparison is by case-folded name, and anything
/// belonging to a path the loader or preflight set aside (ambiguous,
/// unsafe, claim-rejected) is left alone.
fn mark_orphaned_endpoints(
    ctx: &LinkContext,
    tree: &EndpointTree,
    doc: &OpenApiDocument,
    rejected_paths: &BTreeSet<String>,
    protected_files: &HashSet<(String, String)>,
    errors: &mut Vec<String>,
) -> io::Result<Vec<(String, String)>> {
    let active: HashSet<(String, String)> = doc.operations.iter().map(|op| (fold(&op.path), op.method.clone())).collect();
    let protected: HashSet<String> = doc
        .ambiguous
        .iter()
        .chain(doc.skipped_paths.iter())
        .chain(doc.unresolved_path_items.iter())
        .chain(rejected_paths.iter())
        .map(|p| fold(p))
        .collect();

    let mut orphaned = Vec::new();
    for ActiveStub {
        path,
        method,
        stub_path,
        dir_writable,
    } in discover_active_endpoint_files(tree, doc.method_case)
    {
        let folded_path = fold(&path);
        let key = (folded_path, method.clone());
        if active.contains(&key) || protected.contains(&key.0) || protected_files.contains(&key) {
            continue;
        }

        let dir = stub_path.parent().expect("a file always has a parent").to_path_buf();
        let outcome = (|| -> Result<(), EndpointFsError> {
            if !dir_writable {
                return Err(EndpointFsError::LinkEscapes { at: dir.clone(), target: None });
            }
            rename_checked_with(ctx, &dir, &format!("endpoint.{method}.json"), &format!("_endpoint.{method}.json"))?;
            let reference_name = format!("endpoint.{method}.reference.json");
            if matches!(check_file(&dir, &reference_name)?, FileState::Present(_)) {
                rename_checked_with(ctx, &dir, &reference_name, &format!("_endpoint.{method}.reference.json"))?;
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => orphaned.push((path, method)),
            Err(e) => errors.push(format!("{} {}: {e}", crate::openapi::method_token::display_token(&method), untrusted(&path))),
        }
    }
    Ok(orphaned)
}

/// Checks every active endpoint file's `successStatus` (if it declares one
/// at all) against its operation's own declared response codes — run last,
/// against whatever's on disk after generation/migration/orphan-handling,
/// since it's validating the *user's* config, not producing it.
fn validate_success_statuses(tree: &EndpointTree, doc: &OpenApiDocument) -> Vec<String> {
    let mut errors = Vec::new();
    for op in &doc.operations {
        let Ok(segments) = endpoint_segments(&op.path) else { continue };
        let mut dir = tree.endpoints_root().to_path_buf();
        dir.extend(&segments);
        let Some(stub) = tree.file_in(&dir, &format!("endpoint.{}.json", op.method)) else {
            continue;
        };
        let Some(endpoint_file) = read_json(&stub.logical) else {
            continue;
        };
        if let Err(message) = op.validate_success_status(&endpoint_file) {
            errors.push(message);
        }
    }
    errors
}

fn stream_reference(spec: &StreamSpec, components: &HashMap<String, Value>) -> Value {
    let mut mode = serde_json::Map::new();
    mode.insert("kind".to_string(), Value::String("stream".to_string()));
    if let Some(status) = spec.status {
        mode.insert("status".to_string(), Value::from(status));
    }
    mode.insert("mediaType".to_string(), Value::String(spec.media_type.clone()));
    mode.insert(
        "itemSchema".to_string(),
        spec.item_schema.as_ref().map_or(Value::Null, |schema| walk_response_schema(schema, components)),
    );
    mode.insert("itemEncoding".to_string(), spec.item_encoding.clone().unwrap_or(Value::Null));
    Value::Object(mode)
}

fn build_reference_file(op: &Operation, hash: &str, response_descriptor: &Value, components: &HashMap<String, Value>) -> Value {
    let mut reference = serde_json::json!({
        "operationId": op.operation_id,
        "_hash": hash,
        "security": op.security,
        "request": op.request_sources(),
        "response": response_descriptor,
        "availableParameterSources": op.available_parameter_sources(),
    });
    if let ResponseMode::Stream(spec) = &op.response_mode {
        reference["responseMode"] = stream_reference(spec, components);
    }
    if let Some(spec) = &op.request_stream {
        reference["requestMode"] = stream_reference(spec, components);
    }
    reference
}

/// Only set here at *creation* time — an existing hand-edited stub's
/// `security` is never retroactively touched by a later `generate` run
/// even when it drifts from the spec (`write_endpoint_files` rewrites the
/// reference file whenever `security:` changes, but `migrate_stub` only
/// ever touches the stub's `response`, matching how it already leaves
/// `sources` alone). The reference file above is what stays authoritative
/// if the two ever disagree.
fn build_stub_file(op: &Operation, reference_file_name: &str, response_descriptor: &Value) -> Value {
    let mut todo = format!(
        "See {reference_file_name} for available request/response fields. \
         Fill in sources and map each response field to a source path."
    );
    if let ResponseMode::Stream(spec) = &op.response_mode {
        todo.push_str(&format!(
            " Note: openapi.yaml declares a streaming response ({}); this frogs version serves it as a single JSON response — see responseMode in {reference_file_name}.",
            untrusted(&spec.media_type)
        ));
    }
    if let Some(spec) = &op.request_stream {
        todo.push_str(&format!(
            " Note: openapi.yaml declares a streaming request body ({}); this frogs version only reads a single JSON request body — see requestMode in {reference_file_name}.",
            untrusted(&spec.media_type)
        ));
    }
    let mut stub = serde_json::json!({
        "operationId": op.operation_id,
        "_generated": true,
        "_todo": todo,
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
    /// Nothing else drifted, but the parameter details a `$ref`'d component feeds into the
    /// reference file (`request`, `availableParameterSources`) did; only that file was rewritten.
    references_refreshed: usize,
}

/// Writes (or skips) every operation's reference and stub files, per the
/// design doc's hash-based drift detection: an endpoint is only touched at
/// all if its own response-schema hash changed, it references a component
/// that changed, or it was just restored from orphaned status — everything
/// else is left completely alone. An operation whose folder or files can't
/// be used safely is reported in `errors` and skipped; the rest still run.
#[allow(clippy::too_many_arguments)]
fn write_endpoint_files(
    ctx: &LinkContext,
    root: &Path,
    doc: &OpenApiDocument,
    components: &HashMap<String, Value>,
    changed_components: &HashSet<String>,
    just_restored: &HashSet<(String, String)>,
    auto_migrate_endpoints: bool,
    skip: &HashSet<(String, String)>,
    errors: &mut Vec<String>,
) -> io::Result<GenerateSummary> {
    let mut summary = GenerateSummary::default();
    let endpoints_root = root.join("datasources/endpoints");

    for op in &doc.operations {
        if skip.contains(&(op.path.clone(), op.method.clone())) {
            continue;
        }
        match write_one_endpoint(
            ctx,
            &endpoints_root,
            op,
            components,
            changed_components,
            just_restored,
            auto_migrate_endpoints,
            &mut summary,
        ) {
            Ok(()) => {}
            Err(EndpointFsError::Io(e)) => return Err(e),
            Err(e) => errors.push(format!("{} {}: {e}", op.http_method, untrusted(&op.path))),
        }
    }

    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn write_one_endpoint(
    ctx: &LinkContext,
    endpoints_root: &Path,
    op: &Operation,
    components: &HashMap<String, Value>,
    changed_components: &HashSet<String>,
    just_restored: &HashSet<(String, String)>,
    auto_migrate_endpoints: bool,
    summary: &mut GenerateSummary,
) -> Result<(), EndpointFsError> {
    let state = endpoint_dir(ctx, endpoints_root, &op.path)?;
    let reference_file_name = format!("endpoint.{}.reference.json", op.method);
    let stub_file_name = format!("endpoint.{}.json", op.method);
    let reference_state = check_file(state.path(), &reference_file_name)?;
    let stub_state = check_file_with(ctx, state.path(), &stub_file_name)?;

    let current_hash = op.response_schema_hash();
    let stored_reference = match &reference_state {
        FileState::Present(path) | FileState::PresentViaLink(path) => read_json(path),
        FileState::Absent => None,
    };
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

    if !drifted && !matches!(stub_state, FileState::Absent) && matches!(reference_state, FileState::Present(_)) {
        if !reference_parameter_details_match(stored_reference.as_ref(), op) {
            let response_descriptor = op.resolve_response(components).unwrap_or(Value::Null);
            let reference_bytes = serde_json::to_string_pretty(&build_reference_file(op, &current_hash, &response_descriptor, components)).expect("always serializes");
            match create_endpoint_dir_for(ctx, endpoints_root, &op.path)
                .and_then(|dir| write_existing_file(&ctx.boundary, &dir, &reference_file_name, reference_bytes.as_bytes()))
            {
                Ok(()) => summary.references_refreshed += 1,
                Err(e) => {
                    eprintln!(
                        "warning: {} {}: {reference_file_name} is out of date but could not be refreshed ({e})",
                        op.http_method,
                        untrusted(&op.path)
                    );
                    summary.skipped += 1;
                }
            }
            return Ok(());
        }
        summary.skipped += 1;
        return Ok(());
    }

    let dir = create_endpoint_dir_for(ctx, endpoints_root, &op.path)?;
    let response_descriptor = op.resolve_response(components).unwrap_or(Value::Null);

    let reference = build_reference_file(op, &current_hash, &response_descriptor, components);
    let reference_bytes = serde_json::to_string_pretty(&reference).expect("always serializes");
    match &reference_state {
        FileState::Present(_) | FileState::PresentViaLink(_) => write_existing_file(&ctx.boundary, &dir, &reference_file_name, reference_bytes.as_bytes())?,
        FileState::Absent => create_new_file(&ctx.boundary, &dir, &reference_file_name, reference_bytes.as_bytes())?,
    }

    match stub_state {
        FileState::Absent => {
            let stub = build_stub_file(op, &reference_file_name, &response_descriptor);
            create_new_file(
                &ctx.boundary,
                &dir,
                &stub_file_name,
                serde_json::to_string_pretty(&stub).expect("always serializes").as_bytes(),
            )?;
            summary.created += 1;
        }
        FileState::PresentViaLink(stub_path) => {
            eprintln!(
                "warning: {} has drifted from its updated schema but is a link; not migrated, review by hand against {reference_file_name}",
                stub_path.display()
            );
            summary.drift_warned += 1;
        }
        FileState::Present(stub_path) if auto_migrate_endpoints => {
            backup_stub(&ctx.boundary, &dir, &op.method, &stub_path)?;
            migrate_stub(&ctx.boundary, &dir, &stub_file_name, &stub_path, &response_descriptor)?;
            summary.migrated += 1;
        }
        FileState::Present(stub_path) => {
            eprintln!(
                "warning: {} has drifted from its updated schema but autoMigrateEndpoints is off — \
                 review it manually against {reference_file_name}",
                stub_path.display()
            );
            summary.drift_warned += 1;
        }
    }
    Ok(())
}

/// Whether a stored reference file already carries this operation's `request` and
/// `availableParameterSources`. Parameters can come from a `$ref`'d component whose edit changes
/// neither the response-schema hash nor the stub, so this is the only signal that the reference
/// file went stale.
fn reference_parameter_details_match(stored: Option<&Value>, op: &Operation) -> bool {
    let Some(stored) = stored else { return true };
    stored.get("request") == Some(&op.request_sources()) && stored.get("availableParameterSources") == Some(&serde_json::json!(op.available_parameter_sources()))
}

/// Copies the current stub into `_backups/` (inside the path's own folder,
/// alongside its other methods — never a shared directory) before
/// migration touches anything, so a bad automatic migration is always
/// trivially reversible by hand.
fn backup_stub(boundary: &ProjectBoundary, dir: &Path, method: &str, stub_path: &Path) -> Result<(), EndpointFsError> {
    let backups_dir = dir.join("_backups");
    match DirIndex::read(dir)?.lookup("_backups") {
        Lookup::Exact(EntryKind::Dir) => {}
        Lookup::Absent => create_dir_checked(boundary, &backups_dir)?,
        Lookup::Exact(EntryKind::Symlink) => return Err(EndpointFsError::Symlink { at: backups_dir }),
        Lookup::Exact(_) => return Err(EndpointFsError::NotADirectory { at: backups_dir }),
        Lookup::CaseConflict { found } => {
            return Err(EndpointFsError::CaseConflict {
                wanted: "_backups".to_string(),
                found: found.to_string_lossy().into_owned(),
                at: dir.to_path_buf(),
            });
        }
    }
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ");
    let backup_name = format!("endpoint.{method}.{timestamp}.json");
    copy_into_checked(boundary, stub_path, &backups_dir, &backup_name)
}

/// Structurally merges the existing stub's `response` tree onto the fresh
/// one (see `merge_stub_response`); `operationId`/`_generated`/`_todo`/
/// `sources` are carried forward exactly as they were — migration never
/// touches `sources`, and doesn't invent or remove metadata fields the
/// endpoint file didn't already have.
fn migrate_stub(boundary: &ProjectBoundary, dir: &Path, stub_name: &str, stub_path: &Path, response_descriptor: &Value) -> Result<(), EndpointFsError> {
    let mut stub = read_json(stub_path).unwrap_or_else(|| serde_json::json!({}));
    let fresh_response = stub_from_descriptor(response_descriptor);
    let old_response = stub.get("response").cloned().unwrap_or(Value::Null);
    let merged_response = merge_stub_response(&old_response, &fresh_response);

    if let Value::Object(fields) = &mut stub {
        fields.insert("response".to_string(), merged_response);
    }

    write_existing_file(boundary, dir, stub_name, serde_json::to_string_pretty(&stub).expect("always serializes").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_dir_strips_the_leading_slash_and_keeps_brace_segments_literal() {
        let root = Path::new("/proj/datasources/endpoints");
        assert_eq!(endpoint_dir(&test_ctx(root), root, "/cars").unwrap().path(), root.join("cars"));
        assert_eq!(endpoint_dir(&test_ctx(root), root, "/cars/{vin}").unwrap().path(), root.join("cars/{vin}"));
    }

    #[test]
    fn endpoint_dir_maps_the_root_path_to_the_endpoints_folder_itself() {
        let root = Path::new("/proj/datasources/endpoints");
        assert_eq!(endpoint_dir(&test_ctx(root), root, "/").unwrap().path(), root);
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
        let doc = crate::openapi::load(&dir.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
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

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 1,
                migrated: 0,
                drift_warned: 0,
                references_refreshed: 0
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

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 1,
                migrated: 0,
                drift_warned: 0,
                references_refreshed: 0
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

        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v1,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

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

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v2,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 1,
                drift_warned: 0,
                references_refreshed: 0
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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v1,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let reference_path = root.join("datasources/endpoints/ping/endpoint.get.reference.json");
        assert!(read_json(&reference_path).unwrap()["security"].is_null());

        // Same response schema as PING_YAML — only `security:` is new.
        let doc_v2 = doc_from_yaml(PROTECTED_PING_YAML);
        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v2,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 1,
                drift_warned: 0,
                references_refreshed: 0
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

        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        let modified_before = std::fs::metadata(&stub_path).unwrap().modified().unwrap();

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 1,
                created: 0,
                migrated: 0,
                drift_warned: 0,
                references_refreshed: 0
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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v1,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(&stub_path, r#"{ "operationId": "ping", "sources": { "x": 1 }, "response": "sources.x.value" }"#).unwrap();

        // Response schema changes from a bare string to an object — the old
        // "sources.x.value" mapping is now incompatible and must be dropped.
        let changed_yaml = PING_YAML.replace("schema: { type: string }", "schema: { type: object, properties: { value: { type: string } } }");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v2,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 1,
                drift_warned: 0,
                references_refreshed: 0
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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v1,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(&stub_path, r#"{ "operationId": "ping", "sources": {}, "response": "hand-edited" }"#).unwrap();

        let changed_yaml = PING_YAML.replace("type: string", "type: integer");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v2,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            false,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            summary,
            GenerateSummary {
                skipped: 0,
                created: 0,
                migrated: 0,
                drift_warned: 1,
                references_refreshed: 0
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
        let endpoints_root = Path::new("/proj/datasources/endpoints");
        for path in ["/cars", "/cars/{vin}", "/"] {
            let dir = endpoint_dir(&test_ctx(endpoints_root), endpoints_root, path).unwrap();
            assert_eq!(path_for_endpoint_dir(endpoints_root, dir.path()), path);
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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let dir = root.join("datasources/endpoints/ping");
        std::fs::write(dir.join("endpoint.get.test.json"), r#"{ "cases": [] }"#).unwrap();

        let orphaned = mark_orphaned_endpoints(
            &test_ctx(&root),
            &tree_for_tests(&root.join("datasources/endpoints")),
            &doc,
            &BTreeSet::new(),
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(orphaned.is_empty(), "a .test.json sibling must not be treated as its own endpoint file");
        assert!(dir.join("endpoint.get.test.json").is_file(), "the test file itself must be untouched");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_operation_removed_from_the_spec_gets_its_files_prefixed_not_deleted() {
        let root = temp_project();
        let doc_v1 = doc_from_yaml(PING_YAML);
        let components = HashMap::new();
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v1,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        // /ping no longer exists in the new spec.
        let doc_v2 = doc_from_yaml("openapi: 3.0.3\ninfo: { title: t, version: 0.1.0 }\npaths: {}\n");

        let orphaned = mark_orphaned_endpoints(
            &test_ctx(&root),
            &tree_for_tests(&root.join("datasources/endpoints")),
            &doc_v2,
            &BTreeSet::new(),
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v1,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        // Hand-edit the stub before it gets orphaned, so we can prove the
        // mapping survives the whole orphan -> restore -> migrate round trip.
        let stub_path = root.join("datasources/endpoints/ping/endpoint.get.json");
        std::fs::write(&stub_path, r#"{ "operationId": "ping", "sources": { "x": 1 }, "response": "sources.x.value" }"#).unwrap();

        let empty_doc = doc_from_yaml("openapi: 3.0.3\ninfo: { title: t, version: 0.1.0 }\npaths: {}\n");
        mark_orphaned_endpoints(
            &test_ctx(&root),
            &tree_for_tests(&root.join("datasources/endpoints")),
            &empty_doc,
            &BTreeSet::new(),
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!stub_path.exists());

        // /ping comes back, with a schema change (string -> object) at the
        // same time -- restoration must run through the same
        // backup-and-migrate flow as ordinary drift, not a fresh stub.
        let changed_yaml = PING_YAML.replace("schema: { type: string }", "schema: { type: object, properties: { value: { type: string } } }");
        let doc_v2 = doc_from_yaml(&changed_yaml);

        let restored = restore_orphaned_endpoints(&test_ctx(&root), &root, &doc_v2, &HashSet::new(), &mut Vec::new()).unwrap();
        assert_eq!(restored, vec![("/ping".to_string(), "get".to_string())]);
        assert!(stub_path.is_file(), "the active name must be back");

        let restored_set: HashSet<(String, String)> = restored.into_iter().collect();
        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc_v2,
            &components,
            &HashSet::new(),
            &restored_set,
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
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
        write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &HashSet::new(),
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let empty_doc = doc_from_yaml("openapi: 3.0.3\ninfo: { title: t, version: 0.1.0 }\npaths: {}\n");
        mark_orphaned_endpoints(
            &test_ctx(&root),
            &tree_for_tests(&root.join("datasources/endpoints")),
            &empty_doc,
            &BTreeSet::new(),
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

        // Same `doc` as before -- nothing about /ping's schema changed.
        let restored = restore_orphaned_endpoints(&test_ctx(&root), &root, &doc, &HashSet::new(), &mut Vec::new()).unwrap();
        let restored_set: HashSet<(String, String)> = restored.into_iter().collect();

        let summary = write_endpoint_files(
            &test_ctx(&root),
            &root,
            &doc,
            &components,
            &HashSet::new(),
            &restored_set,
            true,
            &HashSet::new(),
            &mut Vec::new(),
        )
        .unwrap();
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
    fn generate_web_never_picks_a_dot_prefixed_html_file_as_the_start_page() {
        let root = temp_project();
        let files = vec![touch(&root, ".aaa.html"), touch(&root, "zebra.html")];

        generate_web(&root, &files).unwrap();

        let config = crate::webserve::load(&root.join("webserve.json")).unwrap();
        assert_eq!(config.start_page, "zebra.html");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn generate_web_never_picks_a_dot_prefixed_404_html_as_the_not_found_page() {
        let root = temp_project();
        let files = vec![touch(&root, "index.html"), touch(&root, "404.html"), touch(&root, ".404.html")];

        generate_web(&root, &files).unwrap();

        let config = crate::webserve::load(&root.join("webserve.json")).unwrap();
        assert_eq!(config.start_page, "index.html");
        assert_eq!(config.not_found_page, Some("404.html".to_string()));

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

        scaffold_config(&ProjectBoundary::new(&root), &api_root).unwrap();

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

        scaffold_config(&ProjectBoundary::new(&root), &api_root).unwrap();

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

        scaffold_config(&ProjectBoundary::new(&root), &api_root).unwrap();

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

        scaffold_config(&ProjectBoundary::new(&root), &api_root).unwrap();

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

        scaffold_config(&ProjectBoundary::new(&root), &api_root).unwrap();

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

#[cfg(test)]
mod mtls_tests;

#[cfg(test)]
mod symlink_tests;

#[cfg(test)]
mod route_tests;

#[cfg(test)]
mod ref_tests;

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-generate-m1-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A spec whose operations all return a plain string. `groups` is
    /// `(path, methods)`; every path is quoted so odd keys survive YAML.
    fn spec(version: &str, groups: &[(&str, &[&str])], components: &str) -> String {
        let mut yaml = format!("openapi: {version}\ninfo: {{ title: t, version: 1 }}\npaths:\n");
        let mut n = 0;
        for (path, methods) in groups {
            yaml.push_str(&format!("  '{path}':\n"));
            for method in *methods {
                n += 1;
                yaml.push_str(&format!(
                    "    {method}:\n      operationId: op{n}\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {{ type: string }}\n"
                ));
            }
        }
        yaml.push_str(components);
        yaml
    }

    fn write_spec(root: &Path, yaml: &str) {
        std::fs::write(root.join("openapi.yaml"), yaml).unwrap();
    }

    fn make_strict(root: &Path) {
        std::fs::create_dir_all(root.join("api/config")).unwrap();
        std::fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
    }

    /// Every file under `root` as `/`-joined relative path -> bytes.
    fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
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
                    out.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    fn names(root: &Path) -> Vec<String> {
        tree(root).into_keys().filter(|k| k != "openapi.yaml").collect()
    }

    fn case_insensitive_fs(dir: &Path) -> bool {
        std::fs::write(dir.join("probe_a"), b"").unwrap();
        let insensitive = dir.join("PROBE_A").exists();
        std::fs::remove_file(dir.join("probe_a")).unwrap();
        eprintln!("case-insensitive filesystem: {insensitive}");
        insensitive
    }

    const SCAFFOLD: [&str; 4] = [
        "api/config/connections.json",
        "api/config/errors/core.json",
        "api/config/server.json",
        "api/security/schemes.json",
    ];

    // ---- G1: traversal never escapes ----

    #[test]
    fn spec_paths_that_try_to_escape_the_project_create_nothing_outside_datasources_endpoints() {
        let root = temp_project();
        let marker = format!("frogs_escape_marker_{}", std::process::id());
        let escape_a = format!("/../../{marker}/x");
        let escape_b = format!("/a/../../../{marker}");
        let escape_c = format!("/{{x/../../../{marker}}}");
        let yaml = spec(
            "3.1.0",
            &[
                ("/fine", &["get"]),
                (&escape_a, &["get"]),
                (&escape_b, &["get"]),
                (&escape_c, &["get"]),
                ("/C:/x", &["get"]),
            ],
            "",
        );
        write_spec(&root, &yaml);

        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "skipped paths must make generate fail");
        assert!(!outcome.strict_aborted);

        // `/C:/x` has no traversal, but ':' is route syntax, so the loader
        // skips it as UnsafePath under every portability policy (M5).
        let endpoints = root.join("api").join("datasources").join("endpoints");

        let mut saw_fine = false;
        for (name, _) in tree(&root) {
            if name == "openapi.yaml" || SCAFFOLD.contains(&name.as_str()) {
                continue;
            }
            if name.starts_with("api/datasources/endpoints/fine/") {
                saw_fine = true;
                continue;
            }
            panic!("unexpected file {name}");
        }
        assert!(saw_fine, "the safe path must still be generated");

        // List the folder rather than probing a joined path: on Windows
        // `join("C:")` would point at the real drive.
        let names: Vec<String> = std::fs::read_dir(&endpoints)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["fine"], "only the safe path may get a folder");

        assert!(!std::env::temp_dir().join(&marker).exists(), "something escaped the project");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_second_guard_rejects_a_traversal_path_that_bypassed_the_loader() {
        let root = temp_project();
        write_spec(&root, &spec("3.1.0", &[("/fine", &["get"])], ""));
        let dir = temp_project();
        let mut doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        for bad in ["/../../escape", "/a/./b", "/a//b", "/a\\b", "/a/../b", "/x\u{0}y"] {
            doc.operations[0].path = bad.to_string();

            let plan = plan_endpoint_files(&dir.join("api"), &doc, &tree_for_tests(&dir.join("api/datasources/endpoints")), &test_ctx(&dir));
            assert_eq!(plan.errors.len(), 1, "{bad:?}");
            assert!(plan.errors[0].strict, "{bad:?}");
            assert!(plan.skip.contains(&(bad.to_string(), "get".to_string())));

            let mut errors = Vec::new();
            let summary = write_endpoint_files(
                &test_ctx(&dir),
                &dir,
                &doc,
                &HashMap::new(),
                &HashSet::new(),
                &HashSet::new(),
                true,
                &HashSet::new(),
                &mut errors,
            )
            .unwrap();
            assert_eq!(errors.len(), 1, "{bad:?}");
            assert_eq!(summary.created, 0);
            assert!(tree(&dir).is_empty(), "{bad:?} created {:?}", tree(&dir).keys().collect::<Vec<_>>());
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secured_operation_generate_skipped_is_reported_when_the_static_catch_all_would_answer_it() {
        let root = temp_project();
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\npaths:\n  '/ad\\min':\n    get:\n      operationId: skipped\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n";
        write_spec(&root, yaml);
        std::fs::write(root.join("webserve.json"), r#"{ "startPage": "index.html" }"#).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "skipped secured op under the web role must make generate fail");
        let text = outcome.errors.join("\n");
        assert!(
            text.contains("fix the path in openapi.yaml") || text.contains("static-content"),
            "the error must explain the exposure, not just the skip: {text}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn endpoint_dir_refuses_traversal_with_a_containment_error() {
        let root = Path::new("/proj/datasources/endpoints");
        for bad in ["/..", "/a/../b", "//", "/a//b", "/a/.", "/a\\b"] {
            assert!(matches!(endpoint_dir(&test_ctx(root), root, bad), Err(EndpointFsError::Containment(_))), "{bad:?}");
        }
    }

    // ---- G2 / G3: strict gate ----

    #[test]
    fn strict_with_an_unsafe_path_aborts_before_writing_anything_but_the_scaffolded_config() {
        let root = temp_project();
        make_strict(&root);
        write_spec(&root, &spec("3.1.0", &[("/ok", &["get"]), ("/x/_backups", &["get"])], ""));

        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.strict_aborted);
        assert!(!outcome.errors.is_empty());
        assert!(!root.join("api/datasources").exists());
        assert_eq!(names(&root), SCAFFOLD.to_vec());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_a_missing_version_aborts_but_non_strict_generates_everything() {
        let strict = temp_project();
        make_strict(&strict);
        let yaml = spec("3.1.0", &[("/ok", &["get"])], "").replace("openapi: 3.1.0\n", "");
        write_spec(&strict, &yaml);
        assert!(generate_api_inner(&strict).unwrap().strict_aborted);
        assert!(!strict.join("api/datasources").exists());

        let lax = temp_project();
        write_spec(&lax, &yaml);
        let outcome = generate_api_inner(&lax).unwrap();
        assert!(!outcome.strict_aborted);
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(lax.join("api/datasources/endpoints/ok/endpoint.get.json").is_file());
        let _ = std::fs::remove_dir_all(&strict);
        let _ = std::fs::remove_dir_all(&lax);
    }

    #[test]
    fn strict_on_a_clean_spec_generates_exactly_what_non_strict_does() {
        let yaml = spec("3.1.0", &[("/", &["get"]), ("/cars", &["get", "post"]), ("/cars/{vin}", &["get"])], "");
        let strict = temp_project();
        make_strict(&strict);
        write_spec(&strict, &yaml);
        let lax = temp_project();
        write_spec(&lax, &yaml);

        let a = generate_api_inner(&strict).unwrap();
        let b = generate_api_inner(&lax).unwrap();
        assert!(a.errors.is_empty() && !a.strict_aborted, "{:?}", a.errors);
        assert!(b.errors.is_empty() && !b.strict_aborted, "{:?}", b.errors);

        let mut ta = tree(&strict);
        let mut tb = tree(&lax);
        ta.remove("api/config/server.json");
        tb.remove("api/config/server.json");
        assert_eq!(ta, tb);
        let _ = std::fs::remove_dir_all(&strict);
        let _ = std::fs::remove_dir_all(&lax);
    }

    #[test]
    fn a_normalised_trailing_slash_alone_is_a_strict_error_but_a_plain_warning_otherwise() {
        let strict = temp_project();
        make_strict(&strict);
        write_spec(&strict, &spec("3.1.0", &[("/cars/", &["get"])], ""));
        assert!(generate_api_inner(&strict).unwrap().strict_aborted);

        let lax = temp_project();
        write_spec(&lax, &spec("3.1.0", &[("/cars/", &["get"])], ""));
        let outcome = generate_api_inner(&lax).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let _ = std::fs::remove_dir_all(&strict);
        let _ = std::fs::remove_dir_all(&lax);
    }

    // ---- G4: golden snapshot ----

    #[test]
    fn golden_file_tree_for_a_mixed_spec_and_a_second_run_that_drops_one_method() {
        let root = temp_project();
        write_spec(
            &root,
            &spec(
                "3.1.0",
                &[
                    ("/", &["get"]),
                    ("/ping", &["get"]),
                    ("/cars", &["get", "post"]),
                    ("/cars/{vin}", &["get"]),
                    ("/_health", &["get"]),
                ],
                "",
            ),
        );
        let first = generate_api_inner(&root).unwrap();
        assert!(first.errors.is_empty(), "{:?}", first.errors);
        let golden_run1 = [
            "api/config/connections.json",
            "api/config/errors/core.json",
            "api/config/server.json",
            "api/datasources/endpoints/_health/endpoint.get.json",
            "api/datasources/endpoints/_health/endpoint.get.reference.json",
            "api/datasources/endpoints/cars/endpoint.get.json",
            "api/datasources/endpoints/cars/endpoint.get.reference.json",
            "api/datasources/endpoints/cars/endpoint.post.json",
            "api/datasources/endpoints/cars/endpoint.post.reference.json",
            "api/datasources/endpoints/cars/{vin}/endpoint.get.json",
            "api/datasources/endpoints/cars/{vin}/endpoint.get.reference.json",
            "api/datasources/endpoints/endpoint.get.json",
            "api/datasources/endpoints/endpoint.get.reference.json",
            "api/datasources/endpoints/ping/endpoint.get.json",
            "api/datasources/endpoints/ping/endpoint.get.reference.json",
            "api/security/schemes.json",
        ];
        assert_eq!(names(&root), golden_run1.to_vec());
        let before = tree(&root);

        write_spec(
            &root,
            &spec(
                "3.1.0",
                &[
                    ("/", &["get"]),
                    ("/ping", &["get"]),
                    ("/cars", &["get"]),
                    ("/cars/{vin}", &["get"]),
                    ("/_health", &["get"]),
                ],
                "",
            ),
        );
        let second = generate_api_inner(&root).unwrap();
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        let mut golden_run2: Vec<&str> = golden_run1.to_vec();
        golden_run2.retain(|n| !n.ends_with("cars/endpoint.post.json") && !n.ends_with("cars/endpoint.post.reference.json"));
        golden_run2.push("api/datasources/endpoints/cars/_endpoint.post.json");
        golden_run2.push("api/datasources/endpoints/cars/_endpoint.post.reference.json");
        golden_run2.sort();
        assert_eq!(names(&root), golden_run2);

        // Untouched endpoints are byte-identical and the orphan kept its content.
        let after = tree(&root);
        assert_eq!(
            before["api/datasources/endpoints/ping/endpoint.get.json"],
            after["api/datasources/endpoints/ping/endpoint.get.json"]
        );
        assert_eq!(
            before["api/datasources/endpoints/cars/endpoint.post.json"],
            after["api/datasources/endpoints/cars/_endpoint.post.json"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- G5: case conflicts ----

    #[test]
    fn an_existing_differently_cased_folder_is_a_case_conflict_and_nothing_is_written_into_it() {
        let root = temp_project();
        case_insensitive_fs(&root);
        let endpoints = root.join("api/datasources/endpoints");
        std::fs::create_dir_all(endpoints.join("Cars")).unwrap();
        write_spec(&root, &spec("3.1.0", &[("/cars", &["get"])], ""));

        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty());
        assert!(
            outcome.errors.iter().any(|e| e.contains("Cars") && e.contains("rename or remove it by hand")),
            "{:?}",
            outcome.errors
        );
        let entries: Vec<String> = std::fs::read_dir(&endpoints)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["Cars".to_string()]);
        assert_eq!(std::fs::read_dir(endpoints.join("Cars")).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_case_conflict_under_strict_aborts_before_any_write_and_otherwise_is_only_noted() {
        let root = temp_project();
        make_strict(&root);
        let endpoints = root.join("api/datasources/endpoints");
        std::fs::create_dir_all(endpoints.join("Cars")).unwrap();
        write_spec(&root, &spec("3.1.0", &[("/cars", &["get"]), ("/ping", &["get"])], ""));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.strict_aborted);
        assert!(!endpoints.join("ping").exists());
        assert!(!root.join("api/datasources/components").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_case_variant_stub_file_blocks_just_that_operation() {
        let root = temp_project();
        case_insensitive_fs(&root);
        let dir = root.join("api/datasources/endpoints/cars");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.GET.json"), "HAND").unwrap();
        write_spec(&root, &spec("3.1.0", &[("/cars", &["get"]), ("/ping", &["get"])], ""));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty());
        assert_eq!(std::fs::read_to_string(dir.join("endpoint.GET.json")).unwrap(), "HAND");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "nothing else written for the conflicted operation");
        assert!(
            root.join("api/datasources/endpoints/ping/endpoint.get.json").is_file(),
            "other operations still generate"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- G6: ambiguous paths ----

    #[test]
    fn case_ambiguous_paths_are_neither_rewritten_nor_orphaned_and_generate_fails() {
        let root = temp_project();
        let dir = root.join("api/datasources/endpoints/cars");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), "ORIGINAL").unwrap();
        write_spec(&root, &spec("3.1.0", &[("/Cars", &["get"]), ("/cars", &["get"]), ("/ping", &["get"])], ""));

        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty());
        assert_eq!(std::fs::read_to_string(dir.join("endpoint.get.json")).unwrap(), "ORIGINAL");
        assert!(!dir.join("_endpoint.get.json").exists(), "must not be orphaned");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert!(root.join("api/datasources/endpoints/ping/endpoint.get.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- G7: trailing slash regression ----

    #[test]
    fn a_trailing_slash_path_is_not_orphaned_on_the_second_run() {
        let root = temp_project();
        write_spec(&root, &spec("3.1.0", &[("/cars/", &["get"])], ""));
        let first = generate_api_inner(&root).unwrap();
        assert!(first.errors.is_empty(), "{:?}", first.errors);
        let before = tree(&root);
        assert!(before.contains_key("api/datasources/endpoints/cars/endpoint.get.json"));

        let second = generate_api_inner(&root).unwrap();
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        assert_eq!(tree(&root), before, "second run must change nothing (and orphan nothing)");
        assert!(!names(&root).iter().any(|n| n.contains("_endpoint")));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- G8: 3.2 vs 3.1 twin ----

    #[test]
    fn a_3_2_spec_generates_byte_identical_files_to_its_3_1_twin() {
        let head = "  '/cars':\n    get:\n      operationId: listCars\n      parameters:\n        - { name: q, in: query, schema: { type: string } }\n";
        let tail = "      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: { $ref: '#/components/schemas/Car' }\n";
        let v32 = format!(
            "openapi: 3.2.0\ninfo: {{ title: t, version: 1 }}\npaths:\n{head}        - {{ name: raw, in: querystring, content: {{ application/x-www-form-urlencoded: {{ schema: {{ type: object }} }} }} }}\n{tail}components:\n  schemas:\n    Car:\n      type: object\n      discriminator: {{ propertyName: kind, defaultMapping: Car }}\n      xml: {{ nodeType: element }}\n      properties: {{ kind: {{ type: string }} }}\n"
        );
        let v31 = format!(
            "openapi: 3.1.0\ninfo: {{ title: t, version: 1 }}\npaths:\n{head}{tail}components:\n  schemas:\n    Car:\n      type: object\n      properties: {{ kind: {{ type: string }} }}\n"
        );
        let a = temp_project();
        write_spec(&a, &v32);
        let b = temp_project();
        write_spec(&b, &v31);
        assert!(generate_api_inner(&a).unwrap().errors.is_empty());
        assert!(generate_api_inner(&b).unwrap().errors.is_empty());
        let mut ta = tree(&a);
        let mut tb = tree(&b);
        ta.remove("openapi.yaml");
        tb.remove("openapi.yaml");
        assert_eq!(ta.keys().collect::<Vec<_>>(), tb.keys().collect::<Vec<_>>());
        for (name, bytes) in &ta {
            assert_eq!(bytes, &tb[name], "{name} differs");
        }
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    // ---- G9: claim check ----

    #[test]
    fn the_claim_check_skips_a_later_path_that_folds_onto_an_earlier_one_even_when_the_loader_was_bypassed() {
        let root = temp_project();
        write_spec(&root, &spec("3.1.0", &[("/first", &["get"]), ("/second", &["get"])], ""));
        let mut doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        doc.operations[0].path = "/Cars".to_string();
        doc.operations[1].path = "/cars".to_string();

        let plan = plan_endpoint_files(&root.join("api"), &doc, &tree_for_tests(&root.join("api/datasources/endpoints")), &test_ctx(&root));
        assert_eq!(plan.errors.len(), 1, "{:?}", plan.errors);
        assert!(plan.errors[0].strict);
        assert!(plan.errors[0].message.contains("/cars") && plan.errors[0].message.contains("/Cars"));
        assert!(plan.skip.contains(&("/cars".to_string(), "get".to_string())));
        assert!(!plan.skip.contains(&("/Cars".to_string(), "get".to_string())), "first in spec order wins");
        assert!(plan.rejected_paths.contains("/cars"));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- G10: component names ----

    #[test]
    fn a_component_named_with_traversal_writes_no_file_and_fails_generate() {
        let root = temp_project();
        let comps = "components:\n  schemas:\n    '../evil':\n      type: object\n      properties: { a: { type: string } }\n    Fine:\n      type: object\n      properties: { a: { type: string } }\n";
        write_spec(&root, &spec("3.1.0", &[("/ping", &["get"])], comps));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty());
        assert!(!names(&root).iter().any(|n| n.contains("evil")), "{:?}", names(&root));
        assert!(!root.join("api/datasources/evil.json").exists());
        assert!(root.join("api/datasources/components/Fine.json").is_file(), "safe components are still cached");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- G11: orphaning never overwrites ----

    #[test]
    fn orphaning_onto_an_existing_underscore_file_is_an_error_and_both_files_keep_their_content() {
        let root = temp_project();
        let dir = root.join("api/datasources/endpoints/cars");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), "ACTIVE").unwrap();
        std::fs::write(dir.join("_endpoint.get.json"), "OLD-ORPHAN").unwrap();
        write_spec(&root, &spec("3.1.0", &[("/ping", &["get"])], ""));

        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(std::fs::read_to_string(dir.join("endpoint.get.json")).unwrap(), "ACTIVE");
        assert_eq!(std::fs::read_to_string(dir.join("_endpoint.get.json")).unwrap(), "OLD-ORPHAN");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_path_removed_from_the_spec_is_orphaned_in_place_and_restored_when_it_returns() {
        let root = temp_project();
        write_spec(&root, &spec("3.1.0", &[("/a", &["get"]), ("/b", &["get"])], ""));
        assert!(generate_api_inner(&root).unwrap().errors.is_empty());
        write_spec(&root, &spec("3.1.0", &[("/a", &["get"])], ""));
        assert!(generate_api_inner(&root).unwrap().errors.is_empty());
        let eps = root.join("api/datasources/endpoints/b");
        assert!(eps.join("_endpoint.get.json").is_file());
        assert!(!eps.join("endpoint.get.json").exists());
        write_spec(&root, &spec("3.1.0", &[("/a", &["get"]), ("/b", &["get"])], ""));
        assert!(generate_api_inner(&root).unwrap().errors.is_empty());
        assert!(eps.join("endpoint.get.json").is_file());
        assert!(!eps.join("_endpoint.get.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_junction_or_symlink_planted_as_an_endpoint_folder_is_refused_and_nothing_lands_in_its_target() {
        let root = temp_project();
        // A separate temp dir: a target inside the project would be a followable link.
        let outside = temp_project();
        let endpoints = root.join("api/datasources/endpoints");
        std::fs::create_dir_all(&endpoints).unwrap();
        let link = endpoints.join("cars");
        if !crate::openapi::fs_os_tests::link_dir(&outside, &link) {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        write_spec(&root, &spec("3.1.0", &[("/cars", &["get"])], ""));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        // Remove the link itself before the recursive delete so cleanup never follows it.
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}

#[cfg(test)]
mod m2_generate_tests {
    use super::*;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-generate-m2-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_strict(root: &Path) {
        std::fs::create_dir_all(root.join("api/config")).unwrap();
        std::fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
    }

    fn write_spec(root: &Path, yaml: &str) {
        std::fs::write(root.join("openapi.yaml"), yaml).unwrap();
    }

    fn read_json(root: &Path, rel: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(root.join("api/datasources/endpoints").join(rel)).unwrap()).unwrap()
    }

    const HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: 1 }\n";

    const STREAMING_SPEC: &str = "paths:\n  /events:\n    get:\n      operationId: events\n      responses:\n        '200':\n          description: ok\n          content:\n            text/event-stream:\n              itemSchema: { $ref: '#/components/schemas/Evt' }\n              itemEncoding: { contentType: text/plain }\ncomponents:\n  schemas:\n    Evt: { type: object, properties: { id: { type: integer } } }\n";

    #[test]
    fn a_streaming_response_gets_a_response_mode_in_the_reference_file_and_a_note_in_the_new_stub() {
        let root = temp_project();
        write_spec(&root, &format!("{HEAD}{STREAMING_SPEC}"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);

        let reference = read_json(&root, "events/endpoint.get.reference.json");
        let mode = &reference["responseMode"];
        assert_eq!(mode["kind"], "stream");
        assert_eq!(mode["status"], 200);
        assert_eq!(mode["mediaType"], "text/event-stream");
        assert_eq!(mode["itemEncoding"], serde_json::json!({ "contentType": "text/plain" }));
        assert!(mode["itemSchema"].is_object(), "walked item schema: {mode}");
        assert!(mode["itemSchema"].to_string().contains("integer"));
        assert!(reference.get("requestMode").is_none());

        let stub = read_json(&root, "events/endpoint.get.json");
        let todo = stub["_todo"].as_str().unwrap();
        assert!(todo.contains("declares a streaming response (text/event-stream)"), "{todo}");
        assert!(todo.contains("responseMode in endpoint.get.reference.json"), "{todo}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_streaming_request_body_gets_a_request_mode_without_a_status() {
        let root = temp_project();
        let spec = "paths:\n  /ingest:\n    post:\n      operationId: ingest\n      requestBody:\n        content:\n          application/jsonl: { itemSchema: { type: object } }\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: string } }\n";
        write_spec(&root, &format!("{HEAD}{spec}"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);

        let reference = read_json(&root, "ingest/endpoint.post.reference.json");
        assert!(reference.get("responseMode").is_none());
        let mode = &reference["requestMode"];
        assert_eq!(mode["kind"], "stream");
        assert_eq!(mode["mediaType"], "application/jsonl");
        assert!(mode.get("status").is_none());
        let stub = read_json(&root, "ingest/endpoint.post.json");
        assert!(stub["_todo"].as_str().unwrap().contains("requestMode in endpoint.post.reference.json"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_plain_json_endpoint_has_no_mode_keys_and_the_original_todo_text() {
        let root = temp_project();
        let spec = "paths:\n  /p:\n    get:\n      operationId: p\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: string } }\n";
        write_spec(&root, &format!("{HEAD}{spec}"));
        generate_api_inner(&root).unwrap();
        let reference = read_json(&root, "p/endpoint.get.reference.json");
        assert!(reference.get("responseMode").is_none() && reference.get("requestMode").is_none());
        let stub = read_json(&root, "p/endpoint.get.json");
        assert_eq!(
            stub["_todo"],
            "See endpoint.get.reference.json for available request/response fields. Fill in sources and map each response field to a source path."
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_existing_stubs_todo_is_untouched_when_the_operation_later_becomes_streaming() {
        let root = temp_project();
        let json_spec = "paths:\n  /events:\n    get:\n      operationId: events\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: string } }\n";
        write_spec(&root, &format!("{HEAD}{json_spec}"));
        generate_api_inner(&root).unwrap();
        let before = read_json(&root, "events/endpoint.get.json")["_todo"].clone();

        write_spec(&root, &format!("{HEAD}{STREAMING_SPEC}"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let after = read_json(&root, "events/endpoint.get.json")["_todo"].clone();
        assert_eq!(before, after);
        // ...but the (always regenerated) reference file now describes the stream.
        assert_eq!(read_json(&root, "events/endpoint.get.reference.json")["responseMode"]["kind"], "stream");
        let _ = std::fs::remove_dir_all(&root);
    }

    const BROKEN_MEDIA_REF: &str = "paths:\n  /a:\n    get:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { $ref: '#/components/mediaTypes/Missing' }\n";
    const BROKEN_DEFAULT_MAPPING: &str = "paths:\n  /a:\n    get:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { $ref: '#/components/schemas/V' } }\ncomponents:\n  schemas:\n    V: { oneOf: [ { type: string } ], discriminator: { propertyName: k, defaultMapping: Nope } }\n";
    const BROKEN_SECURITY: &str = "paths:\n  /a:\n    get:\n      operationId: a\n      security: [ { 'https://x/y': [] } ]\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: string } }\n";

    #[test]
    fn strict_mode_aborts_on_each_of_s9_s10_and_s11_before_writing_any_endpoint_file() {
        for (label, body) in [("S9", BROKEN_MEDIA_REF), ("S10", BROKEN_DEFAULT_MAPPING), ("S11", BROKEN_SECURITY)] {
            let root = temp_project();
            make_strict(&root);
            write_spec(&root, &format!("{HEAD}{body}"));
            let outcome = generate_api_inner(&root).unwrap();
            assert!(outcome.strict_aborted, "{label}");
            assert!(!outcome.errors.is_empty(), "{label}");
            assert!(!root.join("api/datasources").exists(), "{label}: nothing may be written");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn non_strict_s9_still_writes_everything_but_reports_an_error() {
        let root = temp_project();
        write_spec(&root, &format!("{HEAD}{BROKEN_MEDIA_REF}"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.strict_aborted);
        assert!(!outcome.errors.is_empty());
        assert!(root.join("api/datasources/endpoints/a/endpoint.get.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_strict_s10_and_s11_are_warnings_only_so_errors_stay_empty() {
        for body in [BROKEN_DEFAULT_MAPPING, BROKEN_SECURITY] {
            let root = temp_project();
            write_spec(&root, &format!("{HEAD}{body}"));
            let outcome = generate_api_inner(&root).unwrap();
            assert!(!outcome.strict_aborted);
            assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
            assert!(root.join("api/datasources/endpoints/a/endpoint.get.json").is_file());
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn w2_w3_and_w4_alone_are_neither_errors_nor_strict_aborts_even_under_strict() {
        let root = temp_project();
        make_strict(&root);
        let spec = "paths:\n  /events:\n    get:\n      operationId: events\n      security: [ { old: [] } ]\n      responses:\n        '200':\n          description: ok\n          content:\n            text/event-stream: {}\n  /upload:\n    post:\n      operationId: upload\n      requestBody:\n        content:\n          multipart/form-data: { schema: { type: object } }\n      responses:\n        '200': { description: ok }\ncomponents:\n  securitySchemes:\n    old: { type: apiKey, in: header, name: k, deprecated: true }\n";
        write_spec(&root, &format!("{HEAD}{spec}"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.strict_aborted);
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(root.join("api/datasources/endpoints/events/endpoint.get.json").is_file());
        assert!(root.join("api/datasources/endpoints/upload/endpoint.post.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn default_mapping_spec(target: &str) -> String {
        format!(
            "{HEAD}paths:\n  /v:\n    get:\n      operationId: v\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: {{ schema: {{ $ref: '#/components/schemas/Vehicle' }} }}\ncomponents:\n  schemas:\n    Car: {{ type: object, properties: {{ vin: {{ type: string }} }} }}\n    Truck: {{ type: object, properties: {{ axles: {{ type: integer }} }} }}\n    Vehicle: {{ oneOf: [ {{ $ref: '#/components/schemas/Car' }}, {{ $ref: '#/components/schemas/Truck' }} ], discriminator: {{ propertyName: kind, defaultMapping: {target} }} }}\n"
        )
    }

    #[test]
    fn a_default_mapping_end_to_end_yields_a_nested_object_stub_and_changing_the_target_regenerates() {
        let root = temp_project();
        write_spec(&root, &default_mapping_spec("Car"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let stub = read_json(&root, "v/endpoint.get.json");
        assert_eq!(stub["response"], serde_json::json!({ "vin": null }));
        let reference = read_json(&root, "v/endpoint.get.reference.json");
        assert_eq!(reference["response"]["$component"], "Car");
        assert!(reference["response"]["$oneOf"].as_str().unwrap().starts_with("oneOf<"));

        write_spec(&root, &default_mapping_spec("Truck"));
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let reference = read_json(&root, "v/endpoint.get.reference.json");
        assert_eq!(reference["response"]["$component"], "Truck");
        assert_eq!(reference["response"]["axles"], "integer");
        let stub = read_json(&root, "v/endpoint.get.json");
        assert_eq!(stub["response"], serde_json::json!({ "axles": null }));
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m2_7_generate_security_tests {
    use super::*;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-generate-m27-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn spec(security: &str) -> String {
        format!(
            "openapi: 3.2.0\ninfo: {{ title: t, version: 1 }}\ncomponents:\n  securitySchemes:\n    a: {{ type: apiKey, in: header, name: k }}\n    b: {{ type: apiKey, in: header, name: k2 }}\npaths:\n  /p:\n    get:\n      operationId: p\n      security: {security}\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: {{ schema: {{ type: string }} }}\n"
        )
    }

    #[test]
    fn a_fresh_generate_bakes_security_so_the_post_write_check_finds_no_mismatch() {
        for security in ["[ { a: [] } ]", "[ { a: [] }, { b: [] } ]", "[ { a: [], b: [] } ]"] {
            let root = temp_project();
            std::fs::write(root.join("openapi.yaml"), spec(security)).unwrap();
            let outcome = generate_api_inner(&root).unwrap();
            assert!(outcome.errors.is_empty(), "{security}: {:?}", outcome.errors);
            let stub = std::fs::read_to_string(root.join("api/datasources/endpoints/p/endpoint.get.json")).unwrap();
            assert!(stub.contains("\"security\": \"a\""), "{stub}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn a_hand_edited_stub_with_security_removed_fails_generate_and_is_left_byte_identical() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), spec("[ { a: [] } ]")).unwrap();
        generate_api_inner(&root).unwrap();
        let stub_path = root.join("api/datasources/endpoints/p/endpoint.get.json");
        let mut stub: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&stub_path).unwrap()).unwrap();
        stub.as_object_mut().unwrap().remove("security");
        let edited = serde_json::to_string_pretty(&stub).unwrap();
        std::fs::write(&stub_path, &edited).unwrap();

        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.strict_aborted);
        assert!(
            outcome.errors.iter().any(|e| e.contains("openapi.yaml requires security ('a')")),
            "{:?}",
            outcome.errors
        );
        assert_eq!(
            std::fs::read_to_string(&stub_path).unwrap(),
            edited,
            "generate never rewrites an existing stub's security"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stub_with_a_different_scheme_than_the_spec_allows_fails_generate() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), spec("[ { a: [] } ]")).unwrap();
        generate_api_inner(&root).unwrap();
        let stub_path = root.join("api/datasources/endpoints/p/endpoint.get.json");
        let text = std::fs::read_to_string(&stub_path).unwrap().replace("\"security\": \"a\"", "\"security\": \"b\"");
        std::fs::write(&stub_path, text).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.iter().any(|e| e.contains("not one openapi.yaml allows")), "{:?}", outcome.errors);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m3_generate_tests {
    use super::*;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-generate-m3-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const WITH_QUERY: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: object, properties: { id: { type: string } } } }\n    query:\n      operationId: queryThings\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: object, properties: { id: { type: string } } } }\n";
    const WITHOUT_QUERY: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: object, properties: { id: { type: string } } } }\n";

    fn endpoints(root: &Path) -> PathBuf {
        root.join("api/datasources/endpoints/things")
    }

    #[test]
    fn a_query_operation_generates_a_stub_and_a_reference_file_named_with_the_lowercase_token() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITH_QUERY).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let dir = endpoints(&root);
        assert!(dir.join("endpoint.query.json").is_file());
        assert!(dir.join("endpoint.query.reference.json").is_file());
        assert!(dir.join("endpoint.get.json").is_file());
        let stub = std::fs::read_to_string(dir.join("endpoint.query.json")).unwrap();
        assert!(stub.contains("queryThings"), "{stub}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hand_edited_query_stub_is_never_overwritten_by_a_second_generate() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITH_QUERY).unwrap();
        generate_api_inner(&root).unwrap();
        let stub_path = endpoints(&root).join("endpoint.query.json");
        let mut edited = std::fs::read_to_string(&stub_path).unwrap();
        edited.push_str("\n\n");
        std::fs::write(&stub_path, &edited).unwrap();
        generate_api_inner(&root).unwrap();
        assert_eq!(std::fs::read_to_string(&stub_path).unwrap(), edited);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn removing_a_query_operation_orphans_its_files_and_putting_it_back_restores_them() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITH_QUERY).unwrap();
        generate_api_inner(&root).unwrap();
        let dir = endpoints(&root);

        std::fs::write(root.join("openapi.yaml"), WITHOUT_QUERY).unwrap();
        generate_api_inner(&root).unwrap();
        assert!(!dir.join("endpoint.query.json").exists());
        assert!(dir.join("_endpoint.query.json").is_file(), "orphaned in place, never deleted");
        assert!(dir.join("endpoint.get.json").is_file(), "the get operation is untouched");

        std::fs::write(root.join("openapi.yaml"), WITH_QUERY).unwrap();
        generate_api_inner(&root).unwrap();
        assert!(dir.join("endpoint.query.json").is_file(), "restored");
        assert!(!dir.join("_endpoint.query.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn write_non_canonical(root: &Path, name: &str) -> PathBuf {
        let dir = root.join("api/datasources/endpoints/gone");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, r#"{ "operationId": "gone", "sources": {}, "response": {} }"#).unwrap();
        path
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_non_canonical_stub_name_is_never_renamed_as_an_orphan_and_is_only_a_warning_outside_strict() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITHOUT_QUERY).unwrap();
        write_non_canonical(&root, "endpoint.GET.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.strict_aborted);
        assert!(outcome.errors.is_empty(), "S12 must not count toward outcome.errors: {:?}", outcome.errors);
        assert_eq!(names_in(&root.join("api/datasources/endpoints/gone")), ["endpoint.GET.json"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_ordinary_lowercase_stub_for_a_removed_path_is_still_orphaned_beside_a_non_canonical_one() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITHOUT_QUERY).unwrap();
        write_non_canonical(&root, "endpoint.Query.json");
        std::fs::write(
            root.join("api/datasources/endpoints/gone/endpoint.get.json"),
            r#"{ "operationId": "gone", "sources": {}, "response": {} }"#,
        )
        .unwrap();
        generate_api_inner(&root).unwrap();
        assert_eq!(names_in(&root.join("api/datasources/endpoints/gone")), ["_endpoint.get.json", "endpoint.Query.json"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn under_strict_a_non_canonical_stub_name_refuses_generate_before_any_write() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITHOUT_QUERY).unwrap();
        std::fs::create_dir_all(root.join("api/config")).unwrap();
        std::fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
        write_non_canonical(&root, "endpoint.GET.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.strict_aborted, "{:?}", outcome.errors);
        assert!(!endpoints(&root).join("endpoint.get.json").exists(), "nothing may be written under a strict refusal");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn plan_endpoint_files_collects_non_canonical_names_with_the_canonical_spelling() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), WITHOUT_QUERY).unwrap();
        write_non_canonical(&root, "endpoint.Query.json");
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        let plan = plan_endpoint_files(&root.join("api"), &doc, &tree_for_tests(&root.join("api/datasources/endpoints")), &test_ctx(&root));
        assert_eq!(plan.invalid_tokens.len(), 1, "{:?}", plan.invalid_tokens);
        assert!(plan.invalid_tokens[0].contains("rename it to endpoint.query.json"), "{}", plan.invalid_tokens[0]);
        assert!(plan.errors.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m4_generate_tests {
    use super::*;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-generate-m4-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RESPONSES: &str = "responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: object, properties: { id: { type: string } } } }\n";

    fn fixed_op(field: &str, id: &str) -> String {
        format!("    {field}:\n      operationId: {id}\n      {RESPONSES}")
    }

    fn additional(entries: &[(&str, &str)]) -> String {
        let mut out = String::from("    additionalOperations:\n");
        for (key, id) in entries {
            out.push_str(&format!(
                "      '{key}':\n        operationId: {id}\n        responses:\n          '200':\n            description: ok\n            content:\n              application/json: {{ schema: {{ type: object, properties: {{ id: {{ type: string }} }} }} }}\n"
            ));
        }
        out
    }

    fn spec_x(body: &str) -> String {
        format!("openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\npaths:\n  /x:\n{body}")
    }

    fn project(spec: &str, server_json: &str) -> PathBuf {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        std::fs::create_dir_all(root.join("api/config")).unwrap();
        std::fs::write(root.join("api/config/server.json"), server_json).unwrap();
        root
    }

    const EXACT: &str = r#"{ "caseSensitiveMethods": true }"#;
    const DEFAULT: &str = r#"{ "caseSensitiveMethods": false }"#;
    const EXACT_STRICT: &str = r#"{ "caseSensitiveMethods": true, "strictOpenApi": true }"#;
    const DEFAULT_STRICT: &str = r#"{ "caseSensitiveMethods": false, "strictOpenApi": true }"#;

    fn dir_x(root: &Path) -> PathBuf {
        root.join("api/datasources/endpoints/x")
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    const STUB: &str = r#"{ "operationId": "hand", "sources": {}, "response": {}, "note": "hand edited" }"#;

    fn put_stub(root: &Path, file: &str) -> PathBuf {
        let dir = dir_x(root);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(file);
        std::fs::write(&path, STUB).unwrap();
        path
    }

    #[test]
    fn query_and_link_operations_get_stub_and_reference_files_named_by_their_file_tokens() {
        let root = project(&spec_x(&(fixed_op("query", "q") + &additional(&[("LINK", "l")]))), DEFAULT);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(
            names_in(&dir_x(&root)),
            [
                "endpoint.LINK.json",
                "endpoint.LINK.reference.json",
                "endpoint.query.json",
                "endpoint.query.reference.json"
            ]
        );
        let stub = std::fs::read_to_string(dir_x(&root).join("endpoint.LINK.json")).unwrap();
        assert!(stub.contains("\"operationId\": \"l\""), "{stub}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exact_mode_writes_escaped_file_names_for_lowercase_and_mixed_case_methods_with_a_w1_only_run_succeeding() {
        let root = project(&spec_x(&additional(&[("purge", "p"), ("Purge", "pp")])), EXACT);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "W1 warnings must not be errors: {:?}", outcome.errors);
        assert_eq!(
            names_in(&dir_x(&root)),
            [
                "endpoint.~_50urge.json",
                "endpoint.~_50urge.reference.json",
                "endpoint.~purge.json",
                "endpoint.~purge.reference.json"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_lowercase_purge_stub_where_purge_uppercase_is_needed_is_a_case_conflict_and_nothing_is_written() {
        let root = project(&spec_x(&additional(&[("purge", "p")])), DEFAULT);
        let existing = put_stub(&root, "endpoint.purge.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "a case conflict must fail generate");
        assert!(
            outcome
                .errors
                .iter()
                .any(|e| e.contains("endpoint.purge.json exists where endpoint.PURGE.json is needed")),
            "{:?}",
            outcome.errors
        );
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.purge.json"], "nothing may be created, renamed or orphaned");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn switching_from_default_to_exact_with_an_old_upper_stub_reports_that_the_old_route_is_still_served_and_touches_nothing() {
        let root = project(&spec_x(&additional(&[("purge", "p")])), EXACT);
        let existing = put_stub(&root, "endpoint.PURGE.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.strict_aborted);
        let message = outcome
            .errors
            .iter()
            .find(|e| e.contains("STILL BEING SERVED"))
            .unwrap_or_else(|| panic!("{:?}", outcome.errors));
        assert!(
            message.contains("endpoint.PURGE.json (method 'PURGE') vs openapi.yaml's 'purge' on /x under caseSensitiveMethods=true"),
            "{message}"
        );
        assert!(message.contains("requests sending 'purge' get 405"), "{message}");
        assert!(message.contains("endpoint.~purge.json"), "{message}");
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.PURGE.json"], "no stub, no reference, no orphan, no rename");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn switching_from_exact_to_default_with_an_old_tilde_stub_reports_the_rename_hint_and_touches_nothing() {
        let root = project(&spec_x(&additional(&[("purge", "p")])), DEFAULT);
        let existing = put_stub(&root, "endpoint.~purge.json");
        let outcome = generate_api_inner(&root).unwrap();
        let message = outcome
            .errors
            .iter()
            .find(|e| e.contains("rename the file to endpoint.PURGE.json by hand"))
            .unwrap_or_else(|| panic!("{:?}", outcome.errors));
        assert!(
            message.contains("endpoint.~purge.json (method 'purge') vs openapi.yaml's 'PURGE' on /x under caseSensitiveMethods=false"),
            "{message}"
        );
        assert!(!message.contains("STILL BEING SERVED"), "the old file is not served in this mode: {message}");
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.~purge.json"]);
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn under_strict_a_mode_switch_mismatch_refuses_generate_before_any_write() {
        for (server, spec_key, stale) in [(EXACT_STRICT, "purge", "endpoint.PURGE.json"), (DEFAULT_STRICT, "purge", "endpoint.~purge.json")] {
            let root = project(&spec_x(&(fixed_op("get", "g") + &additional(&[(spec_key, "p")]))), server);
            put_stub(&root, stale);
            let outcome = generate_api_inner(&root).unwrap();
            assert!(outcome.strict_aborted, "{server}: {:?}", outcome.errors);
            assert_eq!(names_in(&dir_x(&root)), [stale], "{server}: nothing generated, not even the unrelated get");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn duplicate_case_variant_keys_write_nothing_leave_the_existing_stub_byte_identical_and_fail_generate() {
        let root = project(&spec_x(&additional(&[("purge", "a"), ("PURGE", "b")])), DEFAULT);
        let existing = put_stub(&root, "endpoint.PURGE.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "the S4 issue is an error");
        assert!(outcome.errors.iter().any(|e| e.contains("'purge'") && e.contains("'PURGE'")), "{:?}", outcome.errors);
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.PURGE.json"], "not orphaned, no reference, nothing new");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_case_variant_keys_with_no_existing_file_create_nothing_for_that_method() {
        let root = project(&spec_x(&(additional(&[("purge", "a"), ("PURGE", "b"), ("LINK", "l")]))), DEFAULT);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty());
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.LINK.json", "endpoint.LINK.reference.json"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fixed_name_collision_key_leaves_an_existing_get_stub_unorphaned() {
        let root = project(&spec_x(&additional(&[("get", "g")])), DEFAULT);
        let existing = put_stub(&root, "endpoint.get.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "the S4 issue is an error");
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.get.json"], "protected from orphaning");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_genuine_get_operation_is_still_generated_when_an_additional_key_collides_with_it() {
        let root = project(&spec_x(&(fixed_op("get", "g") + &additional(&[("get", "dup")]))), DEFAULT);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.errors.is_empty(), "the colliding key is still an error");
        let stub = std::fs::read_to_string(dir_x(&root).join("endpoint.get.json")).unwrap();
        assert!(stub.contains("\"operationId\": \"g\""), "{stub}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_wrong_mode_file_with_no_counterpart_is_a_warning_left_alone_and_a_plan_entry() {
        let root = project("openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n", DEFAULT);
        let existing = put_stub(&root, "endpoint.~purge.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(!outcome.strict_aborted);
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.~purge.json"], "never orphaned");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        let plan = plan_endpoint_files(&root.join("api"), &doc, &tree_for_tests(&root.join("api/datasources/endpoints")), &test_ctx(&root));
        assert_eq!(plan.wrong_mode.len(), 1, "{:?}", plan.wrong_mode);
        assert!(
            plan.wrong_mode[0].contains("case-distinct") && plan.wrong_mode[0].contains("caseSensitiveMethods is false"),
            "{}",
            plan.wrong_mode[0]
        );
        assert!(plan.invalid_tokens.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn under_strict_a_wrong_mode_file_with_no_counterpart_refuses_generate_and_generates_nothing_else() {
        let root = project(&spec_x(&fixed_op("get", "g")), DEFAULT_STRICT);
        let other = root.join("api/datasources/endpoints/other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("endpoint.~purge.json"), STUB).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.strict_aborted);
        assert!(!dir_x(&root).exists(), "nothing generated under a strict refusal");
        assert_eq!(names_in(&other), ["endpoint.~purge.json"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_token_files_such_as_endpoint_get_upper_and_mixed_are_never_orphaned_or_restored() {
        let root = project("openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n", DEFAULT);
        // One folder per spelling so the fixture stays unique after case folding on every OS.
        for (folder, file) in [
            ("g1", "endpoint.GET.json"),
            ("g2", "endpoint.Get.json"),
            ("g3", "endpoint.purge.json"),
            ("g4", "endpoint.~_47_45_54.json"),
        ] {
            let dir = root.join("api/datasources/endpoints").join(folder);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(file), STUB).unwrap();
            // and an orphaned twin that must not be restored even when the spec asks for the method
            std::fs::write(dir.join(format!("_{file}")), STUB).unwrap();
        }
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        for (folder, file) in [
            ("g1", "endpoint.GET.json"),
            ("g2", "endpoint.Get.json"),
            ("g3", "endpoint.purge.json"),
            ("g4", "endpoint.~_47_45_54.json"),
        ] {
            let dir = root.join("api/datasources/endpoints").join(folder);
            assert_eq!(names_in(&dir), [format!("_{file}"), file.to_string()], "{folder}");
        }

        // The spec now declares get on /g1, but the orphan twin `_endpoint.GET.json` blocks the name: nothing is restored or created.
        let spec = "openapi: 3.2.0
info: { title: t, version: '1' }
paths:
  /g1:
    get:
      operationId: g1
      responses: { '200': { description: ok } }
";
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        let dir = root.join("api/datasources/endpoints/g1");
        std::fs::remove_file(dir.join("endpoint.GET.json")).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(
            outcome
                .errors
                .iter()
                .any(|e| e.contains("_endpoint.GET.json exists where _endpoint.get.json is needed")),
            "{:?}",
            outcome.errors
        );
        assert_eq!(names_in(&dir), ["_endpoint.GET.json"], "the invalid orphan twin is neither restored nor renamed");
        assert_eq!(std::fs::read_to_string(dir.join("_endpoint.GET.json")).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn round_trip(spec_key_lines: &str, server_json: &str, expected_files: &[&str]) {
        let root = project(&spec_x(spec_key_lines), server_json);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let dir = dir_x(&root);
        let stub_name = expected_files[0];
        assert!(dir.join(stub_name).is_file(), "{:?}", names_in(&dir));
        let original: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join(stub_name)).unwrap()).unwrap();
        // remove the path from the spec
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        generate_api_inner(&root).unwrap();
        assert!(!dir.join(stub_name).exists(), "{stub_name} should be orphaned: {:?}", names_in(&dir));
        assert!(dir.join(format!("_{stub_name}")).is_file(), "{:?}", names_in(&dir));
        // and bring it back
        std::fs::write(root.join("openapi.yaml"), spec_x(spec_key_lines)).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(!dir.join(format!("_{stub_name}")).exists(), "{:?}", names_in(&dir));
        let restored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join(stub_name)).unwrap()).unwrap();
        assert_eq!(restored, original, "the restored stub is the orphaned one");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_then_restore_round_trips_link_in_default_mode() {
        round_trip(&additional(&[("LINK", "l")]), DEFAULT, &["endpoint.LINK.json"]);
    }

    #[test]
    fn orphan_then_restore_round_trips_query_and_get_in_both_modes() {
        for server in [DEFAULT, EXACT] {
            round_trip(&fixed_op("query", "q"), server, &["endpoint.query.json"]);
            round_trip(&fixed_op("get", "g"), server, &["endpoint.get.json"]);
        }
    }

    #[test]
    fn orphan_then_restore_round_trips_tilde_and_escaped_tokens_in_exact_mode() {
        round_trip(&additional(&[("purge", "p")]), EXACT, &["endpoint.~purge.json"]);
        round_trip(&additional(&[("Purge", "p")]), EXACT, &["endpoint.~_50urge.json"]);
        round_trip(&additional(&[("get", "g")]), EXACT, &["endpoint.~get.json"]);
        round_trip(&additional(&[("X.Y", "xy")]), DEFAULT, &["endpoint.~_58_2e_59.json"]);
    }

    #[test]
    fn a_stub_generated_under_exact_mode_is_neither_orphaned_nor_renamed_when_the_mode_flips_to_default() {
        // generated under exact, mode flipped to default: ~purge is WrongMode, PURGE is a brand-new method.
        let root = project(&spec_x(&additional(&[("purge", "p")])), EXACT);
        generate_api_inner(&root).unwrap();
        let dir = dir_x(&root);
        std::fs::write(root.join("api/config/server.json"), DEFAULT).unwrap();
        let outcome = generate_api_inner(&root).unwrap();
        assert!(
            outcome.errors.iter().any(|e| e.contains("rename the file to endpoint.PURGE.json by hand")),
            "{:?}",
            outcome.errors
        );
        assert!(dir.join("endpoint.~purge.json").is_file());
        assert!(!dir.join("endpoint.PURGE.json").exists());
        assert!(!dir.join("_endpoint.~purge.json").exists(), "a wrong-mode file is never orphaned");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stale_get_stub_with_a_spec_declaring_only_an_exact_mode_lowercase_get_is_a_strict_mismatch_and_is_left_alone() {
        let root = project(&spec_x(&additional(&[("get", "lower")])), EXACT);
        let existing = put_stub(&root, "endpoint.get.json");
        let outcome = generate_api_inner(&root).unwrap();
        let message = outcome
            .errors
            .iter()
            .find(|e| e.contains("endpoint.get.json (method 'GET')"))
            .unwrap_or_else(|| panic!("{:?}", outcome.errors));
        assert!(message.contains("vs openapi.yaml's 'get' on /x under caseSensitiveMethods=true"), "{message}");
        assert!(message.contains("STILL BEING SERVED"), "{message}");
        assert!(message.contains("endpoint.~get.json"), "{message}");
        assert_eq!(names_in(&dir_x(&root)), ["endpoint.get.json"], "nothing created, nothing orphaned");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_genuine_get_and_a_lowercase_get_in_exact_mode_each_get_their_own_stub_without_any_mismatch() {
        let root = project(&spec_x(&(fixed_op("get", "upper") + &additional(&[("get", "lower")]))), EXACT);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(
            names_in(&dir_x(&root)),
            [
                "endpoint.get.json",
                "endpoint.get.reference.json",
                "endpoint.~get.json",
                "endpoint.~get.reference.json"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- round 2 ----

    fn tree_names(root: &Path) -> Vec<String> {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    out.push(path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let mut out = Vec::new();
        walk(&root.join("api"), root, &mut out);
        out.sort();
        out
    }

    fn fs_is_case_sensitive(dir: &Path) -> bool {
        let probe = dir.join("case_probe_a");
        std::fs::write(&probe, b"").unwrap();
        let sensitive = !dir.join("CASE_PROBE_A").exists();
        std::fs::remove_file(&probe).unwrap();
        sensitive
    }

    #[test]
    fn golden_file_tree_for_extension_methods_in_exact_mode_is_identical_on_every_os() {
        let root = project(
            &spec_x(&(fixed_op("query", "q") + &additional(&[("LINK", "l"), ("purge", "p"), ("x.y", "xy")]))),
            EXACT,
        );
        let first = generate_api_inner(&root).unwrap();
        assert!(first.errors.is_empty(), "{:?}", first.errors);
        let run1 = [
            "api/config/connections.json",
            "api/config/errors/core.json",
            "api/config/server.json",
            "api/datasources/endpoints/x/endpoint.LINK.json",
            "api/datasources/endpoints/x/endpoint.LINK.reference.json",
            "api/datasources/endpoints/x/endpoint.query.json",
            "api/datasources/endpoints/x/endpoint.query.reference.json",
            "api/datasources/endpoints/x/endpoint.~purge.json",
            "api/datasources/endpoints/x/endpoint.~purge.reference.json",
            "api/datasources/endpoints/x/endpoint.~x_2ey.json",
            "api/datasources/endpoints/x/endpoint.~x_2ey.reference.json",
            "api/security/schemes.json",
        ];
        assert_eq!(tree_names(&root), run1.to_vec());

        // Content is byte-for-byte stable too: LF line endings only, and the exact stub text.
        for name in run1 {
            let bytes = std::fs::read(root.join(name)).unwrap();
            assert!(!bytes.contains(&b'\r'), "{name} contains a CR");
        }
        let link = std::fs::read_to_string(root.join("api/datasources/endpoints/x/endpoint.LINK.json")).unwrap();
        assert_eq!(
            link,
            "{\n  \"operationId\": \"l\",\n  \"_generated\": true,\n  \"_todo\": \"See endpoint.LINK.reference.json for available request/response fields. Fill in sources and map each response field to a source path.\",\n  \"sources\": {},\n  \"response\": {\n    \"id\": null\n  }\n}"
        );
        let escaped = std::fs::read_to_string(root.join("api/datasources/endpoints/x/endpoint.~x_2ey.json")).unwrap();
        assert!(escaped.contains("See endpoint.~x_2ey.reference.json"), "{escaped}");

        // Dropping `purge` orphans exactly its two files, in place.
        std::fs::write(
            root.join("openapi.yaml"),
            spec_x(&(fixed_op("query", "q") + &additional(&[("LINK", "l"), ("x.y", "xy")]))),
        )
        .unwrap();
        let second = generate_api_inner(&root).unwrap();
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        let mut run2: Vec<&str> = run1.iter().copied().filter(|n| !n.contains("~purge")).collect();
        run2.push("api/datasources/endpoints/x/_endpoint.~purge.json");
        run2.push("api/datasources/endpoints/x/_endpoint.~purge.reference.json");
        run2.sort();
        assert_eq!(tree_names(&root), run2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn golden_file_tree_for_the_same_spec_in_default_mode_uses_uppercase_and_escaped_tokens() {
        let root = project(&spec_x(&additional(&[("link", "l"), ("x.y", "xy")])), DEFAULT);
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let names = tree_names(&root);
        for expected in [
            "api/datasources/endpoints/x/endpoint.LINK.json",
            "api/datasources/endpoints/x/endpoint.LINK.reference.json",
            "api/datasources/endpoints/x/endpoint.~_58_2e_59.json",
            "api/datasources/endpoints/x/endpoint.~_58_2e_59.reference.json",
        ] {
            assert!(names.contains(&expected.to_string()), "{expected} missing from {names:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn coexisting_purge_files_in_default_mode_leave_both_untouched_and_generate_neither_orphans_nor_renames() {
        let root = project(&spec_x(&additional(&[("purge", "p")])), DEFAULT);
        if !fs_is_case_sensitive(&root) {
            eprintln!("skipping: case-insensitive filesystem, endpoint.purge.json and endpoint.PURGE.json cannot coexist");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        put_stub(&root, "endpoint.PURGE.json");
        put_stub(&root, "endpoint.purge.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let names = names_in(&dir_x(&root));
        assert!(
            names.contains(&"endpoint.PURGE.json".to_string()) && names.contains(&"endpoint.purge.json".to_string()),
            "{names:?}"
        );
        // `_backups/` is generate's own migration backup folder, not an orphan.
        assert!(!names.iter().any(|n| n.starts_with("_endpoint.")), "nothing orphaned: {names:?}");
        assert!(!names.iter().any(|n| n.contains('~')), "nothing created for another mode: {names:?}");
        // The canonical stub may be migrated (it has no recorded hash); the
        // non-canonical twin is never served, so it must never be touched.
        assert_eq!(std::fs::read_to_string(dir_x(&root).join("endpoint.purge.json")).unwrap(), STUB);
        assert!(!names.contains(&"endpoint.purge.reference.json".to_string()), "{names:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn coexisting_get_and_upper_get_files_are_both_left_alone_when_the_spec_still_declares_get() {
        let root = project(&spec_x(&fixed_op("get", "g")), DEFAULT);
        if !fs_is_case_sensitive(&root) {
            eprintln!("skipping: case-insensitive filesystem, endpoint.get.json and endpoint.GET.json cannot coexist");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        put_stub(&root, "endpoint.get.json");
        put_stub(&root, "endpoint.GET.json");
        let outcome = generate_api_inner(&root).unwrap();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let names = names_in(&dir_x(&root));
        assert!(
            names.contains(&"endpoint.get.json".to_string()) && names.contains(&"endpoint.GET.json".to_string()),
            "{names:?}"
        );
        // `_backups/` is generate's own migration backup folder, not an orphan.
        assert!(!names.iter().any(|n| n.starts_with("_endpoint.")), "{names:?}");
        assert_eq!(
            std::fs::read_to_string(dir_x(&root).join("endpoint.GET.json")).unwrap(),
            STUB,
            "the non-canonical twin is never touched"
        );
        assert!(!names.contains(&"endpoint.GET.reference.json".to_string()), "{names:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_twins_differing_only_in_case_restore_only_the_canonical_one() {
        let root = project(&spec_x(&fixed_op("get", "g")), DEFAULT);
        if !fs_is_case_sensitive(&root) {
            eprintln!("skipping: case-insensitive filesystem, _endpoint.GET.json and _endpoint.get.json cannot coexist");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        put_stub(&root, "_endpoint.get.json");
        put_stub(&root, "_endpoint.GET.json");
        let outcome = generate_api_inner(&root).unwrap();
        let names = names_in(&dir_x(&root));
        eprintln!("errors={:?} names={names:?}", outcome.errors);
        assert!(names.contains(&"endpoint.get.json".to_string()), "the canonical orphan is restored: {names:?}");
        assert!(names.contains(&"_endpoint.GET.json".to_string()), "the invalid twin is never touched: {names:?}");
        assert!(!names.contains(&"_endpoint.get.json".to_string()), "{names:?}");
        assert!(!names.contains(&"endpoint.GET.json".to_string()), "{names:?}");
        assert_eq!(std::fs::read_to_string(dir_x(&root).join("_endpoint.GET.json")).unwrap(), STUB);
        let _ = std::fs::remove_dir_all(&root);
    }
}
