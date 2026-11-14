//! The read-only tools that only look at files: `project_describe`, `endpoint_reference`, `errors_discovered`.
//! Every output is built field by field from an allowlist; nothing here returns a raw config file.

use std::io::Read;
use std::path::Path;

use serde_json::{Value, json};

use super::tools::ToolFailure;
use crate::commands::report::CommandError;
use crate::config::Config;
use crate::errors::{DiscoveredErrors, ErrorRegistry};
use crate::openapi::method_token::{self, MethodCase};
use crate::project::{MANIFEST_FILE, api_base};

const MAX_REFERENCE_BYTES: u64 = 1024 * 1024;
const SAMPLE_MESSAGE_CHARS: usize = 500;

pub(super) fn failure(error: CommandError) -> ToolFailure {
    ToolFailure {
        kind: error.kind.as_str(),
        message: error.message,
        exit_code: error.exit_code,
    }
}

fn load_config(root: &Path) -> Result<Config, ToolFailure> {
    let api_dir = api_base(root);
    Config::load(&api_dir).map_err(|err| failure(CommandError::config_load(&api_dir, err)))
}

fn relative_display(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn project_describe(root: &Path) -> Result<Value, ToolFailure> {
    let has_api = root.join(MANIFEST_FILE).is_file();
    let has_web = root.join("webserve.json").is_file();
    let mut out = json!({
        "root": root.display().to_string(),
        "roles": { "api": has_api, "web": has_web },
    });
    if !has_api {
        return Ok(out);
    }
    let config = load_config(root)?;
    let mode = MethodCase::from_case_sensitive(config.server.case_sensitive_methods());

    let mut connections: Vec<(&String, &str)> = config.connections.iter().map(|(name, c)| (name, c.driver.as_str())).collect();
    connections.sort();
    let mut schemes: Vec<&String> = config.security.schemes.keys().collect();
    schemes.sort();

    out["apiRoot"] = json!(config.server.api_root);
    out["port"] = json!(config.server.port);
    out["features"] = serde_json::to_value(&config.server.features).unwrap_or(Value::Null);
    out["strictOpenApi"] = json!(config.server.strict_open_api());
    out["endpointSymlinks"] = json!(config.server.endpoint_symlinks().as_str());
    out["caseSensitiveMethods"] = json!(config.server.case_sensitive_methods());
    out["connections"] = Value::Array(connections.into_iter().map(|(name, driver)| json!({ "name": name, "driver": driver })).collect());
    out["schemes"] = json!(schemes);

    let tree = crate::commands::run::scan_endpoint_tree(root, &config.server);
    let mut endpoints = crate::endpoint::endpoint_summaries(&tree, mode);
    for (url_path, token, file) in crate::endpoint::discover_endpoint_files(&tree, mode) {
        let path = crate::endpoint::mock::openapi_style_path(&url_path);
        let method = method_token::display_token(&token);
        let Some(summary) = endpoints.iter_mut().find(|e| e["path"] == json!(path) && e["method"] == json!(method)) else {
            continue;
        };
        let parent = file.parent().unwrap_or(Path::new(""));
        summary["hasTestFile"] = json!(tree.file_in(parent, &format!("endpoint.{token}.test.json")).is_some());
        summary["hasReferenceFile"] = json!(tree.file_in(parent, &format!("endpoint.{token}.reference.json")).is_some());
    }
    out["endpoints"] = Value::Array(endpoints);

    out["spec"] = match crate::openapi::load(&root.join(MANIFEST_FILE), config.server.openapi_load_options()) {
        Ok(doc) => json!({
            "loaded": true,
            "operationCount": doc.operations.len(),
            "issues": doc.issues.iter().map(|issue| json!({
                "severity": if issue.severity == crate::openapi::Severity::Error { "error" } else { "warning" },
                "message": issue.message,
            })).collect::<Vec<_>>(),
        }),
        Err(e) => json!({
            "loaded": false,
            "operationCount": 0,
            "issues": [{ "severity": "error", "message": e.to_string() }],
        }),
    };
    Ok(out)
}

/// Finds the reference file by comparing `path`/`method` against the scanned tree's own entries; the arguments are never joined onto a path.
pub(super) fn endpoint_reference(root: &Path, path: &str, method: &str) -> Result<Value, ToolFailure> {
    let config = load_config(root)?;
    let mode = MethodCase::from_case_sensitive(config.server.case_sensitive_methods());
    let not_found = || ToolFailure {
        kind: "notFound",
        message: "no reference file for that path and method — run `frogs generate` to create it".to_string(),
        exit_code: 1,
    };
    let Ok(token) = method_token::normalize_cli_method(method, mode) else {
        return Err(not_found());
    };
    let wanted_name = format!("endpoint.{}.reference.json", token.file_token());
    let tree = crate::commands::run::scan_endpoint_tree(root, &config.server);
    let Some(entry) = tree
        .files()
        .iter()
        .find(|file| file.name == wanted_name && crate::commands::test::display_path(tree.endpoints_root(), &file.logical) == path)
    else {
        return Err(not_found());
    };

    let mut bytes = Vec::new();
    std::fs::File::open(&entry.logical)
        .and_then(|file| file.take(MAX_REFERENCE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| ToolFailure {
            kind: "io",
            message: format!("cannot read the reference file: {e}"),
            exit_code: 1,
        })?;
    if bytes.len() as u64 > MAX_REFERENCE_BYTES {
        return Err(ToolFailure {
            kind: "tooLarge",
            message: format!("the reference file is over {MAX_REFERENCE_BYTES} bytes"),
            exit_code: 1,
        });
    }
    let reference: Value = serde_json::from_slice(&bytes).map_err(|e| ToolFailure {
        kind: "parse",
        message: format!(
            "the reference file is not valid JSON: {}",
            if entry.via_link {
                crate::openapi::endpoint_tree::parse_error_summary(&e)
            } else {
                e.to_string()
            }
        ),
        exit_code: 1,
    })?;
    Ok(json!({
        "path": path,
        "method": method_token::display_token(&token.file_token()),
        "file": relative_display(root, &entry.logical),
        "reference": reference,
    }))
}

pub(super) fn errors_discovered(root: &Path) -> Result<Value, ToolFailure> {
    let config_dir = api_base(root).join("config");
    let registry = ErrorRegistry::load(&config_dir.join("errors")).map_err(|e| ToolFailure {
        kind: "config",
        message: e.to_string(),
        exit_code: crate::exit_codes::config_refusal_exit(),
    })?;
    let loaded = DiscoveredErrors::load_strict(&config_dir.join("errors.discovered.json")).map_err(|e| ToolFailure {
        kind: "io",
        message: format!("cannot read errors.discovered.json: {e}"),
        exit_code: 1,
    })?;
    let discovered = match loaded {
        Ok(discovered) => discovered,
        Err(message) => return Ok(json!({ "corrupt": true, "message": message })),
    };
    let entries: Vec<Value> = discovered
        .entries()
        .into_iter()
        .map(|(code, entry)| {
            let sample: String = entry.sample_message.chars().take(SAMPLE_MESSAGE_CHARS).collect();
            json!({
                "code": code,
                "httpStatus": entry.http_status,
                "exposeDetail": entry.expose_detail,
                "occurrences": entry.occurrences,
                "firstSeen": entry.first_seen.to_rfc3339(),
                "lastSeen": entry.last_seen.to_rfc3339(),
                "sampleMessage": sample,
                "alreadyInRegistry": registry.get(code).is_some(),
            })
        })
        .collect();
    Ok(json!({ "corrupt": false, "entries": entries }))
}
