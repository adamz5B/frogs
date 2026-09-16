use std::fs;
use std::io;
use std::path::{Path, PathBuf};
// Only the systemd/launchd backends below shell out to an external command
// (`systemctl`/`launchctl`) — `windows_svc` talks to the SCM directly via
// the `windows-service` crate, so this import would otherwise go unused on
// a Windows build.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Named the same way a systemd unit/launchd label/scheduled-task name is —
/// always `frogs-<ident>`, never the bare identifier, so a probe of the
/// target platform can recognize "this looks like something frogs itself
/// created" purely from the name, before ever reading the definition's own
/// content.
const FROGS_PREFIX: &str = "frogs-";

/// Embedded in every rendered definition (a leading unit-file comment, a
/// plist dictionary key, an XML `<Source>` element) so a later probe can
/// tell "frogs created this" apart from "something else happens to be
/// registered under this exact name" — see `decide_collision`.
const FROGS_MARKER: &str = "frogs-register";

/// `--user`/`--system` scope, as chosen at `frogs register` time and
/// recorded in `.frogs/service.json` — every later operation
/// (start/stop/restart/uninstall) re-derives the definition's location from
/// this rather than the caller re-guessing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceScope {
    User,
    System,
}

pub fn scope_label(scope: ServiceScope) -> &'static str {
    match scope {
        ServiceScope::User => "user",
        ServiceScope::System => "system",
    }
}

/// Whether a registered service should start automatically at boot/login
/// going forward (the OS's own `systemctl enable`/launchd `RunAtLoad`/
/// Windows `ServiceStartType::AutoStart` concept) or only when started
/// explicitly (`OnDemand`/not-enabled/`RunAtLoad=false`) — chosen once at
/// `frogs register` time. Either way, `frogs register` still starts the
/// service once immediately (per this project's existing "register implies
/// start" decision); `Manual` only changes what happens on the *next* boot
/// or login, not whether it starts right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StartType {
    Automatic,
    Manual,
}

/// Whether a registered service should be automatically restarted by the OS
/// after it exits with a failure — chosen once at `frogs register` time,
/// applied consistently across all three backends (systemd `Restart=`,
/// launchd `KeepAlive`, Windows `SERVICE_CONFIG_FAILURE_ACTIONS`). A
/// *deliberate* stop (`frogs stop`/`frogs unregister`, or the platform's own
/// stop command) never triggers a restart on any backend regardless of this
/// setting — only an unrequested/failure exit does. Defaults to
/// `OnFailure`: crash recovery is standard practice for a production service
/// manager (this is what every one of systemd/launchd/a real Windows Service
/// supports natively, and what a comparable production server like Tomcat/
/// WildFly is normally configured with), so opting out is the exceptional
/// case, not the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RestartPolicy {
    OnFailure,
    Never,
}

/// Which platform-native supervisor a `ServiceRecord` was registered
/// against — decided once, at `frogs register` time, by the OS the binary
/// is actually running on; never user-selectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Systemd,
    Launchd,
    WindowsService,
}

pub fn backend_label(backend: Backend) -> &'static str {
    match backend {
        Backend::Systemd => "systemd",
        Backend::Launchd => "launchd",
        Backend::WindowsService => "Windows Service",
    }
}

/// What `frogs register` writes to `.frogs/service.json` on success, and
/// every later `frogs run`/`frogs stop`/`frogs unregister` reads back.
/// Unlike `pidfile::RunInfo` — rewritten every `frogs run`, meaningless
/// once the process exits — this file deliberately persists across runs:
/// it's the durable record of "this project has a service registered
/// somewhere," not ephemeral process state.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRecord {
    pub name: String,
    pub scope: ServiceScope,
    pub backend: Backend,
    pub definition_path: String,
    /// The resolved Windows account this service runs as (e.g. `NT
    /// AUTHORITY\LocalService`, or a custom account name) — `None` for
    /// `Systemd`/`Launchd` records, which have no equivalent concept.
    pub account: Option<String>,
    /// The Windows service description actually applied (`services.msc`'s
    /// "Description" column / `sc qdescription`) — `None` for
    /// `Systemd`/`Launchd` records, which have no equivalent field.
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

fn runtime_dir(project_root: &Path) -> PathBuf {
    project_root.join(".frogs")
}

pub fn path(project_root: &Path) -> PathBuf {
    runtime_dir(project_root).join("service.json")
}

pub fn write_record(project_root: &Path, record: &ServiceRecord) -> io::Result<()> {
    fs::create_dir_all(runtime_dir(project_root))?;
    let json = serde_json::to_string_pretty(record).expect("ServiceRecord always serializes");
    fs::write(path(project_root), json)
}

/// `None` covers both "never registered here" and "the file is corrupt" —
/// same collapsing rule as `pidfile::read`, for the same reason: neither
/// case gives a caller anything to act on beyond "there is no record."
pub fn read_record(project_root: &Path) -> io::Result<Option<ServiceRecord>> {
    match fs::read_to_string(path(project_root)) {
        Ok(contents) => Ok(serde_json::from_str(&contents).ok()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn remove_record(project_root: &Path) -> io::Result<()> {
    match fs::remove_file(path(project_root)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// Naming / sanitization
// ---------------------------------------------------------------------------

fn is_allowed_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

/// An auto-derived name (the project folder's own name, with no `--name`
/// given) is sanitized rather than rejected outright — a folder name is
/// something the user already picked for an unrelated reason (their OS's
/// own naming rules), not something they typed specifically to become a
/// service identifier, so mangling it into something usable is friendlier
/// than making every oddly-named project folder unregisterable.
pub fn sanitize_derived(folder_name: &str) -> Result<String, String> {
    let mut collapsed = String::with_capacity(folder_name.len());
    let mut prev_dash = false;
    for c in folder_name.chars() {
        let mapped = if is_allowed_name_char(c) { c } else { '-' };
        if mapped == '-' {
            if prev_dash {
                continue;
            }
            prev_dash = true;
        } else {
            prev_dash = false;
        }
        collapsed.push(mapped);
    }

    let trimmed = collapsed.trim_matches(|c: char| c == '-' || c == '.');
    if trimmed.is_empty() {
        return Err(format!("\"{folder_name}\" has no usable characters left for a service identifier after sanitization"));
    }
    if trimmed.len() > 200 {
        return Err(format!("sanitized service identifier is too long ({} chars, max 200)", trimmed.len()));
    }
    Ok(trimmed.to_string())
}

/// An explicit `--name` is something the user typed specifically for this
/// purpose — a disallowed character there is a mistake worth surfacing
/// clearly, not something to silently mangle the way `sanitize_derived`
/// does for an auto-derived folder name.
pub fn validate_explicit(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("--name must not be empty".to_string());
    }
    if name.len() > 200 {
        return Err(format!("--name is too long ({} chars, max 200)", name.len()));
    }
    if let Some(bad) = name.chars().find(|c| !is_allowed_name_char(*c)) {
        return Err(format!(
            "--name contains disallowed character '{bad}' — only ASCII letters, digits, '-', '_', and '.' are allowed"
        ));
    }
    Ok(name.to_string())
}

/// Dispatches to `validate_explicit` (an explicit `--name`) or
/// `sanitize_derived` (the project root's own final path component), then
/// prepends the fixed `frogs-` prefix — never left to the caller to add
/// itself, so it's never accidentally duplicated or forgotten.
pub fn service_name(root: &Path, explicit: Option<&str>) -> Result<String, String> {
    let ident = match explicit {
        Some(name) => validate_explicit(name)?,
        None => {
            let folder_name = root
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("project root {} has no usable final path component to derive a service name from", root.display()))?;
            sanitize_derived(folder_name)?
        }
    };
    Ok(format!("{FROGS_PREFIX}{ident}"))
}

/// A structural gate — mirrors `pidfile::is_plausible_pid`'s role: a cheap,
/// non-negotiable check run before `record.name` ever reaches an OS
/// command, independent of whatever wrote `.frogs/service.json` (a past
/// version of this binary, or a hand-edit).
pub fn is_plausible_service_name(name: &str) -> bool {
    match name.strip_prefix(FROGS_PREFIX) {
        Some(rest) => !rest.is_empty() && rest.len() <= 200 && rest.chars().all(is_allowed_name_char),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Collision detection
// ---------------------------------------------------------------------------

/// What a fresh probe of the target platform found under a candidate name —
/// read from the actual unit file/plist/Task Scheduler XML, never a local
/// cache, so a definition changed or removed outside frogs is always seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingDefinition {
    pub working_directory: PathBuf,
    pub has_frogs_marker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collision {
    None,
    Idempotent,
    Conflict { other_root: Option<PathBuf> },
}

/// Windows paths are case-insensitive at the filesystem level, so comparing
/// a recorded `WorkingDirectory` against the current project root
/// case-sensitively there would report a false conflict for a project
/// whose path merely differs in case from how it was originally
/// registered; Linux/macOS paths are case-sensitive, so no such folding
/// applies there.
#[cfg(windows)]
fn paths_match(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

#[cfg(not(windows))]
fn paths_match(a: &Path, b: &Path) -> bool {
    a == b
}

/// Four-branch decision, deliberately not collapsed further: an existing
/// definition with *no* frogs marker is a hard conflict regardless of
/// working directory — it might be a real, unrelated systemd unit/plist/
/// scheduled task that just happens to share this name, and frogs must
/// never overwrite something it didn't create, even if the paths happen to
/// line up.
pub fn decide_collision(existing: Option<ExistingDefinition>, current_root: &Path) -> Collision {
    let Some(def) = existing else {
        return Collision::None;
    };
    if !def.has_frogs_marker {
        return Collision::Conflict {
            other_root: Some(def.working_directory),
        };
    }
    if paths_match(&def.working_directory, current_root) {
        Collision::Idempotent
    } else {
        Collision::Conflict {
            other_root: Some(def.working_directory),
        }
    }
}

// ---------------------------------------------------------------------------
// Escaping / path safety
// ---------------------------------------------------------------------------

/// systemd's unit-file "specifier" escaping — a bare `%` is otherwise
/// expanded by systemd itself (`%h`, `%i`, ...), so a project path that
/// happens to contain one must have it doubled before it's ever written
/// into `WorkingDirectory=`.
///
/// `#[allow(dead_code)]` on this and several of its neighbors below: each
/// of these pure escaping functions is only actually *called* from within
/// whichever single `#[cfg(...)]`-gated backend module matches the host
/// OS (systemd/launchd) — genuinely used on the platform it was written
/// for, genuinely unreferenced on the others, which `dead_code` can't tell
/// apart from an unused function. `escape_windows_argv` is the one
/// exception left permanently unreferenced by any backend now that
/// `windows_svc` hands `windows-service` a real argv array instead of a
/// pre-quoted command line (see `windows_svc::launch_arguments`'s own doc
/// comment) — kept and still directly tested here regardless, since it's a
/// generically useful, independently correct piece of Windows argv-quoting
/// logic. Kept `pub` and top-level (not nested inside their one real
/// caller's module) so they stay directly unit-testable on every platform,
/// independent of which backend that platform's build actually compiles.
#[allow(dead_code)]
pub fn escape_systemd_specifier(s: &str) -> String {
    s.replace('%', "%%")
}

#[allow(dead_code)]
fn unescape_systemd_specifier(s: &str) -> String {
    s.replace("%%", "%")
}

/// The five XML predefined entities — used for every plist/Task Scheduler
/// XML text node this module writes.
#[allow(dead_code)]
pub fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[allow(dead_code)]
fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Command-line-quoting layer for a single `ExecStart=` token, layered on
/// top of `escape_systemd_specifier`'s file-format escaping: systemd parses
/// `ExecStart=`'s value as a shell-like command line of its own, so each
/// token (the exe path, `run`, `--service-managed`) is individually
/// quoted, then the whole line is built by space-joining the already-quoted
/// tokens — never by quoting the joined line as one unit.
#[allow(dead_code)]
pub fn escape_systemd_exec_arg(s: &str) -> String {
    let specifier_escaped = escape_systemd_specifier(s);
    let backslash_escaped = specifier_escaped.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{backslash_escaped}\"")
}

/// Standard Windows argv-quoting algorithm (the same one
/// `CommandLineToArgvW` expects on the other end): double every backslash
/// run immediately preceding a quote (or at the very end of the token, so
/// the closing quote we add isn't itself escaped), escape embedded quotes,
/// and only wrap in quotes if the token actually needs it (contains
/// whitespace or a quote, or is empty). Applied per-token — the same
/// "quote each token, then join with spaces" discipline as
/// `escape_systemd_exec_arg`, not one quoting pass over the whole joined
/// command line (which would collapse `run --service-managed` into a
/// single argv element instead of two).
#[allow(dead_code)]
pub fn escape_windows_argv(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quoting = s.chars().any(|c| c.is_whitespace() || c == '"');
    if !needs_quoting {
        return s.to_string();
    }

    let mut result = String::from("\"");
    let mut backslashes = 0usize;
    for c in s.chars() {
        if c == '\\' {
            backslashes += 1;
            continue;
        }
        if c == '"' {
            result.push_str(&"\\".repeat(backslashes * 2 + 1));
            result.push('"');
        } else {
            result.push_str(&"\\".repeat(backslashes));
            result.push(c);
        }
        backslashes = 0;
    }
    result.push_str(&"\\".repeat(backslashes * 2));
    result.push('"');
    result
}

/// Rejects (before any templating) a path containing an embedded NUL or
/// newline byte — either would let a maliciously-crafted project path
/// break out of the single-line file-format fields (`WorkingDirectory=`,
/// plist `<string>` text, XML text nodes) this module writes it into.
pub fn reject_unsafe_path(path: &Path) -> io::Result<()> {
    let s = path.to_string_lossy();
    if s.contains('\0') || s.contains('\n') || s.contains('\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to use {} — it contains an embedded NUL or newline byte", path.display()),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Revalidation — the single shared gate every mutating (and the one
// read-only) operation runs through first
// ---------------------------------------------------------------------------

fn backend_definition_path_mismatch(name: &str, expected: &str, recorded: &str) -> String {
    format!("service definition path mismatch for {name}: expected {expected}, recorded {recorded}")
}

/// Recomputes the canonical unit/plist path (or task identity, for Windows)
/// fresh from `record.name`/`record.scope`, using the exact same
/// derivation `install` used to produce it — a mismatch here means
/// `.frogs/service.json` itself has been hand-edited or is stale in a way
/// that would otherwise cause an OS command to touch the wrong definition.
pub fn verify_definition_path_matches(record: &ServiceRecord) -> Result<(), String> {
    let expected = match record.backend {
        #[cfg(target_os = "linux")]
        Backend::Systemd => systemd::unit_path(&record.name, record.scope).to_string_lossy().into_owned(),
        #[cfg(not(target_os = "linux"))]
        Backend::Systemd => return Err(unsupported_backend_message(Backend::Systemd)),

        #[cfg(target_os = "macos")]
        Backend::Launchd => launchd::plist_path(&record.name, record.scope).to_string_lossy().into_owned(),
        #[cfg(not(target_os = "macos"))]
        Backend::Launchd => return Err(unsupported_backend_message(Backend::Launchd)),

        #[cfg(windows)]
        Backend::WindowsService => record.name.clone(),
        #[cfg(not(windows))]
        Backend::WindowsService => return Err(unsupported_backend_message(Backend::WindowsService)),
    };

    if expected == record.definition_path {
        Ok(())
    } else {
        Err(backend_definition_path_mismatch(&record.name, &expected, &record.definition_path))
    }
}

fn unsupported_backend_message(backend: Backend) -> String {
    let os = match backend {
        Backend::Systemd => "Linux",
        Backend::Launchd => "macOS",
        Backend::WindowsService => "Windows",
    };
    format!(
        "this project's service record uses the {} backend, which requires running on {os}",
        backend_label(backend)
    )
}

fn unsupported_backend_error(backend: Backend) -> io::Error {
    io::Error::other(unsupported_backend_message(backend))
}

/// The single shared gate `stop_registered`, `uninstall`,
/// `start_registered`/`restart_registered`, and `report_status_only` all
/// run through first, including the read-only report-only path — a stale
/// or tampered `.frogs/service.json` must never let any of them act (or,
/// for the read-only path, report) on the wrong thing. Three checks, in
/// order, short-circuiting on the first failure: the name's own structural
/// plausibility, the recorded definition path's own freshly-recomputed
/// match, then a live re-probe of the actual platform definition (marker
/// present, working directory still this project's).
pub fn revalidate(record: &ServiceRecord, current_root: &Path) -> Result<(), String> {
    if !is_plausible_service_name(&record.name) {
        return Err(format!("service record name {:?} is not a plausible frogs service name", record.name));
    }

    verify_definition_path_matches(record)?;

    match probe_existing(&record.name, record.scope) {
        Some(def) if !def.has_frogs_marker => Err(format!(
            "the {} definition for {} no longer carries the frogs-managed marker — refusing to act on it",
            backend_label(record.backend),
            record.name
        )),
        Some(def) if paths_match(&def.working_directory, current_root) => Ok(()),
        Some(def) => Err(format!(
            "the {} definition for {} now points at a different working directory ({}) than this project ({})",
            backend_label(record.backend),
            record.name,
            def.working_directory.display(),
            current_root.display()
        )),
        None => Err(format!(
            "no {} definition named {} was found on this system",
            backend_label(record.backend),
            record.name
        )),
    }
}

// ---------------------------------------------------------------------------
// `frogs run`'s registered-project decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDecision {
    Start,
    AlreadyRunningReportOnly,
    Restart,
}

pub fn decide_run_action(running: bool, restart_requested: bool) -> RunDecision {
    match (running, restart_requested) {
        (false, _) => RunDecision::Start,
        (true, false) => RunDecision::AlreadyRunningReportOnly,
        (true, true) => RunDecision::Restart,
    }
}

// ---------------------------------------------------------------------------
// Dispatch layer — one function per capability, matching on `Backend`/the
// target OS to call into the right platform-specific inner module
// ---------------------------------------------------------------------------

/// Probes the target platform for an existing definition under `name` —
/// always a fresh read of the actual unit file/plist/Task Scheduler XML,
/// never a local cache. Used both by `frogs register` (via
/// `decide_collision`) and by `revalidate`'s own live re-probe.
pub fn probe_existing(name: &str, scope: ServiceScope) -> Option<ExistingDefinition> {
    #[cfg(target_os = "linux")]
    {
        systemd::probe(name, scope)
    }
    #[cfg(target_os = "macos")]
    {
        launchd::probe(name, scope)
    }
    #[cfg(windows)]
    {
        let _ = scope;
        // Unlike systemd/launchd's own `probe` (a plain file read, collapsed
        // to `None` via `.ok()` on any failure), a real SCM query can fail
        // for reasons worth surfacing — but `probe_existing`'s signature
        // (shared across all three backends) has no error channel, so a
        // genuine failure is logged rather than silently vanishing the way
        // a plain "not found" already, correctly, does.
        match windows_svc::probe(name) {
            Ok(def) => def,
            Err(e) => {
                tracing::warn!("failed to query Windows service {name}: {e}");
                None
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = scope;
        None
    }
}

/// Renders and installs the platform-native definition, then starts it
/// immediately (`frogs register` implies immediate start on every
/// platform) — returns the freshly built `ServiceRecord`, which the caller
/// (`commands::register::run`) is responsible for writing to
/// `.frogs/service.json`.
/// `account` is Windows-only (which Windows account the service runs
/// as) — Linux/macOS simply ignore it, so this dispatch signature stays
/// uniform across all three platforms rather than growing a
/// platform-conditional parameter list. `description` is likewise
/// Windows-only (the service description shown in `services.msc`/`sc
/// qdescription`; systemd's `Description=` is always set unconditionally
/// from the project name, and launchd has no equivalent field at all).
/// `start_type` and `restart_policy` both apply on every platform (see
/// their own doc comments) — `frogs register` still starts the service once
/// regardless of either choice.
pub fn install(
    name: &str,
    scope: ServiceScope,
    root: &Path,
    account: Option<&str>,
    description: Option<&str>,
    start_type: StartType,
    restart_policy: RestartPolicy,
) -> io::Result<ServiceRecord> {
    reject_unsafe_path(root)?;

    #[cfg(target_os = "linux")]
    let (backend, definition_path, resolved_account, resolved_description) = {
        let _ = (account, description);
        (
            Backend::Systemd,
            systemd::install(name, scope, root, start_type, restart_policy)?.to_string_lossy().into_owned(),
            None,
            None,
        )
    };
    #[cfg(target_os = "macos")]
    let (backend, definition_path, resolved_account, resolved_description) = {
        let _ = (account, description);
        // Same two-layer treatment `root`/`exe` already get: `reject_unsafe_path`
        // rejects control characters that would corrupt the hand-parsed plist
        // file, `escape_xml` (inside `render_plist`) handles XML metacharacters.
        let log_dir = crate::server::logging::peek_logging_directory(root);
        reject_unsafe_path(&log_dir)?;
        (
            Backend::Launchd,
            launchd::install(name, scope, root, &log_dir.to_string_lossy(), start_type, restart_policy)?
                .to_string_lossy()
                .into_owned(),
            None,
            None,
        )
    };
    #[cfg(windows)]
    let (backend, definition_path, resolved_account, resolved_description) = {
        let _ = scope;
        windows_svc::install(name, root, account, description, start_type, restart_policy)?;
        (
            Backend::WindowsService,
            name.to_string(),
            Some(windows_svc::account_display(&windows_svc::resolve_account(account))),
            Some(windows_svc::resolve_description(description, root)),
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let (backend, definition_path, resolved_account, resolved_description): (Backend, String, Option<String>, Option<String>) = {
        let _ = (name, scope, account, description, start_type, restart_policy);
        return Err(io::Error::new(io::ErrorKind::Unsupported, "frogs register is not supported on this platform"));
    };

    Ok(ServiceRecord {
        name: name.to_string(),
        scope,
        backend,
        definition_path,
        account: resolved_account,
        description: resolved_description,
        created_at: Utc::now(),
    })
}

pub fn is_running(record: &ServiceRecord) -> io::Result<bool> {
    match record.backend {
        #[cfg(target_os = "linux")]
        Backend::Systemd => systemd::is_active(&record.name, record.scope),
        #[cfg(not(target_os = "linux"))]
        Backend::Systemd => Err(unsupported_backend_error(Backend::Systemd)),

        #[cfg(target_os = "macos")]
        Backend::Launchd => {
            let stdout = launchd::list_output(&record.name)?;
            Ok(launchd::parse_launchctl_list_running(&stdout))
        }
        #[cfg(not(target_os = "macos"))]
        Backend::Launchd => Err(unsupported_backend_error(Backend::Launchd)),

        #[cfg(windows)]
        Backend::WindowsService => windows_svc::is_running(&record.name),
        #[cfg(not(windows))]
        Backend::WindowsService => Err(unsupported_backend_error(Backend::WindowsService)),
    }
}

pub fn start_registered(record: &ServiceRecord, current_root: &Path) -> io::Result<()> {
    revalidate(record, current_root).map_err(io::Error::other)?;
    match record.backend {
        #[cfg(target_os = "linux")]
        Backend::Systemd => systemd::start(&record.name, record.scope),
        #[cfg(not(target_os = "linux"))]
        Backend::Systemd => Err(unsupported_backend_error(Backend::Systemd)),

        #[cfg(target_os = "macos")]
        Backend::Launchd => launchd::start(&record.name, record.scope),
        #[cfg(not(target_os = "macos"))]
        Backend::Launchd => Err(unsupported_backend_error(Backend::Launchd)),

        #[cfg(windows)]
        Backend::WindowsService => windows_svc::start(&record.name),
        #[cfg(not(windows))]
        Backend::WindowsService => Err(unsupported_backend_error(Backend::WindowsService)),
    }
}

pub fn restart_registered(record: &ServiceRecord, current_root: &Path) -> io::Result<()> {
    revalidate(record, current_root).map_err(io::Error::other)?;
    match record.backend {
        #[cfg(target_os = "linux")]
        Backend::Systemd => systemd::restart(&record.name, record.scope),
        #[cfg(not(target_os = "linux"))]
        Backend::Systemd => Err(unsupported_backend_error(Backend::Systemd)),

        #[cfg(target_os = "macos")]
        Backend::Launchd => launchd::restart(&record.name, record.scope),
        #[cfg(not(target_os = "macos"))]
        Backend::Launchd => Err(unsupported_backend_error(Backend::Launchd)),

        #[cfg(windows)]
        Backend::WindowsService => windows_svc::restart(&record.name),
        #[cfg(not(windows))]
        Backend::WindowsService => Err(unsupported_backend_error(Backend::WindowsService)),
    }
}

/// The read-only counterpart to `start_registered`/`restart_registered` —
/// runs `revalidate` (per this module's own doc comment on that function)
/// but makes no mutating call of its own; `commands::run`'s
/// `AlreadyRunningReportOnly` branch is the only caller.
pub fn report_status_only(record: &ServiceRecord, current_root: &Path) -> io::Result<()> {
    revalidate(record, current_root).map_err(io::Error::other)
}

pub fn stop_registered(record: &ServiceRecord, current_root: &Path) -> io::Result<()> {
    revalidate(record, current_root).map_err(io::Error::other)?;
    match record.backend {
        #[cfg(target_os = "linux")]
        Backend::Systemd => systemd::stop(&record.name, record.scope),
        #[cfg(not(target_os = "linux"))]
        Backend::Systemd => Err(unsupported_backend_error(Backend::Systemd)),

        #[cfg(target_os = "macos")]
        Backend::Launchd => launchd::stop(&record.name, record.scope),
        #[cfg(not(target_os = "macos"))]
        Backend::Launchd => Err(unsupported_backend_error(Backend::Launchd)),

        #[cfg(windows)]
        Backend::WindowsService => windows_svc::stop(&record.name),
        #[cfg(not(windows))]
        Backend::WindowsService => Err(unsupported_backend_error(Backend::WindowsService)),
    }
}

pub fn uninstall(record: &ServiceRecord, current_root: &Path) -> io::Result<()> {
    revalidate(record, current_root).map_err(io::Error::other)?;
    match record.backend {
        #[cfg(target_os = "linux")]
        Backend::Systemd => systemd::uninstall(&record.name, record.scope),
        #[cfg(not(target_os = "linux"))]
        Backend::Systemd => Err(unsupported_backend_error(Backend::Systemd)),

        #[cfg(target_os = "macos")]
        Backend::Launchd => launchd::uninstall(&record.name, record.scope),
        #[cfg(not(target_os = "macos"))]
        Backend::Launchd => Err(unsupported_backend_error(Backend::Launchd)),

        #[cfg(windows)]
        Backend::WindowsService => windows_svc::uninstall(&record.name),
        #[cfg(not(windows))]
        Backend::WindowsService => Err(unsupported_backend_error(Backend::WindowsService)),
    }
}

// ---------------------------------------------------------------------------
// systemd (Linux)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod systemd {
    use super::*;

    pub fn unit_path(name: &str, scope: ServiceScope) -> PathBuf {
        match scope {
            ServiceScope::User => {
                let home = std::env::var("HOME").unwrap_or_default();
                PathBuf::from(home).join(".config/systemd/user").join(format!("{name}.service"))
            }
            ServiceScope::System => PathBuf::from("/etc/systemd/system").join(format!("{name}.service")),
        }
    }

    fn scope_flag(scope: ServiceScope) -> &'static [&'static str] {
        match scope {
            ServiceScope::User => &["--user"],
            ServiceScope::System => &[],
        }
    }

    pub fn render_unit(name: &str, exe: &Path, root: &Path, scope: ServiceScope, restart_policy: RestartPolicy) -> String {
        let exec_start = format!(
            "{} {} {}",
            escape_systemd_exec_arg(&exe.to_string_lossy()),
            escape_systemd_exec_arg("run"),
            escape_systemd_exec_arg("--service-managed")
        );
        let working_directory = escape_systemd_specifier(&root.to_string_lossy());
        // `enable` (called by `install`, below) needs an [Install] section
        // to have anything to symlink — without one it fails outright with
        // "have no installation config."
        let wanted_by = match scope {
            ServiceScope::User => "default.target",
            ServiceScope::System => "multi-user.target",
        };
        // Standard systemd idiom for a service that needs a *usable*
        // network, not just the networking subsystem having started
        // (`network.target` alone doesn't guarantee an interface actually
        // has an address/route/working DNS yet) — frogs's own SQL/HTTP
        // connections at startup can otherwise race a not-yet-configured
        // network right after boot. `After=` orders us behind it if it's
        // going to be reached at all; `Wants=` is what actually pulls it in
        // (a soft dependency — if the wait-online check itself fails, frogs
        // still starts, it just isn't ordered behind a successful one).
        // Mainly load-bearing for `--system` scope: a `--user` unit runs in
        // its own per-user systemd instance with an independent dependency
        // graph, so it can't reliably order against this system-level
        // target the same way — harmless to include either way, since a
        // `--user` session's own network is typically already up by the
        // time a user logs in and that instance starts.
        let unit_deps = "After=network-online.target\nWants=network-online.target\n";
        // Emitted explicitly either way (never omitted, relying on
        // systemd's own default) so a reader of the generated unit sees
        // exactly what was chosen rather than having to know systemd's
        // implicit default. `Restart=on-failure` only restarts after a
        // non-zero exit/signal death — an intentional `systemctl stop`
        // (which `frogs stop`/`frogs unregister` issue) is never treated as
        // a failure, so it never triggers a restart regardless of this
        // setting.
        let restart = match restart_policy {
            RestartPolicy::OnFailure => "Restart=on-failure\nRestartSec=5\n",
            RestartPolicy::Never => "Restart=no\n",
        };
        format!(
            "# Managed-by={FROGS_MARKER}\n\
             [Unit]\n\
             Description=frogs service ({name})\n\
             {unit_deps}\
             \n\
             [Service]\n\
             ExecStart={exec_start}\n\
             WorkingDirectory={working_directory}\n\
             {restart}\
             \n\
             [Install]\n\
             WantedBy={wanted_by}\n"
        )
    }

    pub fn probe(name: &str, scope: ServiceScope) -> Option<ExistingDefinition> {
        let contents = fs::read_to_string(unit_path(name, scope)).ok()?;
        let marker_line = format!("# Managed-by={FROGS_MARKER}");
        let has_frogs_marker = contents.lines().any(|line| line.trim() == marker_line);
        let working_directory = contents
            .lines()
            .find_map(|line| line.trim().strip_prefix("WorkingDirectory=").map(unescape_systemd_specifier))?;
        Some(ExistingDefinition {
            working_directory: PathBuf::from(working_directory),
            has_frogs_marker,
        })
    }

    fn run_systemctl(scope: ServiceScope, args: &[&str]) -> io::Result<()> {
        let status = Command::new("systemctl").args(scope_flag(scope)).args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("systemctl {args:?} exited with {status}")))
        }
    }

    pub fn install(name: &str, scope: ServiceScope, root: &Path, start_type: StartType, restart_policy: RestartPolicy) -> io::Result<PathBuf> {
        let exe = std::env::current_exe()?;
        reject_unsafe_path(&exe)?;

        let path = unit_path(name, scope);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, render_unit(name, &exe, root, scope, restart_policy))?;

        run_systemctl(scope, &["daemon-reload"])?;
        match start_type {
            // `enable --now` both symlinks the unit into its target (so it
            // starts on every future boot/login) and starts it right now.
            StartType::Automatic => run_systemctl(scope, &["enable", "--now", name])?,
            // A plain `start`, with no `enable`, starts it right now without
            // creating that boot-time symlink — the unit stays present and
            // start-able (`frogs run`/`systemctl start`), just not
            // auto-started on the next boot/login.
            StartType::Manual => run_systemctl(scope, &["start", name])?,
        }
        Ok(path)
    }

    /// `systemctl is-active --quiet` — its own exit status is the answer,
    /// no output to parse.
    pub fn is_active(name: &str, scope: ServiceScope) -> io::Result<bool> {
        let status = Command::new("systemctl").args(scope_flag(scope)).args(["is-active", "--quiet", name]).status()?;
        Ok(status.success())
    }

    /// `systemctl start` on an already-active unit, and `restart` on an
    /// inactive one, are both documented no-ops/safe — so misclassifying
    /// `is_active` here never causes a problem for either call.
    pub fn start(name: &str, scope: ServiceScope) -> io::Result<()> {
        run_systemctl(scope, &["start", name])
    }

    pub fn restart(name: &str, scope: ServiceScope) -> io::Result<()> {
        run_systemctl(scope, &["restart", name])
    }

    pub fn stop(name: &str, scope: ServiceScope) -> io::Result<()> {
        run_systemctl(scope, &["stop", name])
    }

    pub fn uninstall(name: &str, scope: ServiceScope) -> io::Result<()> {
        // Best-effort — an already-stopped/disabled unit failing this call
        // must not block removing the file itself.
        let _ = run_systemctl(scope, &["disable", "--now", name]);
        match fs::remove_file(unit_path(name, scope)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        run_systemctl(scope, &["daemon-reload"])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The rendered unit file must carry `render_unit`'s own frogs
        /// marker (what `probe`/`decide_collision` key off of), and a `%`
        /// in a hostile project-root path must come out doubled — a bare
        /// `%` in `WorkingDirectory=` would otherwise be expanded by
        /// systemd itself as one of its own specifiers (`%h`, `%i`, ...)
        /// rather than treated as a literal character of the path.
        #[test]
        fn render_unit_carries_the_frogs_marker_and_escapes_a_percent_in_the_working_directory() {
            let root = Path::new("/srv/100%weird&project");
            let unit = render_unit("frogs-test", Path::new("/usr/bin/frogs"), root, ServiceScope::User, RestartPolicy::OnFailure);

            assert!(unit.contains(&format!("# Managed-by={FROGS_MARKER}")));
            assert!(
                unit.contains("WorkingDirectory=/srv/100%%weird&project"),
                "a literal '%' in the project root must be doubled, not passed through raw: {unit}"
            );
        }

        #[test]
        fn render_unit_uses_the_user_scope_target_for_user_and_the_system_target_for_system() {
            let root = Path::new("/srv/project");
            let exe = Path::new("/usr/bin/frogs");

            let user_unit = render_unit("frogs-test", exe, root, ServiceScope::User, RestartPolicy::OnFailure);
            assert!(user_unit.contains("WantedBy=default.target"));

            let system_unit = render_unit("frogs-test", exe, root, ServiceScope::System, RestartPolicy::OnFailure);
            assert!(system_unit.contains("WantedBy=multi-user.target"));
        }

        #[test]
        fn render_unit_sets_restart_on_failure_and_a_restart_sec_for_on_failure_policy() {
            let root = Path::new("/srv/project");
            let exe = Path::new("/usr/bin/frogs");

            let unit = render_unit("frogs-test", exe, root, ServiceScope::User, RestartPolicy::OnFailure);
            assert!(unit.contains("Restart=on-failure"));
            assert!(unit.contains("RestartSec=5"));
        }

        #[test]
        fn render_unit_sets_restart_no_and_no_restart_sec_for_never_policy() {
            let root = Path::new("/srv/project");
            let exe = Path::new("/usr/bin/frogs");

            let unit = render_unit("frogs-test", exe, root, ServiceScope::User, RestartPolicy::Never);
            assert!(unit.contains("Restart=no"));
            assert!(!unit.contains("RestartSec"));
        }

        #[test]
        fn render_unit_orders_after_and_wants_network_online_target_regardless_of_scope() {
            let root = Path::new("/srv/project");
            let exe = Path::new("/usr/bin/frogs");

            let user_unit = render_unit("frogs-test", exe, root, ServiceScope::User, RestartPolicy::OnFailure);
            assert!(user_unit.contains("After=network-online.target"));
            assert!(user_unit.contains("Wants=network-online.target"));

            let system_unit = render_unit("frogs-test", exe, root, ServiceScope::System, RestartPolicy::OnFailure);
            assert!(system_unit.contains("After=network-online.target"));
            assert!(system_unit.contains("Wants=network-online.target"));
        }
    }
}

// ---------------------------------------------------------------------------
// launchd (macOS)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod launchd {
    use super::*;

    pub fn plist_path(name: &str, scope: ServiceScope) -> PathBuf {
        match scope {
            ServiceScope::User => {
                let home = std::env::var("HOME").unwrap_or_default();
                PathBuf::from(home).join("Library/LaunchAgents").join(format!("{name}.plist"))
            }
            ServiceScope::System => PathBuf::from("/Library/LaunchDaemons").join(format!("{name}.plist")),
        }
    }

    /// `log_dir` (resolved by `server::logging::peek_logging_directory`,
    /// already passed through `reject_unsafe_path` by the caller) backs
    /// `StandardOutPath`/`StandardErrorPath` — launchd's own capture of
    /// whatever this process writes to stdout/stderr directly (not through
    /// `tracing`), which matters for a crash before the tracing subscriber
    /// is even installed. Deliberately distinct filenames
    /// (`launchd-std{out,err}.log`) from `tracing-appender`'s own
    /// `frogs.log.<date>` — those are two independently-buffered writers,
    /// and pointing both at the same path would race each other's file
    /// offsets.
    pub fn render_plist(name: &str, exe: &Path, root: &Path, log_dir: &str, scope: ServiceScope, start_type: StartType, restart_policy: RestartPolicy) -> String {
        let _ = scope; // KeepAlive is identical for both scopes — only the install path differs.
        let exe_esc = escape_xml(&exe.to_string_lossy());
        let root_esc = escape_xml(&root.to_string_lossy());
        let log_dir_esc = escape_xml(log_dir);
        // `RunAtLoad=true` is what makes `load -w` (see `install`, below)
        // start the job immediately as a side effect of loading it — with
        // `false`, loading only registers the definition (and, via `-w`,
        // marks it enabled for a *future* `load`, e.g. after a reboot) but
        // does not itself start anything; `install` issues an explicit
        // `launchctl start` afterward for the `Manual` case so "register
        // still starts it once now" holds regardless of this flag.
        let run_at_load = match start_type {
            StartType::Automatic => "true",
            StartType::Manual => "false",
        };
        // `KeepAlive.SuccessfulExit=false` (the dict form) tells launchd to
        // restart the job whenever its last exit was *not* a clean `exit(0)`
        // — i.e. "on failure," the same semantics as systemd's
        // `Restart=on-failure`. `KeepAlive` can also just be a plain `false`
        // (not a dict at all) to mean "never restart automatically under any
        // circumstance" — the `Never` case. Either way, an intentional
        // `launchctl unload`/`stop` (what `frogs stop`/`frogs unregister`
        // issue) removes the job from launchd's active management entirely,
        // so it's never mistaken for a failure to restart from.
        let keep_alive = match restart_policy {
            RestartPolicy::OnFailure => "<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>".to_string(),
            RestartPolicy::Never => "<false/>".to_string(),
        };
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>{name}</string>\n\
             \t<key>ManagedBy</key>\n\
             \t<string>{FROGS_MARKER}</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>{exe_esc}</string>\n\
             \t\t<string>run</string>\n\
             \t\t<string>--service-managed</string>\n\
             \t</array>\n\
             \t<key>WorkingDirectory</key>\n\
             \t<string>{root_esc}</string>\n\
             \t<key>StandardOutPath</key>\n\
             \t<string>{log_dir_esc}/launchd-stdout.log</string>\n\
             \t<key>StandardErrorPath</key>\n\
             \t<string>{log_dir_esc}/launchd-stderr.log</string>\n\
             \t<key>RunAtLoad</key>\n\
             \t<{run_at_load}/>\n\
             \t<key>KeepAlive</key>\n\
             \t{keep_alive}\n\
             </dict>\n\
             </plist>\n"
        )
    }

    fn extract_plist_string_value(contents: &str, key: &str) -> Option<String> {
        let key_tag = format!("<key>{key}</key>");
        let idx = contents.find(&key_tag)?;
        let rest = &contents[idx + key_tag.len()..];
        let start = rest.find("<string>")? + "<string>".len();
        let end = start + rest[start..].find("</string>")?;
        Some(rest[start..end].to_string())
    }

    /// Hand-rolled scan rather than a plist-parsing crate (zero new
    /// dependencies) — the only two facts `revalidate`/`decide_collision`
    /// ever need out of this file.
    pub fn probe(name: &str, scope: ServiceScope) -> Option<ExistingDefinition> {
        let contents = fs::read_to_string(plist_path(name, scope)).ok()?;
        let has_frogs_marker = contents.contains(&format!("<string>{FROGS_MARKER}</string>"));
        let working_directory = extract_plist_string_value(&contents, "WorkingDirectory")?;
        Some(ExistingDefinition {
            working_directory: PathBuf::from(unescape_xml(&working_directory)),
            has_frogs_marker,
        })
    }

    pub fn list_output(name: &str) -> io::Result<String> {
        let output = Command::new("launchctl").args(["list", name]).output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// `launchctl list <label>`'s stdout, when the job is loaded and
    /// running, includes a `"PID" = <n>;` entry in its dictionary dump;
    /// when it's loaded but not currently running, that entry is simply
    /// absent. Split out as a pure function so it's testable against
    /// canned text without shelling out.
    pub fn parse_launchctl_list_running(stdout: &str) -> bool {
        stdout.lines().any(|line| line.trim_start().starts_with("\"PID\""))
    }

    fn run_launchctl(args: &[&str]) -> io::Result<()> {
        let status = Command::new("launchctl").args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("launchctl {args:?} exited with {status}")))
        }
    }

    pub fn install(name: &str, scope: ServiceScope, root: &Path, log_dir: &str, start_type: StartType, restart_policy: RestartPolicy) -> io::Result<PathBuf> {
        let exe = std::env::current_exe()?;
        reject_unsafe_path(&exe)?;

        let path = plist_path(name, scope);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, render_plist(name, &exe, root, log_dir, scope, start_type, restart_policy))?;

        // `restart` (unload-ignore-fail + `load -w`) loads the definition;
        // with `RunAtLoad=true` (Automatic) that alone starts it. With
        // `RunAtLoad=false` (Manual) loading does not start it, so an
        // explicit `launchctl start` follows — "register still starts it
        // once now" holds either way.
        restart(name, scope)?;
        if start_type == StartType::Manual {
            run_launchctl(&["start", name])?;
        }
        Ok(path)
    }

    /// Start and restart are the *same* sequence by design: `unload`
    /// (ignoring a "not loaded" failure) followed unconditionally by
    /// `load -w`. This designs away any dependency on "`load -w` on an
    /// already-loaded label" being safe — that ambiguous scenario never
    /// occurs, because unload always runs first, here and in `install`.
    pub fn start(name: &str, scope: ServiceScope) -> io::Result<()> {
        restart(name, scope)
    }

    pub fn restart(name: &str, scope: ServiceScope) -> io::Result<()> {
        let path = plist_path(name, scope);
        let _ = run_launchctl(&["unload", &path.to_string_lossy()]);
        run_launchctl(&["load", "-w", &path.to_string_lossy()])
    }

    pub fn stop(name: &str, scope: ServiceScope) -> io::Result<()> {
        let path = plist_path(name, scope);
        run_launchctl(&["unload", &path.to_string_lossy()])
    }

    pub fn uninstall(name: &str, scope: ServiceScope) -> io::Result<()> {
        let path = plist_path(name, scope);
        let _ = run_launchctl(&["unload", &path.to_string_lossy()]);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The rendered plist must carry `render_plist`'s own frogs marker
        /// (what `probe`/`decide_collision` key off of), and a hostile
        /// project-root path containing every XML-significant character
        /// (`&`, `<`, `>`, `"`) must come out entity-escaped rather than
        /// breaking the surrounding `<string>` element's structure.
        #[test]
        fn render_plist_carries_the_frogs_marker_and_escapes_hostile_xml_characters_in_the_working_directory() {
            let root = Path::new("/Users/x/100%<Weird>&\"Folder\"");
            let plist = render_plist(
                "frogs-test",
                Path::new("/usr/local/bin/frogs"),
                root,
                "/Users/x/logs",
                ServiceScope::User,
                StartType::Automatic,
                RestartPolicy::OnFailure,
            );

            assert!(plist.contains(&format!("<string>{FROGS_MARKER}</string>")));
            assert!(
                !plist.contains("<Weird>"),
                "a raw, unescaped '<Weird>' must never appear in the rendered plist: {plist}"
            );
            assert!(plist.contains("&lt;Weird&gt;"));
            assert!(plist.contains("&amp;"));
            assert!(plist.contains("&quot;Folder&quot;"));
        }

        #[test]
        fn render_plist_sets_run_at_load_true_for_automatic_and_false_for_manual() {
            let root = Path::new("/Users/x/project");
            let exe = Path::new("/usr/local/bin/frogs");

            let automatic = render_plist(
                "frogs-test",
                exe,
                root,
                "/Users/x/logs",
                ServiceScope::User,
                StartType::Automatic,
                RestartPolicy::OnFailure,
            );
            assert!(automatic.contains("<key>RunAtLoad</key>\n\t<true/>"));

            let manual = render_plist(
                "frogs-test",
                exe,
                root,
                "/Users/x/logs",
                ServiceScope::User,
                StartType::Manual,
                RestartPolicy::OnFailure,
            );
            assert!(manual.contains("<key>RunAtLoad</key>\n\t<false/>"));
        }

        #[test]
        fn render_plist_uses_the_successful_exit_dict_for_on_failure_policy() {
            let root = Path::new("/Users/x/project");
            let exe = Path::new("/usr/local/bin/frogs");

            let plist = render_plist(
                "frogs-test",
                exe,
                root,
                "/Users/x/logs",
                ServiceScope::User,
                StartType::Automatic,
                RestartPolicy::OnFailure,
            );
            assert!(plist.contains("<key>SuccessfulExit</key>"));
            assert!(plist.contains("<key>KeepAlive</key>\n\t<dict>"));
        }

        #[test]
        fn render_plist_uses_a_plain_false_keep_alive_for_never_policy() {
            let root = Path::new("/Users/x/project");
            let exe = Path::new("/usr/local/bin/frogs");

            let plist = render_plist(
                "frogs-test",
                exe,
                root,
                "/Users/x/logs",
                ServiceScope::User,
                StartType::Automatic,
                RestartPolicy::Never,
            );
            assert!(plist.contains("<key>KeepAlive</key>\n\t<false/>"));
            assert!(!plist.contains("SuccessfulExit"));
        }

        /// `StandardOutPath`/`StandardErrorPath` must both be present,
        /// correctly XML-escaped, pointed at `log_dir`, and named distinctly
        /// from each other and from `tracing-appender`'s own
        /// `frogs.log.<date>` naming (see this function's own doc comment).
        #[test]
        fn render_plist_includes_standard_out_and_error_paths_pointed_at_the_log_directory() {
            let root = Path::new("/Users/x/project");
            let exe = Path::new("/usr/local/bin/frogs");

            let plist = render_plist(
                "frogs-test",
                exe,
                root,
                "/Users/x/100%<Weird>&\"logs\"",
                ServiceScope::User,
                StartType::Automatic,
                RestartPolicy::OnFailure,
            );

            assert!(
                plist.contains("<key>StandardOutPath</key>\n\t<string>/Users/x/100%&lt;Weird&gt;&amp;&quot;logs&quot;/launchd-stdout.log</string>"),
                "StandardOutPath should be XML-escaped and point at launchd-stdout.log under log_dir: {plist}"
            );
            assert!(
                plist.contains("<key>StandardErrorPath</key>\n\t<string>/Users/x/100%&lt;Weird&gt;&amp;&quot;logs&quot;/launchd-stderr.log</string>"),
                "StandardErrorPath should be XML-escaped and point at launchd-stderr.log under log_dir: {plist}"
            );
            assert_ne!(
                extract_plist_string_value(&plist, "StandardOutPath"),
                extract_plist_string_value(&plist, "StandardErrorPath"),
                "stdout and stderr must not be pointed at the same file"
            );
            assert!(
                !plist.contains("frogs.log"),
                "launchd's own stdout/stderr capture files must be named distinctly from tracing-appender's frogs.log.<date> files: {plist}"
            );
        }

        #[test]
        fn parse_launchctl_list_running_is_true_only_when_a_pid_entry_is_present() {
            let running = "{\n\t\"PID\" = 1234;\n\t\"LastExitStatus\" = 0;\n};\n";
            assert!(parse_launchctl_list_running(running));

            let not_running = "{\n\t\"LastExitStatus\" = 0;\n};\n";
            assert!(!parse_launchctl_list_running(not_running));
        }
    }
}

// ---------------------------------------------------------------------------
// Windows Service (Windows)
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub mod windows_svc {
    use super::*;
    use std::ffi::{OsStr, OsString};

    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    // Standard Win32 error codes (`winerror.h`) — hardcoded rather than
    // pulled from `windows-sys` directly, since that crate is only a
    // transitive dependency of `windows-service`, not one this crate
    // depends on itself.
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

    /// Which Windows account a service is (or will be) configured to run
    /// as — `resolve_account`'s output.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ResolvedAccount {
        WellKnown(&'static str),
        Custom(String),
    }

    /// `None` (no `--account` given) resolves to `NT AUTHORITY\LocalService`
    /// — deliberately *not* `LocalSystem` (see `local_system_warning`'s own
    /// doc comment for why defaulting to that would be a
    /// privilege-escalation regression). A handful of other well-known
    /// account names are recognized case-insensitively so `--account
    /// LocalSystem`/`--account NetworkService` don't need exact casing;
    /// anything else is passed through unchanged as a `Custom` account.
    pub fn resolve_account(requested: Option<&str>) -> ResolvedAccount {
        let Some(name) = requested else {
            return ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService");
        };
        match name.to_ascii_lowercase().as_str() {
            "localservice" => ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"),
            "networkservice" => ResolvedAccount::WellKnown("NT AUTHORITY\\NetworkService"),
            "localsystem" => ResolvedAccount::WellKnown("LocalSystem"),
            _ => ResolvedAccount::Custom(name.to_string()),
        }
    }

    /// A group-managed service account (gMSA) name always ends in `$` —
    /// its password is managed automatically by Active Directory and never
    /// supplied by a caller, so `account_credentials` skips the
    /// password-required path for one.
    pub fn is_gmsa(account: &str) -> bool {
        account.trim_end().ends_with('$')
    }

    /// Redacts unconditionally in `Debug`; deliberately no `Display` impl
    /// at all — an accidental `{}` on this type is a compile error, not a
    /// formatting mistake to remember to avoid. No `Clone`/`Copy` either,
    /// so `.into_inner()` can only ever be called once per value (move
    /// semantics enforce this).
    pub struct ServiceAccountPassword(OsString);

    impl std::fmt::Debug for ServiceAccountPassword {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "<redacted>")
        }
    }

    impl ServiceAccountPassword {
        fn into_inner(self) -> OsString {
            self.0
        }
    }

    /// Resolves the account name plus (when needed) its password —
    /// following the same `<field>Env`-style convention this project's own
    /// SQL drivers use for secrets (see e.g. `sql::postgres::build_connection_url`'s
    /// `passwordEnv` handling): a well-known account needs no password at
    /// all, a gMSA's password is managed by Active Directory rather than
    /// supplied here, and any other custom account needs
    /// `FROGS_SERVICE_ACCOUNT_PASSWORD` set in the environment — a missing
    /// value is a hard error naming only the account, never a password.
    pub fn account_credentials(resolved: &ResolvedAccount) -> io::Result<(OsString, Option<ServiceAccountPassword>)> {
        match resolved {
            ResolvedAccount::WellKnown(name) => Ok((OsString::from(*name), None)),
            ResolvedAccount::Custom(name) => {
                if is_gmsa(name) {
                    return Ok((OsString::from(name.clone()), None));
                }
                match std::env::var_os("FROGS_SERVICE_ACCOUNT_PASSWORD") {
                    Some(value) => Ok((OsString::from(name.clone()), Some(ServiceAccountPassword(value)))),
                    None => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "no password available for service account \"{name}\" — set the \
                             FROGS_SERVICE_ACCOUNT_PASSWORD environment variable, or use a group-managed \
                             service account (a name ending in '$'), which needs no password"
                        ),
                    )),
                }
            }
        }
    }

    pub fn account_display(resolved: &ResolvedAccount) -> String {
        match resolved {
            ResolvedAccount::WellKnown(name) => (*name).to_string(),
            ResolvedAccount::Custom(name) => name.clone(),
        }
    }

    /// The command line every service `frogs register` creates is launched
    /// with — a real argv array handed straight to `ServiceInfo`, not shell
    /// or command-line text, so no escaping is needed here; `windows-service`
    /// itself (see its `shell_escape` module) handles quoting when it builds
    /// the actual `binPath` string the SCM stores.
    fn launch_arguments(name: &str, root: &Path) -> Vec<OsString> {
        vec![
            OsString::from("--windows-service-host"),
            OsString::from("--service-name"),
            OsString::from(name),
            OsString::from("--project-root"),
            root.as_os_str().to_os_string(),
            OsString::from("--frogs-marker"),
            OsString::from(FROGS_MARKER),
        ]
    }

    fn contains_flag_value(args: &[OsString], flag: &str, value: &str) -> bool {
        extract_flag_value(args, flag).is_some_and(|v| v == OsStr::new(value))
    }

    /// First-occurrence-wins on a duplicate flag — used by both `probe`
    /// (this module) and `service_host::run_service` (a different module),
    /// hence `pub(crate)` rather than private.
    pub(crate) fn extract_flag_value(args: &[OsString], flag: &str) -> Option<OsString> {
        let position = args.iter().position(|arg| arg == OsStr::new(flag))?;
        args.get(position + 1).cloned()
    }

    /// Splits a Win32 command-line string (as returned by
    /// `QueryServiceConfigW`'s `lpBinaryPathName` — the *entire* quoted
    /// `<exe> <arg1> <arg2> ...` line, not just the executable path) back
    /// into individual tokens, using the same quoting rules
    /// `CommandLineToArgvW` documents (and that `windows-service`'s own
    /// `shell_escape` module writes to): an argument is delimited by
    /// unquoted whitespace, a double quote toggles "inside a quoted run",
    /// and a run of `2n`/`2n+1` backslashes immediately before a quote
    /// collapses to `n` literal backslashes with the quote either acting as
    /// a delimiter or contributing one literal `"` character, respectively.
    fn split_command_line(command_line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut has_token = false;
        let mut chars = command_line.chars().peekable();

        while let Some(&c) = chars.peek() {
            match c {
                '\\' => {
                    let mut backslashes = 0usize;
                    while chars.peek() == Some(&'\\') {
                        backslashes += 1;
                        chars.next();
                    }
                    if chars.peek() == Some(&'"') {
                        current.push_str(&"\\".repeat(backslashes / 2));
                        if backslashes % 2 == 1 {
                            current.push('"');
                            chars.next();
                        }
                    } else {
                        current.push_str(&"\\".repeat(backslashes));
                    }
                    has_token = true;
                }
                '"' => {
                    chars.next();
                    if in_quotes && chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = !in_quotes;
                    }
                    has_token = true;
                }
                c if c.is_whitespace() && !in_quotes => {
                    if has_token {
                        args.push(std::mem::take(&mut current));
                        has_token = false;
                    }
                    chars.next();
                }
                c => {
                    current.push(c);
                    has_token = true;
                    chars.next();
                }
            }
        }
        if has_token {
            args.push(current);
        }
        args
    }

    /// `StartType::Automatic` → `ServiceStartType::AutoStart` (starts at
    /// boot); `StartType::Manual` → `ServiceStartType::OnDemand` (installed
    /// and start-able, but not started automatically) — either way,
    /// `install` still calls `service.start(..)` once at the end, so
    /// "register still starts it once now" holds regardless.
    fn map_start_type(start_type: StartType) -> ServiceStartType {
        match start_type {
            StartType::Automatic => ServiceStartType::AutoStart,
            StartType::Manual => ServiceStartType::OnDemand,
        }
    }

    /// A sensible default when `--description` isn't given — better than
    /// leaving `services.msc`/`sc qdescription` blank, without requiring
    /// the user to type anything. Pure, so it's directly unit-testable.
    pub fn resolve_description(requested: Option<&str>, root: &Path) -> String {
        match requested {
            Some(text) => text.to_string(),
            None => format!("frogs service for the project at {}", root.display()),
        }
    }

    /// Operator note (not enforced here — see
    /// `docs/frogs-persistent-logging.md`): this service defaults to
    /// running as `NT AUTHORITY\LocalService` (see `resolve_account`). If
    /// that account can't write `logging.directory`, `frogs run`'s own
    /// self-healing fallback silently drops to stdout-only — which, for a
    /// real Windows Service with no console handle, means a total logging
    /// blackout, not just a warning. Not checked as part of `register`
    /// today; recommended for a future pass.
    pub fn install(name: &str, root: &Path, account: Option<&str>, description: Option<&str>, start_type: StartType, restart_policy: RestartPolicy) -> io::Result<()> {
        let resolved = resolve_account(account);
        let (account_name, account_password) = account_credentials(&resolved)?;
        let resolved_description = resolve_description(description, root);
        let exe = std::env::current_exe()?;
        reject_unsafe_path(&exe)?;
        reject_unsafe_path(root)?;

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE).map_err(map_win_err)?;
        let service = manager
            .create_service(
                &ServiceInfo {
                    name: OsString::from(name),
                    display_name: OsString::from(name),
                    service_type: ServiceType::OWN_PROCESS,
                    start_type: map_start_type(start_type),
                    error_control: ServiceErrorControl::Normal,
                    executable_path: exe,
                    launch_arguments: launch_arguments(name, root),
                    dependencies: vec![],
                    account_name: Some(account_name.clone()),
                    // Flows directly from `.into_inner()` into this field —
                    // never bound to its own named local variable first, so
                    // there is no intermediate place an accidental debug-log
                    // of a local could ever expose it.
                    account_password: account_password.map(ServiceAccountPassword::into_inner),
                },
                ServiceAccess::START | ServiceAccess::CHANGE_CONFIG,
            )
            // Only named, individually-formatted, non-secret fields ever
            // reach this message — never a `{:?}` of the `ServiceInfo`
            // struct as a whole (which would include the password) or of
            // `e` (whose `Winapi` variant wraps an unrelated `io::Error`,
            // but `{:?}` is still avoided here on principle).
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to create Windows service \"{name}\" for account \"{}\": {}",
                    account_name.to_string_lossy(),
                    map_win_err(e)
                ))
            })?;

        configure_failure_actions(&service, restart_policy)?;
        // `SERVICE_CONFIG_DESCRIPTION` via `set_description` — not part of
        // `ServiceInfo`/`create_service` itself, a separate
        // `ChangeServiceConfig2` call, same as failure actions above. Best
        // effort: a failure here (e.g. a NUL byte the crate rejects) is
        // worth surfacing but shouldn't undo an otherwise-successful
        // registration, so it's logged rather than propagated as a hard
        // error.
        if let Err(e) = service.set_description(&resolved_description) {
            tracing::warn!("registered {name} but failed to set its service description: {}", map_win_err(e));
        }
        service.start(&[] as &[&OsStr]).map_err(map_win_err)?;
        Ok(())
    }

    /// Configures Win32 `SERVICE_CONFIG_FAILURE_ACTIONS` so crash recovery
    /// is consistent with the other two backends (systemd `Restart=`,
    /// launchd `KeepAlive`): `OnFailure` restarts the process 5 seconds
    /// after *any* failure exit, indefinitely (a single `Restart` action
    /// with no further entries applies to every failure past the first,
    /// matching `Restart=on-failure`/`RestartSec=5`'s own "no give-up point"
    /// semantics); `Never` clears the action list entirely so nothing
    /// happens on failure. `set_failure_actions_on_non_crash_failures(true)`
    /// is required for `OnFailure` because the SCM otherwise only runs
    /// failure actions on a genuine process crash/termination — not on the
    /// case `service_host::run_service` actually reports on an internal
    /// error (a clean `SetServiceStatus(Stopped, ServiceSpecific(1))` call,
    /// not a crash) — without this flag, an ordinary startup/runtime error
    /// would never trigger a restart at all. A deliberate stop (`frogs
    /// stop`/`frogs unregister`, which requests `SERVICE_CONTROL_STOP`
    /// before the process reports `Stopped` with a *success* code) is never
    /// treated as a failure by the SCM regardless of this configuration.
    fn configure_failure_actions(service: &windows_service::service::Service, restart_policy: RestartPolicy) -> io::Result<()> {
        let (actions, on_non_crash) = match restart_policy {
            RestartPolicy::OnFailure => (
                Some(vec![ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: std::time::Duration::from_secs(5),
                }]),
                true,
            ),
            RestartPolicy::Never => (Some(vec![]), false),
        };
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(86400)),
                reboot_msg: None,
                command: None,
                actions,
            })
            .map_err(map_win_err)?;
        service.set_failure_actions_on_non_crash_failures(on_non_crash).map_err(map_win_err)?;
        Ok(())
    }

    pub fn probe(name: &str) -> io::Result<Option<ExistingDefinition>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(map_win_err)?;
        let service = match manager.open_service(name, ServiceAccess::QUERY_CONFIG) {
            Ok(service) => service,
            Err(windows_service::Error::Winapi(ref io_err)) if io_err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                return Ok(None);
            }
            Err(e) => return Err(map_win_err(e)),
        };

        let config = service.query_config().map_err(map_win_err)?;
        // `executable_path` here is really the *entire* configured binPath
        // command line (exe plus every launch argument), not just the exe
        // itself — see `split_command_line`'s own doc comment.
        let command_line = config.executable_path.to_string_lossy().into_owned();
        let tokens: Vec<OsString> = split_command_line(&command_line).into_iter().map(OsString::from).collect();
        let launch_args: &[OsString] = if tokens.is_empty() { &[] } else { &tokens[1..] };

        let has_frogs_marker = contains_flag_value(launch_args, "--frogs-marker", FROGS_MARKER);
        // An empty PathBuf (marker present but --project-root missing or
        // malformed) can never equal a real canonicalized root, so
        // `decide_collision` still correctly routes this to `Conflict`
        // rather than falsely reading it as "nothing here."
        let working_directory = extract_flag_value(launch_args, "--project-root").map(PathBuf::from).unwrap_or_default();

        Ok(Some(ExistingDefinition {
            working_directory,
            has_frogs_marker,
        }))
    }

    pub fn is_running(name: &str) -> io::Result<bool> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(map_win_err)?;
        let service = manager.open_service(name, ServiceAccess::QUERY_STATUS).map_err(map_win_err)?;
        let status = service.query_status().map_err(map_win_err)?;
        Ok(status.current_state == ServiceState::Running)
    }

    pub fn start(name: &str) -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(map_win_err)?;
        let service = manager.open_service(name, ServiceAccess::START).map_err(map_win_err)?;
        match service.start(&[] as &[&OsStr]) {
            Ok(()) => Ok(()),
            Err(windows_service::Error::Winapi(ref io_err)) if io_err.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING) => Ok(()),
            Err(e) => Err(map_win_err(e)),
        }
    }

    pub fn restart(name: &str) -> io::Result<()> {
        stop(name)?;
        start(name)
    }

    pub fn stop(name: &str) -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(map_win_err)?;
        let service = manager.open_service(name, ServiceAccess::STOP).map_err(map_win_err)?;
        match service.stop() {
            Ok(_) => Ok(()),
            Err(windows_service::Error::Winapi(ref io_err)) if io_err.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) => Ok(()),
            Err(e) => Err(map_win_err(e)),
        }
    }

    pub fn wait_until_stopped(name: &str, timeout: std::time::Duration) -> io::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(map_win_err)?;
        let service = manager.open_service(name, ServiceAccess::QUERY_STATUS).map_err(map_win_err)?;

        let deadline = std::time::Instant::now() + timeout;
        loop {
            let status = service.query_status().map_err(map_win_err)?;
            if status.current_state == ServiceState::Stopped {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for Windows service {name} to stop"),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    pub fn uninstall(name: &str) -> io::Result<()> {
        wait_until_stopped(name, std::time::Duration::from_secs(10))?;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(map_win_err)?;
        let service = manager.open_service(name, ServiceAccess::DELETE).map_err(map_win_err)?;
        service.delete().map_err(map_win_err)
    }

    fn map_win_err(e: windows_service::Error) -> io::Error {
        if let windows_service::Error::Winapi(ref io_err) = e
            && io_err.raw_os_error() == Some(ERROR_ACCESS_DENIED)
        {
            return io::Error::new(
                io::ErrorKind::PermissionDenied,
                "access denied managing the Windows service — this requires an elevated (Administrator) terminal",
            );
        }
        io::Error::other(e.to_string())
    }

    /// `Some` only for `LocalSystem` — the one account whose blast radius
    /// (full control over the machine, not just this service) is worth
    /// warning about even when a caller explicitly opted into it via
    /// `--account LocalSystem`.
    pub fn local_system_warning(resolved: &ResolvedAccount) -> Option<String> {
        match resolved {
            ResolvedAccount::WellKnown("LocalSystem") => Some(
                "warning: running as LocalSystem gives this service full control over the machine — prefer \
                 --account LocalService (the default) or a dedicated low-privilege/managed account unless this \
                 service genuinely needs LocalSystem's privileges."
                    .to_string(),
            ),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        // -----------------------------------------------------------------
        // resolve_account — direct pin for the round-1 blocking security
        // finding: no `--account` must resolve to LocalService, never
        // LocalSystem.
        // -----------------------------------------------------------------

        #[test]
        fn resolve_account_with_nothing_requested_resolves_to_local_service_not_local_system() {
            assert_eq!(resolve_account(None), ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"));
        }

        #[test]
        fn resolve_account_recognizes_the_well_known_names_case_insensitively() {
            assert_eq!(resolve_account(Some("localservice")), ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"));
            assert_eq!(resolve_account(Some("LocalService")), ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"));
            assert_eq!(resolve_account(Some("networkservice")), ResolvedAccount::WellKnown("NT AUTHORITY\\NetworkService"));
            assert_eq!(resolve_account(Some("NETWORKSERVICE")), ResolvedAccount::WellKnown("NT AUTHORITY\\NetworkService"));
            assert_eq!(resolve_account(Some("localsystem")), ResolvedAccount::WellKnown("LocalSystem"));
            assert_eq!(resolve_account(Some("LocalSystem")), ResolvedAccount::WellKnown("LocalSystem"));
        }

        #[test]
        fn resolve_description_with_nothing_requested_generates_one_naming_the_project_root() {
            let root = Path::new("C:\\Projects\\my-api");
            let description = resolve_description(None, root);
            assert!(
                description.contains("C:\\Projects\\my-api"),
                "the generated default description must name the project root: {description}"
            );
        }

        #[test]
        fn resolve_description_with_an_explicit_value_uses_it_unchanged() {
            let root = Path::new("C:\\Projects\\my-api");
            assert_eq!(resolve_description(Some("My Custom Description"), root), "My Custom Description");
        }

        #[test]
        fn resolve_account_passes_an_unrecognized_name_through_unchanged_as_custom() {
            assert_eq!(
                resolve_account(Some("MyDomain\\CustomSvcAcct")),
                ResolvedAccount::Custom("MyDomain\\CustomSvcAcct".to_string()),
                "a custom account name's original casing must be preserved, not lowercased"
            );
        }

        // -----------------------------------------------------------------
        // ServiceAccountPassword — direct pin for the round-2 blocking
        // security finding: Debug must never expose the real secret.
        // -----------------------------------------------------------------

        #[test]
        fn service_account_password_debug_is_exactly_redacted_and_never_contains_the_real_secret() {
            let pw = ServiceAccountPassword(OsString::from("Sup3rS3cr3tTestPassword!"));
            let debug_output = format!("{pw:?}");
            assert_eq!(debug_output, "<redacted>");
            assert!(
                !debug_output.contains("Sup3rS3cr3t"),
                "the Debug output must never contain any fragment of the real password: {debug_output}"
            );
        }

        // -----------------------------------------------------------------
        // account_credentials — env-var-dependent, so serialized via a
        // Mutex (this codebase's other env-var tests use test-unique var
        // names instead, but FROGS_SERVICE_ACCOUNT_PASSWORD's name is fixed
        // by account_credentials itself, so that trick isn't available
        // here).
        // -----------------------------------------------------------------

        static ENV_LOCK: Mutex<()> = Mutex::new(());
        const PASSWORD_ENV_VAR: &str = "FROGS_SERVICE_ACCOUNT_PASSWORD";

        #[test]
        fn account_credentials_for_a_custom_account_returns_the_env_vars_password_when_set() {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: serialized against every other test in this file that
            // touches this same env var via `ENV_LOCK`.
            unsafe {
                std::env::set_var(PASSWORD_ENV_VAR, "Sup3rS3cr3tTestPassword!");
            }

            let resolved = ResolvedAccount::Custom("svc-custom".to_string());
            let (name, password) = account_credentials(&resolved).expect("the env var is set, so this must succeed");
            assert_eq!(name, OsString::from("svc-custom"));
            let password = password.expect("a non-gMSA custom account with the env var set must return Some(password)");
            assert_eq!(password.into_inner(), OsString::from("Sup3rS3cr3tTestPassword!"));

            // SAFETY: still holding ENV_LOCK.
            unsafe {
                std::env::remove_var(PASSWORD_ENV_VAR);
            }
        }

        #[test]
        fn account_credentials_for_a_custom_account_errors_clearly_when_the_env_var_is_unset() {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: serialized against every other test in this file that
            // touches this same env var via `ENV_LOCK`.
            unsafe {
                std::env::remove_var(PASSWORD_ENV_VAR);
            }

            let resolved = ResolvedAccount::Custom("svc-custom".to_string());
            let err = account_credentials(&resolved).expect_err("no password source at all must be an error");
            let message = err.to_string();
            assert!(message.contains("svc-custom"), "the error must name the account: {message}");
            assert!(
                message.contains(PASSWORD_ENV_VAR),
                "the error must point at the env var to set, not silently fail: {message}"
            );
            assert!(
                message.contains('$') || message.to_lowercase().contains("group-managed"),
                "the error must mention the gMSA exception: {message}"
            );
        }

        #[test]
        fn account_credentials_for_a_well_known_account_needs_no_password_regardless_of_the_env_var() {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: serialized against every other test in this file that
            // touches this same env var via `ENV_LOCK`.
            unsafe {
                std::env::remove_var(PASSWORD_ENV_VAR);
            }

            let resolved = ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService");
            let (name, password) = account_credentials(&resolved).unwrap();
            assert_eq!(name, OsString::from("NT AUTHORITY\\LocalService"));
            assert!(password.is_none());
        }

        #[test]
        fn account_credentials_for_a_gmsa_needs_no_password_even_when_the_env_var_is_unset() {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: serialized against every other test in this file that
            // touches this same env var via `ENV_LOCK`.
            unsafe {
                std::env::remove_var(PASSWORD_ENV_VAR);
            }

            let resolved = ResolvedAccount::Custom("svc-gmsa$".to_string());
            let (name, password) = account_credentials(&resolved).unwrap();
            assert_eq!(name, OsString::from("svc-gmsa$"));
            assert!(password.is_none(), "a gMSA account (name ending in '$') must never require a password");
        }

        // -----------------------------------------------------------------
        // is_gmsa
        // -----------------------------------------------------------------

        #[test]
        fn is_gmsa_is_true_only_for_a_dollar_suffixed_name() {
            assert!(is_gmsa("frogs-gmsa$"));
            assert!(!is_gmsa("frogs-ordinary-account"));
        }

        #[test]
        fn is_gmsa_is_true_when_the_dollar_is_followed_by_trailing_whitespace() {
            assert!(is_gmsa("frogs-gmsa$   "));
            assert!(is_gmsa("frogs-gmsa$\t\n"));
        }

        // -----------------------------------------------------------------
        // launch_arguments
        // -----------------------------------------------------------------

        #[test]
        fn launch_arguments_produces_the_exact_expected_token_sequence_with_no_escaping_of_a_hostile_root() {
            let root = Path::new("C:\\Users\\Adá Zýl\\My Projëct (v2)");
            let args = launch_arguments("frogs-my-svc", root);
            assert_eq!(
                args,
                vec![
                    OsString::from("--windows-service-host"),
                    OsString::from("--service-name"),
                    OsString::from("frogs-my-svc"),
                    OsString::from("--project-root"),
                    root.as_os_str().to_os_string(),
                    OsString::from("--frogs-marker"),
                    OsString::from(FROGS_MARKER),
                ],
                "each token must come out exactly as given — a real argv array needs no command-line escaping"
            );
            // Confirms the path itself survived completely unmodified — no
            // quoting/backslash-doubling of the spaces/unicode it contains.
            assert_eq!(args[4], OsString::from(root));
        }

        // -----------------------------------------------------------------
        // extract_flag_value / contains_flag_value
        // -----------------------------------------------------------------

        #[test]
        fn extract_flag_value_returns_the_value_immediately_following_the_flag() {
            let args = vec![OsString::from("--service-name"), OsString::from("frogs-x")];
            assert_eq!(extract_flag_value(&args, "--service-name"), Some(OsString::from("frogs-x")));
        }

        #[test]
        fn extract_flag_value_returns_none_when_the_flag_is_absent() {
            let args = vec![OsString::from("--other-flag"), OsString::from("value")];
            assert_eq!(extract_flag_value(&args, "--service-name"), None);
        }

        #[test]
        fn extract_flag_value_returns_none_when_the_flag_is_the_last_argument() {
            let args = vec![OsString::from("--service-name")];
            assert_eq!(extract_flag_value(&args, "--service-name"), None);
        }

        #[test]
        fn extract_flag_value_returns_the_first_occurrences_value_on_a_duplicate_flag() {
            let args = vec![
                OsString::from("--service-name"),
                OsString::from("frogs-first"),
                OsString::from("--service-name"),
                OsString::from("frogs-second"),
            ];
            assert_eq!(extract_flag_value(&args, "--service-name"), Some(OsString::from("frogs-first")));
        }

        #[test]
        fn contains_flag_value_matches_and_mismatches_correctly() {
            let args = vec![OsString::from("--frogs-marker"), OsString::from(FROGS_MARKER)];
            assert!(contains_flag_value(&args, "--frogs-marker", FROGS_MARKER));
            assert!(!contains_flag_value(&args, "--frogs-marker", "something-else"));
            assert!(!contains_flag_value(&args, "--missing-flag", FROGS_MARKER));
        }

        #[test]
        fn a_realistic_launch_arguments_output_round_trips_back_through_extract_flag_value() {
            let root = Path::new("C:\\srv\\my project");
            let args = launch_arguments("frogs-round-trip", root);
            assert_eq!(extract_flag_value(&args, "--service-name"), Some(OsString::from("frogs-round-trip")));
            assert_eq!(extract_flag_value(&args, "--project-root"), Some(root.as_os_str().to_os_string()));
            assert!(contains_flag_value(&args, "--frogs-marker", FROGS_MARKER));
        }

        // -----------------------------------------------------------------
        // split_command_line — a CommandLineToArgvW-compatible tokenizer
        // -----------------------------------------------------------------

        #[test]
        fn split_command_line_splits_a_simple_unquoted_command_line_on_whitespace() {
            assert_eq!(
                split_command_line("C:\\bin\\frogs.exe run --service-managed"),
                vec!["C:\\bin\\frogs.exe".to_string(), "run".to_string(), "--service-managed".to_string()]
            );
        }

        #[test]
        fn split_command_line_keeps_a_quoted_argument_containing_a_space_as_one_token() {
            let line = "\"C:\\Program Files\\frogs.exe\" run";
            assert_eq!(split_command_line(line), vec!["C:\\Program Files\\frogs.exe".to_string(), "run".to_string()]);
        }

        #[test]
        fn split_command_line_unescapes_a_backslash_escaped_quote_inside_a_quoted_argument() {
            // Win32 rule: a literal `"` inside a quoted argument is written
            // as `\"` in the command line. `quo\"ted` (raw command-line
            // text) must decode to the single token `quo"ted` (containing a
            // real, un-escaped quote character).
            let line = "\"quo\\\"ted\" plain";
            assert_eq!(split_command_line(line), vec!["quo\"ted".to_string(), "plain".to_string()]);
        }

        #[test]
        fn split_command_line_round_trips_every_token_escape_windows_argv_produces() {
            // Ties `split_command_line` (this module's own tokenizer,
            // needed because `query_config()` only hands back a whole
            // command-line string) together with `escape_windows_argv`
            // (the inverse operation, in the parent module) — building a
            // command line the same way `windows-service`'s own
            // `shell_escape` module would, then decoding it back, must
            // recover the exact original tokens.
            let original = vec![
                "C:\\Program Files\\frogs.exe".to_string(),
                "run".to_string(),
                "arg with \"embedded quotes\" and spaces".to_string(),
                "trailing-backslash\\".to_string(),
                String::new(),
            ];
            let command_line = original.iter().map(|s| super::super::escape_windows_argv(s)).collect::<Vec<_>>().join(" ");
            assert_eq!(split_command_line(&command_line), original);
        }

        // -----------------------------------------------------------------
        // map_win_err
        // -----------------------------------------------------------------

        #[test]
        fn map_win_err_classifies_access_denied_as_permission_denied_mentioning_elevation() {
            let win_err = windows_service::Error::Winapi(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED));
            let mapped = map_win_err(win_err);
            assert_eq!(mapped.kind(), io::ErrorKind::PermissionDenied);
            let message = mapped.to_string();
            assert!(
                message.contains("elevated") || message.contains("Administrator"),
                "an access-denied error must clearly point at needing elevation: {message}"
            );
        }

        #[test]
        fn map_win_err_passes_through_an_unrelated_winapi_error_without_the_elevation_message() {
            let win_err = windows_service::Error::Winapi(io::Error::from_raw_os_error(ERROR_SERVICE_DOES_NOT_EXIST));
            let mapped = map_win_err(win_err);
            assert_ne!(mapped.kind(), io::ErrorKind::PermissionDenied);
            let message = mapped.to_string();
            assert!(
                !message.contains("elevated") && !message.contains("Administrator"),
                "only an actual access-denied error should carry the elevation message: {message}"
            );
        }

        // -----------------------------------------------------------------
        // local_system_warning
        // -----------------------------------------------------------------

        #[test]
        fn local_system_warning_is_some_only_for_the_local_system_account() {
            let warning = local_system_warning(&ResolvedAccount::WellKnown("LocalSystem")).expect("LocalSystem must carry a warning");
            assert!(warning.contains("LocalSystem"));

            assert!(local_system_warning(&ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService")).is_none());
            assert!(local_system_warning(&ResolvedAccount::WellKnown("NT AUTHORITY\\NetworkService")).is_none());
            assert!(local_system_warning(&ResolvedAccount::Custom("svc-custom".to_string())).is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_project() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-service-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    // -----------------------------------------------------------------
    // sanitize_derived / validate_explicit / service_name
    // -----------------------------------------------------------------

    #[test]
    fn sanitize_derived_collapses_disallowed_characters_into_a_single_dash_and_trims_the_ends() {
        assert_eq!(sanitize_derived("my cool!!!project??").unwrap(), "my-cool-project");
        assert_eq!(sanitize_derived("--leading-and-trailing--").unwrap(), "leading-and-trailing");
    }

    #[test]
    fn sanitize_derived_passes_through_an_already_valid_name_unchanged() {
        assert_eq!(sanitize_derived("cars-demo_v2.1").unwrap(), "cars-demo_v2.1");
    }

    #[test]
    fn sanitize_derived_errors_when_nothing_usable_survives() {
        let err = sanitize_derived("!!!???***").expect_err("a folder name with no allowed characters must be rejected");
        assert!(err.contains("no usable characters"));
    }

    #[test]
    fn sanitize_derived_errors_when_the_sanitized_result_is_too_long() {
        let long_name = "a".repeat(201);
        let err = sanitize_derived(&long_name).expect_err("over-200-char sanitized identifiers must be rejected");
        assert!(err.contains("too long"));
    }

    #[test]
    fn sanitize_derived_accepts_exactly_two_hundred_characters() {
        let name = "a".repeat(200);
        assert_eq!(sanitize_derived(&name).unwrap(), name);
    }

    #[test]
    fn validate_explicit_rejects_an_empty_name() {
        let err = validate_explicit("").expect_err("an empty --name must be rejected");
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn validate_explicit_rejects_a_name_over_two_hundred_characters() {
        let long_name = "a".repeat(201);
        let err = validate_explicit(&long_name).expect_err("an over-200-char --name must be rejected");
        assert!(err.contains("too long"));
    }

    #[test]
    fn validate_explicit_rejects_a_disallowed_character_and_names_it_in_the_message() {
        let err = validate_explicit("my/project").expect_err("a --name containing '/' must be rejected, never silently mangled");
        assert!(err.contains('/'));
    }

    #[test]
    fn validate_explicit_accepts_a_name_using_only_allowed_characters() {
        assert_eq!(validate_explicit("my-project_v2.0").unwrap(), "my-project_v2.0");
    }

    #[test]
    fn service_name_prepends_the_frogs_prefix_to_an_explicit_name() {
        let root = Path::new("/does/not/matter");
        assert_eq!(service_name(root, Some("my-api")).unwrap(), "frogs-my-api");
    }

    #[test]
    fn service_name_derives_from_the_project_roots_own_final_path_component_when_no_name_is_given() {
        let root = Path::new("/home/user/projects/cars demo!!");
        assert_eq!(service_name(root, None).unwrap(), "frogs-cars-demo");
    }

    #[test]
    fn service_name_propagates_an_explicit_names_own_validation_error() {
        assert!(service_name(Path::new("/proj"), Some("bad/name")).is_err());
    }

    // -----------------------------------------------------------------
    // is_plausible_service_name — a security-relevant structural gate,
    // not just a happy-path check
    // -----------------------------------------------------------------

    #[test]
    fn is_plausible_service_name_accepts_a_well_formed_name() {
        assert!(is_plausible_service_name("frogs-my-project_v2.0"));
    }

    #[test]
    fn is_plausible_service_name_rejects_a_name_with_no_frogs_prefix_at_all() {
        assert!(!is_plausible_service_name("my-project"));
    }

    #[test]
    fn is_plausible_service_name_rejects_an_embedded_slash() {
        // A hand-corrupted `.frogs/service.json` (or a name that somehow
        // slipped past `validate_explicit`) must never reach an OS command
        // with a path separator smuggled into what's supposed to be a bare
        // identifier.
        assert!(!is_plausible_service_name("frogs-my/project"));
        assert!(!is_plausible_service_name("frogs-../../etc/passwd"));
    }

    #[test]
    fn is_plausible_service_name_rejects_an_empty_identifier_after_the_prefix() {
        assert!(!is_plausible_service_name("frogs-"));
    }

    #[test]
    fn is_plausible_service_name_rejects_an_identifier_over_two_hundred_characters() {
        let too_long = format!("frogs-{}", "a".repeat(201));
        assert!(!is_plausible_service_name(&too_long));
    }

    #[test]
    fn is_plausible_service_name_accepts_an_identifier_of_exactly_two_hundred_characters() {
        let exactly_at_limit = format!("frogs-{}", "a".repeat(200));
        assert!(is_plausible_service_name(&exactly_at_limit));
    }

    // -----------------------------------------------------------------
    // decide_collision — all four branches
    // -----------------------------------------------------------------

    #[test]
    fn decide_collision_is_none_when_nothing_exists_under_the_candidate_name() {
        assert_eq!(decide_collision(None, Path::new("/proj")), Collision::None);
    }

    #[test]
    fn decide_collision_is_idempotent_when_an_existing_frogs_owned_definition_matches_this_project() {
        let existing = ExistingDefinition {
            working_directory: PathBuf::from("/proj"),
            has_frogs_marker: true,
        };
        assert_eq!(decide_collision(Some(existing), Path::new("/proj")), Collision::Idempotent);
    }

    #[test]
    fn decide_collision_is_a_conflict_when_an_existing_frogs_owned_definition_points_elsewhere() {
        let existing = ExistingDefinition {
            working_directory: PathBuf::from("/some/other/project"),
            has_frogs_marker: true,
        };
        assert_eq!(
            decide_collision(Some(existing), Path::new("/proj")),
            Collision::Conflict {
                other_root: Some(PathBuf::from("/some/other/project"))
            }
        );
    }

    #[test]
    fn decide_collision_is_a_conflict_when_the_existing_definition_has_no_frogs_marker_even_if_the_working_directory_matches() {
        // Direct fix for a security finding about collision spoofing: an
        // existing, genuinely unrelated systemd unit/plist/scheduled task
        // that merely happens to share this name — and, by coincidence or
        // by design, this exact working directory too — must still be
        // treated as a hard conflict. Frogs must never come to believe it
        // owns a definition it didn't itself create, no matter how well
        // the working directory lines up.
        let existing = ExistingDefinition {
            working_directory: PathBuf::from("/proj"),
            has_frogs_marker: false,
        };
        assert_eq!(
            decide_collision(Some(existing), Path::new("/proj")),
            Collision::Conflict {
                other_root: Some(PathBuf::from("/proj"))
            },
            "an existing definition without the frogs marker must be a conflict regardless of working-directory match"
        );
    }

    #[test]
    fn decide_collision_is_also_a_conflict_when_the_existing_definition_has_no_frogs_marker_and_a_different_working_directory() {
        let existing = ExistingDefinition {
            working_directory: PathBuf::from("/elsewhere"),
            has_frogs_marker: false,
        };
        assert_eq!(
            decide_collision(Some(existing), Path::new("/proj")),
            Collision::Conflict {
                other_root: Some(PathBuf::from("/elsewhere"))
            }
        );
    }

    // -----------------------------------------------------------------
    // escape_systemd_exec_arg / escape_windows_argv — embedded-quote
    // tokenization safety
    // -----------------------------------------------------------------

    /// A minimal, deliberately naive command-line tokenizer — splits on
    /// unquoted whitespace, treats a `"`-delimited run as one token, and
    /// unescapes a backslash-escaped character inside quotes. Good enough
    /// to prove the specific property this test cares about: a properly
    /// quoted/escaped token round-trips as exactly one element, rather than
    /// an embedded quote prematurely closing it and splitting it into two.
    fn naive_tokenize(line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut chars = line.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
                continue;
            }
            let mut token = String::new();
            if c == '"' {
                chars.next();
                while let Some(&c2) = chars.peek() {
                    if c2 == '\\' {
                        chars.next();
                        if let Some(&escaped) = chars.peek() {
                            token.push(escaped);
                            chars.next();
                        }
                    } else if c2 == '"' {
                        chars.next();
                        break;
                    } else {
                        token.push(c2);
                        chars.next();
                    }
                }
            } else {
                while let Some(&c2) = chars.peek() {
                    if c2.is_whitespace() {
                        break;
                    }
                    token.push(c2);
                    chars.next();
                }
            }
            tokens.push(token);
        }
        tokens
    }

    #[test]
    fn escape_systemd_exec_arg_with_an_embedded_quote_stays_one_token_when_tokenized() {
        let a = "hello world";
        let b = "he said \"hi\" to me";
        let line = format!("{} {}", escape_systemd_exec_arg(a), escape_systemd_exec_arg(b));

        let tokens = naive_tokenize(&line);
        assert_eq!(
            tokens,
            vec![a.to_string(), b.to_string()],
            "an embedded '\"' must not let a naive tokenizer split one argument into two: {line}"
        );
    }

    #[test]
    fn escape_windows_argv_with_an_embedded_quote_stays_one_token_when_tokenized() {
        let a = "run";
        let b = "he said \"hi\" to me";
        let line = format!("{} {}", escape_windows_argv(a), escape_windows_argv(b));

        let tokens = naive_tokenize(&line);
        assert_eq!(
            tokens,
            vec![a.to_string(), b.to_string()],
            "an embedded '\"' must not let a naive tokenizer split one argument into two: {line}"
        );
    }

    #[test]
    fn escape_windows_argv_leaves_a_token_with_no_special_characters_unquoted() {
        assert_eq!(escape_windows_argv("--service-managed"), "--service-managed");
    }

    #[test]
    fn escape_windows_argv_quotes_an_empty_token() {
        assert_eq!(escape_windows_argv(""), "\"\"");
    }

    // -----------------------------------------------------------------
    // reject_unsafe_path
    // -----------------------------------------------------------------

    #[test]
    fn reject_unsafe_path_accepts_an_ordinary_path() {
        assert!(reject_unsafe_path(Path::new("/srv/my-project")).is_ok());
    }

    #[test]
    fn reject_unsafe_path_rejects_an_embedded_nul_byte() {
        let hostile = PathBuf::from(format!("/srv/my{}project", '\0'));
        let err = reject_unsafe_path(&hostile).expect_err("a NUL byte in the path must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn reject_unsafe_path_rejects_an_embedded_newline() {
        let hostile = PathBuf::from(format!("/srv/my{}project", '\n'));
        let err = reject_unsafe_path(&hostile).expect_err("a newline in the path must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn reject_unsafe_path_rejects_an_embedded_carriage_return() {
        let hostile = PathBuf::from(format!("/srv/my{}project", '\r'));
        assert!(reject_unsafe_path(&hostile).is_err());
    }

    // -----------------------------------------------------------------
    // install — macOS-only: `log_dir` (resolved via
    // `logging::peek_logging_directory`) must go through the same
    // `reject_unsafe_path` gate `root`/`exe` already do, before it's ever
    // templated into the rendered plist.
    // -----------------------------------------------------------------

    /// A project whose `config/server.json` sets `logging.directory` to a
    /// value containing an embedded NUL/CR/LF byte — `install`'s macOS
    /// branch must reject it (the same way it already rejects one in
    /// `root`) before ever calling `launchd::install`, not just compile a
    /// code path that happens to touch it.
    #[cfg(target_os = "macos")]
    #[test]
    fn install_rejects_a_logging_directory_containing_an_embedded_control_byte() {
        for (label, hostile) in [("nul", "\u{0}"), ("cr", "\r"), ("lf", "\n")] {
            let root = temp_project();
            std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
            let api_dir = root.join("api");
            std::fs::create_dir_all(api_dir.join("config")).unwrap();
            let directory = format!("logs{hostile}evil");
            std::fs::write(
                api_dir.join("config/server.json"),
                serde_json::json!({ "logging": { "directory": directory } }).to_string(),
            )
            .unwrap();

            let err = install(
                "frogs-log-dir-test",
                ServiceScope::User,
                &root,
                None,
                None,
                StartType::Automatic,
                RestartPolicy::OnFailure,
            )
            .expect_err(&format!(
                "a logging.directory containing an embedded {label} byte must be rejected, not smuggled into the rendered plist"
            ));
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    // -----------------------------------------------------------------
    // decide_run_action — pure function, all three input combinations
    // -----------------------------------------------------------------

    #[test]
    fn decide_run_action_starts_when_not_running_regardless_of_restart() {
        assert_eq!(decide_run_action(false, false), RunDecision::Start);
        assert_eq!(decide_run_action(false, true), RunDecision::Start);
    }

    #[test]
    fn decide_run_action_is_report_only_when_already_running_and_no_restart_was_requested() {
        assert_eq!(decide_run_action(true, false), RunDecision::AlreadyRunningReportOnly);
    }

    #[test]
    fn decide_run_action_restarts_when_already_running_and_restart_was_requested() {
        assert_eq!(decide_run_action(true, true), RunDecision::Restart);
    }

    // -----------------------------------------------------------------
    // verify_definition_path_matches — platform-specific, since the
    // "freshly recomputed canonical path" it checks against is derived
    // differently per backend
    // -----------------------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn verify_definition_path_matches_accepts_a_correct_scheduled_task_record_and_rejects_a_stale_one() {
        let name = "frogs-myproj";
        let good = ServiceRecord {
            name: name.to_string(),
            scope: ServiceScope::User,
            backend: Backend::WindowsService,
            definition_path: name.to_string(),
            account: None,
            description: None,
            created_at: Utc::now(),
        };
        assert!(verify_definition_path_matches(&good).is_ok());

        let stale = ServiceRecord {
            name: name.to_string(),
            scope: ServiceScope::User,
            backend: Backend::WindowsService,
            definition_path: "frogs-someone-elses-project".to_string(),
            account: None,
            description: None,
            created_at: Utc::now(),
        };
        let err = verify_definition_path_matches(&stale).expect_err("a definition_path that doesn't match the freshly recomputed one must be rejected");
        assert!(err.contains(name));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_definition_path_matches_accepts_a_correct_systemd_record_and_rejects_a_stale_one() {
        let name = "frogs-myproj";
        let expected = systemd::unit_path(name, ServiceScope::User).to_string_lossy().into_owned();

        let good = ServiceRecord {
            name: name.to_string(),
            scope: ServiceScope::User,
            backend: Backend::Systemd,
            definition_path: expected,
            account: None,
            description: None,
            created_at: Utc::now(),
        };
        assert!(verify_definition_path_matches(&good).is_ok());

        let stale = ServiceRecord {
            name: name.to_string(),
            scope: ServiceScope::User,
            backend: Backend::Systemd,
            definition_path: "/etc/systemd/system/frogs-someone-elses-project.service".to_string(),
            account: None,
            description: None,
            created_at: Utc::now(),
        };
        let err = verify_definition_path_matches(&stale).expect_err("a definition_path that doesn't match the freshly recomputed one must be rejected");
        assert!(err.contains(name));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_definition_path_matches_accepts_a_correct_launchd_record_and_rejects_a_stale_one() {
        let name = "frogs-myproj";
        let expected = launchd::plist_path(name, ServiceScope::User).to_string_lossy().into_owned();

        let good = ServiceRecord {
            name: name.to_string(),
            scope: ServiceScope::User,
            backend: Backend::Launchd,
            definition_path: expected,
            account: None,
            description: None,
            created_at: Utc::now(),
        };
        assert!(verify_definition_path_matches(&good).is_ok());

        let stale = ServiceRecord {
            name: name.to_string(),
            scope: ServiceScope::User,
            backend: Backend::Launchd,
            definition_path: "/Users/someone-else/Library/LaunchAgents/frogs-someone-elses-project.plist".to_string(),
            account: None,
            description: None,
            created_at: Utc::now(),
        };
        let err = verify_definition_path_matches(&stale).expect_err("a definition_path that doesn't match the freshly recomputed one must be rejected");
        assert!(err.contains(name));
    }

    // -----------------------------------------------------------------
    // ServiceRecord / .frogs/service.json persistence
    // -----------------------------------------------------------------

    fn sample_record() -> ServiceRecord {
        ServiceRecord {
            name: "frogs-sample".to_string(),
            scope: ServiceScope::User,
            backend: Backend::WindowsService,
            definition_path: "frogs-sample".to_string(),
            account: None,
            description: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn path_is_dot_frogs_service_json_under_the_project_root() {
        let root = Path::new("/proj");
        assert_eq!(path(root), root.join(".frogs").join("service.json"));
    }

    #[test]
    fn write_record_creates_the_runtime_dir_and_the_file() {
        let root = temp_project();
        assert!(!path(&root).exists());
        write_record(&root, &sample_record()).unwrap();
        assert!(path(&root).is_file());
    }

    #[test]
    fn write_then_read_record_round_trips() {
        let root = temp_project();
        let record = sample_record();
        write_record(&root, &record).unwrap();

        let read_back = read_record(&root).unwrap().expect("just-written record should read back");
        assert_eq!(read_back.name, record.name);
        assert_eq!(read_back.scope, record.scope);
        assert_eq!(read_back.backend, record.backend);
        assert_eq!(read_back.definition_path, record.definition_path);
    }

    #[test]
    fn read_record_missing_file_returns_none_not_an_error() {
        let root = temp_project();
        assert!(read_record(&root).unwrap().is_none());
    }

    #[test]
    fn read_record_corrupt_json_returns_none_not_an_error() {
        let root = temp_project();
        fs::create_dir_all(runtime_dir(&root)).unwrap();
        fs::write(path(&root), "{ not valid json").unwrap();
        assert!(read_record(&root).unwrap().is_none());
    }

    #[test]
    fn remove_record_is_idempotent_when_the_file_is_already_missing() {
        let root = temp_project();
        assert!(remove_record(&root).is_ok());
    }

    #[test]
    fn remove_record_deletes_an_existing_file() {
        let root = temp_project();
        write_record(&root, &sample_record()).unwrap();
        remove_record(&root).unwrap();
        assert!(read_record(&root).unwrap().is_none());
    }
}
