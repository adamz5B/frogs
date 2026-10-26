use std::collections::HashMap;
use std::path::{Component, Path, PathBuf, Prefix};

use crate::config::{ConnectionConfig, TlsConfig};
use crate::openapi::dir_index::fold;
use crate::openapi::path_rules::{RESERVED_DIR, untrusted, windows_reserved};
use crate::project::{API_DIR, MANIFEST_FILE, WEBSERVE_FILE};

use super::WebServeConfig;
use super::serve::{Located, locate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenyReason {
    DotSegment,
    Backups,
    ReservedRootName,
    Protected,
    UnsafeSegment,
}

impl DenyReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DenyReason::DotSegment => "a path segment starts with '.'",
            DenyReason::Backups => "a path segment is the reserved _backups folder",
            DenyReason::ReservedRootName => "the path is inside a frogs-owned file or folder at the project root",
            DenyReason::Protected => "the path is a protected file or folder (TLS material, log directory or SQLite database)",
            DenyReason::UnsafeSegment => "a path segment is not a safe file name on every platform",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SqliteTarget {
    Memory,
    Temp,
    Path(PathBuf),
    Unrecognized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecKind {
    Path,
    SqliteFamily,
}

#[derive(Debug, Clone)]
enum RawSpec {
    Path(PathBuf),
    Empty,
    Unrecognized(String),
}

#[derive(Debug, Clone)]
struct ProtectedSpec {
    origin: String,
    value: String,
    kind: SpecKind,
    raw: RawSpec,
}

/// Every local file or folder frogs itself reads or writes that a static
/// site rooted at the project root could otherwise expose. Collected where
/// each setting is loaded and resolved against the project's real root only
/// when the static router is built (`DenyList::new`). Any future driver or
/// feature setting that names a local file must be added here.
#[derive(Debug, Clone, Default)]
pub struct ProtectedPaths {
    specs: Vec<ProtectedSpec>,
}

impl ProtectedPaths {
    pub(crate) fn add_path(&mut self, origin: &str, base: &Path, value: &str) {
        let raw = if value.is_empty() { RawSpec::Empty } else { RawSpec::Path(base.join(value)) };
        self.specs.push(ProtectedSpec {
            origin: origin.to_string(),
            value: value.to_string(),
            kind: SpecKind::Path,
            raw,
        });
    }

    pub(crate) fn add_dir(&mut self, origin: &str, path: &Path) {
        self.specs.push(ProtectedSpec {
            origin: origin.to_string(),
            value: path.display().to_string(),
            kind: SpecKind::Path,
            raw: RawSpec::Path(path.to_path_buf()),
        });
    }

    /// Regardless of `tls.mode`: a file named by an inactive block is still
    /// a file frogs owns.
    pub(crate) fn add_tls(&mut self, tls: &TlsConfig, base: &Path) {
        if let Some(manual) = &tls.manual {
            self.add_path("tls.manual.certPath", base, &manual.cert_path);
            self.add_path("tls.manual.keyPath", base, &manual.key_path);
        }
        if let Some(client_auth) = &tls.client_auth {
            if let Some(ca) = &client_auth.ca_path {
                self.add_path("tls.clientAuth.caPath", base, ca);
            }
            for crl in &client_auth.crl_paths {
                self.add_path("tls.clientAuth.crlPaths", base, crl);
            }
        }
    }

    /// A relative database path is resolved against the process working
    /// directory by the driver, but a registered service runs with the
    /// project root as its working directory, so both are protected.
    pub(crate) fn add_sqlite(&mut self, connections: &HashMap<String, ConnectionConfig>, root: &Path) {
        for (name, connection) in connections {
            if connection.driver != "sqlite" {
                continue;
            }
            let Some(database) = connection.settings.get("database").and_then(|v| v.as_str()) else {
                continue;
            };
            let origin = format!("connections.{name}.database");
            match sqlite_target(database) {
                SqliteTarget::Memory | SqliteTarget::Temp => {}
                SqliteTarget::Unrecognized => self.specs.push(ProtectedSpec {
                    origin,
                    value: database.to_string(),
                    kind: SpecKind::SqliteFamily,
                    raw: RawSpec::Unrecognized(database.to_string()),
                }),
                SqliteTarget::Path(path) => {
                    let mut bases: Vec<PathBuf> = Vec::new();
                    if let Ok(cwd) = std::env::current_dir() {
                        bases.push(cwd);
                    }
                    if path.is_relative() {
                        bases.push(root.to_path_buf());
                    }
                    for base in bases {
                        self.specs.push(ProtectedSpec {
                            origin: origin.clone(),
                            value: database.to_string(),
                            kind: SpecKind::SqliteFamily,
                            raw: RawSpec::Path(base.join(&path)),
                        });
                    }
                }
            }
        }
    }
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = ((bytes[i + 1] as char).to_digit(16), (bytes[i + 2] as char).to_digit(16))
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Mirrors how SQLite reads the `database` string sqlx hands it verbatim
/// (sqlx always opens with SQLITE_OPEN_URI). The `file:` prefix is matched
/// case-sensitively, like SQLite does: `FILE:x.db` is a plain path. Query
/// options are ignored: SQLite applies `mode=`/`vfs=` last-wins, so any
/// non-empty, non-`:memory:` path is protected as a file regardless.
pub(crate) fn sqlite_target(value: &str) -> SqliteTarget {
    if value == ":memory:" {
        return SqliteTarget::Memory;
    }
    if value.is_empty() {
        return SqliteTarget::Temp;
    }
    let Some(rest) = value.strip_prefix("file:") else {
        return SqliteTarget::Path(PathBuf::from(value));
    };

    let (before_fragment, _) = rest.split_once('#').unwrap_or((rest, ""));
    let path_part = before_fragment.split_once('?').map_or(before_fragment, |(path, _)| path);

    let path_part = if let Some(after_slashes) = path_part.strip_prefix("//") {
        let (authority, path) = match after_slashes.find('/') {
            Some(i) => after_slashes.split_at(i),
            None => (after_slashes, ""),
        };
        if !authority.is_empty() && authority != "localhost" {
            return SqliteTarget::Unrecognized;
        }
        path
    } else {
        path_part
    };

    let Some(decoded) = percent_decode(path_part) else {
        return SqliteTarget::Unrecognized;
    };
    if decoded.contains('\0') {
        return SqliteTarget::Unrecognized;
    }

    if decoded == ":memory:" {
        return SqliteTarget::Memory;
    }
    if decoded.is_empty() {
        return SqliteTarget::Temp;
    }

    let mut path = decoded.as_str();
    if cfg!(windows) {
        let bytes = path.as_bytes();
        if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
            path = &path[1..];
        }
    }
    SqliteTarget::Path(PathBuf::from(path))
}

/// The prefix is folded as normalised text so a lexical `C:` and a
/// canonicalised `\\?\C:` compare equal.
pub(crate) fn fold_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => fold(&format!("{}:", letter as char)),
                Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => fold(&format!("\\\\{}\\{}", server.to_string_lossy(), share.to_string_lossy())),
                _ => fold(&prefix.as_os_str().to_string_lossy()),
            },
            Component::RootDir => "/".to_string(),
            Component::CurDir => ".".to_string(),
            Component::ParentDir => "..".to_string(),
            Component::Normal(name) => fold(&name.to_string_lossy()),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placement {
    Inside(Vec<Vec<String>>),
    Outside,
    Uncertain(Vec<Vec<String>>),
}

/// Win32 never pops above a prefix or root.
fn collapse_lexically(path: &Path) -> PathBuf {
    let mut parts: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(parts.last(), Some(Component::Normal(_))) {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    parts.iter().collect()
}

fn canonicalize_deepest_ancestor(collapsed: &Path) -> (PathBuf, bool) {
    for ancestor in collapsed.ancestors() {
        if let Ok(canonical) = std::fs::canonicalize(ancestor) {
            let mut result = canonical;
            if let Ok(remainder) = collapsed.strip_prefix(ancestor) {
                result.push(remainder);
            }
            return (result, true);
        }
    }
    (collapsed.to_path_buf(), false)
}

/// Resolves `..` through symlinks the way the OS does when it walks the
/// path, which can differ from `collapse_lexically` once a link is involved.
fn walk_physically(absolute: &Path) -> (PathBuf, bool) {
    let mut current = PathBuf::new();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut certain = false;
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if tail.pop().is_none() {
                    current.pop();
                }
            }
            Component::Normal(name) => {
                if tail.is_empty()
                    && let Ok(canonical) = std::fs::canonicalize(current.join(name))
                {
                    current = canonical;
                    certain = true;
                } else {
                    tail.push(name.to_os_string());
                }
            }
        }
    }
    for name in tail {
        current.push(name);
    }
    (current, certain)
}

fn absolutize(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(path))
    }
}

fn starts_with_components(candidate: &[String], prefix: &[String]) -> bool {
    candidate.len() >= prefix.len() && candidate[..prefix.len()] == *prefix
}

/// Placement is order- and case-independent: both the Win32-style and the
/// physical reading of the path are computed, and decisions compare only
/// folded components of absolute paths. A path that merely could not be
/// resolved is `Uncertain` and kept by its literal spelling, never dropped.
pub(crate) fn place(path: &Path, canonical_root_folded: &[String]) -> Placement {
    let Some(absolute) = absolutize(path) else {
        return Placement::Uncertain(vec![fold_components(path)]);
    };
    let collapsed = collapse_lexically(&absolute);
    let (win32, win32_certain) = canonicalize_deepest_ancestor(&collapsed);
    let (physical, physical_certain) = walk_physically(&absolute);
    let forms = vec![fold_components(&win32), fold_components(&physical)];

    if forms.iter().any(|form| starts_with_components(form, canonical_root_folded)) {
        Placement::Inside(forms)
    } else if win32_certain || physical_certain {
        Placement::Outside
    } else {
        Placement::Uncertain(vec![fold_components(&collapsed)])
    }
}

#[derive(Debug, Clone)]
struct Entry {
    components: Vec<String>,
    family: bool,
}

/// What a static router refuses to serve, decided on folded components so
/// the answer never depends on the host filesystem's case rules.
#[derive(Debug, Clone)]
pub(crate) struct DenyList {
    root_folded: Vec<String>,
    entries: Vec<Entry>,
    problems: Vec<String>,
    warnings: Vec<String>,
}

fn is_unsafe_segment(segment: &str) -> bool {
    segment.chars().any(|c| matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') || c.is_control())
        || segment.ends_with('.')
        || segment.ends_with(' ')
        || windows_reserved(segment)
        || segment.as_bytes().windows(2).any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
}

fn push_unique(list: &mut Vec<String>, message: String) {
    if !list.contains(&message) {
        list.push(message);
    }
}

impl DenyList {
    pub(crate) fn new(lexical_root: &Path, canonical_root: &Path, canonical_root_is_fallback: bool, protected: &ProtectedPaths) -> Self {
        let root_folded = fold_components(canonical_root);
        let lexical_root_folded = absolutize(lexical_root).map(|p| fold_components(&collapse_lexically(&p)));
        let mut list = DenyList {
            root_folded,
            entries: Vec::new(),
            problems: Vec::new(),
            warnings: Vec::new(),
        };
        if canonical_root_is_fallback {
            list.problems
                .push("the project root could not be canonicalised; protected paths are denied by their literal spelling only".to_string());
        }

        for spec in &protected.specs {
            let family = spec.kind == SpecKind::SqliteFamily;
            let unresolved = format!(
                "protected path {}={} could not be resolved; it is denied by its literal spelling only",
                spec.origin,
                untrusted(&spec.value)
            );
            match &spec.raw {
                RawSpec::Empty => push_unique(&mut list.problems, unresolved),
                RawSpec::Unrecognized(text) => {
                    push_unique(&mut list.problems, unresolved);
                    let mut components = list.root_folded.clone();
                    components.extend(fold_components(Path::new(text)).into_iter().filter(|c| c != "/"));
                    list.entries.push(Entry { components, family });
                }
                RawSpec::Path(path) => match place(path, &list.root_folded) {
                    Placement::Inside(forms) => {
                        for form in forms {
                            list.add_inside(spec, form, family);
                        }
                    }
                    Placement::Outside if !canonical_root_is_fallback => {}
                    Placement::Outside => {
                        push_unique(&mut list.problems, unresolved);
                        list.add_literal(path, lexical_root_folded.as_deref(), family);
                    }
                    Placement::Uncertain(_) => {
                        push_unique(&mut list.problems, unresolved);
                        list.add_literal(path, lexical_root_folded.as_deref(), family);
                    }
                },
            }
        }
        list
    }

    /// The same list `webserve::router` serves with, plus the page and
    /// diagnostic checks — `webserve.json`'s own TLS is added here so a
    /// startPage naming a key file is caught too.
    pub(crate) fn for_site(root: &Path, config: &WebServeConfig, protected: &ProtectedPaths) -> (Self, PathBuf) {
        let mut protected = protected.clone();
        protected.add_tls(&config.tls, root);
        let (canonical_root, fallback) = match std::fs::canonicalize(root) {
            Ok(canonical) => (canonical, false),
            Err(_) => (root.to_path_buf(), true),
        };
        let list = DenyList::new(root, &canonical_root, fallback, &protected);
        (list, canonical_root)
    }

    fn add_inside(&mut self, spec: &ProtectedSpec, form: Vec<String>, family: bool) {
        if !starts_with_components(&form, &self.root_folded) {
            return;
        }
        if form.len() == self.root_folded.len() {
            push_unique(
                &mut self.problems,
                format!(
                    "protected path {}={} is the project root itself; the whole site would be denied",
                    spec.origin,
                    untrusted(&spec.value)
                ),
            );
        }
        if form[self.root_folded.len()..].iter().any(|c| !c.is_ascii()) {
            push_unique(
                &mut self.warnings,
                format!(
                    "protected path {}={} has non-ASCII components; an alternate Unicode spelling may not be matched on this filesystem",
                    spec.origin,
                    untrusted(&spec.value)
                ),
            );
        }
        self.entries.push(Entry { components: form, family });
    }

    fn add_literal(&mut self, path: &Path, lexical_root_folded: Option<&[String]>, family: bool) {
        let Some(absolute) = absolutize(path) else {
            self.entries.push(Entry {
                components: fold_components(path),
                family,
            });
            return;
        };
        let literal = fold_components(&collapse_lexically(&absolute));
        if let Some(lexical_root) = lexical_root_folded
            && starts_with_components(&literal, lexical_root)
        {
            let mut anchored = self.root_folded.clone();
            anchored.extend_from_slice(&literal[lexical_root.len()..]);
            self.entries.push(Entry { components: anchored, family });
        }
        self.entries.push(Entry { components: literal, family });
    }

    fn entry_matches(&self, candidate: &[String]) -> bool {
        self.entries.iter().any(|entry| {
            let len = entry.components.len();
            if starts_with_components(candidate, &entry.components) {
                return true;
            }
            entry.family
                && len > 0
                && candidate.len() >= len
                && candidate[..len - 1] == entry.components[..len - 1]
                && candidate[len - 1].starts_with(&format!("{}-", entry.components[len - 1]))
        })
    }

    pub(crate) fn request_verdict(&self, relative: &str) -> Option<DenyReason> {
        let mut folded = self.root_folded.clone();
        let mut first = true;
        for segment in relative.split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment.starts_with('.') {
                return Some(DenyReason::DotSegment);
            }
            let name = fold(segment);
            if name == RESERVED_DIR {
                return Some(DenyReason::Backups);
            }
            if first && (name == API_DIR || name == MANIFEST_FILE || name == WEBSERVE_FILE) {
                return Some(DenyReason::ReservedRootName);
            }
            if is_unsafe_segment(segment) {
                return Some(DenyReason::UnsafeSegment);
            }
            first = false;
            folded.push(name);
        }
        self.entry_matches(&folded).then_some(DenyReason::Protected)
    }

    /// Fails closed when the canonical path is not under the canonical root.
    pub(crate) fn canonical_verdict(&self, canonical: &Path) -> Option<DenyReason> {
        let folded = fold_components(canonical);
        if !starts_with_components(&folded, &self.root_folded) {
            return Some(DenyReason::Protected);
        }
        let rest = &folded[self.root_folded.len()..];
        if let Some(first) = rest.first()
            && (first == API_DIR || first == MANIFEST_FILE || first == WEBSERVE_FILE)
        {
            return Some(DenyReason::ReservedRootName);
        }
        if rest.iter().any(|c| c.starts_with('.')) {
            return Some(DenyReason::DotSegment);
        }
        if rest.iter().any(|c| c == RESERVED_DIR) {
            return Some(DenyReason::Backups);
        }
        self.entry_matches(&folded).then_some(DenyReason::Protected)
    }

    pub(crate) fn problems(&self) -> &[String] {
        &self.problems
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Shared by `frogs run` (printed as warnings) and `frogs validate`
/// (problems fail the command): the first vec is problems, the second
/// warnings.
pub(crate) fn page_problems(root: &Path, config: &WebServeConfig, protected: &ProtectedPaths) -> (Vec<String>, Vec<String>) {
    let (deny, canonical_root) = DenyList::for_site(root, config, protected);
    let mut problems = deny.problems().to_vec();
    let warnings = deny.warnings().to_vec();

    let pages = [("startPage", Some(&config.start_page)), ("notFoundPage", config.not_found_page.as_ref())];
    for (field, page) in pages {
        let Some(page) = page else { continue };
        if let Located::Denied(reason) = locate(root, &canonical_root, &deny, page) {
            problems.push(format!("{field} {} is never served: {}", untrusted(page), reason.as_str()));
        }
    }
    (problems, warnings)
}

/// Lexical rules only, for `frogs generate` picking a start page from the
/// project root's own files.
pub(crate) fn lexically_denied(root: &Path, relative: &str) -> Option<DenyReason> {
    DenyList::new(root, root, false, &ProtectedPaths::default()).request_verdict(relative)
}
