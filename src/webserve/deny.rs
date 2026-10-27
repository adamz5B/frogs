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
    /// Folded component lists (each starting with `.well-known`) exempt from the dot-segment rule.
    dot_allow: Vec<Vec<String>>,
    /// (device, inode) of every existing protected file and folder: a hard link or bind mount keeps the identity.
    ids: ProtectedIds,
}

/// A file's identity as the OS sees it: (device or volume, inode or file index). A hard link and a bind
/// mount or other alias of the same file share it, whatever path they are reached by.
type FileId = (u64, u64);

#[cfg(unix)]
fn file_identity(path: &Path) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// `GetFileInformationByHandle` through a query-only handle (no data access, so a locked or
/// unreadable file still answers); `FILE_FLAG_BACKUP_SEMANTICS` is what lets a folder be opened.
#[cfg(windows)]
fn file_identity(path: &Path) -> Option<FileId> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, GetFileInformationByHandle};

    let file = std::fs::OpenOptions::new().access_mode(0).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path).ok()?;
    // SAFETY: `info` is plain data that the call fully initialises on success, and the handle is open for the whole call.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    (ok != 0).then(|| {
        (
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_path: &Path) -> Option<FileId> {
    None
}

/// How long the protected identities are reused before the protected paths are looked at again.
/// A protected file created after startup (a CRL, a `-wal` sidecar, the log file) is picked up within this.
const IDENTITY_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Default)]
struct IdentitySets {
    taken: Option<std::time::Instant>,
    files: std::collections::HashSet<FileId>,
    dirs: std::collections::HashSet<FileId>,
}

/// The protected files and folders frogs owns, remembered by path and re-read as identities
/// (a hard link or bind mount of one keeps its identity).
#[derive(Debug, Clone)]
struct ProtectedIds {
    /// Every protected path, with whether it is a sqlite database whose `-wal`/`-shm`/`-journal` siblings count too.
    sources: Vec<(PathBuf, bool)>,
    refresh_after: std::time::Duration,
    cache: std::sync::Arc<std::sync::Mutex<IdentitySets>>,
}

impl Default for ProtectedIds {
    fn default() -> Self {
        ProtectedIds {
            sources: Vec::new(),
            refresh_after: IDENTITY_REFRESH,
            cache: std::sync::Arc::default(),
        }
    }
}

impl ProtectedIds {
    fn add_source(&mut self, path: &Path, family: bool) {
        if !self.sources.iter().any(|(p, f)| p == path && *f == family) {
            self.sources.push((path.to_path_buf(), family));
        }
    }

    fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    fn read_all(&self) -> IdentitySets {
        let mut sets = IdentitySets {
            taken: Some(std::time::Instant::now()),
            ..IdentitySets::default()
        };
        let mut record = |p: &Path| {
            if let Some(id) = file_identity(p) {
                match std::fs::metadata(p) {
                    Ok(meta) if meta.is_dir() => sets.dirs.insert(id),
                    Ok(_) => sets.files.insert(id),
                    Err(_) => false,
                };
            }
        };
        for (path, family) in &self.sources {
            record(path);
            if *family {
                for suffix in ["-wal", "-shm", "-journal"] {
                    let mut sibling = path.as_os_str().to_os_string();
                    sibling.push(suffix);
                    record(Path::new(&sibling));
                }
            }
        }
        sets
    }

    /// Whether `file` is a protected file, or any of `folders` is a protected folder. Recovers a poisoned lock:
    /// the cache is only ever replaced whole, so there is no half-written state to distrust.
    fn matches(&self, file: Option<FileId>, folders: &[FileId]) -> bool {
        let mut cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.taken.is_none_or(|taken| taken.elapsed() >= self.refresh_after) {
            *cache = self.read_all();
        }
        file.is_some_and(|id| cache.files.contains(&id)) || folders.iter().any(|id| cache.dirs.contains(id))
    }
}

fn is_unsafe_segment(segment: &str) -> bool {
    segment.chars().any(|c| matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') || c.is_control())
        || segment.ends_with('.')
        || segment.ends_with(' ')
        || windows_reserved(segment)
        || segment.as_bytes().windows(2).any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
}

/// An `allowDotPaths` entry as folded components: a plain path whose first segment is `.well-known`.
fn parse_dot_allow(entry: &str) -> Result<Vec<String>, String> {
    let trimmed = entry.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err("it is empty".to_string());
    }
    let mut components = Vec::new();
    for (index, segment) in trimmed.split('/').enumerate() {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("it has an empty, '.' or '..' segment".to_string());
        }
        if index == 0 {
            if fold(segment) != ".well-known" {
                return Err("only paths under .well-known can be allowed".to_string());
            }
        } else if segment.starts_with('.') {
            return Err("a segment below .well-known may not start with '.'".to_string());
        }
        if is_unsafe_segment(segment) || fold(segment) == RESERVED_DIR {
            return Err(format!("segment {} is not a safe file name", untrusted(segment)));
        }
        components.push(fold(segment));
    }
    Ok(components)
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
            dot_allow: Vec::new(),
            ids: ProtectedIds::default(),
        };
        if canonical_root_is_fallback {
            list.problems
                .push("the project root could not be canonicalised; protected paths are denied by their literal spelling only".to_string());
        }

        for spec in &protected.specs {
            let family = spec.kind == SpecKind::SqliteFamily;
            if let RawSpec::Path(path) = &spec.raw {
                list.ids.add_source(path, family);
            }
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
        let mut list = DenyList::new(root, &canonical_root, fallback, &protected);
        list.set_dot_allow(&config.allow_dot_paths);
        (list, canonical_root)
    }

    /// Installs `webserve.json`'s `allowDotPaths`. An entry that is not a plain path under
    /// `.well-known` is reported as a problem and ignored, so a typo never opens `.git` or `.env`.
    pub(crate) fn set_dot_allow(&mut self, entries: &[String]) {
        for entry in entries {
            match parse_dot_allow(entry) {
                Ok(components) => {
                    if !self.dot_allow.contains(&components) {
                        self.dot_allow.push(components);
                    }
                }
                Err(reason) => push_unique(&mut self.problems, format!("allowDotPaths entry {} is ignored: {reason}", untrusted(entry))),
            }
        }
    }

    /// How many leading segments of `segments` (folded) an `allowDotPaths` entry exempts from the dot rule:
    /// the longest entry that is a prefix of the path. A dot segment beyond that prefix is still denied.
    fn dot_exempt_len(&self, segments: &[String]) -> usize {
        self.dot_allow
            .iter()
            .filter(|entry| starts_with_components(segments, entry))
            .map(|entry| entry.len())
            .max()
            .unwrap_or(0)
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
        let segments: Vec<&str> = relative.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        let exempt = self.dot_exempt_len(&segments.iter().map(|s| fold(s)).collect::<Vec<_>>());
        for (index, segment) in segments.into_iter().enumerate() {
            if segment.starts_with('.') && index >= exempt {
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
        let exempt = self.dot_exempt_len(rest);
        if rest.iter().enumerate().any(|(index, c)| c.starts_with('.') && index >= exempt) {
            return Some(DenyReason::DotSegment);
        }
        if rest.iter().any(|c| c == RESERVED_DIR) {
            return Some(DenyReason::Backups);
        }
        self.entry_matches(&folded).then_some(DenyReason::Protected)
    }

    /// A hard link or bind mount to a protected file keeps the original's identity; so does a bind-mounted
    /// (or otherwise aliased) protected folder, which makes every file under it reachable by another path.
    /// Checked on the canonical file just before it is opened.
    pub(crate) fn identity_verdict(&self, canonical: &Path, canonical_root: &Path) -> Option<DenyReason> {
        if self.ids.is_empty() {
            return None;
        }
        let folders: Vec<FileId> = canonical
            .ancestors()
            .skip(1)
            .take_while(|ancestor| *ancestor != canonical_root && ancestor.starts_with(canonical_root))
            .filter_map(file_identity)
            .collect();
        self.ids.matches(file_identity(canonical), &folders).then_some(DenyReason::Protected)
    }

    /// Files and folders under `root` that are hard links or aliases of protected ones. They are already denied at
    /// request time; this lists them for `frogs validate`. Does not follow links and skips whatever the path rules
    /// already deny. Stops after `limit` entries.
    pub(crate) fn identity_scan(&self, root: &Path, limit: usize) -> Vec<String> {
        let mut found = Vec::new();
        if self.ids.is_empty() {
            return found;
        }
        let mut seen = 0usize;
        let mut pending: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
        while let Some((dir, relative)) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                seen += 1;
                if seen > limit {
                    found.push(format!("the site has more than {limit} entries; the hard-link scan stopped early"));
                    found.sort();
                    return found;
                }
                let Ok(file_type) = entry.file_type() else { continue };
                if file_type.is_symlink() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let child = if relative.is_empty() { name } else { format!("{relative}/{name}") };
                if self.request_verdict(&child).is_some() {
                    continue;
                }
                let path = entry.path();
                if file_type.is_dir() {
                    if self.ids.matches(None, &file_identity(&path).into_iter().collect::<Vec<_>>()) {
                        found.push(format!(
                            "{} is an alias (such as a bind mount) of a protected folder; everything under it is denied",
                            untrusted(&child)
                        ));
                    } else {
                        pending.push((path, child));
                    }
                } else if file_type.is_file() && self.ids.matches(file_identity(&path), &[]) {
                    found.push(format!(
                        "{} is a hard link or alias of a protected file; it is denied like a missing file",
                        untrusted(&child)
                    ));
                }
            }
        }
        found.sort();
        found
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

/// For `frogs validate`: site files that are hard links or aliases of protected ones. They are denied at request
/// time anyway, so these are warnings. Walks the whole site, hence not part of `page_problems` (which `run` calls).
pub(crate) fn site_identity_warnings(root: &Path, config: &WebServeConfig, protected: &ProtectedPaths) -> Vec<String> {
    const SCAN_LIMIT: usize = 100_000;
    let (deny, canonical_root) = DenyList::for_site(root, config, protected);
    deny.identity_scan(&canonical_root, SCAN_LIMIT)
}

/// Lexical rules only, for `frogs generate` picking a start page from the
/// project root's own files.
pub(crate) fn lexically_denied(root: &Path, relative: &str) -> Option<DenyReason> {
    DenyList::new(root, root, false, &ProtectedPaths::default()).request_verdict(relative)
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn site() -> (PathBuf, PathBuf) {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let parent = std::env::temp_dir().join(format!("frogs-identity-{}-{nanos}", std::process::id()));
        let root = parent.join("site");
        std::fs::create_dir_all(&root).unwrap();
        (parent, std::fs::canonicalize(&root).unwrap())
    }

    /// A bind mount cannot be made without privileges, but it keeps the folder's identity; protecting the folder
    /// and asking about a file under it exercises the same ancestor check a file reached through a mount would hit.
    #[test]
    fn a_file_under_a_protected_folder_identity_is_denied_and_a_sibling_is_not() {
        let (parent, root) = site();
        std::fs::create_dir_all(root.join("mounted/deeper")).unwrap();
        std::fs::write(root.join("mounted/deeper/file.txt"), "x").unwrap();
        std::fs::write(root.join("ordinary.txt"), "x").unwrap();
        let mut protected = ProtectedPaths::default();
        protected.add_dir("logging.directory", &root.join("mounted"));
        let list = DenyList::new(&root, &root, false, &protected);

        assert_eq!(list.identity_verdict(&root.join("mounted/deeper/file.txt"), &root), Some(DenyReason::Protected));
        assert_eq!(list.identity_verdict(&root.join("ordinary.txt"), &root), None);
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_protected_file_created_after_the_list_was_built_is_covered_once_the_cache_refreshes() {
        let (parent, root) = site();
        let mut protected = ProtectedPaths::default();
        protected.add_path("tls.clientAuth.crlPaths", &root, "later.crl");
        let mut list = DenyList::new(&root, &root, false, &protected);
        std::fs::write(root.join("other.txt"), "x").unwrap();
        assert_eq!(list.identity_verdict(&root.join("other.txt"), &root), None, "nothing protected exists yet");

        std::fs::write(root.join("later.crl"), "crl").unwrap();
        std::fs::hard_link(root.join("later.crl"), root.join("alias.txt")).unwrap();
        list.ids.refresh_after = std::time::Duration::ZERO;
        assert_eq!(list.identity_verdict(&root.join("alias.txt"), &root), Some(DenyReason::Protected));
        assert_eq!(list.identity_verdict(&root.join("other.txt"), &root), None);
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn the_site_scan_lists_hard_links_to_protected_files_and_skips_denied_and_ordinary_paths() {
        let (parent, root) = site();
        std::fs::create_dir_all(root.join("assets/deep")).unwrap();
        std::fs::create_dir_all(root.join("tls")).unwrap();
        std::fs::write(root.join("tls/server.key"), "key").unwrap();
        std::fs::hard_link(root.join("tls/server.key"), root.join("assets/deep/logo.png")).unwrap();
        std::fs::write(root.join("assets/plain.css"), "x").unwrap();
        std::fs::create_dir_all(root.join("_backups")).unwrap();
        std::fs::hard_link(root.join("tls/server.key"), root.join("_backups/copy")).unwrap();
        let mut protected = ProtectedPaths::default();
        protected.add_path("tls.manual.keyPath", &root, "tls/server.key");
        let list = DenyList::new(&root, &root, false, &protected);

        let found = list.identity_scan(&root, 10_000);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("assets/deep/logo.png is a hard link"), "{found:?}");
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn the_site_scan_stops_at_its_limit_and_says_so() {
        let (parent, root) = site();
        for n in 0..5 {
            std::fs::write(root.join(format!("f{n}.txt")), "x").unwrap();
        }
        let mut protected = ProtectedPaths::default();
        protected.add_path("tls.manual.keyPath", &root, "key.pem");
        let list = DenyList::new(&root, &root, false, &protected);
        let found = list.identity_scan(&root, 3);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("scan stopped early"), "{found:?}");
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn no_protected_paths_means_no_identity_work_at_all() {
        let (parent, root) = site();
        std::fs::write(root.join("a.txt"), "x").unwrap();
        let list = DenyList::new(&root, &root, false, &ProtectedPaths::default());
        assert_eq!(list.identity_verdict(&root.join("a.txt"), &root), None);
        assert!(list.identity_scan(&root, 10).is_empty());
        let _ = std::fs::remove_dir_all(&parent);
    }
}
