//! The one place that decides what a link (symlink, or on Windows a junction)
//! under `api/datasources/endpoints/` means: which files get served, and which
//! locations `generate`/`frogs test record` may ever write to. Kept free of
//! `cfg!` so every OS runs the same logic; OS-specific link creation lives in
//! `fs_os_tests.rs`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::dir_index::{DirIndex, EndpointFsError, EntryKind, OutsideReason};
use super::path_rules::untrusted;
use crate::config::EndpointSymlinks;

/// Logical nesting beyond this is never walked (bind mounts and hard-linked
/// directories aren't detectable as aliases, so this bounds them).
pub const MAX_TREE_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafRule {
    /// A content write: the final component must not be a link at all.
    NoLink,
    /// A directory target: a link is allowed as long as it resolves inside the project.
    Dir,
}

/// What every check is measured against: the canonical project root, with
/// `.frogs/` and `.git/` carved out. Deliberately independent of
/// `config/server.json` (scaffolding runs before that file exists, and the file
/// may be untrusted), so no write guarantee can be relaxed by configuration.
#[derive(Debug, Clone)]
pub struct ProjectBoundary {
    lexical_root: PathBuf,
    canonical_root: Result<PathBuf, String>,
}

impl ProjectBoundary {
    pub fn new(project_root: &Path) -> ProjectBoundary {
        let canonical_root = fs::canonicalize(project_root).map_err(|e| format!("cannot resolve the project root {}: {e}", project_root.display()));
        ProjectBoundary {
            lexical_root: project_root.to_path_buf(),
            canonical_root,
        }
    }

    pub fn lexical_root(&self) -> &Path {
        &self.lexical_root
    }

    fn root_for(&self, at: &Path) -> Result<&Path, EndpointFsError> {
        match &self.canonical_root {
            Ok(root) => Ok(root),
            Err(message) => Err(EndpointFsError::OutsideProject {
                at: at.to_path_buf(),
                resolved: None,
                reason: OutsideReason::BadRoot(message.clone()),
            }),
        }
    }

    /// `canonical` must come from `fs::canonicalize` (or be a lexical tail
    /// appended under such a path) so both sides spell the path the same way.
    pub fn is_inside(&self, canonical: &Path) -> bool {
        match &self.canonical_root {
            Ok(root) => canonical.starts_with(root) && !self.is_excluded(canonical),
            Err(_) => false,
        }
    }

    pub fn is_excluded(&self, canonical: &Path) -> bool {
        match &self.canonical_root {
            Ok(root) => canonical.starts_with(root.join(".frogs")) || canonical.starts_with(root.join(".git")),
            Err(_) => false,
        }
    }

    fn outside(&self, at: &Path, resolved: PathBuf) -> EndpointFsError {
        let reason = if self.is_excluded(&resolved) {
            OutsideReason::Excluded
        } else {
            OutsideReason::Outside
        };
        EndpointFsError::OutsideProject {
            at: at.to_path_buf(),
            resolved: Some(resolved),
            reason,
        }
    }

    /// Walks `path` one component at a time starting from the canonical
    /// project root, resolving every component that exists (a dangling link
    /// counts as existing and fails to resolve, so it is refused rather than
    /// treated as absent), and returns the canonical physical location. Only a
    /// component that is genuinely absent may be appended lexically, together
    /// with everything after it.
    pub fn check_write_target(&self, path: &Path, leaf: LeafRule) -> Result<PathBuf, EndpointFsError> {
        let root = self.root_for(path)?;
        let relative = path.strip_prefix(&self.lexical_root).map_err(|_| {
            EndpointFsError::Containment(format!(
                "{} is not under the project root {}",
                untrusted(&path.display().to_string()),
                self.lexical_root.display()
            ))
        })?;
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(name) => names.push(name),
                _ => {
                    return Err(EndpointFsError::Containment(format!(
                        "{} has a component that is not a plain name",
                        untrusted(&path.display().to_string())
                    )));
                }
            }
        }

        let mut current = root.to_path_buf();
        let mut appended = false;
        for (index, name) in names.iter().enumerate() {
            let candidate = current.join(name);
            if appended {
                current = candidate;
                continue;
            }
            match fs::symlink_metadata(&candidate) {
                Ok(meta) => {
                    if index + 1 == names.len() && leaf == LeafRule::NoLink && meta.file_type().is_symlink() {
                        return Err(EndpointFsError::Symlink { at: path.to_path_buf() });
                    }
                    match fs::canonicalize(&candidate) {
                        Ok(resolved) => {
                            if !self.is_inside(&resolved) {
                                return Err(self.outside(path, resolved));
                            }
                            current = resolved;
                        }
                        Err(e) => return Err(unresolvable(path, name, &e)),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    current = candidate;
                    appended = true;
                }
                Err(e) => return Err(unresolvable(path, name, &e)),
            }
        }
        if !self.is_inside(&current) {
            return Err(self.outside(path, current));
        }
        Ok(current)
    }

    /// Whether any component of `path` below the project root is a link (or
    /// `path` is not under the root at all, which is treated the same way).
    pub fn path_has_link(&self, path: &Path) -> bool {
        let (Ok(root), Ok(relative)) = (self.root_for(path), path.strip_prefix(&self.lexical_root)) else {
            return true;
        };
        let mut current = root.to_path_buf();
        for component in relative.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        false
    }
}

fn unresolvable(path: &Path, component: &std::ffi::OsStr, error: &std::io::Error) -> EndpointFsError {
    EndpointFsError::OutsideProject {
        at: path.to_path_buf(),
        resolved: None,
        reason: OutsideReason::Unresolvable {
            component: component.to_string_lossy().into_owned(),
            error: error.to_string(),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Dir,
    File,
    Other,
    Dangling,
}

#[derive(Debug, Clone)]
pub struct LinkTarget {
    pub kind: LinkKind,
    pub canonical: Option<PathBuf>,
    pub inside: bool,
    pub excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFindingKind {
    Refused,
    Escapes,
    Excluded,
    Cycle,
    Alias { kept: PathBuf },
    Dangling,
    DepthLimit,
}

/// A boundary plus the configured read policy: the single place a link's
/// target is classified and a read/write decision made.
#[derive(Debug, Clone)]
pub struct LinkContext {
    pub boundary: ProjectBoundary,
    pub policy: EndpointSymlinks,
}

impl LinkContext {
    pub fn new(project_root: &Path, policy: EndpointSymlinks) -> LinkContext {
        LinkContext {
            boundary: ProjectBoundary::new(project_root),
            policy,
        }
    }

    pub fn classify_link(&self, link: &Path) -> LinkTarget {
        let Ok(canonical) = fs::canonicalize(link) else {
            return LinkTarget {
                kind: LinkKind::Dangling,
                canonical: None,
                inside: false,
                excluded: false,
            };
        };
        let kind = match fs::metadata(&canonical) {
            Ok(meta) if meta.is_dir() => LinkKind::Dir,
            Ok(meta) if meta.is_file() => LinkKind::File,
            Ok(_) => LinkKind::Other,
            Err(_) => LinkKind::Dangling,
        };
        LinkTarget {
            kind,
            inside: self.boundary.is_inside(&canonical),
            excluded: self.boundary.is_excluded(&canonical),
            canonical: Some(canonical),
        }
    }

    pub fn decide(&self, target: &LinkTarget, access: Access) -> Result<(), LinkFindingKind> {
        if target.kind == LinkKind::Dangling {
            return Err(LinkFindingKind::Dangling);
        }
        if target.excluded {
            return Err(LinkFindingKind::Excluded);
        }
        match (self.policy, access) {
            (EndpointSymlinks::Refuse, _) => Err(LinkFindingKind::Refused),
            (EndpointSymlinks::Follow, Access::Read) => Ok(()),
            (EndpointSymlinks::Contained, _) | (EndpointSymlinks::Follow, Access::Write) => {
                if target.inside {
                    Ok(())
                } else {
                    Err(LinkFindingKind::Escapes)
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeFile {
    pub logical: PathBuf,
    pub rel_dir: Vec<String>,
    pub name: String,
    /// The file, or any folder above it, is a link.
    pub via_link: bool,
    /// Whether every link on the way here may also be written through.
    pub dir_writable: bool,
}

#[derive(Debug, Clone)]
pub struct LinkFinding {
    pub kind: LinkFindingKind,
    pub link: PathBuf,
    pub target: Option<PathBuf>,
    pub strict: bool,
}

impl LinkFinding {
    pub fn message(&self, policy: EndpointSymlinks) -> String {
        let link = untrusted(&self.link.display().to_string());
        let target = self.target.as_ref().map(|t| untrusted(&t.display().to_string())).unwrap_or_default();
        match &self.kind {
            LinkFindingKind::Refused => format!("{link} is a symbolic link or junction — not followed (endpointSymlinks is \"refuse\")"),
            LinkFindingKind::Escapes => format!(
                "{link} is a symbolic link or junction whose target {target} is outside the project — not served (endpointSymlinks is \"{}\"; \
                 set endpointSymlinks to \"follow\" in config/server.json to serve it)",
                policy.as_str()
            ),
            LinkFindingKind::Excluded => format!("{link} points into {target}, inside the project's .frogs or .git folder — never followed"),
            LinkFindingKind::Cycle => format!("{link} points back at {target}, a folder it is already inside of — not followed"),
            LinkFindingKind::Alias { kept } => format!(
                "{link} points at {target}, which is already served as {} — skipped so one folder is not served twice",
                untrusted(&kept.display().to_string())
            ),
            LinkFindingKind::Dangling => format!("{link} is a link whose target does not exist — ignored"),
            LinkFindingKind::DepthLimit => format!("{link}: folders nested more than {MAX_TREE_DEPTH} levels deep are not walked"),
        }
    }
}

/// Everything under one endpoints folder that any walker may act on, built by a
/// single scan so every command sees the same set of files and findings.
#[derive(Debug, Clone)]
pub struct EndpointTree {
    endpoints_root: PathBuf,
    files: Vec<TreeFile>,
    findings: Vec<LinkFinding>,
    index: HashMap<PathBuf, usize>,
    policy: EndpointSymlinks,
}

fn is_endpoint_name(name: &str) -> bool {
    name.starts_with("endpoint.") || name.starts_with("_endpoint.")
}

struct PendingLink {
    physical: PathBuf,
    logical: PathBuf,
    rel: Vec<String>,
    chain: Vec<PathBuf>,
    writable: bool,
    is_dir: bool,
}

struct Scanner<'a> {
    ctx: &'a LinkContext,
    files: Vec<TreeFile>,
    findings: Vec<LinkFinding>,
    visited: HashMap<PathBuf, PathBuf>,
    pending: Vec<PendingLink>,
}

impl Scanner<'_> {
    fn finding(&mut self, kind: LinkFindingKind, link: PathBuf, target: Option<PathBuf>) {
        self.findings.push(LinkFinding {
            kind,
            link,
            target,
            strict: true,
        });
    }

    fn walk_dir(&mut self, physical: &Path, logical: &Path, rel: &[String], chain: &mut Vec<PathBuf>, writable: bool, via_link: bool) {
        let Ok(index) = DirIndex::read(physical) else { return };
        let entries: Vec<(String, EntryKind)> = index.entries().map(|(name, kind)| (name.to_string(), kind)).collect();
        for (name, kind) in entries {
            if name == "_backups" {
                continue;
            }
            let child_physical = physical.join(&name);
            let child_logical = logical.join(&name);
            match kind {
                EntryKind::Dir => {
                    let mut child_rel = rel.to_vec();
                    child_rel.push(name);
                    self.descend(child_physical, child_logical, child_rel, chain, writable, via_link);
                }
                EntryKind::File if is_endpoint_name(&name) => self.files.push(TreeFile {
                    logical: child_logical,
                    rel_dir: rel.to_vec(),
                    name,
                    via_link,
                    dir_writable: writable,
                }),
                EntryKind::Symlink => self.note_link(&name, child_physical, child_logical, rel, chain, writable),
                _ => {}
            }
        }
    }

    /// `physical` is already canonical here (a real child of a canonical
    /// directory, or a followed link's canonical target).
    fn descend(&mut self, physical: PathBuf, logical: PathBuf, rel: Vec<String>, chain: &mut Vec<PathBuf>, writable: bool, via_link: bool) {
        if rel.len() > MAX_TREE_DEPTH {
            self.finding(LinkFindingKind::DepthLimit, logical, None);
            return;
        }
        if self.ctx.boundary.is_excluded(&physical) {
            self.finding(LinkFindingKind::Excluded, logical, Some(physical));
            return;
        }
        if chain.contains(&physical) {
            self.finding(LinkFindingKind::Cycle, logical, Some(physical));
            return;
        }
        if let Some(kept) = self.visited.get(&physical).cloned() {
            self.finding(LinkFindingKind::Alias { kept }, logical, Some(physical));
            return;
        }
        self.visited.insert(physical.clone(), logical.clone());
        chain.push(physical.clone());
        self.walk_dir(&physical, &logical, &rel, chain, writable, via_link);
        chain.pop();
    }

    fn note_link(&mut self, name: &str, physical: PathBuf, logical: PathBuf, rel: &[String], chain: &[PathBuf], writable: bool) {
        let relevant_name = is_endpoint_name(name);
        let is_dir = match fs::metadata(&physical) {
            Ok(meta) if meta.is_dir() => true,
            Ok(meta) if meta.is_file() && relevant_name => false,
            Ok(_) => return,
            Err(_) => {
                if relevant_name || !name.contains('.') {
                    let target = fs::read_link(&physical).ok();
                    self.finding(LinkFindingKind::Dangling, logical, target);
                }
                return;
            }
        };
        let mut link_rel = rel.to_vec();
        link_rel.push(name.to_string());
        self.pending.push(PendingLink {
            physical,
            logical,
            rel: link_rel,
            chain: chain.to_vec(),
            writable,
            is_dir,
        });
    }

    fn process_link(&mut self, link: PendingLink) {
        let target = self.ctx.classify_link(&link.physical);
        if let Err(kind) = self.ctx.decide(&target, Access::Read) {
            self.finding(kind, link.logical, target.canonical);
            return;
        }
        let Some(canonical) = target.canonical.clone() else { return };
        let writable = link.writable && self.ctx.decide(&target, Access::Write).is_ok();
        if link.is_dir {
            if target.kind != LinkKind::Dir {
                return;
            }
            let mut chain = link.chain;
            self.descend(canonical, link.logical, link.rel, &mut chain, writable, true);
        } else if target.kind == LinkKind::File {
            let mut rel_dir = link.rel;
            let name = rel_dir.pop().unwrap_or_default();
            self.files.push(TreeFile {
                logical: link.logical,
                rel_dir,
                name,
                via_link: true,
                dir_writable: link.writable,
            });
        }
    }
}

impl EndpointTree {
    fn empty(endpoints_root: &Path, policy: EndpointSymlinks) -> EndpointTree {
        EndpointTree {
            endpoints_root: endpoints_root.to_path_buf(),
            files: Vec::new(),
            findings: Vec::new(),
            index: HashMap::new(),
            policy,
        }
    }

    /// Walks the endpoints folder once. Every real folder is walked before any
    /// link, links are then followed in rounds sorted by logical path, and a
    /// physical folder is only ever walked once, so a real path always beats a
    /// link to it and between two links the first in sorted order wins.
    pub fn scan(ctx: &LinkContext, endpoints_root: &Path) -> EndpointTree {
        let mut tree = EndpointTree::empty(endpoints_root, ctx.policy);
        if fs::symlink_metadata(endpoints_root).is_err() {
            return tree;
        }
        let mut scanner = Scanner {
            ctx,
            files: Vec::new(),
            findings: Vec::new(),
            visited: HashMap::new(),
            pending: Vec::new(),
        };

        let root_via_link = ctx.boundary.path_has_link(endpoints_root);
        let Ok(canonical) = fs::canonicalize(endpoints_root) else {
            let target = fs::read_link(endpoints_root).ok();
            scanner.finding(LinkFindingKind::Dangling, endpoints_root.to_path_buf(), target);
            tree.findings = scanner.findings;
            return tree;
        };
        let mut writable = true;
        if root_via_link {
            let target = ctx.classify_link(endpoints_root);
            if let Err(kind) = ctx.decide(&target, Access::Read) {
                scanner.finding(kind, endpoints_root.to_path_buf(), target.canonical);
                tree.findings = scanner.findings;
                return tree;
            }
            writable = ctx.decide(&target, Access::Write).is_ok();
        }
        if !fs::metadata(&canonical).map(|m| m.is_dir()).unwrap_or(false) {
            return tree;
        }

        scanner.visited.insert(canonical.clone(), endpoints_root.to_path_buf());
        let mut chain = vec![canonical.clone()];
        scanner.walk_dir(&canonical, endpoints_root, &[], &mut chain, writable, root_via_link);
        while !scanner.pending.is_empty() {
            let mut round = std::mem::take(&mut scanner.pending);
            round.sort_by(|a, b| a.logical.cmp(&b.logical));
            for link in round {
                scanner.process_link(link);
            }
        }

        tree.files = scanner.files;
        tree.files.sort_by(|a, b| a.logical.cmp(&b.logical));
        tree.findings = scanner.findings;
        tree.index = tree.files.iter().enumerate().map(|(i, f)| (f.logical.clone(), i)).collect();
        tree
    }

    pub fn endpoints_root(&self) -> &Path {
        &self.endpoints_root
    }

    pub fn policy(&self) -> EndpointSymlinks {
        self.policy
    }

    pub fn files(&self) -> &[TreeFile] {
        &self.files
    }

    pub fn findings(&self) -> &[LinkFinding] {
        &self.findings
    }

    pub fn file_in(&self, dir: &Path, name: &str) -> Option<&TreeFile> {
        self.index.get(&dir.join(name)).map(|&i| &self.files[i])
    }

    /// A file in `dir` whose name differs from `name` only by letter case.
    pub fn case_variant_in(&self, dir: &Path, name: &str) -> Option<&TreeFile> {
        let folded = super::dir_index::fold(name);
        self.files
            .iter()
            .find(|f| f.name != name && f.logical.parent() == Some(dir) && super::dir_index::fold(&f.name) == folded)
    }

    pub fn is_via_link(&self, file: &Path) -> bool {
        self.index.get(file).is_some_and(|&i| self.files[i].via_link)
    }

    pub fn link_messages(&self) -> Vec<String> {
        self.findings.iter().map(|f| f.message(self.policy)).collect()
    }

    /// Logical paths of every file reached through a link, for callers that
    /// must not echo such a file's contents.
    #[allow(dead_code)] // Part of the tree surface; exercised by tests.
    pub fn linked_files(&self) -> HashSet<&Path> {
        self.files.iter().filter(|f| f.via_link).map(|f| f.logical.as_path()).collect()
    }
}

/// What may be said about a JSON parse failure of a file reached through a
/// link: position and category only, never serde's message (which can quote
/// the offending value, i.e. arbitrary bytes from wherever the link points).
pub fn parse_error_summary(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "unexpected end of file",
    };
    format!("invalid JSON at line {} column {} ({category})", error.line(), error.column())
}

/// Same scan as production with the default policy, with the project boundary
/// drawn around the endpoints folder itself — enough for tests that only need a
/// tree of real files.
#[cfg(test)]
pub fn tree_for_tests(endpoints_root: &Path) -> EndpointTree {
    tree_for_tests_with(endpoints_root, endpoints_root, EndpointSymlinks::Contained)
}

#[cfg(test)]
pub fn tree_for_tests_with(project_root: &Path, endpoints_root: &Path, policy: EndpointSymlinks) -> EndpointTree {
    EndpointTree::scan(&LinkContext::new(project_root, policy), endpoints_root)
}
