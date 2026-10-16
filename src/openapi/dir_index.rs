use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::path_rules::{is_single_normal_component, untrusted};

/// Case folding used for every "do these two names collide" question. The
/// upper-then-lower round trip makes `Straße` and `STRASSE` fold together;
/// it is deliberately the same on every OS so results never depend on the
/// host filesystem's own case rules.
pub fn fold(s: &str) -> String {
    s.to_uppercase().to_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    /// Symlinks, and on Windows junctions too.
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
struct Entry {
    name: OsString,
    utf8: Option<String>,
    folded: Option<String>,
    kind: EntryKind,
}

/// One directory listing, so every name question is answered from the
/// listing's exact bytes rather than by an OS name lookup (which is
/// case-insensitive on Windows/macOS and case-sensitive on Linux).
#[derive(Debug, Clone)]
pub struct DirIndex {
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Exact(EntryKind),
    CaseConflict { found: OsString },
    Absent,
}

impl DirIndex {
    /// A missing directory is an empty index, not an error.
    pub fn read(dir: &Path) -> io::Result<DirIndex> {
        let read_dir = match fs::read_dir(dir) {
            Ok(read_dir) => read_dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DirIndex { entries: Vec::new() }),
            Err(e) => return Err(e),
        };
        let mut entries = Vec::new();
        for entry in read_dir {
            let entry = entry?;
            let kind = match entry.file_type() {
                Ok(t) if t.is_symlink() => EntryKind::Symlink,
                Ok(t) if t.is_dir() => EntryKind::Dir,
                Ok(t) if t.is_file() => EntryKind::File,
                _ => EntryKind::Other,
            };
            let name = entry.file_name();
            let utf8 = name.to_str().map(str::to_string);
            let folded = utf8.as_deref().map(fold);
            entries.push(Entry { name, utf8, folded, kind });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(DirIndex { entries })
    }

    #[allow(dead_code)] // Part of the DirIndex surface; exercised by tests.
    pub fn exact(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.utf8.as_deref() == Some(name))
    }

    pub fn case_variants(&self, name: &str) -> Vec<OsString> {
        let folded = fold(name);
        self.entries
            .iter()
            .filter(|e| e.folded.as_deref() == Some(folded.as_str()) && e.utf8.as_deref() != Some(name))
            .map(|e| e.name.clone())
            .collect()
    }

    pub fn lookup(&self, name: &str) -> Lookup {
        if let Some(entry) = self.entries.iter().find(|e| e.utf8.as_deref() == Some(name)) {
            return Lookup::Exact(entry.kind);
        }
        match self.case_variants(name).into_iter().next() {
            Some(found) => Lookup::CaseConflict { found },
            None => Lookup::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirState {
    Exists(PathBuf),
    WillCreate(PathBuf),
}

impl DirState {
    pub fn path(&self) -> &Path {
        match self {
            DirState::Exists(p) | DirState::WillCreate(p) => p,
        }
    }
}

#[derive(Debug)]
pub enum EndpointFsError {
    CaseConflict { wanted: String, found: String, at: PathBuf },
    Symlink { at: PathBuf },
    NotADirectory { at: PathBuf },
    NotARegularFile { at: PathBuf },
    Containment(String),
    AlreadyExists { at: PathBuf },
    Io(io::Error),
}

impl EndpointFsError {
    /// Whether this is the kind of problem `strictOpenApi` turns into a
    /// refusal (as opposed to a plain I/O failure).
    pub fn is_strict_error(&self) -> bool {
        matches!(
            self,
            EndpointFsError::CaseConflict { .. } | EndpointFsError::Symlink { .. } | EndpointFsError::NotARegularFile { .. } | EndpointFsError::Containment(_)
        )
    }
}

impl fmt::Display for EndpointFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointFsError::CaseConflict { wanted, found, at } => {
                write!(f, "{found} exists where {wanted} is needed — rename or remove it by hand (in {})", at.display())
            }
            EndpointFsError::Symlink { at } => write!(f, "{} is a symbolic link or junction — refusing to follow it", at.display()),
            EndpointFsError::NotADirectory { at } => write!(f, "{} exists but is not a directory", at.display()),
            EndpointFsError::NotARegularFile { at } => write!(f, "{} exists but is not a regular file", at.display()),
            EndpointFsError::Containment(message) => write!(f, "{message}"),
            EndpointFsError::AlreadyExists { at } => write!(f, "{} already exists — refusing to overwrite it", at.display()),
            EndpointFsError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EndpointFsError {}

impl From<io::Error> for EndpointFsError {
    fn from(e: io::Error) -> Self {
        EndpointFsError::Io(e)
    }
}

impl From<EndpointFsError> for io::Error {
    fn from(e: EndpointFsError) -> Self {
        match e {
            EndpointFsError::Io(e) => e,
            EndpointFsError::Containment(message) => io::Error::new(io::ErrorKind::InvalidInput, message),
            EndpointFsError::AlreadyExists { .. } => io::Error::new(io::ErrorKind::AlreadyExists, e.to_string()),
            other => io::Error::other(other.to_string()),
        }
    }
}

fn check_segments(segments: &[&str]) -> Result<(), EndpointFsError> {
    for seg in segments {
        if seg.is_empty() || !is_single_normal_component(seg) || seg.contains('\0') || seg.contains('\\') || seg.contains('/') {
            return Err(EndpointFsError::Containment(format!("path segment '{}' is not a plain name", untrusted(seg))));
        }
    }
    Ok(())
}

/// `Ok(true)` if the root exists as a real directory, `Ok(false)` if absent.
fn check_root(endpoints_root: &Path) -> Result<bool, EndpointFsError> {
    match fs::symlink_metadata(endpoints_root) {
        Ok(meta) if meta.file_type().is_symlink() => Err(EndpointFsError::Symlink {
            at: endpoints_root.to_path_buf(),
        }),
        Ok(meta) if !meta.is_dir() => Err(EndpointFsError::NotADirectory {
            at: endpoints_root.to_path_buf(),
        }),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn join_all(base: &Path, segments: &[&str]) -> PathBuf {
    let mut path = base.to_path_buf();
    for seg in segments {
        path.push(seg);
    }
    path
}

fn case_conflict(wanted: &str, found: OsString, at: &Path) -> EndpointFsError {
    EndpointFsError::CaseConflict {
        wanted: wanted.to_string(),
        found: found.to_string_lossy().into_owned(),
        at: at.to_path_buf(),
    }
}

pub fn resolve_endpoint_dir(endpoints_root: &Path, segments: &[&str]) -> Result<DirState, EndpointFsError> {
    check_segments(segments)?;
    if !check_root(endpoints_root)? {
        return Ok(DirState::WillCreate(join_all(endpoints_root, segments)));
    }
    let mut current = endpoints_root.to_path_buf();
    for (i, seg) in segments.iter().enumerate() {
        let index = DirIndex::read(&current)?;
        match index.lookup(seg) {
            Lookup::Exact(EntryKind::Dir) => current.push(seg),
            Lookup::Exact(EntryKind::Symlink) => return Err(EndpointFsError::Symlink { at: current.join(seg) }),
            Lookup::Exact(_) => return Err(EndpointFsError::NotADirectory { at: current.join(seg) }),
            Lookup::CaseConflict { found } => return Err(case_conflict(seg, found, &current)),
            Lookup::Absent => return Ok(DirState::WillCreate(join_all(&current, &segments[i..]))),
        }
    }
    Ok(DirState::Exists(current))
}

/// Creates every missing level one `create_dir` at a time (never
/// `create_dir_all`, which would follow a link planted between the check
/// and the create).
pub fn create_endpoint_dir(endpoints_root: &Path, segments: &[&str]) -> Result<PathBuf, EndpointFsError> {
    check_segments(segments)?;
    if !check_root(endpoints_root)? {
        fs::create_dir_all(endpoints_root)?;
        check_root(endpoints_root)?;
    }
    let mut current = endpoints_root.to_path_buf();
    for seg in segments {
        let index = DirIndex::read(&current)?;
        match index.lookup(seg) {
            Lookup::Exact(EntryKind::Dir) => current.push(seg),
            Lookup::Exact(EntryKind::Symlink) => return Err(EndpointFsError::Symlink { at: current.join(seg) }),
            Lookup::Exact(_) => return Err(EndpointFsError::NotADirectory { at: current.join(seg) }),
            Lookup::CaseConflict { found } => return Err(case_conflict(seg, found, &current)),
            Lookup::Absent => {
                current.push(seg);
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        let meta = fs::symlink_metadata(&current)?;
                        if meta.file_type().is_symlink() {
                            return Err(EndpointFsError::Symlink { at: current });
                        }
                        if !meta.is_dir() {
                            return Err(EndpointFsError::NotADirectory { at: current });
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(current)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    Present(PathBuf),
    Absent,
}

/// What `dir/name` is, judged from `dir`'s listing: only a regular file is
/// ever read or overwritten, and a differently-cased sibling is a conflict
/// rather than something the OS might or might not silently alias.
pub fn check_file(dir: &Path, name: &str) -> Result<FileState, EndpointFsError> {
    check_segments(&[name])?;
    let index = DirIndex::read(dir)?;
    match index.lookup(name) {
        Lookup::Exact(EntryKind::File) => Ok(FileState::Present(dir.join(name))),
        Lookup::Exact(EntryKind::Symlink) => Err(EndpointFsError::Symlink { at: dir.join(name) }),
        Lookup::Exact(_) => Err(EndpointFsError::NotARegularFile { at: dir.join(name) }),
        Lookup::CaseConflict { found } => Err(case_conflict(name, found, dir)),
        Lookup::Absent => Ok(FileState::Absent),
    }
}

pub fn create_new_file(dir: &Path, name: &str, contents: &[u8]) -> Result<(), EndpointFsError> {
    if let FileState::Present(path) = check_file(dir, name)? {
        return Err(EndpointFsError::AlreadyExists { at: path });
    }
    let path = dir.join(name);
    let mut file = match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(EndpointFsError::AlreadyExists { at: path }),
        Err(e) => return Err(e.into()),
    };
    file.write_all(contents)?;
    Ok(())
}

/// Renames `dir/from` to `dir/to`, refusing when the target exists in any
/// casing (a plain `fs::rename` silently overwrites on every OS).
pub fn rename_checked(dir: &Path, from: &str, to: &str) -> Result<(), EndpointFsError> {
    check_segments(&[from, to])?;
    let index = DirIndex::read(dir)?;
    match index.lookup(from) {
        Lookup::Exact(EntryKind::File) => {}
        Lookup::Exact(EntryKind::Symlink) => return Err(EndpointFsError::Symlink { at: dir.join(from) }),
        Lookup::Exact(_) => return Err(EndpointFsError::NotARegularFile { at: dir.join(from) }),
        Lookup::CaseConflict { found } => return Err(case_conflict(from, found, dir)),
        Lookup::Absent => return Err(io::Error::new(io::ErrorKind::NotFound, format!("{} does not exist", dir.join(from).display())).into()),
    }
    match index.lookup(to) {
        Lookup::Absent => {}
        Lookup::Exact(_) => return Err(EndpointFsError::AlreadyExists { at: dir.join(to) }),
        Lookup::CaseConflict { found } => return Err(case_conflict(to, found, dir)),
    }
    fs::rename(dir.join(from), dir.join(to))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-dirindex-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Whether this temp dir's filesystem folds case on lookup; printed so a
    /// CI log shows which flavour ran, and the tests assert the same outcome
    /// either way.
    fn case_insensitive_fs(dir: &Path) -> bool {
        fs::write(dir.join("probe_a"), b"").unwrap();
        let insensitive = dir.join("PROBE_A").exists();
        fs::remove_file(dir.join("probe_a")).unwrap();
        eprintln!("case-insensitive filesystem: {insensitive}");
        insensitive
    }

    #[test]
    fn fold_makes_sharp_s_and_double_s_collide_and_is_case_blind() {
        assert_eq!(fold("Straße"), fold("STRASSE"));
        assert_eq!(fold("Cars"), "cars");
        assert_ne!(fold("cars"), fold("cart"));
    }

    #[test]
    fn a_directory_differing_only_by_case_is_a_case_conflict_on_every_filesystem() {
        let root = tempdir();
        case_insensitive_fs(&root);
        let endpoints = root.join("endpoints");
        fs::create_dir_all(endpoints.join("Cars")).unwrap();
        let err = resolve_endpoint_dir(&endpoints, &["cars"]).unwrap_err();
        match err {
            EndpointFsError::CaseConflict { wanted, found, .. } => {
                assert_eq!(wanted, "cars");
                assert_eq!(found, "Cars");
            }
            other => panic!("expected CaseConflict, got {other:?}"),
        }
        assert!(matches!(
            create_endpoint_dir(&endpoints, &["cars"]).unwrap_err(),
            EndpointFsError::CaseConflict { .. }
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_exact_directory_resolves_to_exists_and_a_missing_tail_to_will_create() {
        let root = tempdir();
        let endpoints = root.join("endpoints");
        fs::create_dir_all(endpoints.join("cars")).unwrap();
        assert_eq!(resolve_endpoint_dir(&endpoints, &["cars"]).unwrap(), DirState::Exists(endpoints.join("cars")));
        let state = resolve_endpoint_dir(&endpoints, &["cars", "{vin}"]).unwrap();
        assert_eq!(state, DirState::WillCreate(endpoints.join("cars").join("{vin}")));
        assert_eq!(state.path(), endpoints.join("cars").join("{vin}"));
        assert_eq!(resolve_endpoint_dir(&endpoints, &[]).unwrap(), DirState::Exists(endpoints.clone()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_absent_endpoints_root_resolves_to_will_create_for_the_whole_chain() {
        let root = tempdir();
        let endpoints = root.join("nope");
        let state = resolve_endpoint_dir(&endpoints, &["a", "b"]).unwrap();
        assert_eq!(state, DirState::WillCreate(endpoints.join("a").join("b")));
        assert!(!endpoints.exists(), "resolve is read-only");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_where_a_directory_is_expected_is_not_a_directory() {
        let root = tempdir();
        let endpoints = root.join("endpoints");
        fs::create_dir_all(&endpoints).unwrap();
        fs::write(endpoints.join("cars"), b"x").unwrap();
        assert!(matches!(
            resolve_endpoint_dir(&endpoints, &["cars"]).unwrap_err(),
            EndpointFsError::NotADirectory { .. }
        ));
        let file_root = root.join("file_root");
        fs::write(&file_root, b"x").unwrap();
        assert!(matches!(
            resolve_endpoint_dir(&file_root, &["cars"]).unwrap_err(),
            EndpointFsError::NotADirectory { .. }
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn traversal_segments_are_a_containment_error_before_any_filesystem_access() {
        let root = tempdir();
        let endpoints = root.join("endpoints");
        for seg in ["..", ".", "", "a/b", "a\0b"] {
            let err = resolve_endpoint_dir(&endpoints, &[seg]).unwrap_err();
            assert!(matches!(err, EndpointFsError::Containment(_)), "{seg:?} -> {err:?}");
            assert!(err.is_strict_error());
            assert!(matches!(create_endpoint_dir(&endpoints, &[seg]).unwrap_err(), EndpointFsError::Containment(_)));
        }
        assert!(!endpoints.exists());
        let io_err: io::Error = EndpointFsError::Containment("x".into()).into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn create_endpoint_dir_creates_each_missing_level_and_is_idempotent() {
        let root = tempdir();
        let endpoints = root.join("endpoints");
        let made = create_endpoint_dir(&endpoints, &["cars", "{vin}"]).unwrap();
        assert_eq!(made, endpoints.join("cars").join("{vin}"));
        assert!(made.is_dir());
        assert_eq!(create_endpoint_dir(&endpoints, &["cars", "{vin}"]).unwrap(), made);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_differently_cased_file_is_a_case_conflict_with_the_documented_message() {
        let root = tempdir();
        case_insensitive_fs(&root);
        fs::write(root.join("endpoint.purge.json"), b"{}").unwrap();
        let err = check_file(&root, "endpoint.PURGE.json").unwrap_err();
        match &err {
            EndpointFsError::CaseConflict { wanted, found, .. } => {
                assert_eq!(wanted, "endpoint.PURGE.json");
                assert_eq!(found, "endpoint.purge.json");
            }
            other => panic!("expected CaseConflict, got {other:?}"),
        }
        assert!(
            err.to_string()
                .starts_with("endpoint.purge.json exists where endpoint.PURGE.json is needed — rename or remove it by hand")
        );
        assert!(err.is_strict_error());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn check_file_reports_present_absent_and_non_regular_entries() {
        let root = tempdir();
        fs::write(root.join("a.json"), b"{}").unwrap();
        fs::create_dir(root.join("d.json")).unwrap();
        assert_eq!(check_file(&root, "a.json").unwrap(), FileState::Present(root.join("a.json")));
        assert_eq!(check_file(&root, "b.json").unwrap(), FileState::Absent);
        assert!(matches!(check_file(&root, "d.json").unwrap_err(), EndpointFsError::NotARegularFile { .. }));
        assert_eq!(check_file(&root.join("missing_dir"), "a.json").unwrap(), FileState::Absent);
        assert!(matches!(check_file(&root, "../a.json").unwrap_err(), EndpointFsError::Containment(_)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn create_new_file_writes_a_new_file_and_refuses_to_overwrite_an_existing_one() {
        let root = tempdir();
        create_new_file(&root, "x.json", b"first").unwrap();
        assert_eq!(fs::read(root.join("x.json")).unwrap(), b"first");
        let err = create_new_file(&root, "x.json", b"second").unwrap_err();
        assert!(matches!(err, EndpointFsError::AlreadyExists { .. }));
        assert_eq!(fs::read(root.join("x.json")).unwrap(), b"first");
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::AlreadyExists);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn create_new_file_refuses_when_only_a_case_variant_exists() {
        let root = tempdir();
        case_insensitive_fs(&root);
        fs::write(root.join("x.json"), b"first").unwrap();
        let err = create_new_file(&root, "X.json", b"second").unwrap_err();
        assert!(matches!(err, EndpointFsError::CaseConflict { .. }), "{err:?}");
        assert_eq!(fs::read(root.join("x.json")).unwrap(), b"first");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_checked_moves_a_file_to_a_free_name() {
        let root = tempdir();
        fs::write(root.join("a.json"), b"A").unwrap();
        rename_checked(&root, "a.json", "_a.json").unwrap();
        assert!(!root.join("a.json").exists());
        assert_eq!(fs::read(root.join("_a.json")).unwrap(), b"A");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_checked_refuses_an_existing_target_and_leaves_both_files_intact() {
        let root = tempdir();
        fs::write(root.join("a.json"), b"A").unwrap();
        fs::write(root.join("_a.json"), b"OLD").unwrap();
        let err = rename_checked(&root, "a.json", "_a.json").unwrap_err();
        assert!(matches!(err, EndpointFsError::AlreadyExists { .. }), "{err:?}");
        assert_eq!(fs::read(root.join("a.json")).unwrap(), b"A");
        assert_eq!(fs::read(root.join("_a.json")).unwrap(), b"OLD");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_checked_refuses_a_case_variant_target_and_leaves_the_source_untouched() {
        let root = tempdir();
        case_insensitive_fs(&root);
        fs::write(root.join("a.json"), b"A").unwrap();
        fs::write(root.join("_A.json"), b"OTHER").unwrap();
        let err = rename_checked(&root, "a.json", "_a.json").unwrap_err();
        assert!(matches!(err, EndpointFsError::CaseConflict { .. }), "{err:?}");
        assert_eq!(fs::read(root.join("a.json")).unwrap(), b"A");
        assert_eq!(fs::read(root.join("_A.json")).unwrap(), b"OTHER");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_checked_on_a_missing_source_is_a_not_found_io_error() {
        let root = tempdir();
        match rename_checked(&root, "nope.json", "_nope.json").unwrap_err() {
            EndpointFsError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dir_index_exact_and_case_variants_and_lookup_agree() {
        let root = tempdir();
        fs::write(root.join("Cars.json"), b"").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        let index = DirIndex::read(&root).unwrap();
        assert!(index.exact("Cars.json"));
        assert!(!index.exact("cars.json"));
        assert_eq!(index.case_variants("cars.json"), vec![OsString::from("Cars.json")]);
        assert!(index.case_variants("Cars.json").is_empty());
        assert_eq!(index.lookup("Cars.json"), Lookup::Exact(EntryKind::File));
        assert_eq!(index.lookup("sub"), Lookup::Exact(EntryKind::Dir));
        assert_eq!(index.lookup("other"), Lookup::Absent);
        assert!(matches!(index.lookup("CARS.JSON"), Lookup::CaseConflict { .. }));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reading_a_missing_directory_gives_an_empty_index() {
        let root = tempdir();
        let index = DirIndex::read(&root.join("missing")).unwrap();
        assert_eq!(index.lookup("anything"), Lookup::Absent);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn only_filesystem_class_errors_are_strict_errors() {
        assert!(!EndpointFsError::Io(io::Error::other("x")).is_strict_error());
        assert!(!EndpointFsError::NotADirectory { at: PathBuf::new() }.is_strict_error());
        assert!(!EndpointFsError::AlreadyExists { at: PathBuf::new() }.is_strict_error());
        assert!(EndpointFsError::Symlink { at: PathBuf::new() }.is_strict_error());
        assert!(EndpointFsError::NotARegularFile { at: PathBuf::new() }.is_strict_error());
    }
}
