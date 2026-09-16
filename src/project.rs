use std::path::{Path, PathBuf};

/// The file whose presence marks the root of a frogs project when it's an
/// API project. Deliberately not a dedicated manifest (e.g. `frogs.toml`) —
/// the user's own `openapi.yaml` doubles as the marker, mirroring
/// `Cargo.toml` for cargo. Frogs never writes this file itself — there is
/// no `init` step; the user creates it (or an `.html` file, see below)
/// themselves.
pub const MANIFEST_FILE: &str = "openapi.yaml";

/// Files directly inside `dir` (non-recursive — a project's own files, not
/// its subdirectories' — e.g. `datasources/` is deliberately not walked
/// into) whose extension is one of `extensions`. Shared by the project-root
/// html-marker check below and by `generate`'s web-asset discovery, which
/// needs the actual file list, not just a yes/no.
pub fn find_files_with_extensions(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| extensions.contains(&ext)))
        .collect()
}

/// A directory containing at least one `.html` file is *also* a valid
/// frogs project root — a future frogs project may serve static webpages
/// with no API at all, so project discovery can't require `openapi.yaml`
/// specifically. `generate` checks for `openapi.yaml` and web asset files
/// independently, since a project can have either, both, or (per this
/// check) at least one.
fn has_html_file(dir: &Path) -> bool {
    !find_files_with_extensions(dir, &["html"]).is_empty()
}

/// `pub(crate)` (not just private) because `server::service_host` also uses
/// it, on Windows, to validate an externally-supplied `--project-root`
/// argument baked into a registered Windows Service's own command line
/// before ever treating it as a real project root.
pub(crate) fn is_project_root(dir: &Path) -> bool {
    dir.join(MANIFEST_FILE).is_file() || has_html_file(dir)
}

/// Walks up from `start` looking for a project root (an `openapi.yaml` or
/// at least one `.html` file), the same way `cargo` locates `Cargo.toml`
/// from any subdirectory of a project. Returns the directory containing
/// the marker — never a hardcoded path, since a frogs project can live
/// anywhere the user creates it.
pub fn find_project_root(start: &Path) -> Option<PathBuf> {
    find_project_root_within(start, None)
}

/// `find_project_root`'s real logic, plus an optional `boundary`: once the
/// walk has checked `boundary` itself, it stops instead of continuing to
/// `boundary`'s parent. `find_project_root` always passes `None` (climb
/// all the way to the filesystem root — the real, intended behavior).
/// `boundary` exists purely so a test can own the *entire* directory range
/// the walk will ever look at, rather than the walk continuing past
/// whatever the test created into real, ambient ancestor directories (like
/// the OS temp directory) that are outside the test's control — see
/// `neither_marker_present_finds_nothing`, which caught exactly this: a
/// stray `.html` file sitting directly in `%TEMP%` made an unbounded walk
/// from a temp subdirectory find a false "project root" there.
fn find_project_root_within(start: &Path, boundary: Option<&Path>) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        if is_project_root(dir) {
            return Some(dir.to_path_buf());
        }
        if boundary == Some(dir) {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// Where everything API-related lives: `datasources/`, `config/`,
/// `security/`, generated or hand-authored alike. Always `<root>/api`,
/// regardless of whether this project also serves static content — a fixed
/// name, not a config option, so a static site's own content (which stays
/// directly at `root`) only ever has to avoid one reserved folder name, not
/// three. `openapi.yaml` itself is the one exception: it's the project-root
/// marker `find_project_root` looks for, so it stays at `root` and is never
/// looked for under here.
pub fn api_base(root: &Path) -> PathBuf {
    root.join("api")
}

/// Like `find_project_root`, but exits the process with a helpful message
/// when no project is found — the shared failure path for every subcommand.
pub fn require_project_root(start: &Path) -> PathBuf {
    find_project_root(start).unwrap_or_else(|| {
        eprintln!(
            "no {} or *.html file found in {} or any parent directory — \
             create one to start a frogs project here",
            MANIFEST_FILE,
            start.display()
        );
        std::process::exit(1);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "frogs-project-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn finds_root_via_openapi_yaml() {
        let dir = tempdir();
        std::fs::write(dir.path().join("openapi.yaml"), "").unwrap();
        assert_eq!(find_project_root(dir.path()), Some(dir.path().to_path_buf()));
    }

    #[test]
    fn finds_root_via_an_html_file_with_no_openapi_yaml_at_all() {
        let dir = tempdir();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();
        assert_eq!(find_project_root(dir.path()), Some(dir.path().to_path_buf()));
    }

    #[test]
    fn finds_root_from_a_nested_subdirectory() {
        let dir = tempdir();
        std::fs::write(dir.path().join("openapi.yaml"), "").unwrap();
        let nested = dir.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_project_root(&nested), Some(dir.path().to_path_buf()));
    }

    #[test]
    fn find_files_with_extensions_is_non_recursive_and_extension_filtered() {
        let dir = tempdir();
        std::fs::write(dir.path().join("index.html"), "").unwrap();
        std::fs::write(dir.path().join("app.js"), "").unwrap();
        std::fs::write(dir.path().join("style.css"), "").unwrap();
        std::fs::write(dir.path().join("readme.txt"), "").unwrap();
        std::fs::create_dir_all(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested/deep.html"), "").unwrap();

        let mut found: Vec<String> = find_files_with_extensions(dir.path(), &["html", "js", "css"])
            .into_iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
            .collect();
        found.sort();

        assert_eq!(found, vec!["app.js", "index.html", "style.css"]);
    }

    #[test]
    fn neither_marker_present_finds_nothing() {
        let dir = tempdir();
        std::fs::write(dir.path().join("readme.txt"), "").unwrap();
        // Bounded at `dir.path()` itself: the walk must never climb past
        // the one directory this test actually owns and cleans up — real,
        // ambient parents (like the OS temp directory) are outside the
        // test's control and shouldn't matter to the result either way.
        assert_eq!(find_project_root_within(dir.path(), Some(dir.path())), None);
    }

    #[test]
    fn the_boundary_stops_the_walk_even_when_a_real_marker_exists_further_up() {
        let dir = tempdir();
        std::fs::write(dir.path().join("openapi.yaml"), "").unwrap();
        let boundary = dir.path().join("sub");
        let leaf = boundary.join("leaf");
        std::fs::create_dir_all(&leaf).unwrap();

        // A real marker sits at `dir` — reachable by an *unbounded* walk —
        // but the boundary is `sub`, one level below it, so a bounded walk
        // from `leaf` must stop at `sub` without ever checking `dir`.
        assert_eq!(find_project_root_within(&leaf, Some(&boundary)), None);
        assert_eq!(find_project_root(&leaf), Some(dir.path().to_path_buf()));
    }

    #[test]
    fn api_base_is_a_fixed_api_subfolder() {
        let root = Path::new("/proj");
        assert_eq!(api_base(root), root.join("api"));
    }
}
