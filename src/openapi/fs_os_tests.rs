//! OS-specific filesystem test helpers (symlinks/junctions, non-UTF-8 names).
//! Kept out of `dir_index.rs` so that file stays free of `cfg` attributes.

use std::fs;
use std::path::{Path, PathBuf};

use super::dir_index::{DirIndex, EndpointFsError, EntryKind, Lookup, check_file, create_endpoint_dir, resolve_endpoint_dir};

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-fsos-test-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Makes `link` point at the directory `target`. Windows tries a real
/// directory symlink first and falls back to a junction (no admin needed).
/// Returns false (after saying so) when neither can be created.
fn link_dir(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        match std::os::unix::fs::symlink(target, link) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("skipping: could not create a symlink: {e}");
                false
            }
        }
    }
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return true;
        }
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => true,
            _ => {
                eprintln!("skipping: could neither create a directory symlink nor a junction");
                false
            }
        }
    }
}

fn link_file(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}

#[test]
fn a_symlinked_or_junctioned_directory_component_is_refused_and_nothing_is_created_through_it() {
    let root = tempdir();
    let endpoints = root.join("endpoints");
    let outside = root.join("outside");
    fs::create_dir_all(&endpoints).unwrap();
    fs::create_dir_all(&outside).unwrap();
    if !link_dir(&outside, &endpoints.join("cars")) {
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let index = DirIndex::read(&endpoints).unwrap();
    assert_eq!(index.lookup("cars"), Lookup::Exact(EntryKind::Symlink));

    assert!(matches!(resolve_endpoint_dir(&endpoints, &["cars"]).unwrap_err(), EndpointFsError::Symlink { .. }));
    assert!(matches!(
        resolve_endpoint_dir(&endpoints, &["cars", "{vin}"]).unwrap_err(),
        EndpointFsError::Symlink { .. }
    ));
    assert!(matches!(
        create_endpoint_dir(&endpoints, &["cars", "{vin}"]).unwrap_err(),
        EndpointFsError::Symlink { .. }
    ));
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0, "nothing may be created through the link");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_symlinked_endpoints_root_is_refused() {
    let root = tempdir();
    let outside = root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let endpoints = root.join("endpoints");
    if !link_dir(&outside, &endpoints) {
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert!(matches!(resolve_endpoint_dir(&endpoints, &["cars"]).unwrap_err(), EndpointFsError::Symlink { .. }));
    assert!(matches!(create_endpoint_dir(&endpoints, &["cars"]).unwrap_err(), EndpointFsError::Symlink { .. }));
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_symlinked_reference_file_is_refused_and_its_target_left_unchanged() {
    let root = tempdir();
    let target = root.join("victim.txt");
    fs::write(&target, b"precious").unwrap();
    if !link_file(&target, &root.join("endpoint.get.reference.json")) {
        eprintln!("skipping: could not create a file symlink");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let err = check_file(&root, "endpoint.get.reference.json").unwrap_err();
    assert!(matches!(err, EndpointFsError::Symlink { .. }), "{err:?}");
    assert!(err.is_strict_error());
    assert!(matches!(
        super::dir_index::create_new_file(&root, "endpoint.get.reference.json", b"overwritten").unwrap_err(),
        EndpointFsError::Symlink { .. }
    ));
    assert_eq!(fs::read(&target).unwrap(), b"precious");
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn a_non_utf8_entry_name_never_panics_and_never_matches() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let root = tempdir();
    let weird = root.join(OsStr::from_bytes(b"caf\xe9.json"));
    if fs::write(&weird, b"x").is_err() {
        eprintln!("skipping: this filesystem rejects non-UTF-8 names");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    fs::write(root.join("ok.json"), b"x").unwrap();
    let index = DirIndex::read(&root).unwrap();
    assert!(index.exact("ok.json"));
    assert_eq!(index.lookup("caf\u{e9}.json"), Lookup::Absent);
    assert_eq!(index.lookup("cafe.json"), Lookup::Absent);
    assert!(index.case_variants("CAFE.json").is_empty());
    let _ = fs::remove_dir_all(&root);
}
