//! Tests for `ProjectBoundary`, `LinkContext`, `EndpointTree::scan` and the
//! checked write primitives. Every fixture is a fresh temp dir; "outside" is
//! always a second, separate temp dir (never a folder inside the project).

use std::fs;
use std::path::{Path, PathBuf};

use super::dir_index::{
    DirIndex, EndpointFsError, FileState, OutsideReason, check_file_with, copy_into_checked, create_dir_checked, create_dirs_checked, create_endpoint_dir,
    create_new_checked, create_new_file, rename_checked, rename_checked_with, resolve_endpoint_dir, write_existing_file,
};
use super::endpoint_tree::{
    EndpointTree, LeafRule, LinkContext, LinkFindingKind, MAX_TREE_DEPTH, ProjectBoundary, parse_error_summary, tree_for_tests, tree_for_tests_with,
};
use super::fs_os_tests::{link_dangling_dir, link_dangling_file, link_dir, link_file};
use crate::config::EndpointSymlinks;

fn tempdir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-tree-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A project root plus a separate "outside" folder. Links made through
/// `link_dir`/`link_file` are removed before the recursive delete.
struct Fx {
    root: PathBuf,
    outside: PathBuf,
    links: std::cell::RefCell<Vec<PathBuf>>,
}

impl Fx {
    fn new() -> Fx {
        let root = tempdir("root");
        let outside = tempdir("outside");
        fs::create_dir_all(root.join("api/datasources/endpoints")).unwrap();
        Fx {
            root,
            outside,
            links: Default::default(),
        }
    }

    fn api(&self) -> PathBuf {
        self.root.join("api")
    }

    fn endpoints(&self) -> PathBuf {
        self.root.join("api/datasources/endpoints")
    }

    fn dir_link(&self, target: &Path, link: &Path) -> bool {
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let ok = link_dir(target, link);
        if ok {
            self.links.borrow_mut().push(link.to_path_buf());
        }
        ok
    }

    fn file_link(&self, target: &Path, link: &Path) -> bool {
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let ok = link_file(target, link);
        if ok {
            self.links.borrow_mut().push(link.to_path_buf());
        } else {
            eprintln!("skipping: could not create a file symlink");
        }
        ok
    }

    fn dangling_dir(&self, target: &Path, link: &Path) -> bool {
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let ok = link_dangling_dir(target, link);
        if ok {
            self.links.borrow_mut().push(link.to_path_buf());
        }
        ok
    }

    fn dangling_file(&self, target: &Path, link: &Path) -> bool {
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let ok = link_dangling_file(target, link);
        if ok {
            self.links.borrow_mut().push(link.to_path_buf());
        } else {
            eprintln!("skipping: could not create a dangling file symlink");
        }
        ok
    }

    fn ctx(&self, policy: EndpointSymlinks) -> LinkContext {
        LinkContext::new(&self.root, policy)
    }

    fn scan(&self, policy: EndpointSymlinks) -> EndpointTree {
        EndpointTree::scan(&self.ctx(policy), &self.endpoints())
    }

    fn boundary(&self) -> ProjectBoundary {
        ProjectBoundary::new(&self.root)
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        for link in self.links.borrow().iter() {
            if fs::remove_dir(link).is_err() {
                let _ = fs::remove_file(link);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.outside);
    }
}

fn touch(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, br#"{ "operationId": "x", "sources": {}, "response": {} }"#).unwrap();
}

/// Logical files relative to the endpoints root, `/`-joined, sorted.
fn names(tree: &EndpointTree) -> Vec<String> {
    let mut out: Vec<String> = tree
        .files()
        .iter()
        .map(|f| {
            f.logical
                .strip_prefix(tree.endpoints_root())
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    out.sort();
    out
}

fn kinds(tree: &EndpointTree) -> Vec<LinkFindingKind> {
    tree.findings().iter().map(|f| f.kind.clone()).collect()
}

const ALL_POLICIES: [EndpointSymlinks; 3] = [EndpointSymlinks::Contained, EndpointSymlinks::Refuse, EndpointSymlinks::Follow];

// ---------------------------------------------------------------- plan item 1: ProjectBoundary / dangling

#[test]
fn a_dangling_file_link_at_a_scaffold_leaf_is_outside_and_fails_closed_naming_the_path() {
    let fx = Fx::new();
    let link = fx.api().join("config/connections.json");
    if !fx.dangling_file(&fx.outside.join("victim.json"), &link) {
        return;
    }
    let err = fx.boundary().check_write_target(&link, LeafRule::NoLink).unwrap_err();
    assert!(matches!(err, EndpointFsError::Symlink { .. } | EndpointFsError::OutsideProject { .. }), "{err:?}");
    assert!(err.is_strict_error());
    assert!(err.to_string().contains("connections.json"), "message must name the path: {err}");
    assert!(!fx.outside.join("victim.json").exists());
}

#[test]
fn a_dangling_directory_link_at_security_is_refused_as_a_write_target() {
    let fx = Fx::new();
    let link = fx.api().join("security");
    if !fx.dangling_dir(&fx.outside.join("gone"), &link) {
        return;
    }
    let err = fx.boundary().check_write_target(&link, LeafRule::Dir).unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    // A child below the dangling link must not be treated as "absent, append lexically".
    let err = fx.boundary().check_write_target(&link.join("schemes.json"), LeafRule::NoLink).unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    assert!(!fx.outside.join("gone").exists());
}

#[test]
fn a_dangling_directory_link_at_the_components_folder_is_refused() {
    let fx = Fx::new();
    let link = fx.api().join("datasources/components");
    if !fx.dangling_dir(&fx.outside.join("gone"), &link) {
        return;
    }
    let err = fx.boundary().check_write_target(&link, LeafRule::Dir).unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    assert!(create_dirs_checked(&fx.boundary(), &link).is_err());
    assert!(!fx.outside.join("gone").exists());
}

#[test]
fn a_dangling_intermediate_link_reports_the_component_that_could_not_be_resolved() {
    let fx = Fx::new();
    // api -> <outside>/missing, where "missing" never exists.
    fs::remove_dir_all(fx.api()).unwrap();
    if !fx.dangling_dir(&fx.outside.join("missing"), &fx.api()) {
        return;
    }
    let err = fx.boundary().check_write_target(&fx.api().join("config/errors"), LeafRule::Dir).unwrap_err();
    match err {
        EndpointFsError::OutsideProject {
            reason: OutsideReason::Unresolvable { component, error },
            ..
        } => {
            assert_eq!(component, "api");
            assert!(!error.is_empty(), "the OS error must be named");
        }
        other => panic!("expected OutsideProject{{Unresolvable}}, got {other:?}"),
    }
}

#[test]
fn a_live_link_inside_the_project_at_a_no_link_leaf_is_still_refused() {
    let fx = Fx::new();
    let real = fx.api().join("real.json");
    fs::create_dir_all(fx.api()).unwrap();
    fs::write(&real, b"{}").unwrap();
    let link = fx.api().join("linked.json");
    if !fx.file_link(&real, &link) {
        return;
    }
    let err = fx.boundary().check_write_target(&link, LeafRule::NoLink).unwrap_err();
    assert!(matches!(err, EndpointFsError::Symlink { .. }), "{err:?}");
    // The real file itself is fine.
    assert!(fx.boundary().check_write_target(&real, LeafRule::NoLink).is_ok());
}

#[test]
fn a_live_directory_link_inside_the_project_is_accepted_for_a_dir_leaf_but_not_a_no_link_leaf() {
    let fx = Fx::new();
    let real = fx.api().join("real");
    fs::create_dir_all(&real).unwrap();
    let link = fx.api().join("linked");
    if !fx.dir_link(&real, &link) {
        return;
    }
    assert!(fx.boundary().check_write_target(&link, LeafRule::Dir).is_ok());
}

#[test]
fn a_not_yet_existing_target_below_an_existing_inside_folder_is_accepted_and_appended_lexically() {
    let fx = Fx::new();
    let resolved = fx.boundary().check_write_target(&fx.api().join("config/errors/core.json"), LeafRule::NoLink).unwrap();
    assert!(resolved.ends_with(Path::new("config").join("errors").join("core.json")));
}

#[test]
fn a_path_with_a_parent_component_or_outside_the_root_is_a_containment_error() {
    let fx = Fx::new();
    let sneaky = fx.api().join("..").join("..").join("x");
    assert!(matches!(
        fx.boundary().check_write_target(&sneaky, LeafRule::Dir).unwrap_err(),
        EndpointFsError::Containment(_)
    ));
    assert!(matches!(
        fx.boundary().check_write_target(&fx.outside.join("x"), LeafRule::Dir).unwrap_err(),
        EndpointFsError::Containment(_)
    ));
}

// ---------------------------------------------------------------- plan item 2: ProjectBoundary other

#[test]
fn a_missing_project_root_fails_closed_for_every_check_and_names_the_root() {
    let missing = std::env::temp_dir().join("frogs-tree-definitely-missing-root-4711");
    let boundary = ProjectBoundary::new(&missing);
    let err = boundary.check_write_target(&missing.join("api"), LeafRule::Dir).unwrap_err();
    match &err {
        EndpointFsError::OutsideProject {
            reason: OutsideReason::BadRoot(message),
            ..
        } => assert!(message.contains("frogs-tree-definitely-missing-root-4711"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert!(!boundary.is_inside(&missing.join("api")));
    assert!(!boundary.is_inside(Path::new("/")));
}

#[test]
fn the_frogs_and_git_folders_are_outside_and_everything_else_under_the_root_is_inside() {
    let fx = Fx::new();
    fs::create_dir_all(fx.root.join(".frogs")).unwrap();
    fs::create_dir_all(fx.root.join(".git/hooks")).unwrap();
    let canonical = fs::canonicalize(&fx.root).unwrap();
    let boundary = fx.boundary();
    assert!(boundary.is_inside(&canonical));
    assert!(boundary.is_inside(&canonical.join("api")));
    assert!(!boundary.is_inside(&canonical.join(".frogs")));
    assert!(!boundary.is_inside(&canonical.join(".frogs").join("run.json")));
    assert!(!boundary.is_inside(&canonical.join(".git").join("hooks")));
    assert!(
        boundary.is_inside(&canonical.join(".gitignore")),
        "only the .git folder, not a name that merely starts with it"
    );
    assert!(!boundary.is_inside(&fs::canonicalize(&fx.outside).unwrap()));

    let err = boundary.check_write_target(&fx.root.join(".git/hooks/pre-commit"), LeafRule::NoLink).unwrap_err();
    assert!(
        matches!(
            err,
            EndpointFsError::OutsideProject {
                reason: OutsideReason::Excluded,
                ..
            }
        ),
        "{err:?}"
    );
    let err = boundary.check_write_target(&fx.root.join(".frogs/new"), LeafRule::Dir).unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
}

#[test]
fn a_project_root_reached_through_a_directory_link_is_still_inside() {
    let fx = Fx::new();
    let alias = fx.outside.join("alias-to-project");
    if !fx.dir_link(&fx.root, &alias) {
        return;
    }
    let boundary = ProjectBoundary::new(&alias);
    let resolved = boundary.check_write_target(&alias.join("api/config/server.json"), LeafRule::NoLink).unwrap();
    assert!(boundary.is_inside(&resolved));
}

#[test]
fn a_project_root_spelled_with_different_casing_is_inside_where_the_filesystem_ignores_case() {
    let fx = Fx::new();
    fs::write(fx.root.join("probe_a"), b"").unwrap();
    let insensitive = fx.root.join("PROBE_A").exists();
    eprintln!("case-insensitive filesystem: {insensitive}");
    if !insensitive {
        return;
    }
    let root_str = fx.root.to_string_lossy().to_uppercase();
    let shouty = PathBuf::from(root_str);
    if !shouty.exists() {
        return;
    }
    let boundary = ProjectBoundary::new(&shouty);
    let resolved = boundary.check_write_target(&shouty.join("api/config/server.json"), LeafRule::NoLink).unwrap();
    assert!(boundary.is_inside(&resolved), "{resolved:?}");
}

// ---------------------------------------------------------------- plan item 3: endpoint_tree

#[test]
fn a_tree_without_links_matches_the_hard_coded_file_list_and_has_no_findings() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    touch(&eps.join("cars/endpoint.get.json"));
    touch(&eps.join("cars/{vin}/endpoint.get.json"));
    touch(&eps.join("cars/{vin}/endpoint.put.json"));
    touch(&eps.join("_orphan/_endpoint.get.json"));
    fs::write(eps.join("cars/endpoint.get.reference.json"), b"{}").unwrap();
    fs::write(eps.join("cars/notes.txt"), b"x").unwrap();
    fs::create_dir_all(eps.join("cars/_backups")).unwrap();
    touch(&eps.join("cars/_backups/endpoint.get.json"));
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        assert_eq!(
            names(&tree),
            vec![
                "_orphan/_endpoint.get.json",
                "cars/endpoint.get.json",
                "cars/endpoint.get.reference.json",
                "cars/{vin}/endpoint.get.json",
                "cars/{vin}/endpoint.put.json"
            ],
            "{policy:?}"
        );
        assert!(tree.findings().is_empty(), "{policy:?}: {:?}", tree.findings());
        assert!(tree.files().iter().all(|f| !f.via_link));
    }
}

#[test]
fn a_missing_endpoints_root_gives_an_empty_tree_without_findings() {
    let fx = Fx::new();
    fs::remove_dir_all(fx.endpoints()).unwrap();
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty());
    assert!(tree.findings().is_empty());
}

#[test]
fn an_in_project_directory_link_is_followed_and_served_under_its_logical_path() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    touch(&fx.root.join("shared/endpoint.get.json"));
    if !fx.dir_link(&fx.root.join("shared"), &eps.join("v2")) {
        return;
    }
    for policy in [EndpointSymlinks::Contained, EndpointSymlinks::Follow] {
        let tree = fx.scan(policy);
        assert_eq!(names(&tree), vec!["v2/endpoint.get.json"], "{policy:?}");
        assert!(tree.files()[0].via_link);
        assert!(tree.is_via_link(&tree.files()[0].logical));
        assert!(tree.files()[0].dir_writable, "an in-project link may be written through");
        assert!(tree.findings().is_empty(), "{:?}", tree.findings());
        assert_eq!(tree.files()[0].rel_dir, vec!["v2".to_string()]);
    }
}

#[test]
fn an_outside_directory_link_is_reported_as_escaping_under_contained_and_nothing_is_served() {
    let fx = Fx::new();
    touch(&fx.outside.join("endpoint.get.json"));
    if !fx.dir_link(&fx.outside, &fx.endpoints().join("ext")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Escapes]);
    assert!(tree.findings()[0].strict);
    let message = tree.link_messages().remove(0);
    assert!(message.contains("follow"), "the message must name the fix: {message}");
    assert!(message.contains("contained"), "the message must name the mode: {message}");
}

#[test]
fn an_outside_directory_link_is_read_under_follow_but_not_writable() {
    let fx = Fx::new();
    touch(&fx.outside.join("endpoint.get.json"));
    if !fx.dir_link(&fx.outside, &fx.endpoints().join("ext")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Follow);
    assert_eq!(names(&tree), vec!["ext/endpoint.get.json"]);
    assert!(tree.findings().is_empty());
    assert!(tree.files()[0].via_link);
    assert!(!tree.files()[0].dir_writable, "follow mode never makes an outside target writable");
}

#[test]
fn every_link_is_refused_under_refuse_even_when_it_points_inside_the_project() {
    let fx = Fx::new();
    touch(&fx.root.join("shared/endpoint.get.json"));
    touch(&fx.outside.join("endpoint.get.json"));
    if !fx.dir_link(&fx.root.join("shared"), &fx.endpoints().join("inner")) || !fx.dir_link(&fx.outside, &fx.endpoints().join("outer")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Refuse);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Refused, LinkFindingKind::Refused]);
}

#[test]
fn a_link_into_the_frogs_folder_is_excluded_in_every_mode_and_its_files_are_never_listed() {
    let fx = Fx::new();
    touch(&fx.root.join(".frogs/endpoint.get.json"));
    if !fx.dir_link(&fx.root.join(".frogs"), &fx.endpoints().join("sneaky")) {
        return;
    }
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        assert!(tree.files().is_empty(), "{policy:?}: {:?}", names(&tree));
        // Excluded takes precedence over the policy (it is reported the same way in every mode).
        assert_eq!(kinds(&tree), vec![LinkFindingKind::Excluded], "{policy:?}");
    }
}

#[test]
fn a_link_to_the_project_root_never_walks_dot_git_or_dot_frogs_and_terminates() {
    let fx = Fx::new();
    touch(&fx.root.join(".git/hooks/endpoint.get.json"));
    touch(&fx.root.join(".frogs/endpoint.get.json"));
    touch(&fx.root.join("docs/endpoint.get.json"));
    if !fx.dir_link(&fx.root, &fx.endpoints().join("x")) {
        return;
    }
    for policy in [EndpointSymlinks::Contained, EndpointSymlinks::Follow] {
        let tree = fx.scan(policy);
        let listed = names(&tree);
        assert!(listed.iter().all(|n| !n.contains(".git") && !n.contains(".frogs")), "{policy:?}: {listed:?}");
        assert!(listed.contains(&"x/docs/endpoint.get.json".to_string()), "{policy:?}: {listed:?}");
        // x/api/datasources/endpoints is the endpoints root again: never walked a second time.
        assert!(listed.iter().all(|n| !n.starts_with("x/api/datasources/endpoints")), "{listed:?}");
        let found = kinds(&tree);
        assert!(found.contains(&LinkFindingKind::Excluded), "{policy:?}: {found:?}");
        assert!(found.contains(&LinkFindingKind::Cycle), "{policy:?}: {found:?}");
    }
}

#[test]
fn a_link_back_at_the_endpoints_folder_is_a_cycle_under_every_policy() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    touch(&eps.join("cars/endpoint.get.json"));
    if !fx.dir_link(&eps, &eps.join("a")) {
        return;
    }
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        assert_eq!(names(&tree), vec!["cars/endpoint.get.json"], "{policy:?}");
        let found = kinds(&tree);
        assert_eq!(found.len(), 1, "{policy:?}: {found:?}");
        if policy == EndpointSymlinks::Refuse {
            assert_eq!(found[0], LinkFindingKind::Refused);
        } else {
            assert_eq!(found[0], LinkFindingKind::Cycle, "{policy:?}");
        }
    }
}

#[test]
fn a_link_to_a_parent_folder_does_not_loop_and_never_yields_a_repeated_a_slash_a_path() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    touch(&eps.join("cars/endpoint.get.json"));
    if !fx.dir_link(&fx.root.join("api/datasources"), &eps.join("a")) {
        return;
    }
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        let listed = names(&tree);
        assert!(listed.iter().all(|n| !n.contains("a/a")), "{policy:?}: {listed:?}");
        assert!(listed.contains(&"cars/endpoint.get.json".to_string()));
        assert!(
            listed.iter().filter(|n| n.ends_with("cars/endpoint.get.json")).count() == 1,
            "the same physical file must not be listed twice: {listed:?}"
        );
    }
}

#[test]
fn a_cycle_inside_a_linked_folder_terminates_under_every_policy() {
    let fx = Fx::new();
    touch(&fx.outside.join("sub/endpoint.get.json"));
    let shared = fx.root.join("shared");
    touch(&shared.join("sub/endpoint.get.json"));
    if !fx.dir_link(&shared, &shared.join("sub/back")) || !fx.dir_link(&shared, &fx.endpoints().join("v1")) {
        return;
    }
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        let listed = names(&tree);
        assert!(listed.iter().all(|n| !n.contains("back/sub/back")), "{policy:?}: {listed:?}");
        if policy != EndpointSymlinks::Refuse {
            assert!(listed.contains(&"v1/sub/endpoint.get.json".to_string()), "{policy:?}: {listed:?}");
            assert!(kinds(&tree).contains(&LinkFindingKind::Cycle), "{policy:?}");
        }
    }
}

#[test]
fn a_link_to_a_real_folder_in_the_same_tree_is_an_alias_and_the_real_path_wins_in_either_name_order() {
    for (real_name, link_name) in [("zzz", "aaa"), ("aaa", "zzz")] {
        let fx = Fx::new();
        let eps = fx.endpoints();
        touch(&eps.join(real_name).join("endpoint.get.json"));
        if !fx.dir_link(&eps.join(real_name), &eps.join(link_name)) {
            return;
        }
        let tree = fx.scan(EndpointSymlinks::Contained);
        assert_eq!(names(&tree), vec![format!("{real_name}/endpoint.get.json")], "real={real_name} link={link_name}");
        assert_eq!(tree.findings().len(), 1);
        match &tree.findings()[0].kind {
            LinkFindingKind::Alias { kept } => assert!(kept.ends_with(real_name), "{kept:?}"),
            other => panic!("expected Alias, got {other:?}"),
        }
        assert!(tree.findings()[0].link.ends_with(link_name));
    }
}

#[test]
fn two_links_to_one_folder_serve_it_once_under_the_first_link_in_sorted_order() {
    let fx = Fx::new();
    touch(&fx.root.join("shared/endpoint.get.json"));
    let eps = fx.endpoints();
    // Created in reverse order on purpose: ordering must come from the sort, not creation order.
    if !fx.dir_link(&fx.root.join("shared"), &eps.join("bbb")) || !fx.dir_link(&fx.root.join("shared"), &eps.join("aaa")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert_eq!(names(&tree), vec!["aaa/endpoint.get.json"]);
    assert!(
        matches!(&tree.findings()[0].kind, LinkFindingKind::Alias { kept } if kept.ends_with("aaa")),
        "{:?}",
        tree.findings()
    );
}

#[test]
fn an_in_project_file_link_is_routed_under_its_logical_location() {
    let fx = Fx::new();
    let target = fx.root.join("shared.json");
    touch(&target);
    if !fx.file_link(&target, &fx.endpoints().join("cars/endpoint.get.json")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert_eq!(names(&tree), vec!["cars/endpoint.get.json"]);
    assert!(tree.files()[0].via_link);
    assert!(tree.findings().is_empty());
}

#[test]
fn an_outside_file_link_is_skipped_with_a_finding_under_contained_and_read_under_follow() {
    let fx = Fx::new();
    let target = fx.outside.join("shared.json");
    touch(&target);
    if !fx.file_link(&target, &fx.endpoints().join("cars/endpoint.get.json")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Escapes]);
    let tree = fx.scan(EndpointSymlinks::Follow);
    assert_eq!(names(&tree), vec!["cars/endpoint.get.json"]);
    assert!(!tree.files()[0].dir_writable || tree.files()[0].via_link);
}

#[test]
fn a_file_link_is_refused_under_refuse_with_a_finding() {
    let fx = Fx::new();
    let target = fx.root.join("shared.json");
    touch(&target);
    if !fx.file_link(&target, &fx.endpoints().join("cars/endpoint.get.json")) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Refuse);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Refused]);
}

#[test]
fn a_file_link_with_an_irrelevant_name_is_ignored_silently_in_every_mode() {
    let fx = Fx::new();
    let target = fx.outside.join("notes.txt");
    fs::write(&target, b"x").unwrap();
    if !fx.file_link(&target, &fx.endpoints().join("cars/notes.txt")) {
        return;
    }
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        assert!(tree.files().is_empty());
        assert!(tree.findings().is_empty(), "{policy:?}: {:?}", tree.findings());
    }
}

#[test]
fn a_dangling_directory_link_and_a_dangling_endpoint_file_link_are_reported_as_dangling() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    if !fx.dangling_dir(&fx.outside.join("gone"), &eps.join("ghost")) {
        return;
    }
    let file_ok = fx.dangling_file(&fx.outside.join("gone.json"), &eps.join("cars/endpoint.get.json"));
    // An unrelated dangling file link (has a dot, not an endpoint name) stays silent.
    let _ = fx.dangling_file(&fx.outside.join("gone2.txt"), &eps.join("cars/readme.txt"));
    for policy in [EndpointSymlinks::Contained, EndpointSymlinks::Follow] {
        let tree = fx.scan(policy);
        assert!(tree.files().is_empty());
        let dangling = kinds(&tree).iter().filter(|k| **k == LinkFindingKind::Dangling).count();
        assert_eq!(dangling, if file_ok { 2 } else { 1 }, "{policy:?}: {:?}", tree.findings());
    }
}

#[test]
fn folders_nested_deeper_than_the_depth_cap_are_not_walked_and_say_so() {
    let fx = Fx::new();
    let mut dir = fx.endpoints();
    for _ in 0..(MAX_TREE_DEPTH + 6) {
        dir = dir.join("d");
    }
    touch(&dir.join("endpoint.get.json"));
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty(), "the file beyond the cap must not be served");
    assert!(kinds(&tree).contains(&LinkFindingKind::DepthLimit), "{:?}", tree.findings());
    // Windows' own removal limits are not what is being tested.
    let _ = fs::remove_dir_all(fx.endpoints().join("d"));
}

#[test]
fn a_backups_folder_or_a_link_named_backups_is_never_walked_or_reported() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    touch(&eps.join("cars/endpoint.get.json"));
    touch(&fx.outside.join("endpoint.get.json"));
    fs::create_dir_all(eps.join("cars")).unwrap();
    if !fx.dir_link(&fx.outside, &eps.join("cars/_backups")) {
        return;
    }
    for policy in ALL_POLICIES {
        let tree = fx.scan(policy);
        assert_eq!(names(&tree), vec!["cars/endpoint.get.json"], "{policy:?}");
        assert!(tree.findings().is_empty(), "{policy:?}: {:?}", tree.findings());
    }
}

#[cfg(unix)]
#[test]
fn a_non_utf8_folder_or_file_name_is_skipped_without_panicking() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let fx = Fx::new();
    touch(&fx.endpoints().join("ok/endpoint.get.json"));
    let weird = fx.endpoints().join(OsStr::from_bytes(b"caf\xe9"));
    if fs::create_dir_all(&weird).is_err() {
        eprintln!("skipping: this filesystem rejects non-UTF-8 names");
        return;
    }
    fs::write(weird.join("endpoint.get.json"), b"{}").unwrap();
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert_eq!(names(&tree), vec!["ok/endpoint.get.json"]);
}

#[test]
fn an_endpoints_root_that_is_itself_a_link_inside_the_project_is_served_and_outside_is_escaping() {
    let fx = Fx::new();
    fs::remove_dir_all(fx.endpoints()).unwrap();
    let inside = fx.root.join("elsewhere");
    touch(&inside.join("cars/endpoint.get.json"));
    if !fx.dir_link(&inside, &fx.endpoints()) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert_eq!(names(&tree), vec!["cars/endpoint.get.json"]);
    assert!(tree.files()[0].via_link);
    assert_eq!(fx.scan(EndpointSymlinks::Refuse).files().len(), 0);
    assert_eq!(kinds(&fx.scan(EndpointSymlinks::Refuse)), vec![LinkFindingKind::Refused]);

    // Now the outside variant.
    let fx = Fx::new();
    fs::remove_dir_all(fx.endpoints()).unwrap();
    touch(&fx.outside.join("cars/endpoint.get.json"));
    if !fx.dir_link(&fx.outside, &fx.endpoints()) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Escapes]);
    let tree = fx.scan(EndpointSymlinks::Follow);
    assert_eq!(names(&tree), vec!["cars/endpoint.get.json"]);
    assert!(!tree.files()[0].dir_writable);
}

#[test]
fn an_api_folder_linked_outside_yields_an_empty_tree_with_an_escape_finding_under_contained() {
    let fx = Fx::new();
    touch(&fx.outside.join("datasources/endpoints/cars/endpoint.get.json"));
    fs::remove_dir_all(fx.api()).unwrap();
    if !fx.dir_link(&fx.outside, &fx.api()) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Escapes]);
    let tree = fx.scan(EndpointSymlinks::Refuse);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Refused]);
}

#[test]
fn a_dangling_endpoints_root_is_reported_and_gives_an_empty_tree() {
    let fx = Fx::new();
    fs::remove_dir_all(fx.endpoints()).unwrap();
    if !fx.dangling_dir(&fx.outside.join("gone"), &fx.endpoints()) {
        return;
    }
    let tree = fx.scan(EndpointSymlinks::Contained);
    assert!(tree.files().is_empty());
    assert_eq!(kinds(&tree), vec![LinkFindingKind::Dangling]);
}

#[test]
fn the_test_helper_trees_scan_the_same_files_as_a_real_context() {
    let fx = Fx::new();
    touch(&fx.endpoints().join("cars/endpoint.get.json"));
    let a = tree_for_tests(&fx.endpoints());
    let b = tree_for_tests_with(&fx.root, &fx.endpoints(), EndpointSymlinks::Contained);
    assert_eq!(names(&a), names(&b));
}

#[test]
fn file_in_and_case_variant_in_look_files_up_by_logical_directory_and_name() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    touch(&eps.join("cars/endpoint.get.json"));
    fs::write(eps.join("cars/endpoint.GET.test.json"), b"{}").unwrap();
    let tree = fx.scan(EndpointSymlinks::Contained);
    let dir = eps.join("cars");
    assert!(tree.file_in(&dir, "endpoint.get.json").is_some());
    assert!(tree.file_in(&dir, "endpoint.put.json").is_none());
    assert!(tree.file_in(&eps, "endpoint.get.json").is_none());
    assert!(tree.case_variant_in(&dir, "endpoint.get.test.json").is_some());
    assert!(tree.case_variant_in(&dir, "endpoint.GET.test.json").is_none());
}

// ---------------------------------------------------------------- plan item 6/12 support: parse_error_summary

#[test]
fn a_parse_error_summary_carries_position_and_category_but_never_the_offending_text() {
    let err = serde_json::from_str::<serde_json::Value>("{\n  \"a\": TOPSECRET-123\n}").unwrap_err();
    let summary = parse_error_summary(&err);
    assert!(summary.contains("line 2"), "{summary}");
    assert!(summary.contains("column"), "{summary}");
    assert!(summary.contains("syntax"), "{summary}");
    assert!(!summary.contains("TOPSECRET"), "{summary}");

    let eof = serde_json::from_str::<serde_json::Value>("{ \"a\": ").unwrap_err();
    assert!(parse_error_summary(&eof).contains("unexpected end of file"));
}

// ---------------------------------------------------------------- plan item 5: swap-after-scan, per write primitive

/// A folder that was a real in-project dir when "scanned" and is now a link to
/// an outside folder holding a victim file.
fn swapped(fx: &Fx) -> Option<PathBuf> {
    let dir = fx.endpoints().join("cars");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("endpoint.get.json"), b"{}").unwrap();
    fs::remove_dir_all(&dir).unwrap();
    fs::write(fx.outside.join("endpoint.get.json"), b"victim").unwrap();
    if !fx.dir_link(&fx.outside, &dir) {
        return None;
    }
    Some(dir)
}

fn outside_is_untouched(fx: &Fx) {
    let mut entries: Vec<String> = fs::read_dir(&fx.outside)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["endpoint.get.json"], "nothing may be created outside");
    assert_eq!(fs::read(fx.outside.join("endpoint.get.json")).unwrap(), b"victim");
}

#[test]
fn create_new_file_through_a_swapped_in_outside_link_is_refused_and_outside_stays_untouched() {
    let fx = Fx::new();
    let Some(dir) = swapped(&fx) else { return };
    let err = create_new_file(&fx.boundary(), &dir, "endpoint.post.json", b"{}").unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    let err = create_new_checked(&fx.boundary(), &dir, "endpoint.post.json", b"{}").unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    outside_is_untouched(&fx);
}

#[test]
fn write_existing_file_through_a_swapped_in_outside_link_is_refused_and_the_victim_survives() {
    let fx = Fx::new();
    let Some(dir) = swapped(&fx) else { return };
    let err = write_existing_file(&fx.boundary(), &dir, "endpoint.get.json", b"pwned").unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    outside_is_untouched(&fx);
}

#[test]
fn write_existing_file_refuses_a_leaf_that_is_a_link_to_an_inside_file() {
    let fx = Fx::new();
    let real = fx.root.join("real.json");
    fs::write(&real, b"keep").unwrap();
    if !fx.file_link(&real, &fx.endpoints().join("endpoint.get.json")) {
        return;
    }
    let err = write_existing_file(&fx.boundary(), &fx.endpoints(), "endpoint.get.json", b"x").unwrap_err();
    assert!(matches!(err, EndpointFsError::Symlink { .. }), "{err:?}");
    assert_eq!(fs::read(&real).unwrap(), b"keep");
}

#[test]
fn copy_into_checked_through_a_swapped_in_outside_link_is_refused() {
    let fx = Fx::new();
    let Some(dir) = swapped(&fx) else { return };
    let src = fx.root.join("src.json");
    fs::write(&src, b"backup").unwrap();
    let err = copy_into_checked(&fx.boundary(), &src, &dir, "endpoint.get.json").unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    outside_is_untouched(&fx);
}

#[test]
fn create_dir_checked_and_create_dirs_checked_through_a_swapped_in_outside_link_are_refused() {
    let fx = Fx::new();
    let Some(dir) = swapped(&fx) else { return };
    let err = create_dir_checked(&fx.boundary(), &dir.join("sub")).unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    let err = create_dirs_checked(&fx.boundary(), &dir.join("sub").join("deeper")).unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    outside_is_untouched(&fx);
}

#[test]
fn renames_through_a_swapped_in_outside_link_are_refused_in_every_variant() {
    let fx = Fx::new();
    let Some(dir) = swapped(&fx) else { return };
    let err = rename_checked(&fx.boundary(), &dir, "endpoint.get.json", "_endpoint.get.json").unwrap_err();
    assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{err:?}");
    for policy in ALL_POLICIES {
        let err = rename_checked_with(&fx.ctx(policy), &dir, "endpoint.get.json", "_endpoint.get.json").unwrap_err();
        assert!(matches!(err, EndpointFsError::OutsideProject { .. }), "{policy:?}: {err:?}");
    }
    outside_is_untouched(&fx);
}

#[test]
fn create_endpoint_dir_and_resolve_endpoint_dir_refuse_an_outside_link_component_in_every_mode_including_follow() {
    let fx = Fx::new();
    let Some(_dir) = swapped(&fx) else { return };
    for policy in ALL_POLICIES {
        let ctx = fx.ctx(policy);
        let err = create_endpoint_dir(&ctx, &fx.endpoints(), &["cars", "{vin}"]).unwrap_err();
        assert!(err.is_strict_error(), "{policy:?}: {err:?}");
        assert!(
            matches!(
                err,
                EndpointFsError::Symlink { .. } | EndpointFsError::LinkEscapes { .. } | EndpointFsError::OutsideProject { .. }
            ),
            "{policy:?}: {err:?}"
        );
        assert!(resolve_endpoint_dir(&ctx, &fx.endpoints(), &["cars"]).is_err(), "{policy:?}");
        if policy == EndpointSymlinks::Refuse {
            assert!(matches!(
                create_endpoint_dir(&ctx, &fx.endpoints(), &["cars"]).unwrap_err(),
                EndpointFsError::Symlink { .. }
            ));
        }
    }
    outside_is_untouched(&fx);
}

#[test]
fn an_in_project_link_component_is_written_through_under_contained_and_follow_but_refused_under_refuse() {
    let fx = Fx::new();
    let shared = fx.root.join("shared");
    fs::create_dir_all(&shared).unwrap();
    if !fx.dir_link(&shared, &fx.endpoints().join("v2")) {
        return;
    }
    for policy in [EndpointSymlinks::Contained, EndpointSymlinks::Follow] {
        let made = create_endpoint_dir(&fx.ctx(policy), &fx.endpoints(), &["v2", "cars"]).unwrap();
        assert!(shared.join("cars").is_dir(), "{policy:?}");
        assert!(made.ends_with("cars"));
        let _ = fs::remove_dir(shared.join("cars"));
    }
    assert!(matches!(
        create_endpoint_dir(&fx.ctx(EndpointSymlinks::Refuse), &fx.endpoints(), &["v2", "cars"]).unwrap_err(),
        EndpointFsError::Symlink { .. }
    ));
    assert!(!shared.join("cars").exists());
}

#[test]
fn a_link_to_the_project_root_cannot_be_used_to_create_dot_frogs_or_dot_git_content() {
    let fx = Fx::new();
    if !fx.dir_link(&fx.root, &fx.endpoints().join("x")) {
        return;
    }
    let b = fx.boundary();
    // Neither exists yet: creating them through the link must still be refused.
    for policy in ALL_POLICIES {
        let ctx = fx.ctx(policy);
        assert!(create_endpoint_dir(&ctx, &fx.endpoints(), &["x", ".frogs", "a"]).is_err(), "{policy:?}");
        assert!(create_endpoint_dir(&ctx, &fx.endpoints(), &["x", ".git", "hooks"]).is_err(), "{policy:?}");
    }
    assert!(create_dir_checked(&b, &fx.endpoints().join("x").join(".frogs")).is_err());
    assert!(create_new_file(&b, &fx.endpoints().join("x").join(".git"), "endpoint.get.json", b"{}").is_err());
    assert!(!fx.root.join(".frogs").exists(), ".frogs must not have been created");
    assert!(!fx.root.join(".git").exists(), ".git must not have been created");
}

#[test]
fn rename_of_a_link_entry_moves_the_link_not_its_target_unless_the_policy_is_refuse() {
    let fx = Fx::new();
    let target = fx.root.join("real.json");
    fs::write(&target, b"keep").unwrap();
    let eps = fx.endpoints();
    if !fx.file_link(&target, &eps.join("endpoint.get.json")) {
        return;
    }
    assert!(matches!(
        rename_checked_with(&fx.ctx(EndpointSymlinks::Refuse), &eps, "endpoint.get.json", "_endpoint.get.json").unwrap_err(),
        EndpointFsError::Symlink { .. }
    ));
    assert!(matches!(
        rename_checked(&fx.boundary(), &eps, "endpoint.get.json", "_endpoint.get.json").unwrap_err(),
        EndpointFsError::Symlink { .. }
    ));
    rename_checked_with(&fx.ctx(EndpointSymlinks::Contained), &eps, "endpoint.get.json", "_endpoint.get.json").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"keep", "the target is never renamed or touched");
    assert!(fs::symlink_metadata(eps.join("_endpoint.get.json")).unwrap().file_type().is_symlink());
    assert!(fs::symlink_metadata(eps.join("endpoint.get.json")).is_err());
    fx.links.borrow_mut().push(eps.join("_endpoint.get.json"));
}

#[test]
fn rename_refuses_a_destination_that_exists_exactly_or_as_a_case_variant() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    fs::write(eps.join("endpoint.get.json"), b"a").unwrap();
    fs::write(eps.join("_endpoint.get.json"), b"b").unwrap();
    assert!(matches!(
        rename_checked(&fx.boundary(), &eps, "endpoint.get.json", "_endpoint.get.json").unwrap_err(),
        EndpointFsError::AlreadyExists { .. }
    ));
    fs::remove_file(eps.join("_endpoint.get.json")).unwrap();
    fs::write(eps.join("_ENDPOINT.get.json"), b"c").unwrap();
    let err = rename_checked(&fx.boundary(), &eps, "endpoint.get.json", "_endpoint.get.json");
    assert!(err.is_err(), "a case variant at the destination must be refused");
    assert_eq!(fs::read(eps.join("endpoint.get.json")).unwrap(), b"a");
}

#[test]
fn check_file_with_reports_a_stub_link_as_present_via_link_and_refuses_an_escaping_or_dangling_one() {
    let fx = Fx::new();
    let eps = fx.endpoints();
    let inside = fx.root.join("real.json");
    touch(&inside);
    if !fx.file_link(&inside, &eps.join("endpoint.get.json")) {
        return;
    }
    assert!(matches!(
        check_file_with(&fx.ctx(EndpointSymlinks::Contained), &eps, "endpoint.get.json").unwrap(),
        FileState::PresentViaLink(_)
    ));
    assert!(check_file_with(&fx.ctx(EndpointSymlinks::Refuse), &eps, "endpoint.get.json").is_err());
    assert!(matches!(
        check_file_with(&fx.ctx(EndpointSymlinks::Contained), &eps, "endpoint.put.json").unwrap(),
        FileState::Absent
    ));

    let outside_file = fx.outside.join("o.json");
    touch(&outside_file);
    if fx.file_link(&outside_file, &eps.join("endpoint.post.json")) {
        let err = check_file_with(&fx.ctx(EndpointSymlinks::Contained), &eps, "endpoint.post.json").unwrap_err();
        assert!(err.is_strict_error(), "{err:?}");
        // Follow reads it, but there is still no way to write it: it is only ever PresentViaLink.
        assert!(matches!(
            check_file_with(&fx.ctx(EndpointSymlinks::Follow), &eps, "endpoint.post.json").unwrap(),
            FileState::PresentViaLink(_)
        ));
    }
}

#[test]
fn the_dir_index_still_lists_a_link_as_a_symlink_entry() {
    let fx = Fx::new();
    if !fx.dir_link(&fx.outside, &fx.endpoints().join("ext")) {
        return;
    }
    let index = DirIndex::read(&fx.endpoints()).unwrap();
    assert!(index.entries().any(|(name, kind)| name == "ext" && kind == super::dir_index::EntryKind::Symlink));
}
