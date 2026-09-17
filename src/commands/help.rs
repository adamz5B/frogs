use std::io;
use std::path::Path;

use crate::project::find_project_root;

const OVERVIEW: &str = "\
frogs — Free Rust OpenAPI Generated Server

USAGE:
    frogs <COMMAND>

COMMANDS:
    generate       Generate datasource stub/reference files from openapi.yaml
    run            Start the server for the current project (--restart restarts a registered service)
    stop           Stop the running server for the current project
    register       Register this project as an OS-managed service (systemd/launchd/Windows Service)
    unregister     Remove this project's OS-managed service registration
    test           Serve the API as a mock server from *.test.json mocks, or record a new case
    errors freeze  Batch config/errors.discovered.json into the canonical registry
    drivers list   Print which SQL drivers this binary was built with
    validate       Dry-run config/SQL/endpoint checks without starting the server
    help           Print this message

A frogs project is any directory containing an openapi.yaml file (or, for a
static-webpage project with no API, at least one .html file) — frogs never
writes either of these itself, you create them, and it finds the project
root by walking up from the current directory, the same way cargo finds
Cargo.toml, so commands work from any subdirectory of a project.";

pub fn run(cwd: &Path) -> io::Result<()> {
    println!("{OVERVIEW}");

    match find_project_root(cwd) {
        Some(root) => println!("\ncurrently inside a project at {} — try `frogs generate` or `frogs run`", root.display()),
        None => println!("\nno project found from {} — create an openapi.yaml (or an .html file) to start one", cwd.display()),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "frogs-help-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn succeeds_when_run_outside_any_project() {
        let root = temp_dir("outside");
        assert!(run(&root).is_ok());
    }

    #[test]
    fn succeeds_when_run_inside_an_openapi_project() {
        let root = temp_dir("openapi");
        fs::write(root.join("openapi.yaml"), "").unwrap();
        assert!(run(&root).is_ok());
    }

    #[test]
    fn succeeds_when_run_inside_an_html_only_project() {
        let root = temp_dir("html");
        fs::write(root.join("index.html"), "<html></html>").unwrap();
        assert!(run(&root).is_ok());
    }

    /// `find_project_root` walks *up* from `cwd`, so running from a
    /// subdirectory of a project must still find the project's
    /// `openapi.yaml` — a different code path than being run from the
    /// project root itself.
    #[test]
    fn finds_the_project_root_from_a_subdirectory() {
        let root = temp_dir("subdir");
        fs::write(root.join("openapi.yaml"), "").unwrap();
        let subdir = root.join("nested");
        fs::create_dir_all(&subdir).unwrap();

        assert!(run(&subdir).is_ok());
    }
}
