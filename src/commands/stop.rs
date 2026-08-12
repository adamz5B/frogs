use std::io;
use std::path::Path;

use crate::project::require_project_root;
use crate::server::pidfile;

pub fn run(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);

    let Some(info) = pidfile::read(&root)? else {
        println!(
            "no running server found for this project ({} doesn't exist)",
            pidfile::path(&root).display()
        );
        return Ok(());
    };

    if !pidfile::is_alive(info.pid) {
        println!("pid {} is no longer running — removing the stale run file", info.pid);
        pidfile::remove(&root)?;
        return Ok(());
    }

    println!("stopping frogs server (pid {}, port {})...", info.pid, info.port);
    pidfile::terminate(info.pid)?;
    pidfile::remove(&root)?;
    println!("stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::pidfile::RunInfo;
    use std::fs;

    /// A project root `require_project_root` will accept without exiting
    /// the process — real `frogs stop` calls that helper first, but exiting
    /// mid-test would kill the whole test binary, so every test here gives
    /// it a directory with an `openapi.yaml` already in place.
    fn temp_project() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "frogs-stop-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        root
    }

    #[test]
    fn no_running_server_is_reported_not_an_error() {
        let root = temp_project();
        assert!(run(&root).is_ok());
        assert!(pidfile::read(&root).unwrap().is_none());
    }

    #[test]
    fn a_stale_pidfile_for_a_dead_process_is_cleaned_up_without_erroring() {
        let root = temp_project();
        pidfile::write(
            &root,
            &RunInfo {
                // Not a real PID on any platform this project targets —
                // `is_alive` must report this as dead, not error out.
                pid: u32::MAX,
                port: 8080,
                started_at: chrono::Utc::now(),
            },
        )
        .unwrap();

        assert!(run(&root).is_ok());
        assert!(
            pidfile::read(&root).unwrap().is_none(),
            "the stale run file must be removed once its process is found to be dead"
        );
    }
}
