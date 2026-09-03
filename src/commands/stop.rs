use std::io;
use std::path::Path;

use crate::project::require_project_root;
use crate::server::pidfile;

pub fn run(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);

    let Some(info) = pidfile::read(&root)? else {
        println!("no running server found for this project ({} doesn't exist)", pidfile::path(&root).display());
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
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
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

    /// A real, genuinely long-running child process to stop — killed in
    /// `Drop` too, so a failed assertion mid-test can't leak a lingering
    /// process. Same pattern `server::pidfile`'s own tests use to exercise
    /// `terminate` against something real rather than a fake PID.
    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(unix)]
    fn spawn_long_running_child() -> ChildGuard {
        ChildGuard(
            std::process::Command::new("sh")
                .args(["-c", "sleep 30"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("sh should be available to spawn a throwaway sleep"),
        )
    }

    #[cfg(windows)]
    fn spawn_long_running_child() -> ChildGuard {
        ChildGuard(
            std::process::Command::new("ping")
                .args(["-n", "30", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("ping should be available to spawn a throwaway long-running process"),
        )
    }

    /// The one branch neither test above exercises: a pidfile pointing at
    /// a genuinely *live* process — the actual "stop a running server"
    /// path `frogs stop` exists for, previously only ever checked by hand
    /// against the real binary.
    #[test]
    fn a_live_process_is_actually_terminated_and_the_run_file_removed() {
        let root = temp_project();
        let mut child = spawn_long_running_child();
        let pid = child.0.id();
        assert!(pidfile::is_alive(pid), "the freshly spawned child should be alive before run() stops it");

        pidfile::write(
            &root,
            &RunInfo {
                pid,
                port: 8080,
                started_at: chrono::Utc::now(),
            },
        )
        .unwrap();

        assert!(run(&root).is_ok());

        assert!(
            pidfile::read(&root).unwrap().is_none(),
            "the run file must be removed once the process has actually been stopped"
        );

        // `terminate` itself waits for the kill/taskkill command to
        // complete, but the OS updating the process table for `is_alive`'s
        // own query can lag by a beat — poll briefly instead of asserting
        // immediately, same as `server::pidfile`'s own `terminate` test.
        let mut confirmed_dead = false;
        for _ in 0..20 {
            // Reap eagerly — see `server::pidfile::tests::terminate_kills_a_real_process`'s
            // matching comment: `is_alive` reports a zombie as alive until
            // its parent reaps it, and this test is that parent.
            let _ = child.0.try_wait();
            if !pidfile::is_alive(pid) {
                confirmed_dead = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(confirmed_dead, "run() should result in the process no longer being alive");
    }
}
