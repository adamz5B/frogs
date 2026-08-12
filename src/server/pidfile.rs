use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Basic info about a running `frogs run` process, written once the server
/// has actually bound its listener. This is what `frogs stop` reads to find
/// and terminate the right process, instead of the user having to hunt down
/// a PID by hand and run `taskkill`/`kill` themselves.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunInfo {
    pub pid: u32,
    pub port: u16,
    pub started_at: DateTime<Utc>,
}

/// `.frogs/` is deliberately separate from `config/`/`datasources/` — it's
/// ephemeral runtime state (regenerated every run, meaningless once the
/// process exits), not project config a user authors or commits.
fn runtime_dir(project_root: &Path) -> PathBuf {
    project_root.join(".frogs")
}

pub fn path(project_root: &Path) -> PathBuf {
    runtime_dir(project_root).join("run.json")
}

pub fn write(project_root: &Path, info: &RunInfo) -> io::Result<()> {
    fs::create_dir_all(runtime_dir(project_root))?;
    let json = serde_json::to_string_pretty(info).expect("RunInfo always serializes");
    fs::write(path(project_root), json)
}

/// `None` covers both "never ran here" and "the file is corrupt" — either
/// way, there's nothing a caller can act on, so both collapse to the same
/// result rather than being separate error cases.
pub fn read(project_root: &Path) -> io::Result<Option<RunInfo>> {
    match fs::read_to_string(path(project_root)) {
        Ok(contents) => Ok(serde_json::from_str(&contents).ok()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn remove(project_root: &Path) -> io::Result<()> {
    match fs::remove_file(path(project_root)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Whether `pid` still refers to a live process. Shelled out to the
/// platform's own process-listing tool rather than a signals/WinAPI crate —
/// one dependency-free implementation per OS, matching how little this
/// project needs from either.
#[cfg(unix)]
pub fn is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
pub fn is_alive(pid: u32) -> bool {
    let output = Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/NH"]).output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()),
        Err(_) => false,
    }
}

/// Terminates `pid` immediately — no graceful in-flight-request draining.
/// That's a deliberate scope decision, not an oversight: frogs holds no
/// state of its own across a request (the real data lives in Postgres/
/// downstream APIs), so the only risk a hard kill carries is a caller not
/// finding out whether their in-flight write's response made it back —
/// which a clean shutdown signal wouldn't fully eliminate either, since the
/// write can already have committed upstream before the signal arrives.
#[cfg(unix)]
pub fn terminate(pid: u32) -> io::Result<()> {
    let status = Command::new("kill").args(["-TERM", &pid.to_string()]).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("kill exited with {status}")))
    }
}

#[cfg(windows)]
pub fn terminate(pid: u32) -> io::Result<()> {
    let status = Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("taskkill exited with {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::time::Duration;

    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "frogs-pidfile-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
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
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sample_info() -> RunInfo {
        RunInfo { pid: 4242, port: 8080, started_at: Utc::now() }
    }

    #[test]
    fn path_is_dot_frogs_run_json_under_the_project_root() {
        let root = Path::new("/proj");
        assert_eq!(path(root), root.join(".frogs").join("run.json"));
    }

    #[test]
    fn write_creates_the_runtime_dir_and_the_file() {
        let dir = tempdir();
        assert!(!path(dir.path()).exists());
        write(dir.path(), &sample_info()).unwrap();
        assert!(path(dir.path()).is_file());
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempdir();
        let info = sample_info();
        write(dir.path(), &info).unwrap();

        let read_back = read(dir.path()).unwrap().expect("just-written info should read back");
        assert_eq!(read_back.pid, info.pid);
        assert_eq!(read_back.port, info.port);
    }

    #[test]
    fn read_missing_file_returns_none_not_an_error() {
        let dir = tempdir();
        assert!(read(dir.path()).unwrap().is_none());
    }

    #[test]
    fn read_corrupt_json_returns_none_not_an_error() {
        // Per this module's own doc comment: a hand-corrupted or truncated
        // run.json collapses to the same "nothing to act on" result as a
        // missing file, rather than surfacing as a distinct error case.
        let dir = tempdir();
        fs::create_dir_all(runtime_dir(dir.path())).unwrap();
        fs::write(path(dir.path()), "{ not valid json").unwrap();

        assert!(read(dir.path()).unwrap().is_none());
    }

    #[test]
    fn remove_is_idempotent_when_the_file_is_already_missing() {
        let dir = tempdir();
        assert!(remove(dir.path()).is_ok());
    }

    #[test]
    fn remove_deletes_an_existing_file() {
        let dir = tempdir();
        write(dir.path(), &sample_info()).unwrap();
        remove(dir.path()).unwrap();
        assert!(read(dir.path()).unwrap().is_none());
    }

    #[test]
    fn is_alive_is_true_for_the_current_process() {
        assert!(is_alive(std::process::id()));
    }

    #[test]
    fn is_alive_is_false_for_a_pid_that_cannot_exist() {
        assert!(!is_alive(u32::MAX));
    }

    /// A real, genuinely long-running child process to exercise `terminate`
    /// against — killed in `Drop` too, so a failed assertion mid-test can't
    /// leak a lingering process.
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
            Command::new("sh")
                .args(["-c", "sleep 30"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("sh should be available to spawn a throwaway sleep"),
        )
    }

    #[cfg(windows)]
    fn spawn_long_running_child() -> ChildGuard {
        ChildGuard(
            Command::new("ping")
                .args(["-n", "30", "127.0.0.1"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("ping should be available to spawn a throwaway long-running process"),
        )
    }

    #[test]
    fn terminate_kills_a_real_process() {
        let mut child = spawn_long_running_child();
        let pid = child.0.id();
        assert!(is_alive(pid), "the freshly spawned child should be alive before terminate() runs");

        terminate(pid).unwrap();

        // `terminate` waits for the kill/taskkill command itself to
        // complete, but the OS updating the process table for `is_alive`'s
        // own query can lag by a beat — poll briefly instead of asserting
        // immediately.
        let mut confirmed_dead = false;
        for _ in 0..20 {
            if !is_alive(pid) {
                confirmed_dead = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(confirmed_dead, "terminate() should result in the process no longer being alive");
        let _ = child.0.wait();
    }
}
