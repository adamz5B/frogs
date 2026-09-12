//! The Windows-only counterpart to `commands::run` for a project registered
//! via `frogs register`: the process the SCM itself launches (per the
//! `binPath`/launch arguments `service::windows_svc::install` bakes in),
//! not something a user ever runs by hand — see `main`'s own
//! `--windows-service-host` sentinel check for how execution ever reaches
//! `run_as_service` at all.
#![cfg(windows)]

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Registers `ffi_service_main` with the SCM and blocks this thread until
/// the service is stopped. `--service-name` is parsed from the process's
/// own real argv (`std::env::args_os()`) — not anything derived from
/// `Cli::parse()`, since this runs before `main` ever constructs a `Cli` —
/// because `service_dispatcher::start` needs the name up front, before the
/// SCM ever calls back into `service_main` itself.
pub fn run_as_service() -> io::Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let service_name = extract_required(&args, "--service-name")?;

    // Outside a real SCM-launched context this fails fast (documented crate
    // behavior — there is no dispatcher table to join) rather than hanging,
    // so an interactively-typed `frogs --windows-service-host ...` gets a
    // clear error instead of an unexplained freeze.
    windows_service::service_dispatcher::start(&service_name, ffi_service_main).map_err(|e| io::Error::other(format!("failed to start Windows service dispatcher: {e}")))
}

/// The low-level entry point the SCM calls back on a background thread.
/// Its own `arguments` parameter is the SCM's *service* argument vector
/// (populated only when something calls `StartService` with extra
/// arguments, which nothing here ever does) — not the real process argv,
/// which is where `--service-name`/`--project-root`/`--frogs-marker`
/// actually live, so `run_service` re-reads `std::env::args_os()` itself
/// instead of trusting this parameter.
fn service_main(_arguments: Vec<OsString>) {
    let args: Vec<OsString> = std::env::args_os().collect();

    // The Win32 FFI boundary this function sits on can't unwind — catching
    // a panic here exists purely so a bug further down still leaves the SCM
    // with a clean Stopped status update, rather than the process just
    // vanishing with the SCM left waiting.
    let outcome = std::panic::catch_unwind(|| run_service(args.clone()));

    if let Ok(Err(e)) = &outcome {
        eprintln!("error: {e}");
    }

    if outcome.is_err() {
        report_best_effort_stop(&args);
    }
}

/// Best-effort only: `run_service` normally registers its own control
/// handler and reports its own final status, so this path is reached only
/// when it panicked before (or during) doing so. A second
/// `service_control_handler::register` call for the same name is safe to
/// attempt — if it fails, there is nothing further to fall back to, so the
/// failure is silently swallowed here rather than propagated (there is no
/// one left to propagate it to).
fn report_best_effort_stop(args: &[OsString]) {
    let Some(name) = crate::server::service::windows_svc::extract_flag_value(args, "--service-name").and_then(|v| v.into_string().ok()) else {
        return;
    };
    if let Ok(handle) = service_control_handler::register(&name, |_control| ServiceControlHandlerResult::NotImplemented) {
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(1),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }
}

/// The real body of the hosted service: validates the arguments baked into
/// its own launch command line, reports status transitions to the SCM, and
/// runs the exact same `run_direct_with_shutdown` every unregistered
/// project's `frogs run` uses — a registered Windows Service is not a
/// different code path from a normal run, just a different way of starting
/// and stopping one.
fn run_service(arguments: Vec<OsString>) -> io::Result<()> {
    let service_name = extract_required(&arguments, "--service-name")?;
    if !crate::server::service::is_plausible_service_name(&service_name) {
        return Err(io::Error::other("refusing to host a service whose own registered name fails basic validation"));
    }

    let project_root = PathBuf::from(extract_required(&arguments, "--project-root")?);
    crate::server::service::reject_unsafe_path(&project_root)?;
    if !crate::project::is_project_root(&project_root) {
        return Err(io::Error::other(format!("{} does not look like a frogs project root", project_root.display())));
    }

    // `event_handler` is `FnMut`, but a `oneshot::Sender` is single-use —
    // the `Mutex<Option<_>>` bridges the two, and the handler only ever
    // takes the sender out once regardless of how many Stop/Shutdown
    // control events the SCM happens to deliver.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Mutex::new(Some(shutdown_tx));

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Ok(mut guard) = shutdown_tx.lock()
                    && let Some(tx) = guard.take()
                {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            // Every service must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(&service_name, event_handler)
        .map_err(|e| io::Error::other(format!("failed to register the Windows service control handler: {e}")))?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::NO_ERROR,
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
        .map_err(|e| io::Error::other(format!("failed to report StartPending to the SCM: {e}")))?;

    // This thread is the one the SCM handed this process — never nested
    // inside another runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| io::Error::other(format!("failed to build the tokio runtime: {e}")))?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::NO_ERROR,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| io::Error::other(format!("failed to report Running to the SCM: {e}")))?;

    // A dropped sender (e.g. this closure never runs again after the
    // handler's one-shot `.take()`) also unblocks the receiver — treated
    // the same as an explicit Stop/Shutdown, i.e. "shut down."
    let shutdown = async {
        let _ = shutdown_rx.await;
    };
    let result = runtime.block_on(crate::commands::run::run_direct_with_shutdown(&project_root, shutdown));

    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    result
}

fn extract_required(args: &[OsString], flag: &str) -> io::Result<String> {
    crate::server::service::windows_svc::extract_flag_value(args, flag)
        .and_then(|v| v.into_string().ok())
        .ok_or_else(|| io::Error::other(format!("missing or invalid {flag} argument")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_project() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-service-host-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn args(pairs: &[(&str, &str)]) -> Vec<OsString> {
        // A leading element standing in for argv[0] (the exe path) — real
        // process argv always has one, and `extract_flag_value` skips
        // nothing special about position 0, but a realistic fixture should
        // still include it.
        let mut v = vec![OsString::from("frogs.exe")];
        for (flag, value) in pairs {
            v.push(OsString::from(*flag));
            v.push(OsString::from(*value));
        }
        v
    }

    // -----------------------------------------------------------------
    // extract_required
    // -----------------------------------------------------------------

    #[test]
    fn extract_required_returns_the_value_when_the_flag_is_present() {
        let a = args(&[("--service-name", "frogs-x")]);
        assert_eq!(extract_required(&a, "--service-name").unwrap(), "frogs-x");
    }

    #[test]
    fn extract_required_errors_clearly_when_the_flag_is_missing() {
        let a = args(&[("--other-flag", "value")]);
        let err = extract_required(&a, "--service-name").expect_err("a missing required flag must be an error");
        assert!(err.to_string().contains("--service-name"));
    }

    // -----------------------------------------------------------------
    // run_service's own argument-validation prefix — each of these must
    // produce a clear Err before ever reaching control-handler
    // registration/SCM calls. A malformed input reaching any of these
    // three checks returns immediately (this function never gets far
    // enough to touch `service_control_handler::register`), so a
    // synchronous `Err` return here (rather than a panic or a hang) is
    // itself proof the checks are gating in the right order.
    // -----------------------------------------------------------------

    #[test]
    fn run_service_rejects_a_structurally_malformed_service_name_before_touching_anything_else() {
        let root = temp_project();
        let a = args(&[
            ("--service-name", "not-frogs-prefixed"),
            ("--project-root", root.to_str().unwrap()),
            ("--frogs-marker", "frogs-register"),
        ]);
        let err = run_service(a).expect_err("a service name failing is_plausible_service_name must be rejected");
        assert!(err.to_string().contains("basic validation"), "unexpected message: {err}");
    }

    #[test]
    fn run_service_rejects_a_project_root_containing_an_embedded_nul_byte() {
        let hostile_root = format!("C:\\te{}mp", '\0');
        let a = args(&[
            ("--service-name", "frogs-testsvc"),
            ("--project-root", &hostile_root),
            ("--frogs-marker", "frogs-register"),
        ]);
        let err = run_service(a).expect_err("an embedded NUL byte in --project-root must be rejected");
        let message = err.to_string();
        assert!(message.contains("NUL") || message.contains("nul"), "unexpected message: {message}");
    }

    #[test]
    fn run_service_rejects_a_syntactically_fine_but_non_project_directory() {
        // A real, existing, ordinary directory — but with no openapi.yaml
        // or *.html file in it, so it fails `project::is_project_root`.
        let root = temp_project();
        let a = args(&[
            ("--service-name", "frogs-testsvc"),
            ("--project-root", root.to_str().unwrap()),
            ("--frogs-marker", "frogs-register"),
        ]);
        let err = run_service(a).expect_err("a directory that isn't a frogs project root must be rejected");
        assert!(err.to_string().contains("does not look like a frogs project root"), "unexpected message: {err}");
    }
}
