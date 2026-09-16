use std::io;
use std::path::Path;

use crate::project::require_project_root;
use crate::server::pidfile;
use crate::server::service::{self, ServiceScope};

/// Removes the current project's OS-managed service registration — stops
/// it first automatically, then removes the platform definition, then
/// `.frogs/service.json` and any stale `.frogs/run.json`.
pub fn run(cwd: &Path, scope: ServiceScope) -> io::Result<()> {
    let root = require_project_root(cwd);

    let Some(record) = service::read_record(&root)? else {
        println!("this project is not registered as a service");
        return Ok(());
    };

    if scope != record.scope {
        // The recorded scope (from whatever `frogs register` call actually
        // created this definition) is authoritative — there's only ever
        // one registration per project, so a mismatched flag here is just
        // a mistaken assumption on the caller's part, not a second
        // registration to disambiguate between.
        println!(
            "note: this project was registered with --{} — using that recorded scope, not --{}",
            service::scope_label(record.scope),
            service::scope_label(scope)
        );
    }

    if let Err(e) = service::revalidate(&record, &root) {
        eprintln!("error: refusing to unregister {} — {e}", record.name);
        std::process::exit(1);
    }

    println!(
        "unregistering {} (registered service, via {})...",
        record.name,
        service::backend_label(record.backend)
    );

    service::stop_registered(&record, &root)?;
    // `stop_registered` only *requests* the stop (e.g. Win32's
    // `ControlService(STOP)` is asynchronous — a request, not a synchronous
    // stop); `uninstall` is what actually waits for the service to reach a
    // stopped state (via `wait_until_stopped` on Windows) before deleting
    // it, which can take a few seconds — worth its own status line so the
    // terminal doesn't look hung for the duration.
    println!("stop requested — waiting for it to fully stop before removing the registration...");

    service::uninstall(&record, &root)?;
    service::remove_record(&root)?;
    pidfile::remove(&root)?;

    println!("unregistered {}.", record.name);
    Ok(())
}
