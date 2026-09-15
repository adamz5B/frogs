use std::io;
use std::path::Path;

use crate::project::require_project_root;
use crate::server::service::{self, ServiceScope, StartType};

/// Registers the current project as an OS-managed service (systemd on
/// Linux, launchd on macOS, a real Windows Service on Windows), started
/// immediately regardless of `start_type` (see `StartType`'s own doc
/// comment) — `start_type` only decides whether it also starts
/// automatically on every *future* boot/login. `account` is Windows-only
/// (which account the service runs as) — ignored on every other platform.
pub fn run(cwd: &Path, name: Option<&str>, scope: ServiceScope, account: Option<&str>, start_type: StartType) -> io::Result<()> {
    let root = require_project_root(cwd);

    #[cfg(windows)]
    {
        let resolved_account = service::windows_svc::resolve_account(account);
        for line in windows_register_messages(scope, &resolved_account) {
            println!("{line}");
        }
    }
    #[cfg(not(windows))]
    {
        // Consistent with this codebase's `--restart`-on-unregistered-project
        // precedent (`commands::run::run`): a platform-inapplicable flag the
        // user actually supplied gets a one-line note, not silence.
        if account.is_some() {
            println!("note: --account has no effect on this platform");
        }
    }

    let service_name = match service::service_name(&root, name) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    // A cheap, defensive re-check of the exact invariant `service_name`'s
    // own construction is supposed to already guarantee — this is the one
    // place a freshly-computed name is used before any `ServiceRecord`
    // (and thus before `revalidate`'s own gate) exists yet.
    if !service::is_plausible_service_name(&service_name) {
        eprintln!("error: internal error — computed service name {service_name:?} failed its own plausibility check");
        std::process::exit(1);
    }

    let existing = service::probe_existing(&service_name, scope);
    match service::decide_collision(existing, &root) {
        service::Collision::Conflict { other_root } => {
            let other = other_root.map(|p| p.display().to_string()).unwrap_or_else(|| "an unknown location".to_string());
            eprintln!(
                "error: a service named {service_name} already exists (registered for {other}) and does not look like \
                 it belongs to this project — use `frogs register --name <NAME>` to pick a different name"
            );
            std::process::exit(1);
        }
        service::Collision::None => {
            println!("registering {service_name} (--{})...", service::scope_label(scope));
        }
        service::Collision::Idempotent => {
            println!("{service_name} is already registered for this exact project — updating its definition in place...");
        }
    }

    let record = service::install(&service_name, scope, &root, account, start_type)?;
    service::write_record(&root, &record)?;

    let boot_note = match start_type {
        StartType::Automatic => "it will now start automatically at boot/login going forward",
        StartType::Manual => "it will NOT start automatically at boot/login — start it explicitly with `frogs run` or the platform's own tool when needed",
    };
    println!("registered and started {service_name} via {} — {boot_note}", service::backend_label(record.backend));
    Ok(())
}

/// Every line `run` prints about the Windows-specific account/elevation
/// story, as one pure function — so a later refactor of `run` itself can't
/// silently drop the `LocalSystem` warning by inlining ad hoc messaging
/// instead of calling this.
#[cfg(windows)]
pub fn windows_register_messages(requested_scope: ServiceScope, resolved_account: &service::windows_svc::ResolvedAccount) -> Vec<String> {
    let mut lines = vec![format!(
        "Windows: this service will run as {} (default NT AUTHORITY\\LocalService; use --account to change) \
         and registering/unregistering requires an elevated (Administrator) terminal.",
        service::windows_svc::account_display(resolved_account)
    )];
    if requested_scope == ServiceScope::User {
        lines.push(
            "note: --user has no effect on Windows — only --account controls the run-as privilege level; \
             elevation is always required regardless of --user/--system."
                .to_string(),
        );
    }
    if let Some(warning) = service::windows_svc::local_system_warning(resolved_account) {
        lines.push(warning);
    }
    lines
}

/// Regression pin for the non-blocking round-2 finding about the
/// LocalSystem warning silently getting dropped in a future refactor —
/// exercises every `(requested_scope, resolved_account)` combination
/// `windows_register_messages` can actually be called with.
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::server::service::windows_svc::ResolvedAccount;

    fn contains_line_containing(lines: &[String], needle: &str) -> bool {
        lines.iter().any(|line| line.contains(needle))
    }

    #[test]
    fn user_scope_always_includes_the_user_has_no_effect_line_regardless_of_account() {
        for account in [
            ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"),
            ResolvedAccount::WellKnown("NT AUTHORITY\\NetworkService"),
            ResolvedAccount::WellKnown("LocalSystem"),
            ResolvedAccount::Custom("svc-custom".to_string()),
        ] {
            let lines = windows_register_messages(ServiceScope::User, &account);
            assert!(
                contains_line_containing(&lines, "--user has no effect"),
                "ServiceScope::User must always include the --user-has-no-effect note for {account:?}: {lines:?}"
            );
        }
    }

    #[test]
    fn system_scope_never_includes_the_user_has_no_effect_line() {
        for account in [
            ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"),
            ResolvedAccount::WellKnown("LocalSystem"),
            ResolvedAccount::Custom("svc-custom".to_string()),
        ] {
            let lines = windows_register_messages(ServiceScope::System, &account);
            assert!(
                !contains_line_containing(&lines, "--user has no effect"),
                "ServiceScope::System must never include the --user-has-no-effect note for {account:?}: {lines:?}"
            );
        }
    }

    #[test]
    fn a_local_system_resolved_account_always_includes_the_warning_line_regardless_of_scope() {
        for scope in [ServiceScope::User, ServiceScope::System] {
            let lines = windows_register_messages(scope, &ResolvedAccount::WellKnown("LocalSystem"));
            assert!(
                contains_line_containing(&lines, "LocalSystem"),
                "a LocalSystem-resolved account must always carry the warning line, for scope {scope:?}: {lines:?}"
            );
            assert!(
                lines.iter().any(|line| line.starts_with("warning:")),
                "the LocalSystem warning line must actually be present, not just any line mentioning LocalSystem: {lines:?}"
            );
        }
    }

    #[test]
    fn local_service_never_includes_the_local_system_warning_line() {
        for scope in [ServiceScope::User, ServiceScope::System] {
            let lines = windows_register_messages(scope, &ResolvedAccount::WellKnown("NT AUTHORITY\\LocalService"));
            assert!(
                !lines.iter().any(|line| line.starts_with("warning:")),
                "LocalService must never carry the LocalSystem warning: {lines:?}"
            );
        }
    }

    #[test]
    fn network_service_never_includes_the_local_system_warning_line() {
        for scope in [ServiceScope::User, ServiceScope::System] {
            let lines = windows_register_messages(scope, &ResolvedAccount::WellKnown("NT AUTHORITY\\NetworkService"));
            assert!(
                !lines.iter().any(|line| line.starts_with("warning:")),
                "NetworkService must never carry the LocalSystem warning: {lines:?}"
            );
        }
    }

    #[test]
    fn a_custom_account_never_includes_the_local_system_warning_line() {
        for scope in [ServiceScope::User, ServiceScope::System] {
            let lines = windows_register_messages(scope, &ResolvedAccount::Custom("svc-custom".to_string()));
            assert!(
                !lines.iter().any(|line| line.starts_with("warning:")),
                "a custom account must never carry the LocalSystem warning: {lines:?}"
            );
        }
    }
}
