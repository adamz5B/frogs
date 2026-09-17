mod commands;
mod config;
mod endpoint;
mod errors;
mod http;
mod openapi;
mod project;
mod security;
mod server;
mod sql;
mod testing;
mod webserve;

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use commands::generate::Role;
use commands::test::TestServerOptions;
use server::service::{RestartPolicy, ServiceScope, StartType};
use testing::ReportFormat;

#[derive(Parser)]
#[command(name = "frogs", version, about = "Free Rust OpenAPI Generated Server", disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate datasource stub/reference files from openapi.yaml, a
    /// webserve.json for a static-content project, or both
    Generate {
        /// Forces generating only the API or only the web side, when a
        /// project has both an openapi.yaml and a web asset file present —
        /// with neither flag, both are generated
        #[arg(long, value_enum)]
        role: Option<Role>,
    },
    /// Start the server for the current project
    Run {
        /// Set automatically on the command line baked into a service
        /// definition by `frogs register` — internal-only, not meant to be
        /// passed by hand
        #[arg(long = "service-managed", hide = true)]
        service_managed: bool,
        /// Restart the service if it's already running (only meaningful
        /// for a project registered via `frogs register`)
        #[arg(long)]
        restart: bool,
    },
    /// Stop the running server for the current project
    Stop,
    /// Register this project to run as an OS-managed service (systemd on
    /// Linux, launchd on macOS, a real Windows Service on Windows) —
    /// started immediately and set to start automatically going forward
    Register {
        /// Identifier to use in place of the project folder name — the
        /// final registered name is always frogs-<NAME>
        #[arg(long)]
        name: Option<String>,
        /// Register for the current user only (default) — on Windows this
        /// has no effect (see --account below); a Windows Service always
        /// requires an elevated (Administrator) terminal to register or
        /// unregister, regardless of --user/--system
        #[arg(long, conflicts_with = "system")]
        user: bool,
        /// Register system-wide (requires appropriate OS privileges — no
        /// self-elevation is attempted) — on Windows this has no effect
        /// (see --account below)
        #[arg(long, conflicts_with = "user")]
        system: bool,
        /// Windows only: the account the service runs as — a well-known
        /// name (LocalService, NetworkService, LocalSystem, matched
        /// case-insensitively) or a custom account name. Defaults to NT
        /// AUTHORITY\LocalService when omitted (never LocalSystem, to avoid
        /// granting more privilege than a service needs by default). A
        /// custom account (other than a group-managed service account,
        /// whose name ends in '$') needs its password supplied via the
        /// FROGS_SERVICE_ACCOUNT_PASSWORD environment variable. Ignored on
        /// non-Windows platforms.
        #[arg(long)]
        account: Option<String>,
        /// Windows only: the description shown in services.msc/`sc
        /// qdescription` for this service. Defaults to a generated
        /// description naming the project's path when omitted. Ignored on
        /// non-Windows platforms
        #[arg(long)]
        description: Option<String>,
        /// Whether the service starts automatically at boot/login going
        /// forward (default) or only when started explicitly (`frogs run`,
        /// or the platform's own tool) — either way, `register` still
        /// starts it once immediately regardless of this choice
        #[arg(long, value_enum, default_value = "automatic")]
        start_type: StartType,
        /// Whether the service is automatically restarted by the OS if it
        /// later exits with a failure (default: on-failure) — never
        /// triggered by a deliberate `frogs stop`/`frogs unregister`,
        /// regardless of this setting
        #[arg(long, value_enum, default_value = "on-failure")]
        restart_policy: RestartPolicy,
    },
    /// Remove this project's OS-managed service registration
    Unregister {
        /// The project was registered for the current user only (default)
        #[arg(long, conflicts_with = "system")]
        user: bool,
        /// The project was registered system-wide
        #[arg(long, conflicts_with = "user")]
        system: bool,
    },
    /// Serve the API as a mock server: every source resolves from the
    /// project's *.test.json mocks, never a real database or upstream
    /// service, until stopped (Ctrl+C) — or record a new case from a real
    /// request
    Test {
        #[command(subcommand)]
        action: Option<TestCommand>,
        /// Override config/server.json's port for this process only
        #[arg(long)]
        port: Option<u16>,
        /// Interface to listen on — loopback by default; anything else
        /// exposes the unauthenticated /_frogs/scenario control plane to
        /// the network
        #[arg(long, default_value = "127.0.0.1")]
        bind: IpAddr,
        /// Fix the active scenario for the whole process (a header or the
        /// control plane can still override it per request/session)
        #[arg(long)]
        scenario: Option<String>,
        /// Report format — text streams one line per request to stdout;
        /// json/junit are written to --report-file
        #[arg(long, value_enum, default_value = "text")]
        report: ReportFormat,
        /// Where to write the report (required for json/junit; optional
        /// for text, which then also appends its lines there)
        #[arg(long, required_if_eq_any([("report", "json"), ("report", "junit")]))]
        report_file: Option<PathBuf>,
    },
    /// Manage the error code registry
    Errors {
        #[command(subcommand)]
        action: ErrorsCommand,
    },
    /// Inspect which SQL drivers this binary was built with
    Drivers {
        #[command(subcommand)]
        action: DriversCommand,
    },
    /// Dry-run every startup check (config, SQL connections, endpoint
    /// files) without binding a port — safe to run repeatedly, e.g. in CI
    Validate,
    /// Print an overview of frogs and the current project's status
    Help,
}

#[derive(Subcommand)]
enum ErrorsCommand {
    /// Batch every entry in config/errors.discovered.json into a new,
    /// dated file under config/errors/, then purge the scratch file
    Freeze,
}

#[derive(Subcommand)]
enum DriversCommand {
    /// Print which SQL drivers are compiled into this binary
    List,
}

#[derive(Subcommand)]
enum TestCommand {
    /// Run one real request against real infrastructure and record what
    /// each source actually returned as a mocks block
    Record {
        /// The endpoint path, e.g. /cars/1HGCM82633A004352 (a query string
        /// after `?` is parsed too)
        path: String,
        /// The HTTP method, e.g. get
        method: String,
    },
}

/// `--system` wins if both were somehow passed (clap's own `conflicts_with`
/// already rejects that combination before this ever runs); with neither
/// flag given, `--user` is the documented default.
fn resolve_scope(user: bool, system: bool) -> ServiceScope {
    let _ = user;
    if system { ServiceScope::System } else { ServiceScope::User }
}

/// Installs the process-wide rustls crypto provider — must happen before
/// any TLS operation (an HTTPS `frogs run`, or any outbound `reqwest`/
/// `sqlx` TLS connection) — see the doc comment on this dependency in
/// Cargo.toml for why rustls needs this told to it explicitly rather than
/// picking a default on its own. Shared by both `main`'s own normal
/// startup path and the Windows `--windows-service-host` sentinel branch
/// below, since exactly one of the two ever runs per process.
fn install_rustls_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("installing the process-wide rustls crypto provider should only ever be attempted once");
}

/// A plain, non-`#[tokio::main]` `fn main()` — a mechanical de-sugaring,
/// not a behavior change — specifically so the Windows-only
/// `--windows-service-host` sentinel check below can run, and exit,
/// *before* a tokio runtime, `Cli::parse()`, or anything else in the
/// normal startup path is ever touched. That sentinel is how a process the
/// SCM itself launches (per a registered service's own baked-in command
/// line — see `server::service_host`) ends up hosting the real Windows
/// Service machinery instead of being parsed as an ordinary `frogs`
/// subcommand invocation.
fn main() {
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--windows-service-host") {
        install_rustls_crypto_provider();
        // No subscriber installed here either way: real wiring only happens
        // once `run_as_service()` reaches `run_direct_with_shutdown`'s own
        // `server::logging::install_run_subscriber` call, deep inside
        // `service_host::run_service`. The `tracing::error!` below is
        // therefore inert if that point is never reached (e.g. the
        // dispatcher itself fails to start) — accepted, since a real
        // SCM-launched process has no console for the `eprintln!` right
        // next to it to reach in that scenario either, so nothing is
        // actually lost versus today.
        std::process::exit(match crate::server::service_host::run_as_service() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                tracing::error!("error: {e}");
                1
            }
        });
    }

    install_rustls_crypto_provider();

    let cli = Cli::parse();

    // Every subcommand gets the stdout-only bootstrap subscriber except
    // `Run` — that one installs its own persistent stdout+file subscriber
    // later, once it knows the project's role and `logging` config (see
    // `commands::run`/`server::logging::install_run_subscriber`), so
    // installing a bootstrap one here first would just be immediately
    // replaced (or, for a registered project's `run`, which never reaches
    // that point, installed separately in `commands::run::run` itself).
    if !matches!(cli.command, Command::Run { .. }) {
        server::logging::install_bootstrap_subscriber();
    }

    let cwd = std::env::current_dir().expect("failed to read current directory");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build the tokio runtime");

    let result = runtime.block_on(async {
        match cli.command {
            Command::Generate { role } => commands::generate::run(&cwd, role),
            Command::Run { service_managed, restart } => commands::run::run(&cwd, service_managed, restart).await,
            Command::Stop => commands::stop::run(&cwd),
            Command::Register {
                name,
                user,
                system,
                account,
                description,
                start_type,
                restart_policy,
            } => commands::register::run(
                &cwd,
                name.as_deref(),
                resolve_scope(user, system),
                account.as_deref(),
                description.as_deref(),
                start_type,
                restart_policy,
            ),
            Command::Unregister { user, system } => commands::unregister::run(&cwd, resolve_scope(user, system)),
            Command::Test {
                action: None,
                port,
                bind,
                scenario,
                report,
                report_file,
            } => {
                commands::test::run(
                    &cwd,
                    TestServerOptions {
                        port,
                        bind,
                        scenario,
                        report,
                        report_file,
                    },
                )
                .await
            }
            Command::Test {
                action: Some(TestCommand::Record { path, method }),
                ..
            } => commands::test::record(&cwd, &path, &method).await,
            Command::Errors { action: ErrorsCommand::Freeze } => commands::errors::freeze(&cwd),
            Command::Drivers { action: DriversCommand::List } => commands::drivers::list(),
            Command::Validate => commands::validate::run(&cwd).await,
            Command::Help => commands::help::run(&cwd),
        }
    });

    if let Err(err) = result {
        eprintln!("error: {err}");
        tracing::error!("error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `main()` itself isn't unit-testable — it reads real argv, installs a
    /// process-global tracing subscriber that panics on a second `init()`,
    /// and terminates via `std::process::exit`. What *is* testable, and
    /// worth pinning down given how easy a clap attribute typo is to miss
    /// (e.g. when a subcommand like `Errors` gets added), is that `Cli`
    /// actually parses the arguments each subcommand claims to accept.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["frogs"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap_or_else(|e| panic!("expected {args:?} to parse: {e}")).command
    }

    #[test]
    fn parses_generate_with_no_role() {
        assert!(matches!(parse(&["generate"]), Command::Generate { role: None }));
    }

    #[test]
    fn parses_generate_with_role_api() {
        assert!(matches!(parse(&["generate", "--role", "api"]), Command::Generate { role: Some(Role::Api) }));
    }

    #[test]
    fn parses_generate_with_role_web() {
        assert!(matches!(parse(&["generate", "--role", "web"]), Command::Generate { role: Some(Role::Web) }));
    }

    #[test]
    fn parses_run() {
        assert!(matches!(
            parse(&["run"]),
            Command::Run {
                service_managed: false,
                restart: false
            }
        ));
    }

    #[test]
    fn parses_stop() {
        assert!(matches!(parse(&["stop"]), Command::Stop));
    }

    #[test]
    fn parses_run_with_restart() {
        assert!(matches!(
            parse(&["run", "--restart"]),
            Command::Run {
                service_managed: false,
                restart: true
            }
        ));
    }

    #[test]
    fn parses_run_with_service_managed_even_though_the_flag_is_hidden() {
        // `hide = true` only affects `--help` output — the flag must still
        // actually parse, since every registered service's own command
        // line bakes it in.
        assert!(matches!(
            parse(&["run", "--service-managed"]),
            Command::Run {
                service_managed: true,
                restart: false
            }
        ));
    }

    #[test]
    fn parses_register_with_no_flags() {
        match parse(&["register"]) {
            Command::Register {
                name,
                user,
                system,
                account,
                description,
                start_type,
                restart_policy,
            } => {
                assert_eq!(name, None);
                assert!(!user);
                assert!(!system);
                assert_eq!(account, None);
                assert_eq!(description, None);
                assert_eq!(start_type, StartType::Automatic, "the default start type must be Automatic");
                assert_eq!(restart_policy, RestartPolicy::OnFailure, "the default restart policy must be OnFailure");
            }
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_restart_policy_never() {
        match parse(&["register", "--restart-policy", "never"]) {
            Command::Register { restart_policy, .. } => assert_eq!(restart_policy, RestartPolicy::Never),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_restart_policy_on_failure_explicitly() {
        match parse(&["register", "--restart-policy", "on-failure"]) {
            Command::Register { restart_policy, .. } => assert_eq!(restart_policy, RestartPolicy::OnFailure),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_start_type_manual() {
        match parse(&["register", "--start-type", "manual"]) {
            Command::Register { start_type, .. } => assert_eq!(start_type, StartType::Manual),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_start_type_automatic_explicitly() {
        match parse(&["register", "--start-type", "automatic"]) {
            Command::Register { start_type, .. } => assert_eq!(start_type, StartType::Automatic),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_a_name() {
        match parse(&["register", "--name", "foo"]) {
            Command::Register { name, .. } => assert_eq!(name, Some("foo".to_string())),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_system() {
        match parse(&["register", "--system"]) {
            Command::Register { user, system, .. } => {
                assert!(!user);
                assert!(system);
            }
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_user() {
        match parse(&["register", "--user"]) {
            Command::Register { user, system, .. } => {
                assert!(user);
                assert!(!system);
            }
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_a_description() {
        match parse(&["register", "--description", "my custom description"]) {
            Command::Register { description, .. } => assert_eq!(description, Some("my custom description".to_string())),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn parses_register_with_an_account() {
        match parse(&["register", "--account", "NetworkService"]) {
            Command::Register { account, .. } => assert_eq!(account, Some("NetworkService".to_string())),
            _ => panic!("expected Command::Register"),
        }
    }

    #[test]
    fn register_user_and_system_together_is_a_parse_error() {
        assert!(
            Cli::try_parse_from(["frogs", "register", "--user", "--system"]).is_err(),
            "--user and --system are mutually exclusive via conflicts_with"
        );
    }

    #[test]
    fn parses_unregister_with_no_flags() {
        assert!(matches!(parse(&["unregister"]), Command::Unregister { user: false, system: false }));
    }

    #[test]
    fn parses_unregister_with_system() {
        assert!(matches!(parse(&["unregister", "--system"]), Command::Unregister { user: false, system: true }));
    }

    #[test]
    fn unregister_user_and_system_together_is_a_parse_error() {
        assert!(
            Cli::try_parse_from(["frogs", "unregister", "--user", "--system"]).is_err(),
            "--user and --system are mutually exclusive via conflicts_with"
        );
    }

    #[test]
    fn parses_help() {
        assert!(matches!(parse(&["help"]), Command::Help));
    }

    #[test]
    fn parses_test_with_no_subcommand() {
        assert!(matches!(parse(&["test"]), Command::Test { action: None, .. }));
    }

    #[test]
    fn parses_test_record_with_its_path_and_method() {
        match parse(&["test", "record", "/cars/1HGCM82633A004352", "get"]) {
            Command::Test {
                action: Some(TestCommand::Record { path, method }),
                ..
            } => {
                assert_eq!(path, "/cars/1HGCM82633A004352");
                assert_eq!(method, "get");
            }
            _ => panic!("expected Command::Test {{ action: Some(TestCommand::Record {{ .. }}) }}"),
        }
    }

    #[test]
    fn parses_errors_freeze() {
        assert!(matches!(parse(&["errors", "freeze"]), Command::Errors { action: ErrorsCommand::Freeze }));
    }

    #[test]
    fn bare_test_defaults_to_loopback_text_report_and_no_port_scenario_or_report_file() {
        match parse(&["test"]) {
            Command::Test {
                action: None,
                port,
                bind,
                scenario,
                report,
                report_file,
            } => {
                assert_eq!(port, None);
                assert_eq!(bind, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), "loopback by default, never all interfaces");
                assert_eq!(scenario, None);
                assert_eq!(report, ReportFormat::Text);
                assert_eq!(report_file, None);
            }
            _ => panic!("expected a bare Command::Test"),
        }
    }

    #[test]
    fn parses_test_with_a_port() {
        match parse(&["test", "--port", "9090"]) {
            Command::Test { port, .. } => assert_eq!(port, Some(9090)),
            _ => panic!("expected Command::Test"),
        }
    }

    #[test]
    fn parses_test_with_a_bind_address() {
        match parse(&["test", "--bind", "0.0.0.0"]) {
            Command::Test { bind, .. } => assert_eq!(bind, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            _ => panic!("expected Command::Test"),
        }
        assert!(Cli::try_parse_from(["frogs", "test", "--bind", "not-an-ip"]).is_err(), "--bind must be a real IpAddr");
    }

    #[test]
    fn parses_test_with_a_scenario() {
        match parse(&["test", "--scenario", "db-down"]) {
            Command::Test { scenario, .. } => assert_eq!(scenario, Some("db-down".to_string())),
            _ => panic!("expected Command::Test"),
        }
    }

    #[test]
    fn parses_test_with_a_json_report_and_its_file() {
        match parse(&["test", "--report", "json", "--report-file", "out/report.json"]) {
            Command::Test { report, report_file, .. } => {
                assert_eq!(report, ReportFormat::Json);
                assert_eq!(report_file, Some(PathBuf::from("out/report.json")));
            }
            _ => panic!("expected Command::Test"),
        }
        match parse(&["test", "--report", "junit", "--report-file", "junit.xml"]) {
            Command::Test { report, .. } => assert_eq!(report, ReportFormat::Junit),
            _ => panic!("expected Command::Test"),
        }
    }

    #[test]
    fn a_json_or_junit_report_without_a_report_file_is_a_parse_error() {
        assert!(Cli::try_parse_from(["frogs", "test", "--report", "json"]).is_err());
        assert!(Cli::try_parse_from(["frogs", "test", "--report", "junit"]).is_err());
    }

    #[test]
    fn a_text_report_file_is_optional() {
        match parse(&["test", "--report", "text"]) {
            Command::Test { report_file, .. } => assert_eq!(report_file, None),
            _ => panic!("expected Command::Test"),
        }
        match parse(&["test", "--report-file", "log.txt"]) {
            Command::Test { report, report_file, .. } => {
                assert_eq!(report, ReportFormat::Text);
                assert_eq!(report_file, Some(PathBuf::from("log.txt")));
            }
            _ => panic!("expected Command::Test"),
        }
    }

    #[test]
    fn an_unknown_report_format_is_a_parse_error() {
        assert!(Cli::try_parse_from(["frogs", "test", "--report", "yaml", "--report-file", "x"]).is_err());
    }

    #[test]
    fn parses_drivers_list() {
        assert!(matches!(parse(&["drivers", "list"]), Command::Drivers { action: DriversCommand::List }));
    }

    #[test]
    fn drivers_with_no_action_is_a_parse_error() {
        assert!(Cli::try_parse_from(["frogs", "drivers"]).is_err());
    }

    #[test]
    fn parses_validate() {
        assert!(matches!(parse(&["validate"]), Command::Validate));
    }

    #[test]
    fn an_unknown_subcommand_is_a_parse_error() {
        assert!(Cli::try_parse_from(["frogs", "bogus"]).is_err());
    }

    #[test]
    fn test_record_without_its_required_path_and_method_is_a_parse_error() {
        assert!(Cli::try_parse_from(["frogs", "test", "record"]).is_err());
    }

    #[test]
    fn errors_with_no_action_is_a_parse_error() {
        // Unlike `Test`, `Errors`'s `action` isn't `Option` — `frogs errors`
        // alone isn't a complete command, it needs `freeze`.
        assert!(Cli::try_parse_from(["frogs", "errors"]).is_err());
    }

    #[test]
    fn resolve_scope_defaults_to_user_when_neither_flag_is_set() {
        assert_eq!(resolve_scope(false, false), ServiceScope::User);
    }

    #[test]
    fn resolve_scope_is_user_when_user_is_explicitly_set() {
        assert_eq!(resolve_scope(true, false), ServiceScope::User);
    }

    #[test]
    fn resolve_scope_is_system_when_system_is_set() {
        assert_eq!(resolve_scope(false, true), ServiceScope::System);
    }
}
