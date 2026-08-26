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

use clap::{Parser, Subcommand};

use commands::generate::Role;

#[derive(Parser)]
#[command(
    name = "frogs",
    version,
    about = "Free Rust OpenAPI Generated Server",
    disable_help_subcommand = true
)]
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
    Run,
    /// Stop the running server for the current project
    Stop,
    /// Run every *.test.json file's cases against the mock-substitution
    /// framework
    Test {
        #[command(subcommand)]
        action: Option<TestCommand>,
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

#[tokio::main]
async fn main() {
    // Must happen before any TLS operation (an HTTPS `frogs run`, or any
    // outbound `reqwest`/`sqlx` TLS connection) — see the doc comment on
    // this dependency in Cargo.toml for why rustls needs this told to it
    // explicitly rather than picking a default on its own.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("installing the process-wide rustls crypto provider should only ever be attempted once");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cwd = std::env::current_dir().expect("failed to read current directory");

    let result = match cli.command {
        Command::Generate { role } => commands::generate::run(&cwd, role),
        Command::Run => commands::run::run(&cwd).await,
        Command::Stop => commands::stop::run(&cwd),
        Command::Test { action: None } => commands::test::run(&cwd).await,
        Command::Test { action: Some(TestCommand::Record { path, method }) } => {
            commands::test::record(&cwd, &path, &method).await
        }
        Command::Errors { action: ErrorsCommand::Freeze } => commands::errors::freeze(&cwd),
        Command::Drivers { action: DriversCommand::List } => commands::drivers::list(),
        Command::Validate => commands::validate::run(&cwd).await,
        Command::Help => commands::help::run(&cwd),
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
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
        assert!(matches!(parse(&["run"]), Command::Run));
    }

    #[test]
    fn parses_stop() {
        assert!(matches!(parse(&["stop"]), Command::Stop));
    }

    #[test]
    fn parses_help() {
        assert!(matches!(parse(&["help"]), Command::Help));
    }

    #[test]
    fn parses_test_with_no_subcommand() {
        assert!(matches!(parse(&["test"]), Command::Test { action: None }));
    }

    #[test]
    fn parses_test_record_with_its_path_and_method() {
        match parse(&["test", "record", "/cars/1HGCM82633A004352", "get"]) {
            Command::Test { action: Some(TestCommand::Record { path, method }) } => {
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
}