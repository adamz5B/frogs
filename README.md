# frogs

**F**ree **R**ust **O**penAPI **G**enerated **S**erver — a config-driven API server. Give it an OpenAPI spec plus per-endpoint mapping files (SQL/HTTP "sources" mapped onto response fields), and it serves real traffic without hand-written handler code.

> **Status: early development.** From-scratch, work-in-progress — useful as a look at where the project is, not yet something to run in production.

## What it does

- **Cargo-style CLI** (`frogs generate|run|stop|register|unregister|test|errors|drivers|validate|help`) — a project's root is just wherever you put an `openapi.yaml` and/or a web asset file, found by walking up like `cargo` finds `Cargo.toml`.
- **`frogs generate`** turns `openapi.yaml` into stub + reference files per endpoint, with drift detection and backup-and-migrate on spec changes. Hand-edited stubs are never overwritten.
- **Real SQL sources**: SQLite (always compiled in), Postgres (default), MySQL/MariaDB, MS SQL Server, and Oracle (all opt-in Cargo features), plus real HTTP sources with templating and auth.
- **Response formatting**, a stable **error envelope** classified against a merged `config/errors/*.json` registry, and **endpoint security** via `sql`/`http` verifiers.
- **Write operations** (POST/PUT/PATCH/DELETE) with body parameters and per-request transaction correlation.
- **A mock server for testing** (`*.test.json` / `frogs test`) that serves real HTTP from canned per-source mocks — request matching, scenario switching, and a pass/fail report — without touching real infrastructure.
- **Static-content serving** (`webserve.json`) that can run standalone or alongside the API in one process, mounted under a configurable `apiRoot`.
- Operational basics: PID-file process management, `/healthz`/`/readyz`/`/metrics`, rate limiting, a service registry, and manual-cert HTTPS.
- **`frogs register`/`frogs unregister`** installs (or removes) this project as a platform-native service — systemd on Linux, launchd on macOS, a real Windows Service on Windows — so it starts automatically at boot/login instead of needing an open terminal.

## Quickstart

```sh
cargo build --release
```

Try the bundled example (a small SQLite-backed "cars" API with a chained HTTP pricing lookup):

```sh
cd examples/cars-demo
../../target/release/frogs run
```

Or start your own project:

```sh
mkdir my-api && cd my-api
# ... write your own openapi.yaml, then ...
frogs generate      # scaffolds api/config/, api/security/, and a stub per operation
# ... fill in each stub's sources/response mapping under api/datasources/endpoints/ ...
frogs run
frogs stop          # from another terminal
```

Run `frogs help` any time for the current command list and project status.

## Building

```sh
cargo build --release                        # sqlite + postgres (the defaults)
cargo build --release --no-default-features  # sqlite only, no postgres/TLS
cargo build --release --features mysql       # add MySQL/MariaDB
cargo build --release --features mssql       # add MS SQL Server
cargo build --release --features oracle       # add Oracle
cargo build --release --all-features         # every driver
cargo build-standalone                       # statically-linked-CRT Windows build
```

A project's `connections.json` fails fast at startup if it names a driver the binary wasn't built with.

## Project layout

```
src/
├── commands/     # generate, run, stop, test, errors, drivers, validate, help
├── endpoint/     # endpoint parsing, source resolution, formatting, error classification
├── openapi/      # openapi.yaml parsing + the schema walk generate builds stubs from
├── security/     # schemes/verifiers, validIf parsing, TTL caching
├── sql/          # the SqlDriver trait + postgres/sqlite/mysql/mssql/oracle adapters
├── http/         # outbound HTTP source execution
├── testing/      # *.test.json schema, mock server (case selection, scenarios, report)
├── webserve/     # webserve.json schema + static file serving
├── server/       # the axum process skeleton (/healthz, correlation IDs, PID file)
└── project.rs    # project-root discovery
examples/
├── cars-demo/         # an API project
├── library-demo/      # both API and static roles, one process
└── static-site-demo/  # a static-content project only
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
