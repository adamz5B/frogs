# frogs

**F**ree **R**ust **O**penAPI **G**enerated **S**erver — a config-driven API server. Give it an OpenAPI spec plus per-endpoint mapping files (SQL/HTTP "sources" mapped onto response fields), and it serves real traffic without hand-written handler code.

> **Status: early development.** From-scratch, work-in-progress — useful as a look at where the project is, not yet something to run in production.

## What it does

- **Cargo-style CLI** (`frogs generate|run|stop|register|unregister|test|errors|drivers|validate|help`) — a project's root is just wherever you put an `openapi.yaml` and/or a web asset file, found by walking up like `cargo` finds `Cargo.toml`.
- **`frogs generate`** turns `openapi.yaml` into stub + reference files per endpoint, with drift detection and backup-and-migrate on spec changes. Hand-edited stubs are never overwritten.
- **Spec hardening**: `openapi.yaml` is version-checked and its paths are validated at load (traversal, case-only collisions, Windows-unsafe names are skipped and reported, and `frogs generate` exits 1 if any were). Set `"strictOpenApi": true` in `config/server.json` (default `false`) to make those problems fatal in `generate`/`validate`/`run`/`test` instead. A service registered with `frogs register` whose spec has strict errors will restart every 5s under the default `--restart-policy on-failure`; use `--restart-policy never` or fix the spec. Symlinks/junctions under `datasources/endpoints/` are followed only when they stay inside the project by default; `"endpointSymlinks": "contained"|"refuse"|"follow"` in `config/server.json` changes that for reads (`generate` writes never leave the project). Regardless of `strictOpenApi`, `frogs run`/`test`/`register` refuse to start (before binding anything) when the endpoint folders can't form a valid route table (e.g. `{a}` and `{b}` siblings, a folder shadowing `/healthz`), or when a secured `openapi.yaml` operation would be served by an endpoint file that doesn't enforce its security; spec paths containing `:` or `*` (e.g. `/orders/{id}:cancel`) are skipped on every OS. An endpoint file that fails to load answers 503 `endpoint.unavailable` rather than falling through to a sibling route. Same-document `$ref`s to parameters, request bodies, 2xx responses and path items are followed; one that can't be resolved fails closed (reported, and start is refused where an endpoint file would otherwise be served unprotected) rather than being silently dropped. External-file `$ref`s are not supported.
- **Any HTTP method**: `QUERY` and OpenAPI 3.2 `additionalOperations` methods (e.g. `PURGE`) are served. Extension-method endpoint files use the method verbatim when it is uppercase letters, digits and `-` (`endpoint.PURGE.json`), otherwise `~`-encoded (`endpoint.~purge.json` for a case-sensitive `purge`).
- **Real SQL sources**: SQLite (always compiled in), Postgres (default), MySQL/MariaDB, MS SQL Server, and Oracle (all opt-in Cargo features), plus real HTTP sources with templating and auth.
- **Response formatting**, a stable **error envelope** classified against a merged `config/errors/*.json` registry, and **endpoint security** via `sql`/`http` verifiers. If `openapi.yaml` declares `security` for an operation but its endpoint file doesn't apply an acceptable scheme, `frogs run`/`test`/`register` refuse to start (always, regardless of `strictOpenApi`) and `validate`/`generate` report it as an error. A registered service that hits this restarts every 5s under the default `--restart-policy on-failure`; fix the endpoint file's `"security"` or use `--restart-policy never`.
- **Write operations** (POST/PUT/PATCH/DELETE) with body parameters and per-request transaction correlation.
- **A mock server for testing** (`*.test.json` / `frogs test`) that serves real HTTP from canned per-source mocks — request matching, scenario switching, and a pass/fail report — without touching real infrastructure.
- **Static-content serving** (`webserve.json`) that can run standalone or alongside the API in one process, mounted under a configurable `apiRoot`. frogs never serves its own files: `api/`, `openapi.yaml`, `webserve.json`, `.frogs/`, any dotfile or dot-folder, `_backups`, and configured TLS, log and SQLite files all answer 404.
- Operational basics: PID-file process management, `/healthz`/`/readyz`/`/metrics`, rate limiting, a service registry, and manual-cert HTTPS with optional mutual TLS (client-certificate auth, with static CRL revocation, authorized per route via `mtls` or `cert.*`-parameterized verifiers; CA/CRL changes need a restart).
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
