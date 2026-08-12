# frogs

**F**ree **R**ust **O**penAPI **G**enerated **S**erver — a config-driven API server. Give it an OpenAPI spec plus per-endpoint mapping files (SQL/HTTP "sources" mapped onto response fields), and it serves real traffic without hand-written handler code.

> **Status: early development.** This is a from-scratch, work-in-progress implementation of the design in [`docs/`](docs/) — useful as a look at where the project is, not yet something to run in production. See [Current status](#current-status-vs-the-roadmap) below for exactly what works today.

## What it does today

- **Cargo-style CLI**, not a fixed-path server: frogs never writes `openapi.yaml` itself — there's no `init` step. You create it (or, for a static-content project with no API, at least one `.html` file) yourself, and every command finds the project root the same way `cargo` finds `Cargo.toml`, by walking up from the current directory looking for one of those.
- **`frogs generate`**: turns an `openapi.yaml` into stub + reference files under `api/datasources/` — full spec parsing, a recursive schema walk (`$ref`, `allOf`, `oneOf`/`anyOf`, arrays, cycle detection), hash-based drift detection with backup-and-migrate on schema changes, orphaned-endpoint handling (underscore-prefixed on removal, restored on reappearance), and `successStatus` validation against the spec's declared response codes. Hand-edited stubs are never overwritten, and every `api/config/`-side file (`server.json`, `connections.json`, `security/schemes.json`, `config/errors/core.json`) is scaffolded on first run too, not just endpoints. A project generates its API side, its static-content side, or both — `--role api`/`--role web` forces just one when both an `openapi.yaml` and a web asset file are found; with only one kind present, or no flag at all, whatever's actually there is generated.
- **Real SQL sources**, compile-time selectable: Postgres and SQLite today, each behind its own Cargo feature so a binary only carries the driver(s) it was built with.
- **Real HTTP sources**: `{{param}}` templating, bearer/apiKey/basic auth, `responsePath` envelope unwrapping.
- **Response formatting**: `integer`/`decimal`/`boolean`/`date-time`/`date`/`string` coercions with precision, source-format (`unix-seconds`/`unix-millis`/`rfc3339`), and trim/case options.
- **A real error envelope**: SQL/HTTP failures classify into stable string codes (e.g. `datasource.sql.not_found`), looked up in a directory-merged `config/errors/*.json` registry for their HTTP status and whether detail is safe to expose to a caller; `debugMode` always shows it.
- **Endpoint security**: a `security/schemes.json` scheme maps to a `sql`/`http` verifier (same datasource shape as a regular source) checked with a `validIf` equality expression, TTL-cached per credential, and enforced before a protected route's own sources ever run. `frogs generate` picks up an operation's `security:` from `openapi.yaml` and bakes it into a freshly generated stub automatically.
- **Write operations**: POST/PUT/PATCH/DELETE are routed the same way GET is, with `successStatus` applied to the real response. A source's `parameters` can pull from the request body (`body.<field>`, or bare `body` for the whole value), array-shaped body fields are passed straight through to SQL as JSON-encoded text or to an HTTP body's whole-value `"{{name}}"` form as real JSON, and `context.transactionId` gives every source in one request the same correlation ID for its own write auditing/coordination. A SQL write is just a function/procedure call returning a result set — same `response` mapping as any GET.
- **A mock-substitution testing framework**: `*.test.json` files declare requests, per-source mocks (a literal success value or a `{"fail": "<code>"}`), and expectations (with `$any`/`$type:<name>` matchers) against an endpoint without touching real infrastructure. `frogs test` runs every case and prints ✓/✗ per case; `frogs test record <path> <method>` runs one request for real and appends a new case with each source's actual returned value captured as its mock.
- **Static-content serving**: an explicit, hand-edited `webserve.json` names a start page, port, and optional 404 page; requests are served with safe path resolution (percent-decoded, `..` rejected outright, canonicalize-and-contain to catch a symlink escape), a small built-in MIME table, a custom 404 page, and basic HTTP caching (weak `ETag`/`Last-Modified` from file metadata, honoring `If-None-Match`/`If-Modified-Since` with real `304 Not Modified` responses). `webserve.json` itself is never served, no matter what path resolves to it.
- **API + static content from one process**: a project can serve both at once — API-side content always lives under a fixed `api/` subfolder (so a static site's own content only has to avoid one reserved name, not several), and `config/server.json`'s `apiRoot` field mounts the whole API under a URL prefix via a real router-level nest, so the two sides never collide on the same path even when merged behind one listener.
- **Process management**: `frogs stop` reads a PID file instead of you having to `kill`/`taskkill` it yourself; a second `frogs run` against an already-running project refuses to start instead of silently colliding. Works identically whether the project is API-only, static-content-only, or both merged into one process.
- **Structured logging & correlation IDs**: every request gets an `X-Request-Id` (reused if the caller sent one) tagging its log lines.
- **Operational endpoints**: `/healthz` always on; `/readyz` (feature-gated) pings every configured SQL connection and reports unready if any can't be reached, rather than just confirming the process is up; `/metrics` (feature-gated) exposes Prometheus-format request counts by status code and a request-latency histogram.
- **Error discovery, freeze, and a startup nudge**: in `debugMode`, an error code with no matching entry in `config/errors/` gets logged and recorded into a scratch file, `config/errors.discovered.json`, instead of silently falling back to `unexpected.error` unnoticed. `frogs run` warns at startup once that file passes `discoveredErrorsWarnThreshold` entries. `frogs errors freeze` batches the whole scratch file into a new, dated file under `config/errors/` (skipping — and reporting — any code already hand-classified there) and purges the scratch file, so acting on the warning is one command, not per-entry transcription.
- **Small binaries**: a size-tuned release profile plus per-driver feature flags keep a Postgres-only build around 3.7MB, SQLite-only around 3.2MB.

## Quickstart

```sh
cargo build --release
```

Try it against the bundled example (a small "cars" API backed by SQLite + a chained HTTP pricing lookup):

```sh
cd examples/cars-demo
../../target/release/frogs run
```

Or start a project of your own from scratch:

```sh
mkdir my-api && cd my-api
# ... write your own openapi.yaml here, then ...
frogs generate              # scaffolds api/config/, api/security/, and a stub per operation
# ... fill in each stub's sources/response mapping under api/datasources/endpoints/ (see docs/) ...
frogs run
frogs stop                  # from another terminal
```

Run `frogs help` any time for the current command list and project status.

## Building with specific SQL drivers

Drivers are selected at compile time via Cargo features, not bundled by default:

```sh
cargo build --release --features postgres        # default
cargo build --release --features sqlite
cargo build --release --features postgres,sqlite  # both in one binary
cargo build --release --no-default-features --features sqlite  # sqlite only, no postgres/TLS at all
```

A project's `connections.json` fails fast at startup — not on the first query — if it names a driver the binary wasn't built with.

## Building a standalone binary

```sh
cargo build-standalone
```

The default `cargo build --release` links the MSVC C runtime dynamically, so it depends on `VCRUNTIME140.dll` and a handful of `api-ms-win-crt-*.dll` forwarders being present on the target machine (normally satisfied by the Visual C++ Redistributable, which is very commonly already installed). `cargo build-standalone` statically links the CRT instead (`-C target-feature=+crt-static`), producing a `frogs.exe` with no such dependency — copy it to a bare machine and it runs. The trade-off: the binary is a little larger, and if you're running many instances on one host, they lose the memory-sharing benefit a system-wide CRT DLL would otherwise give them — so this is opt-in, not the default.

It builds to `target/standalone/release/frogs.exe`, a separate tree from `target/release/frogs.exe`, so both variants can exist side by side. The alias is defined in `.cargo/config.toml`.

## Project layout

```
src/
├── commands/     # generate, run, stop, test, errors (freeze), help — one file each
├── config/       # server.json / connections.json loading
├── errors/       # the directory-merged error registry + discovered-errors scratch file
├── endpoint/     # endpoint file parsing, source resolution, response formatting, error classification
├── http/         # outbound HTTP source execution
├── openapi/      # openapi.yaml parsing + the recursive schema walk generate builds stubs from
├── security/     # schemes/verifiers config, validIf parsing, verifier execution, TTL caching
├── sql/          # the SqlDriver trait + postgres/sqlite adapters
├── testing/      # *.test.json schema, mock substitution, $any/$type matching, memory/sequencing
├── webserve/     # webserve.json schema + static file serving (safe paths, MIME, caching)
├── server/       # the axum process skeleton (/healthz, correlation IDs, PID file)
└── project.rs    # project-root discovery (openapi.yaml, or an .html file, as the marker)
examples/
├── cars-demo/         # an API project — openapi.yaml at root, everything else under api/
├── library-demo/      # both roles at once — a real SQLite-backed API plus a static front end, one process
└── static-site-demo/  # a static-content project — no api/ at all, just webserve.json + assets
docs/                  # the full design spec and phased implementation roadmap
```

## Documentation

- [`docs/datasource-schema-design.md`](docs/datasource-schema-design.md) — the full config/schema design: directory layout, endpoint mapping format, error registry, OpenAPI-to-stub generation algorithm, plugin system, testing framework. This is the authoritative spec; the code aims to match it, and any deliberate deviation is called out in code comments where it happens.
- [`docs/implementation-roadmap.md`](docs/implementation-roadmap.md) — the phased build order this project follows.

## Current status vs. the roadmap

- **Phase 0 (Foundations): done**, plus extras beyond the original scope — the cargo-style CLI itself, `frogs stop`/PID-file process management, release binary-size tuning, and a standalone (static-CRT) build variant alongside the default.
- **Phase 1 (Minimal read path): mostly done.** Real SQL and HTTP source execution, `optional`/`onError` degradation, response formatting, and the `{code, name, detail}` error envelope all work end to end. Not yet done: request validation — which needs actual `openapi.yaml` *parsing* to exist first (that parsing now exists, built for Phase 2 below, but isn't yet wired into request handling).
- **Phase 2 (OpenAPI-driven generation): done**, including orphan handling (underscore-prefix on removal, forced re-migration on restoration), hash-based drift detection with backup-and-migrate, and `successStatus` validation against declared response codes. `frogs generate` turns an `openapi.yaml` into stub + reference files under `api/datasources/`.
- **Phase 3 (Security): done.** `security/schemes.json` + `security/verifiers/*.json` config loading (fails closed at startup on a missing/malformed verifier), `validIf` parsing and evaluation, verifier execution and route enforcement (a protected route rejects a missing/wrong credential and accepts a valid one), TTL-based verifier result caching, and `openapi.yaml` → `generate` wiring so a protected operation's scheme is baked into a freshly generated stub automatically.
- **Phase 4 (Write operations): done.** POST/PUT/PATCH/DELETE routing with `successStatus` applied to the real response, `body.*`/bare-`body` parameters, array-typed parameters (JSON-encoded for SQL, real JSON passthrough for an HTTP body's whole-value `"{{name}}"` form), and `context.transactionId` shared across every source in a request. Verified against a real, file-backed SQLite database with a genuine `INSERT ... RETURNING` — the row was still there after the server was stopped, read back by a separate process.
- **Phase 5 (Testing framework): done.** `*.test.json` schema, mock-substitution execution (a per-source literal value or a `{"fail": "<code>"}`), `$any`/`$type:<name>` expectation matching, the `frogs test` runner, request/response sequencing with per-file `memory` and save/transform steps, and `frogs test record` to capture a real request's actual per-source values as a new case's mocks.
- **Phase 6 (Web server / static-content serving): done.** Now a real phase in [`docs/implementation-roadmap.md`](docs/implementation-roadmap.md), not just an ad-hoc extension. A real `webserve.json` schema plus `generate --role api|web`; safe static file serving (percent-decoded paths, `..` rejected outright, canonicalize-and-contain against symlink escapes, a small built-in MIME table, a custom 404 page); basic HTTP caching (weak `ETag`/`Last-Modified`, real `304 Not Modified` responses honoring `If-None-Match`/`If-Modified-Since` with correct RFC 7232 precedence). A project can be an API, a static site, or **both from one process**: API-side content always lives under a fixed `api/` subfolder (so a static site's own content only has to avoid one reserved name, not several), `config/server.json`'s `apiRoot` field mounts the whole API under a URL prefix via a real router-level nest so both roles can coexist without colliding on the same paths, and `generate` now scaffolds every config file (`server.json`, `config/errors/core.json` with real working defaults; `connections.json`/`security/schemes.json` left empty, since only a human can supply real credentials or verifier logic) rather than just endpoint stubs. `frogs run`/`frogs stop` pick API-only, web-only, or both-merged-into-one-listener from what's on disk, with zero changes needed to `frogs stop` itself.
- **Phase 7** (deployment/operational polish): **in progress.** Done so far: `/metrics` and `/readyz`; the `discoveredErrorsWarnThreshold` startup notice, backed by real observe-time recording of unclassified error codes into `config/errors.discovered.json` (this didn't exist before Phase 7 — only the read side did); and `frogs errors freeze` to batch that scratch file into the canonical registry. Not yet done: rate limiting, the service registry (`config/services.json`), the driver matrix, and `frogs validate` as a standalone command.
- **Phase 8** (WASM plugins): postponed — the design needs another pass (`wasmtime` is a real, sizable dependency, worth reconsidering against this project's "small binaries" priority) before it's scheduled for real.

## A note on testing

Every feature above was verified by actually running the built binary — real SQLite files, a real chained SQL+HTTP endpoint with the HTTP dependency killed mid-test to confirm graceful degradation, two concurrent `frogs run` processes calling each other, a real static site served and cached correctly behind `frogs run`/`frogs stop`, a real SQL-backed API endpoint and a real static site served together from one `frogs run` process with the API correctly mounted under a custom `apiRoot`, a raw TCP request proving a path-traversal attempt is rejected server-side (not just by an HTTP client's own URL normalization) — not just unit tests. For a fake upstream HTTP dependency in a test, an in-memory-SQLite-backed `frogs run` instance with a literal `SELECT <value> AS <field>` script (no table, no seeding) works well as a zero-setup stand-in; see `src/sql/sqlite.rs`'s tests for the same idea as an actual unit test.

The mock-substitution testing framework (`frogs test`) is frogs' own equivalent for a *project built with frogs* — it exists precisely so a project's author doesn't need real infrastructure running to test their endpoints either.
