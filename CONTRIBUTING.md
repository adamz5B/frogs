# Contributing to frogs

frogs is early-development, from-scratch work — see the README for what's built vs. still pending. Contributions are welcome, but given the project's stage, please open an issue to discuss any non-trivial change (new SQL driver, new CLI command, config-format change) before writing code, so it doesn't go to waste.

## Before opening a PR

```sh
cargo build --release
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt
```

All of the above run in CI (`.github/workflows/ci.yml`) on Linux, Windows, and macOS; `clippy` is blocking, `fmt` is currently advisory. Live-database tests (Postgres/MySQL/MSSQL/Oracle) are `#[ignore]`d and only run in CI's dedicated integration jobs — you don't need a local instance of each to contribute, but if you touch a driver adapter, note in the PR which live tests you were and weren't able to run locally.

## Style

- `rustfmt.toml` sets `max_width = 170` to match this codebase's verbose, descriptive-identifier style — don't fight it.
- Prefer clear, self-documenting identifiers over comments; only comment on the *why* (a non-obvious constraint, a workaround, a subtle invariant), not the *what*.
- Keep PRs focused — one change per PR is easier to review than a bundle of unrelated fixes.

## Reporting bugs / requesting features

Use the issue templates. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of opening a public issue.
