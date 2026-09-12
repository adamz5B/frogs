# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's [private vulnerability reporting](https://github.com/adamz5B/frogs/security/advisories/new) for this repository (Security tab → "Report a vulnerability"). This opens a private advisory visible only to the maintainer until a fix is ready.

Include, where relevant:
- The affected version/commit.
- Steps to reproduce, or a minimal config that triggers the issue.
- The impact you believe it has (e.g. auth bypass, SQL injection, crash/DoS, information disclosure).

## Supported Versions

frogs is pre-1.0 and under active development. Security fixes are made against the `main` branch; there is no separate long-term-support branch at this stage.

## Scope

This project executes SQL and HTTP calls defined by project configuration files (`datasources/`, `security/`) and serves both API and static content over HTTP/HTTPS. Reports involving the core request pipeline, SQL driver adapters, endpoint security verifiers, or TLS handling are all in scope. Issues in a *user's own* project configuration (e.g. a hand-written SQL mapping with an injection flaw) are not a frogs vulnerability unless the server itself fails to apply the safety guarantees documented in the README/docs.
