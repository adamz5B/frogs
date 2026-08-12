# Library demo — API and web content, one process

A very small library management system — books, members, and a rental registry, plus a settings
row (rental period, librarian credentials) — served from **one `frogs run` process** alongside a
static front-desk web UI that drives the API live via `fetch()`. This is the Phase 6 "both roles at
once" feature end to end, not just side by side:

- `openapi.yaml` + `api/` (config, SQL scripts, endpoint mappings) — the API side.
- `index.html` + `css/`/`js/` + `webserve.json` — the static side.
- `config/server.json`'s `apiRoot: "/api"` mounts the whole API under that prefix via a real
  `Router::nest`, so the front-desk page's own `fetch("/api/...")` calls are same-origin — no CORS,
  no separate port.

## Running it

```sh
cargo build --features sqlite
cd examples/library-demo
../../target/debug/frogs run
```

Open http://localhost:8080 — the front desk lists books/members/rentals (fetched from the
co-hosted API), and lets you:

- Check a book out or return one (`POST /api/rentals`, `POST /api/rentals/{id}/return`).
- Add, edit, soft-delete, or restore a book or member (full CRUD — `GET`/`POST`/`PUT`/`DELETE` on
  `/api/books` and `/api/members`, plus `GET /api/books/deleted` and `POST /api/books/{id}/restore`,
  same for members). Deleting never removes a row — it flips a `deleted` flag, and a deleted
  book/member is invisible to normal listing/checkout but always restorable.
- Search **Open Library** by title when adding a book (`GET /api/books/lookup?title=...` — a real
  external API, no key needed) and click a result to prefill the add-book form instead of typing
  the author/ISBN by hand.

`GET /api/healthz` also lives under the same prefix.

Stop it from another terminal:

```sh
../../target/debug/frogs stop
```

## The data

`api/library.db` is a pre-built, checked-in SQLite file — no setup step. `build_db.py` (needs a
plain `python3`/Python 3 with the stdlib `sqlite3` module — nothing else) is what built it and can
rebuild it from scratch at any time, e.g. after playing with checkouts/returns for a while:

```sh
python build_db.py
```

Seeded with 6 books, 3 members, one active rental (Dune, due in the future) and one already-returned
rental (Foundation) — enough to see both an unavailable book and rental history on first load.

## Where the interesting bits are

- **`api/config/server.json`**'s `apiRoot` — the URL-prefix half of both-role coexistence.
- **`api/datasources/sql/library_db/checkout_book.sql`** — computes the due date from the
  `settings` table *inside the SQL script itself* (`strftime('now', '+' || (SELECT
  rental_period_days FROM settings...) || ' days')`), since frogs has no way to feed one source's
  result into another source's parameters.
- **`api/datasources/sql/library_db/list_books.sql`** — a book's `available` flag is computed via
  `LEFT JOIN ... WHERE returned_at IS NULL`, not stored — it can never drift out of sync with the
  rentals table.
- **`api/datasources/endpoints/books/endpoint.get.json`** — a `cardinality: "many"` SQL source
  mapped to a top-level array response (`{"type": "array", "source": "sources.books", "items":
  {...}}`). Multi-row responses like this only work as of this example being built — see the
  project's own history for why.
- Every SQL script that produces a timestamp uses `strftime('%Y-%m-%dT%H:%M:%SZ', ...)`, not
  `datetime(...)` — frogs' `"format": "date-time"` response mapping expects genuine RFC 3339, and
  SQLite's own `datetime()` doesn't produce that.
- **Soft delete, not hard delete.** `delete_book.sql`/`delete_member.sql` are an `UPDATE ... SET
  deleted = 1`, never a real `DELETE` — a row is never actually removed, so there's no foreign-key
  risk to guard against in the first place (frogs' SQLite driver doesn't turn on `PRAGMA
  foreign_keys` anyway, so a real `DELETE` would have needed its own explicit guard against
  orphaning rental rows). `restore_book.sql`/`restore_member.sql` just flip it back.
  `list_books.sql`/`get_book.sql`/`update_book.sql` all filter `deleted = 0`, so a deleted row is
  invisible to normal use and only reachable via `GET /books/deleted`.
- **`checkout_book.sql`** is an `INSERT ... SELECT ... WHERE`, not `INSERT ... VALUES` — the `WHERE`
  is what makes it conditional at all: it blocks checkout if the book or member is deleted, or the
  book already has an open (unreturned) rental. Zero rows matching means nothing is inserted, and
  `RETURNING` naturally produces nothing — which a `"one"`-cardinality source already classifies as
  404, so checkout's three different failure reasons all collapse into the same status without
  needing a new error shape.
- **`api/datasources/endpoints/books/lookup/endpoint.get.json`** — an HTTP source hitting Open
  Library's free, keyless search API, with `"responsePath": "docs"` unwrapping straight to the
  results array and `"cardinality": "one"` (HTTP `"many"` isn't supported — see the SQL note above)
  used precisely *because* the already-unwrapped array becomes that one source's whole resolved
  value, which the endpoint's top-level array response then maps over like any other list.

## A deliberate simplification

The librarian login/password in `GET /api/settings` are plain data fields, not a real security
scheme — this example is about API+web coexistence, not re-demonstrating the (already-built)
security feature. Don't copy the plaintext-password-in-a-response pattern into anything real.