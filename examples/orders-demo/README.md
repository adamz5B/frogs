# Orders demo — a heavier showcase than cars-demo

A small e-commerce backend — products, customers, and orders — built to exercise more of frogs at
once than cars-demo or library-demo do individually: mixed SQL/HTTP sources on one endpoint,
optional/`onError` degradation, `allowNestedMany` fan-out, security verifiers, an `allOf` schema
merge, and a properly worked-through `frogs test` suite with scenarios.

## Running it

```sh
cargo build   # sqlite is always compiled in — no --features flag needed
cd examples/orders-demo
../../target/debug/frogs run
```

`api/orders.db` is a pre-built, checked-in SQLite file. `build_db.py` (plain `python3`, stdlib
`sqlite3` only) rebuilds it from scratch at any time:

```sh
python build_db.py
```

Seeded with 5 products, 3 customers, and 3 orders in different statuses (`delivered`, `pending`,
`shipped`) — enough to see a nested items list, a cancellable order, and a 409-on-cancel in one
seed. `orders-demo-key` is the seeded active API key for the two protected endpoints
(`GET /customers/{id}`, `POST /orders/{id}/cancel`); `revoked-key` is seeded inactive to exercise
the 401 path.

Try the mock-server test suite instead of real infrastructure:

```sh
../../target/debug/frogs test
# in another terminal:
curl -H "X-Frogs-Scenario: services-down" http://localhost:8080/orders/1
```

## Where the interesting bits are

- **`GET /orders/{id}`** (`api/datasources/endpoints/orders/{id}/endpoint.get.json`) is the main
  showcase: `items` is a plain `cardinality: "many"` SQL source, `stock` fans out per row over it
  via `allowNestedMany` (one HTTP call per line item, bounded by `maxConcurrency`/`maxRows`/
  `rowTimeoutMs` — same mechanism as cars-demo's `by-maker`, just nested inside a single resource
  instead of driving a top-level list), and `payment` is a separate, ordinary optional HTTP source
  on the order itself. Both `stock` and `payment` degrade to `null` rather than failing the request
  when their upstream is unreachable — there's no real inventory/payment/loyalty service behind
  `*.example.com`, so a plain `frogs run` always exercises the degraded path; `frogs test` mocks
  them to exercise the happy path too.
- **`components.schemas.Order`** in `openapi.yaml` is `allOf: [OrderSummary, {...}]` — deliberately
  exercises `frogs generate`'s `SchemaWalker` merge path, which neither cars-demo nor library-demo's
  schemas use.
- **`create_order.sql`** takes the whole `items` array as one bind parameter (`SqlValue::Array`
  always binds as JSON text for SQLite) and unpacks it with `json_each()`/`->>` rather than issuing
  one call per line item — a CTE computes the priced subtotal and validates every SKU matched a
  product in the same statement, `INSERT ... SELECT ... WHERE` style, same "all failure reasons
  collapse to the same status" pattern as library-demo's `checkout_book.sql`. `create_order_items.sql`
  then inserts every line item in one more `json_each()`-driven statement, chained off
  `sources.order.id` (not the request body) so it only ever runs after the order really exists.
- **`cancel_order.sql`** reuses `get_order.sql` as a sibling "order" source first (a plain existence
  check, 404 if missing), then its own `UPDATE ... WHERE status = 'pending'` is bound to
  `sources.order.id` rather than `path.id` — guaranteeing existence is already confirmed — and
  declares its own `"onError": 409` override, so a zero-row update (order exists but already
  shipped) reports 409 instead of the registry's default 404 for a zero-row result.
- **`security/verifiers/apiKeyVerifier.json`** + `verify_api_key.sql` — same shape as cars-demo's.
  One SQLite-specific gotcha hit while wiring it up: `api_keys.active` must be declared `BOOLEAN` in
  the schema (not `INTEGER`), or the verifier's `"validIf": "row.active = true"` silently never
  matches — frogs' SQLite driver picks `SqlValue::Bool` vs `SqlValue::Int` from the column's
  *declared* type name (`src/sql/sqlite.rs`), and `validIf` compares that raw value, not through the
  `format: "boolean"` coercion a response mapping would apply. `products.in_stock` is plain
  `INTEGER` and works fine specifically because its endpoint mapping applies `"format": "boolean"`
  explicitly — that coercion happens at response-building time, not before.

## Two real frogs bugs/gotchas found building this (not specific to this demo)

1. **Never write a bind parameter's name with its colon attached inside a SQL comment.**
   `translate_named_params` (`src/sql/sqlite.rs`, and the equivalent in every other driver) does a
   raw text scan for `:name` with no awareness of `--` comments or string literals. An explanatory
   comment like `` -- `:items` arrives as a JSON array `` adds a phantom extra parameter occurrence
   that silently shifts every later positional bind. Hit this for real writing `create_order.sql`'s
   first draft: it landed the `items` JSON array into the `customer_id` column and surfaced as a
   confusing `FOREIGN KEY constraint failed` (409) instead of a successful insert, with no hint that
   the cause was a comment. `create_order.sql` now carries a `NOTE:` explaining this in place.
2. **`frogs test`'s no-real-infrastructure fill-in doesn't know about source dependencies.**
   `enforce_no_real_infrastructure` synthetically fails *every* `endpoint.sources` key a case didn't
   mock, unconditionally — and a source with *any* mock (real or synthetic) never even looks at its
   own dependencies (`resolve_one` only walks a source's parameter dependencies when it has no mock
   at all). So leaving a second non-optional sibling source unmocked in a "the first source fails"
   test case doesn't make it unreachable the way a real dependent request would — it just means
   *both* sources now have independent mocked failures, and depending on `HashMap` iteration order
   for that process, whichever one is reached first wins the response's status code. This bit
   `orders/{id}/endpoint.get.test.json`'s original "order not found" case (`items` was left unmocked
   and its synthetic `test.source_not_mocked` won the race, giving 501 instead of the intended 404)
   and `orders/{id}/cancel/endpoint.post.test.json`'s equivalent case. Fixed by giving every other
   non-optional sibling source a harmless *success* mock in every case, so it can never
   independently determine the response — see those two files' "order not found" cases, and
   `orders/endpoint.post.test.json`'s 404 case, for the pattern.

## `frogs test` scenario tags

Several cases need a `"scenario"` tag because their `request` block is otherwise identical to
another case in the same file (`testing::select` breaks ties in favor of the earlier-declared case,
so an untagged duplicate is simply unreachable — see `docs/frogs-test-mock-server.md`'s own
"Scenarios" section). Drive a tagged case with `X-Frogs-Scenario: <name>`:

| File | Scenario | What it exercises |
|---|---|---|
| `products/{sku}/endpoint.get.test.json` | `inventory-down` | optional HTTP source degrades to `null` |
| `customers/{id}/endpoint.get.test.json` | `loyalty-down` / `no-api-key` | optional degrade / verifier rejection |
| `orders/{id}/endpoint.get.test.json` | `services-down` / `too-many-items` | two optional sources both down / nested-many `maxRows` rejection degrading gracefully |
| `orders/{id}/cancel/endpoint.post.test.json` | `no-api-key` | verifier rejection |
