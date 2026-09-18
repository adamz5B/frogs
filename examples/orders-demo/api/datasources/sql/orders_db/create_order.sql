-- The items parameter arrives as a JSON array (frogs' SqlValue::Array always
-- binds as JSON text, see src/sql/sqlite.rs), so it's parsed with
-- json_each()/`->>` rather than needing a separate call per line item.
--
-- NOTE: never spell out a bind parameter's name with its colon prefix
-- attached inside a SQL comment — frogs' own SQLite param translator does a
-- raw text scan with no awareness of `--` comments, so a colon directly
-- followed by a parameter name in a comment reads as a phantom extra
-- parameter occurrence and silently shifts every later positional bind.
-- Hit this for real while building this example: it landed the items JSON
-- array into the customer_id column and surfaced as a confusing FK
-- constraint violation instead of a successful insert.
--
-- INSERT ... SELECT ... WHERE, not INSERT ... VALUES — same pattern as
-- checkout_book.sql in library-demo. The WHERE clause makes the insert
-- conditional: an unknown customer, an empty items array, or any item whose
-- sku doesn't match a product all make `totals` fail the check, so zero
-- rows are inserted and RETURNING produces nothing — which a "one"
-- cardinality source already classifies as 404, so all three failure
-- reasons collapse into the same status without a new error shape.
WITH parsed AS (
  SELECT
    je.value ->> '$.sku' AS sku,
    CAST(je.value ->> '$.quantity' AS INTEGER) AS quantity
  FROM json_each(:items) je
),
priced AS (
  SELECT p.sku, p.price, p.currency, parsed.quantity, ROUND(p.price * parsed.quantity, 2) AS line_total
  FROM parsed
  JOIN products p ON p.sku = parsed.sku
),
totals AS (
  SELECT
    COALESCE(SUM(line_total), 0) AS subtotal,
    MIN(currency) AS currency,
    COUNT(*) AS matched,
    (SELECT COUNT(*) FROM parsed) AS requested
  FROM priced
)
INSERT INTO orders (customer_id, status, subtotal, tax, total, currency, placed_at)
SELECT
  :customerId,
  'pending',
  totals.subtotal,
  ROUND(totals.subtotal * 0.08, 2),
  ROUND(totals.subtotal * 1.08, 2),
  COALESCE(totals.currency, 'USD'),
  strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
FROM totals
WHERE EXISTS (SELECT 1 FROM customers WHERE id = :customerId)
  AND totals.requested > 0
  AND totals.matched = totals.requested
RETURNING
  id,
  customer_id,
  (SELECT name FROM customers WHERE customers.id = orders.customer_id) AS customer_name,
  status,
  subtotal,
  tax,
  total,
  currency,
  placed_at;
