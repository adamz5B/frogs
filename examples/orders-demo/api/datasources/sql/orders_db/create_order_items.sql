-- The orderId parameter is bound from `sources.order.id` (see
-- orders/endpoint.post.json), not from the request body — that dependency is what guarantees this only
-- ever runs after create_order.sql has actually inserted a row.
INSERT INTO order_items (order_id, sku, name, quantity, unit_price, line_total)
SELECT
  :orderId,
  p.sku,
  p.name,
  parsed.quantity,
  p.price,
  ROUND(p.price * parsed.quantity, 2)
FROM (
  SELECT
    je.value ->> '$.sku' AS sku,
    CAST(je.value ->> '$.quantity' AS INTEGER) AS quantity
  FROM json_each(:items) je
) parsed
JOIN products p ON p.sku = parsed.sku
RETURNING sku, name, quantity, unit_price, line_total;
