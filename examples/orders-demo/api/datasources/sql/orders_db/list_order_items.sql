SELECT sku, name, quantity, unit_price, line_total
FROM order_items
WHERE order_id = :id
ORDER BY id;
