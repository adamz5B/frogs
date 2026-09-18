SELECT o.id, o.customer_id, c.name AS customer_name, o.status, o.subtotal, o.tax, o.total, o.currency, o.placed_at
FROM orders o
JOIN customers c ON c.id = o.customer_id
ORDER BY o.placed_at DESC;
