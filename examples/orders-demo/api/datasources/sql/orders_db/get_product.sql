SELECT sku, name, category, price, currency, description, in_stock
FROM products
WHERE sku = :sku;
