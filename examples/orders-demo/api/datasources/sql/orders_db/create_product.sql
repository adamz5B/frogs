-- A duplicate sku value hits products.sku's PRIMARY KEY and fails with SQLite's
-- own constraint error, which frogs classifies as
-- datasource.sql.constraint_violation (409) — no hand-written duplicate
-- check needed here.
INSERT INTO products (sku, name, category, price, currency, description, in_stock)
VALUES (:sku, :name, :category, :price, :currency, :description, 1)
RETURNING sku, name, category, price, currency, description, in_stock;
