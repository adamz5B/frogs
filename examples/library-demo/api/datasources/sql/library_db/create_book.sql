-- A brand-new book has no rental history yet, so it's always available —
-- no need for list_books.sql's LEFT JOIN just to prove that. `deleted`
-- defaults to 0 via the schema, but RETURNING it explicitly keeps the
-- response shape self-documenting rather than relying on the caller to
-- know the column default.
INSERT INTO books (title, author, isbn)
VALUES (:title, :author, :isbn)
RETURNING id, title, author, isbn, 1 AS available, deleted;
