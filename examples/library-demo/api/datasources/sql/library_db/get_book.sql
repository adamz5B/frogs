-- Same availability computation as list_books.sql, scoped to one row.
-- Excludes soft-deleted books, same as list_books.sql — a deleted book is
-- only reachable via GET /books/deleted.
SELECT
  b.id,
  b.title,
  b.author,
  b.isbn,
  (r.id IS NULL) AS available,
  b.deleted
FROM books b
LEFT JOIN rentals r ON r.book_id = b.id AND r.returned_at IS NULL
WHERE b.id = :id AND b.deleted = 0;
