-- The reverse of delete_book.sql. `AND deleted = 1` guards the same way
-- delete's `AND deleted = 0` does: restoring something not currently
-- deleted (or nonexistent) affects zero rows, surfaced as 404.
UPDATE books
SET deleted = 0
WHERE id = :id AND deleted = 1
RETURNING
  id, title, author, isbn,
  (NOT EXISTS (SELECT 1 FROM rentals WHERE book_id = books.id AND returned_at IS NULL)) AS available,
  deleted;
