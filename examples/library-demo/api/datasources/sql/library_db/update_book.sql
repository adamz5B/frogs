-- RETURNING only ever sees the modified table's own columns, not a JOIN —
-- so availability is a scalar subquery here instead of list_books.sql's
-- LEFT JOIN, same underlying rule either way: no open (unreturned) rental.
-- A deleted book can't be edited through this endpoint at all — same
-- "invisible outside the deleted list/restore" rule as get_book.sql.
UPDATE books
SET title = :title, author = :author, isbn = :isbn
WHERE id = :id AND deleted = 0
RETURNING
  id, title, author, isbn,
  (NOT EXISTS (SELECT 1 FROM rentals WHERE book_id = books.id AND returned_at IS NULL)) AS available,
  deleted;
