-- A book is "available" precisely when it has no open (not yet returned)
-- rental — computed here, not stored as a redundant flag, so it can never
-- drift out of sync with the rentals table itself. Soft-deleted books are
-- excluded — see delete_book.sql/list_deleted_books.sql.
SELECT
  b.id,
  b.title,
  b.author,
  b.isbn,
  (r.id IS NULL) AS available,
  b.deleted
FROM books b
LEFT JOIN rentals r ON r.book_id = b.id AND r.returned_at IS NULL
WHERE b.deleted = 0
ORDER BY b.title;
