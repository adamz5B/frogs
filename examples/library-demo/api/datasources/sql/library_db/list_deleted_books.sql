-- `available` is always false here — a deleted book can't be checked out
-- regardless of its rental history, so there's nothing to compute.
SELECT id, title, author, isbn, 0 AS available, deleted
FROM books
WHERE deleted = 1
ORDER BY title;
