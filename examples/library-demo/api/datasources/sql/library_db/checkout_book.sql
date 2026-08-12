-- The due date is computed here, from the library's own settings row, at
-- the moment of checkout — frogs has no way to feed one source's result
-- into another source's parameters, so the settings lookup has to happen
-- inside this same script rather than as a separate resolved source.
--
-- strftime with an explicit '%Y-%m-%dT%H:%M:%SZ' format, not datetime() —
-- frogs' "date-time" response format expects real RFC 3339
-- (2024-01-01T00:00:00Z), and SQLite's own datetime() produces a
-- space-separated, timezone-less string that doesn't parse as one.
--
-- INSERT ... SELECT ... WHERE, not INSERT ... VALUES — the WHERE clause is
-- what lets this be conditional at all: a deleted book, a deleted member,
-- or a book that's already out (an open rental with no returned_at yet)
-- all make the SELECT produce zero rows, so nothing is inserted. Zero rows
-- from RETURNING is exactly what already makes a "one"-cardinality source
-- classify as not-found (404) elsewhere in this project — checkout reuses
-- that same behavior rather than needing a new error shape.
INSERT INTO rentals (book_id, member_id, checked_out_at, due_at)
SELECT
  :bookId,
  :memberId,
  strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
  strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+' || (SELECT rental_period_days FROM settings LIMIT 1) || ' days')
WHERE
  EXISTS (SELECT 1 FROM books WHERE id = :bookId AND deleted = 0)
  AND EXISTS (SELECT 1 FROM members WHERE id = :memberId AND deleted = 0)
  AND NOT EXISTS (SELECT 1 FROM rentals WHERE book_id = :bookId AND returned_at IS NULL)
RETURNING id, book_id, member_id, checked_out_at, due_at;
