-- The `returned_at IS NULL` guard means returning an already-returned (or
-- nonexistent) rental affects zero rows rather than clobbering a real
-- return timestamp — RETURNING then yields no row, which the endpoint's
-- "one" cardinality surfaces as a not-found-style failure.
--
-- strftime, not datetime() — see checkout_book.sql for why: frogs' own
-- "date-time" format needs real RFC 3339, not SQLite's default rendering.
UPDATE rentals
SET returned_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE id = :id AND returned_at IS NULL
RETURNING id, book_id, member_id, checked_out_at, due_at, returned_at;
