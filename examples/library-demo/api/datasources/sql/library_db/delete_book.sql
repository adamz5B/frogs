-- Soft delete: flips `deleted` rather than removing the row, so rental
-- history (and the row itself) is never lost — see restore_book.sql for
-- the reverse. `AND deleted = 0` makes this a no-op (zero rows, 404) on
-- something already deleted, same as it is on something that never
-- existed — the endpoint can't tell those two apart either way.
UPDATE books
SET deleted = 1
WHERE id = :id AND deleted = 0
RETURNING id, 1 AS deleted;
