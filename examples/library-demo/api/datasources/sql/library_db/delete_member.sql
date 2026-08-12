-- Soft delete, same shape as delete_book.sql.
UPDATE members
SET deleted = 1
WHERE id = :id AND deleted = 0
RETURNING id, 1 AS deleted;
