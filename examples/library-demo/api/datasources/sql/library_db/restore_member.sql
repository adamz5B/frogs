UPDATE members
SET deleted = 0
WHERE id = :id AND deleted = 1
RETURNING id, name, email, deleted;
