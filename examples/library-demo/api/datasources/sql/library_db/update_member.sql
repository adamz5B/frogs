UPDATE members
SET name = :name, email = :email
WHERE id = :id AND deleted = 0
RETURNING id, name, email, deleted;
