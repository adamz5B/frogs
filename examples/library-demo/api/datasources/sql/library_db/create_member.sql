INSERT INTO members (name, email)
VALUES (:name, :email)
RETURNING id, name, email, deleted;
