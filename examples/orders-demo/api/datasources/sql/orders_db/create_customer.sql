INSERT INTO customers (name, email, tier, created_at)
VALUES (:name, :email, 'bronze', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
RETURNING id, name, email, tier, created_at;
