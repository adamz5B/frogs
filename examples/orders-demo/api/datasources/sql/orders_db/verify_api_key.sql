SELECT active
FROM api_keys
WHERE key = :key
LIMIT 1;
