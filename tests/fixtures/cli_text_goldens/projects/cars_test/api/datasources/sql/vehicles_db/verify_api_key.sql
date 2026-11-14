-- verify_api_key.sql
SELECT active
FROM api_keys
WHERE key = :key
LIMIT 1;
