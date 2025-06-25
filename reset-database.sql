-- WARNING: This will delete ALL data in your database
-- Only use this in development environment

-- Drop all tables in correct order (respecting foreign keys)
DROP TABLE IF EXISTS security_questions CASCADE;

DROP TABLE IF EXISTS auth_notifications CASCADE;

DROP TABLE IF EXISTS security_audit_logs CASCADE;

DROP TABLE IF EXISTS user_details CASCADE;

DROP TABLE IF EXISTS user_roles CASCADE;

DROP TABLE IF EXISTS user_account CASCADE;

-- Drop trigger function if exists
DROP FUNCTION IF EXISTS trigger_set_timestamp () CASCADE;

SELECT 'ALTER TABLE "' || relname || '" DROP CONSTRAINT "' || conname || '";' AS drop_sql
FROM pg_constraint
    JOIN pg_class ON pg_class.oid = pg_constraint.conrelid
WHERE
    conrelid = 'user_account'::regclass
    OR confrelid = 'user_account'::regclass;

ALTER TABLE user_account DROP CONSTRAINT user_account_pkey CASCADE;

SELECT * FROM user_account WHERE user_id IS NULL;

UPDATE user_account
SET
    user_id = gen_random_uuid () -- or another valid value
WHERE
    user_id IS NULL;