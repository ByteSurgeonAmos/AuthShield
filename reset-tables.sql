-- Reset all tables to fix foreign key constraint issues
-- Run this script to drop all existing tables so TypeORM can recreate them properly

-- Drop all tables in the correct order (child tables first)
DROP TABLE IF EXISTS "Roles" CASCADE;

DROP TABLE IF EXISTS "other_user_details" CASCADE;

DROP TABLE IF EXISTS "security_questions" CASCADE;

DROP TABLE IF EXISTS "security_audit_log" CASCADE;

DROP TABLE IF EXISTS "auth_notifications" CASCADE;

DROP TABLE IF EXISTS "user_account" CASCADE;

-- Drop the uuid extension if it exists and recreate it
DROP EXTENSION IF EXISTS "uuid-ossp" CASCADE;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Note: After running this script, restart your NestJS application
-- TypeORM will automatically recreate all tables with the correct schema