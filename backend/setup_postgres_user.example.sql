-- PostgreSQL User Setup Example for Security Posture Agent
-- This is an example file. Copy it and customize for your environment.
--
-- Usage:
-- 1. Copy this file to setup_postgres_user.sql
-- 2. Replace <CHANGE_ME> with your desired password
-- 3. Run: psql -U postgres -f setup_postgres_user.sql
--
-- Connect to PostgreSQL as postgres user first:
--   psql -U postgres

-- 1. Create the application user if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ai_tip_user') THEN
        CREATE ROLE ai_tip_user WITH LOGIN PASSWORD '<CHANGE_ME>';
    END IF;
END
$$;

-- 2. Grant necessary permissions
-- Replace 'ai_tip' with your database name
GRANT CONNECT ON DATABASE ai_tip TO ai_tip_user;
GRANT USAGE ON SCHEMA public TO ai_tip_user;
GRANT CREATE ON SCHEMA public TO ai_tip_user;

-- 3. Grant permissions on existing tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ai_tip_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ai_tip_user;

-- 4. Set default permissions for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ai_tip_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ai_tip_user;

-- 5. Verify user was created
\du ai_tip_user

-- Exit psql
\q
