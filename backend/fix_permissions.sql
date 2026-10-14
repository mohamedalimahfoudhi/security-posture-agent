-- Historical PostgreSQL permission example for Architecture Intelligence.
-- Substitute the database name and role for your own environment.

-- Connect to the database:
-- psql -h <DB_HOST> -p <DB_PORT> -U <ADMIN_USER> -d <DB_NAME>

-- Grant CREATE permission to cti_user on public schema
GRANT USAGE ON SCHEMA public TO <APPLICATION_ROLE>;
GRANT CREATE ON SCHEMA public TO <APPLICATION_ROLE>;

-- Change ownership of existing tables that were created by postgres
ALTER TABLE assessments OWNER TO <APPLICATION_ROLE>;
ALTER TABLE assets OWNER TO <APPLICATION_ROLE>;

-- Verify permissions
SELECT tablename, tableowner 
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY tablename;

-- After running this, re-run the migration:
-- python run_migration.py
