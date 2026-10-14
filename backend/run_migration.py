import sys
from app.database.connection import get_connection
import psycopg2

# Ensure stdout uses UTF-8 encoding on Windows (Python 3.7+)
# This prevents UnicodeEncodeError when printing emoji/special characters
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def run_migration():
    print("=" * 60)
    print("DATABASE MIGRATION - ARCHITECTURE INTELLIGENCE")
    print("=" * 60)
    
    conn = get_connection()
    cur = conn.cursor()
    
    # Log connection details
    print(f"\n📊 Database Connection Info:")
    print(f"  Database: {conn.info.dbname}")
    print(f"  User: {conn.info.user}")
    print(f"  Host: {conn.info.host}")
    print(f"  Port: {conn.info.port}")
    
    # Check current table structure
    print(f"\n🔍 Checking current table structure...")
    try:
        cur.execute("""
            SELECT tablename, tableowner 
            FROM pg_tables 
            WHERE schemaname = 'public'
            ORDER BY tablename;
        """)
        tables = cur.fetchall()
        print(f"  Current tables in public schema ({len(tables)}):")
        for table, owner in tables:
            print(f"    - {table} (owner: {owner})")
    except Exception as e:
        print(f"  Warning: Could not check existing tables: {e}")
    
    try:
        # Create documents table
        print(f"\n🔧 Creating documents table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                filename VARCHAR(255) NOT NULL,
                file_type VARCHAR(50) NOT NULL,
                file_size INTEGER NOT NULL,
                file_path VARCHAR(500) NOT NULL,
                upload_status VARCHAR(50) DEFAULT 'pending',
                extraction_status VARCHAR(50) DEFAULT 'pending',
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                error_message TEXT
            );
        """)
        print(f"  ✓ Documents table created")
        
        # Add missing columns to existing assets table
        print(f"\n🔧 Adding Architecture Intelligence columns to assets table...")
        
        columns_to_add = [
            ("document_id", "INTEGER REFERENCES documents(id)"),
            ("vendor", "VARCHAR(255)"),
            ("category", "VARCHAR(100)"),
            ("operating_system", "VARCHAR(255)"),
            ("database", "VARCHAR(255)"),
            ("cloud_provider", "VARCHAR(255)"),
            ("web_server", "VARCHAR(255)"),
            ("firewall", "VARCHAR(255)"),
            ("virtualization", "VARCHAR(255)"),
            ("programming_language", "VARCHAR(255)"),
            ("framework", "VARCHAR(255)"),
            ("security_tools", "VARCHAR(255)"),
            ("network_devices", "VARCHAR(255)"),
            ("confidence", "INTEGER DEFAULT 80"),
            ("extraction_metadata", "JSONB"),
            ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        ]
        
        for column_name, column_def in columns_to_add:
            try:
                cur.execute(f"ALTER TABLE assets ADD COLUMN IF NOT EXISTS {column_name} {column_def};")
                print(f"  ✓ Added column: {column_name}")
            except Exception as e:
                print(f"  ⚠ Could not add column {column_name}: {e}")
        
        # Create indexes only if columns exist
        print(f"\n🔧 Creating indexes...")
        
        # Check which columns exist before creating indexes
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'assets'
            AND table_schema = 'public'
        """)
        existing_columns = {row[0] for row in cur.fetchall()}
        
        # Assets table indexes
        assets_indexes = [
            ("idx_assets_customer", "customer_id"),
            ("idx_assets_technology", "technology"),
            ("idx_assets_vendor", "vendor"),
            ("idx_assets_document", "document_id")
        ]
        
        for index_name, column in assets_indexes:
            if column in existing_columns:
                try:
                    cur.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON assets({column});")
                    print(f"  ✓ Created index: {index_name} on assets({column})")
                except Exception as e:
                    print(f"  ⚠ Could not create index {index_name}: {e}")
            else:
                print(f"  ⊘ Skipped index {index_name} (column {column} does not exist)")
        
        # Documents table indexes
        documents_indexes = [
            ("idx_documents_customer", "customer_id"),
            ("idx_documents_status", "upload_status, extraction_status")
        ]
        
        for index_name, column in documents_indexes:
            try:
                cur.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON documents({column});")
                print(f"  ✓ Created index: {index_name} on documents({column})")
            except Exception as e:
                print(f"  ⚠ Could not create index {index_name}: {e}")
        
        # Create third_party_incidents table for ransomware/breach/incident disclosures
        print(f"\n🔧 Creating third_party_incidents table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS third_party_incidents (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                incident_type VARCHAR(50) NOT NULL
                    CHECK (incident_type IN ('ransomware', 'breach')),
                victim VARCHAR(255) NOT NULL,
                group_name VARCHAR(255),
                disclosure_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source_name VARCHAR(100) NOT NULL,
                source_url TEXT,
                raw_payload JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        print("  third_party_incidents table created")

        # Ensure NOT NULL + DEFAULT on disclosure_date (idempotent on existing table)
        cur.execute("""
            ALTER TABLE third_party_incidents
            ALTER COLUMN disclosure_date SET DEFAULT CURRENT_TIMESTAMP
        """)
        cur.execute("""
            ALTER TABLE third_party_incidents
            ALTER COLUMN disclosure_date SET NOT NULL
        """)

        # Drop old 3-value constraint if it exists, then recreate as 2-value
        # (safe to run on fresh DB where neither exists yet)
        cur.execute("""
            ALTER TABLE third_party_incidents
            DROP CONSTRAINT IF EXISTS third_party_incidents_incident_type_check
        """)
        cur.execute("""
            ALTER TABLE third_party_incidents
            ADD CONSTRAINT third_party_incidents_incident_type_check
            CHECK (incident_type IN ('ransomware', 'breach'))
        """)

        # Unique index to prevent duplicate ingestion runs from double-inserting
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_third_party_incidents_unique
            ON third_party_incidents (source_name, victim, disclosure_date)
        """)
        print("  Incident constraints and unique index ensured")

        print(f"\n🔧 Adding assessments linkage for third-party incidents...")
        cur.execute("""
            ALTER TABLE assessments
            ADD COLUMN IF NOT EXISTS third_party_incident_id INTEGER REFERENCES third_party_incidents(id);
        """)
        print(f"  ✓ Added assessments.third_party_incident_id")

        # Create trigger function
        print(f"\n🔧 Creating trigger function...")
        cur.execute("""
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)
        print(f"  ✓ Trigger function created")
        
        # Create trigger only if updated_at column exists
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'assets'
            AND column_name = 'updated_at'
        """)
        if cur.fetchone():
            print(f"\n🔧 Creating trigger...")
            cur.execute("""
                DROP TRIGGER IF EXISTS update_assets_updated_at ON assets;
                CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
                    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
            """)
            print(f"  ✓ Trigger created")
        else:
            print(f"\n⊘ Skipped trigger creation (updated_at column does not exist)")
        
        # Add escalation_recommendation column to alerts table if it doesn't exist
        print(f"\n🔧 Adding escalation_recommendation column to alerts table...")
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'alerts'
            AND column_name = 'escalation_recommendation'
        """)
        if not cur.fetchone():
            cur.execute("""
                ALTER TABLE alerts
                ADD COLUMN escalation_recommendation VARCHAR(50) DEFAULT 'MONITOR'
            """)
            print(f"  ✓ escalation_recommendation column added")
        else:
            print(f"  ⊘ escalation_recommendation column already exists")
        
        conn.commit()
        
        print(f"\n" + "=" * 60)
        print("✅ MIGRATION COMPLETED SUCCESSFULLY")
        print("=" * 60)
        
        # Verify table creation
        print(f"\n🔍 Verifying table structure...")
        cur.execute("""
            SELECT tablename, tableowner 
            FROM pg_tables 
            WHERE schemaname = 'public' 
            AND tablename IN ('documents', 'assets', 'third_party_incidents')
            ORDER BY tablename;
        """)
        new_tables = cur.fetchall()
        print(f"  Tables verified:")
        for table, owner in new_tables:
            print(f"    - {table} (owner: {owner})")
        
        # Verify assets columns
        cur.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'assets'
            AND table_schema = 'public'
            ORDER BY ordinal_position;
        """)
        asset_columns = cur.fetchall()
        print(f"\n  Assets table columns ({len(asset_columns)}):")
        for col_name, data_type in asset_columns:
            print(f"    - {col_name}: {data_type}")

        cur.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'third_party_incidents'
            AND table_schema = 'public'
            ORDER BY ordinal_position;
        """)
        incident_columns = cur.fetchall()
        print(f"\n  Third-party incidents table columns ({len(incident_columns)}):")
        for col_name, data_type in incident_columns:
            print(f"    - {col_name}: {data_type}")
        
    except psycopg2.errors.InsufficientPrivilege as e:
        conn.rollback()
        print(f"\n" + "=" * 60)
        print("❌ PERMISSION ERROR")
        print("=" * 60)
        print(f"\nError: {e}")
        print(f"\nThe database user '{conn.info.user}' does not have permission to CREATE tables.")
        print(f"\nTo fix this, run the following SQL as a database administrator (postgres):")
        print(f"\n-- Connect to the database as postgres user:")
        print("psql -h <DB_HOST> -p <DB_PORT> -U <ADMIN_USER> -d <DB_NAME>")
        print(f"\n-- Grant CREATE permission to cti_user:")
        print(f"GRANT USAGE ON SCHEMA public TO cti_user;")
        print(f"GRANT CREATE ON SCHEMA public TO cti_user;")
        print(f"\n-- If tables already exist with wrong owner, change ownership:")
        print(f"ALTER TABLE documents OWNER TO cti_user;")
        print(f"ALTER TABLE assets OWNER TO cti_user;")
        print(f"\n-- Then re-run the migration:")
        print(f"python run_migration.py")
        print(f"\n" + "=" * 60)
        raise
        
    except Exception as e:
        conn.rollback()
        print(f"\n" + "=" * 60)
        print("❌ MIGRATION FAILED")
        print("=" * 60)
        print(f"\nError: {e}")
        import traceback
        print(f"\nTraceback:")
        print(traceback.format_exc())
        print(f"\n" + "=" * 60)
        raise
        
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    run_migration()
