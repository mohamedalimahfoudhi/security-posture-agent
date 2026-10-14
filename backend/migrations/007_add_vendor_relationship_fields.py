"""
Migration 007: Add relationship fields to customer_vendors table
Adds: relationship_type, data_sensitivity, source_document_id, confidence, notes, created_at
"""

import psycopg2
import os

def migrate():
    conn = psycopg2.connect(
        dbname=os.getenv('DB_NAME', 'ai_tip'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD'),
        host=os.getenv('DB_HOST', 'localhost'),
        port=os.getenv('DB_PORT', '5432'),
        connect_timeout=10
    )
    cur = conn.cursor()

    try:
        # Add relationship_type column
        cur.execute("""
            ALTER TABLE customer_vendors 
            ADD COLUMN IF NOT EXISTS relationship_type VARCHAR(50)
        """)
        print("Added relationship_type column")

        # Add data_sensitivity column
        cur.execute("""
            ALTER TABLE customer_vendors 
            ADD COLUMN IF NOT EXISTS data_sensitivity VARCHAR(20)
        """)
        print("Added data_sensitivity column")

        # Add source_document_id column (nullable)
        cur.execute("""
            ALTER TABLE customer_vendors 
            ADD COLUMN IF NOT EXISTS source_document_id INTEGER
        """)
        print("Added source_document_id column")

        # Add confidence column
        cur.execute("""
            ALTER TABLE customer_vendors 
            ADD COLUMN IF NOT EXISTS confidence INTEGER
        """)
        print("Added confidence column")

        # Add notes column
        cur.execute("""
            ALTER TABLE customer_vendors 
            ADD COLUMN IF NOT EXISTS notes TEXT
        """)
        print("Added notes column")

        # Add created_at column
        cur.execute("""
            ALTER TABLE customer_vendors 
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
        """)
        print("Added created_at column")

        conn.commit()
        print("\nMigration completed successfully")

    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    migrate()
