"""
Migration 008: Add hunting_guidance column to assessments table
Adds: hunting_guidance JSONB column for MITRE ATT&CK-based hunting guidance
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
        # Add hunting_guidance column
        cur.execute("""
            ALTER TABLE assessments 
            ADD COLUMN IF NOT EXISTS hunting_guidance JSONB
        """)
        print("Added hunting_guidance column")

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
