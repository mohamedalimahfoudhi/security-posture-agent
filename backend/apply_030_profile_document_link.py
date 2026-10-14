"""
Migration 030: Add architecture document link to third_party_profiles.

Run:
  python apply_030_profile_document_link.py
"""
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database.connection import get_connection

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
MIGRATIONS_DIR = os.path.join(BACKEND_DIR, "migrations")


def read_sql(filename):
    path = os.path.join(MIGRATIONS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Migration file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def column_exists(cur, table, col):
    cur.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
        (table, col),
    )
    return cur.fetchone() is not None


def main():
    conn = get_connection()
    cur = conn.cursor()
    try:
        print("=== Migration 030: Profile Document Link ===")
        sql = read_sql("030_add_profile_document_link.sql")
        print("  Applying 030_add_profile_document_link.sql ...")
        cur.execute(sql)
        conn.commit()
        print("  Applied 030_add_profile_document_link.sql")

        found = column_exists(cur, 'third_party_profiles', 'document_id')
        print(f"  third_party_profiles.document_id: {'OK' if found else 'MISSING'}")

        print("\nMigration 030 complete.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()