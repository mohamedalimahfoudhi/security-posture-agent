"""
Migration 031: Architecture change detection events.

Run:
  python apply_031_architecture_changes.py
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


def table_exists(cur, name):
    cur.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=%s",
        (name,),
    )
    return cur.fetchone() is not None


def main():
    conn = get_connection()
    cur = conn.cursor()
    try:
        print("=== Migration 031: Architecture Changes ===")
        sql = read_sql("031_add_architecture_changes.sql")
        print("  Applying 031_add_architecture_changes.sql ...")
        cur.execute(sql)
        conn.commit()
        print("  Applied 031_add_architecture_changes.sql")

        found = table_exists(cur, 'architecture_changes')
        print(f"  architecture_changes table: {'OK' if found else 'MISSING'}")

        print("\nMigration 031 complete.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()