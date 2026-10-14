"""
Migration 032: Third-party SOC alerts.

Run:
  python apply_032_third_party_alerts.py
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
        print("=== Migration 032: Third-Party Alerts ===")
        sql = read_sql("032_add_third_party_alerts.sql")
        print("  Applying 032_add_third_party_alerts.sql ...")
        cur.execute(sql)
        conn.commit()
        print("  Applied 032_add_third_party_alerts.sql")

        found = table_exists(cur, 'third_party_alerts')
        print(f"  third_party_alerts table: {'OK' if found else 'MISSING'}")

        print("\nMigration 032 complete.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()