"""
Migration 029: Add profile intelligence columns to third_party_exposures.

Run:
  python apply_029_profile_intelligence.py
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
        print("=== Migration 029: Profile Intelligence on Exposures ===")
        sql = read_sql("029_add_profile_intelligence.sql")
        print("  Applying 029_add_profile_intelligence.sql ...")
        cur.execute(sql)
        conn.commit()
        print("  Applied 029_add_profile_intelligence.sql")

        # Verify
        for col in ('profile_id', 'affected_technology', 'evidence', 'recommended_action'):
            found = column_exists(cur, 'third_party_exposures', col)
            print(f"  third_party_exposures.{col}: {'OK' if found else 'MISSING'}")

        # Show final schema
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'third_party_exposures'
            ORDER BY ordinal_position
        """)
        cols = [r[0] for r in cur.fetchall()]
        print(f"\n  third_party_exposures columns ({len(cols)}):")
        print("  " + ", ".join(cols))
        print("\nMigration 029 complete.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()