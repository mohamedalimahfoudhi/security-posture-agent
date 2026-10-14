from app.database.connection import get_connection
import os
import sys

MIGRATION = os.path.join(os.path.dirname(__file__), "migrations", "014_chat_messages.sql")

if not os.path.exists(MIGRATION):
    print(f"Migration file not found: {MIGRATION}")
    sys.exit(1)

with open(MIGRATION, "r", encoding="utf-8") as f:
    sql = f.read()

conn = get_connection()
cur = conn.cursor()
try:
    print(f"Applying migration: {MIGRATION}")
    cur.execute(sql)
    conn.commit()
    print("Migration applied successfully")
except Exception as e:
    conn.rollback()
    print("Migration failed:")
    import traceback
    traceback.print_exc()
    sys.exit(2)
finally:
    cur.close()
    conn.close()

print("Done")