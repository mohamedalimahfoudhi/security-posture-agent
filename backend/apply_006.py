import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from app.database.connection import get_connection
import os

MIGRATION = os.path.join(os.path.dirname(__file__), "migrations", "006_assessment_third_party_fields.sql")

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
    raise
finally:
    cur.close()
    conn.close()

print("Done")
