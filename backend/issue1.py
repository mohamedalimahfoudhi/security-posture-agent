import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from app.database.connection import get_connection

conn = get_connection()
cur = conn.cursor()

print('--- BEFORE ---')
cur.execute("SELECT id, technology, vendor, version FROM assets WHERE vendor ~ '^[0-9.]+$'")
rows = cur.fetchall()
for r in rows:
    print(r)

print('--- UPDATING ---')
update_queries = [
    "UPDATE assets SET vendor = 'Jenkins Project', version = '2.375.1' WHERE technology = 'Jenkins' AND vendor = '2.375.1';",
    "UPDATE assets SET vendor = 'Snort/Sourcefire', version = '3.1' WHERE technology = 'Snort' AND vendor = '3.1';",
    "UPDATE assets SET vendor = 'SonarSource', version = '9.4' WHERE technology = 'SonarQube' AND vendor = '9.4';"
]

for q in update_queries:
    cur.execute(q)
    print(q)
conn.commit()

print('--- AFTER (numeric vendors) ---')
cur.execute("SELECT id, technology, vendor, version FROM assets WHERE vendor ~ '^[0-9.]+$'")
print(cur.fetchall())

print('--- AFTER (corrected rows) ---')
cur.execute("SELECT id, technology, vendor, version FROM assets WHERE technology IN ('Jenkins', 'Snort', 'SonarQube')")
for r in cur.fetchall():
    print(r)

cur.close()
conn.close()
