import sys
sys.path.insert(0, 'backend')
from app.database.connection import get_connection

conn = get_connection()
cur = conn.cursor()

cur.execute("SELECT COUNT(*) FROM threat_articles")
total = cur.fetchone()[0]
print("Total threat_articles:", total)

cur.execute("SELECT MAX(published_date) FROM threat_articles")
max_pub = cur.fetchone()[0]
print("Max published_date:", max_pub)

cur.execute("SELECT MAX(created_at) FROM threat_articles")
max_created = cur.fetchone()[0]
print("Max created_at:", max_created)

cur.execute("SELECT source, COUNT(*), MAX(published_date) FROM threat_articles GROUP BY source ORDER BY source")
print("\nPer-source stats:")
for r in cur.fetchall():
    print("  ", r)

cur.execute("SELECT title, source, published_date, created_at FROM threat_articles ORDER BY published_date DESC NULLS LAST LIMIT 5")
print("\nNewest 5 by published_date:")
for r in cur.fetchall():
    print("  ", r)

cur.close()
conn.close()
print("\nDone")
