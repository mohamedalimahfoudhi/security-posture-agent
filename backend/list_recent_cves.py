from app.database.connection import get_connection
conn = get_connection()
cur = conn.cursor()
cur.execute("SELECT id, cve_id, title, severity, published_date FROM cve_events ORDER BY id DESC LIMIT 10")
rows = cur.fetchall()
print('RECENT_CVES:', len(rows))
for r in rows:
    print(r)
cur.close(); conn.close()
