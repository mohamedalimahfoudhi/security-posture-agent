import sys
sys.path.insert(0, '.')
from app.database.connection import get_connection

conn = get_connection()
cur = conn.cursor()
cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='threat_articles' ORDER BY ordinal_position")
rows = cur.fetchall()
cur.close()
conn.close()
print('THREAT_ARTICLES COLUMNS:')
for name, dtype in rows:
    print(f'{name}: {dtype}')
