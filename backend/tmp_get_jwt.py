from app.database.connection import get_connection
from app.auth.security import create_access_token

conn = get_connection()
cur = conn.cursor()
cur.execute("SELECT id FROM users WHERE username='admin' LIMIT 1")
row = cur.fetchone()
cur.close()
conn.close()
user_id = row[0] if row else 1
print(create_access_token({"sub": str(user_id), "role": "Admin", "customer_id": 1}))
