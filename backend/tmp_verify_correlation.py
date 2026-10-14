from app.database.connection import get_connection

conn = get_connection()
cur = conn.cursor()
cur.execute(
    "SELECT article_id, customer_id, asset_id, match_type, matched_value, risk_score, severity, confidence, reason, recommendation FROM threat_correlations ORDER BY created_at DESC LIMIT 20"
)
rows = cur.fetchall()
for row in rows:
    print(row)
cur.close()
conn.close()
