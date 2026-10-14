from app.database.connection import get_connection

conn = get_connection()
cur = conn.cursor()
cur.execute("SELECT id, customer_id, technology, vendor, version, internet_exposed, criticality FROM assets WHERE lower(vendor) LIKE '%fortinet%' OR lower(technology) LIKE '%forti%' LIMIT 20")
assets = cur.fetchall()
print('fortinet_assets', assets)
cur.execute("SELECT id, title, vendors, products, cves, severity FROM threat_articles WHERE processed=true AND (lower(vendors::text) LIKE '%fortinet%' OR lower(products::text) LIKE '%forti%' OR lower(cves::text) LIKE '%cve-2024-21762%') LIMIT 20")
rows = cur.fetchall()
print('fortinet_threat_articles', rows)
cur.close()
conn.close()
