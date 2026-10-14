"""Insert test assets for assessment variability testing"""
import sys
sys.path.insert(0, r'C:\Users\mahfo\Projects\third-party-cyber-posture-agent\backend')

from app.database.connection import get_connection
import psycopg2.extras

conn = get_connection()
cur = conn.cursor()

# Insert test assets for Apache HTTP Server, PostgreSQL, and OpenSSL
test_assets = [
    {
        'customer_id': 1,
        'document_id': 115,
        'technology': 'Apache HTTP Server',
        'vendor': 'Apache Software Foundation',
        'version': '2.4.49',
        'category': 'web_server',
        'criticality': 'HIGH',
        'confidence': 95
    },
    {
        'customer_id': 1,
        'document_id': 115,
        'technology': 'PostgreSQL',
        'vendor': 'PostgreSQL Global Development Group',
        'version': '15.2',
        'category': 'database',
        'criticality': 'MEDIUM',
        'confidence': 80
    },
    {
        'customer_id': 1,
        'document_id': 115,
        'technology': 'OpenSSL',
        'vendor': 'The OpenSSL Project',
        'version': '3.0.2',
        'category': 'security_tool',
        'criticality': 'HIGH',
        'confidence': 90
    }
]

for asset in test_assets:
    try:
        cur.execute("""
            INSERT INTO assets
            (customer_id, document_id, technology, vendor, version,
             criticality, internet_exposed, sensitive_data, category,
             operating_system, database, cloud_provider, web_server,
             firewall, virtualization, programming_language, framework,
             security_tools, network_devices, confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s)
        """, (
            asset['customer_id'],
            asset['document_id'],
            asset['technology'],
            asset['vendor'],
            asset['version'],
            asset['criticality'],
            False,
            False,
            asset['category'],
            None, None, None, None, None, None, None, None, None, None,
            asset['confidence']
        ))
        print(f"Inserted: {asset['technology']} ({asset['vendor']})")
    except Exception as e:
        print(f"Failed to insert {asset['technology']}: {e}")

conn.commit()
cur.close()
conn.close()
print("Test assets inserted successfully")
