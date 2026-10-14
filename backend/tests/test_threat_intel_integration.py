import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import get_connection
from app.threat_intel.service import ThreatIntelService

client = TestClient(app)


def get_any_customer_id():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM customers ORDER BY id LIMIT 1;")
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise unittest.SkipTest("No customer records available for threat intel tests.")
    return row[0]


class ThreatIntelIntegrationTests(unittest.TestCase):
    def test_collect_threat_intel_endpoint(self):
        # This test assumes no authentication and simply verifies the endpoint exists.
        response = client.post("/api/threat-intel/collect")
        self.assertIn(response.status_code, (200, 401, 403))

    def test_read_threat_articles_endpoint(self):
        response = client.get("/api/threat-intel/articles?page=1&limit=5")
        self.assertEqual(response.status_code, 401)

    def test_correlate_threat_intel_endpoint(self):
        response = client.post("/api/threat-intel/correlate")
        self.assertIn(response.status_code, (200, 401, 403))

    def test_read_threat_correlations_endpoint(self):
        response = client.get("/api/threat-intel/correlations?page=1&limit=5")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
