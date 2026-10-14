import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import get_connection
from app.risk.vulnerability_applicability import assess_vulnerability_applicability
from app.correlation.asset_cve_matcher import get_assets as get_assets_from_db

client = TestClient(app)


def get_any_customer_id():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM customers ORDER BY id LIMIT 1;")
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise unittest.SkipTest("No customer records available for alert tests.")
    return row[0]


def delete_test_alert(alert_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts WHERE id = %s;", (alert_id,))
    conn.commit()
    cur.close()
    conn.close()


class AlertWritePathTests(unittest.TestCase):
    def test_save_applicability_alert_and_verify_fields(self):
        customer_id = get_any_customer_id()
        # Load real assets from the DB for this customer (tests the real SELECT)
        raw_assets = get_assets_from_db(customer_id)
        # raw_assets are tuples: (id, technology, version, criticality, internet_exposed, sensitive_data, vendor)
        assets = []
        for row in raw_assets:
            if not row:
                continue
            asset_id, technology, version, criticality, internet_exposed, sensitive_data, vendor = row
            assets.append({
                "id": asset_id,
                "technology": technology,
                "vendor": vendor,
                "version": version,
                "criticality": criticality,
                "internet_exposed": internet_exposed,
                "sensitive_data": sensitive_data,
            })

        vuln_title = "nginx security vulnerability CVE-XXXX-YYYY"

        result = assess_vulnerability_applicability(customer_id, vuln_title, assets)

        # The pipeline returns 'alert' containing stored alert info
        alert = result.get("alert")
        self.assertIsNotNone(alert, "Pipeline did not return an alert object")

        alert_id = alert.get("id") or alert.get("stored_alert_id")
        self.assertIsNotNone(alert_id, "Stored alert id not returned")

        from app.auth.security import create_access_token
        token = create_access_token(data={"sub": "1", "role": "Admin", "customer_id": customer_id})
        headers = {"Authorization": f"Bearer {token}"}

        # Fetch via API
        response = client.get(f"/api/alerts/{alert_id}", headers=headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()


        # Assertions required by you: confidence_score non-null int, evidence non-empty list,
        # business_impact and recommendation non-null strings.
        self.assertIn("confidence_score", payload)
        self.assertIsInstance(payload["confidence_score"], int)
        self.assertGreaterEqual(payload["confidence_score"], 0)

        self.assertIn("analysis", payload)
        evidence = payload["analysis"].get("evidence")
        self.assertIsNotNone(evidence)
        self.assertIsInstance(evidence, list)
        self.assertGreater(len(evidence), 0, "Evidence array is empty")

        self.assertIn("analysis", payload)
        business = payload["analysis"].get("business_impact")
        self.assertIsNotNone(business)
        self.assertIsInstance(business, str)
        self.assertGreater(len(business.strip()), 0)

        self.assertIn("recommendation", payload)
        rec = payload.get("recommendation")
        self.assertIsNotNone(rec)
        self.assertIsInstance(rec, str)
        self.assertGreater(len(rec.strip()), 0)

        # Cleanup
        delete_test_alert(alert_id)

        # New assertion: affected third party (asset vendor) should be present and non-empty
        self.assertIn("asset", payload)
        vendor_val = payload["asset"].get("vendor")
        self.assertIsNotNone(vendor_val, "asset.vendor is missing from persisted alert")
        self.assertIsInstance(vendor_val, str)
        self.assertGreater(len(vendor_val.strip()), 0, "asset.vendor is empty")


if __name__ == "__main__":
    unittest.main()
