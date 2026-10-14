import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import get_connection

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


def create_test_alert(customer_id, risk_level="HIGH", status="NEW"):
    conn = get_connection()
    cur = conn.cursor()
    # Get a customer_vendor_id for this customer
    cur.execute("SELECT id FROM customer_vendors WHERE customer_id = %s LIMIT 1;", (customer_id,))
    cv_row = cur.fetchone()
    if not cv_row:
        # Get a vendor_id
        cur.execute("SELECT id FROM vendors LIMIT 1;")
        v_row = cur.fetchone()
        v_id = v_row[0] if v_row else 1
        cur.execute("INSERT INTO customer_vendors (customer_id, vendor_id, vendor_name) VALUES (%s, %s, %s) RETURNING id;",
                    (customer_id, v_id, "Test Vendor"))
        cv_id = cur.fetchone()[0]
    else:
        cv_id = cv_row[0]

    cur.execute(
        """INSERT INTO third_party_alerts (customer_id, customer_vendor_id, severity, status, vendor, alert_type)
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;""",
        (customer_id, cv_id, risk_level, status, "Test Vendor", "VULNERABILITY"),
    )
    alert_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return alert_id


def delete_test_alert(alert_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM third_party_alerts WHERE id = %s;", (alert_id,))
    conn.commit()
    cur.close()
    conn.close()



from app.auth.security import create_access_token

def get_auth_headers(customer_id=1, role="Admin"):
    token = create_access_token(data={"sub": "1", "role": role, "customer_id": customer_id})
    return {"Authorization": f"Bearer {token}"}


class AlertApiTests(unittest.TestCase):
    def test_get_alerts_list(self):
        response = client.get("/api/alerts/", headers=get_auth_headers())
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)

    def test_get_alert_detail(self):
        customer_id = get_any_customer_id()
        alert_id = create_test_alert(customer_id)

        response = client.get(f"/api/alerts/{alert_id}", headers=get_auth_headers(customer_id))
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(payload["id"], alert_id)
        self.assertEqual(payload["status"], "NEW")
        self.assertEqual(payload["risk_level"], "HIGH")
        self.assertEqual(payload["customer_id"], customer_id)
        self.assertIn("vendor", payload)
        self.assertIn("alert_type", payload)

        delete_test_alert(alert_id)

    def test_patch_alert_status_updates_status(self):
        customer_id = get_any_customer_id()
        alert_id = create_test_alert(customer_id)

        response = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "IN_PROGRESS"},
            headers=get_auth_headers(customer_id)
        )
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(payload["id"], alert_id)
        self.assertEqual(payload["status"], "IN_PROGRESS")


        delete_test_alert(alert_id)

    def test_patch_alert_status_invalid_status(self):
        customer_id = get_any_customer_id()
        alert_id = create_test_alert(customer_id)

        response = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "INVALID"},
            headers=get_auth_headers(customer_id)
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid status", response.json().get("detail", ""))

        delete_test_alert(alert_id)

    def test_get_alert_detail_not_found(self):
        response = client.get("/api/alerts/99999999", headers=get_auth_headers())
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json().get("detail"), "Alert not found")



if __name__ == "__main__":
    unittest.main()
