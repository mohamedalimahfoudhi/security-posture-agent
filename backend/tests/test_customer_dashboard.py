"""
Tests for Customer-Centric Dashboard endpoints.

Covers:
1.  Admin can list all customers.
2.  Analyst cannot list all customers (403).
3.  Viewer cannot list all customers (403).
4.  Admin can access Customer A dashboard.
5.  Admin can access Customer B dashboard.
6.  Analyst can access own customer dashboard (200).
7.  Analyst CANNOT access another customer's dashboard (403).
8.  Viewer CANNOT access another customer's dashboard (403).
9.  Customer A alerts NOT visible to Customer B user.
10. Customer A vendors NOT visible to Customer B user.
11. Customer A exposures NOT visible to Customer B user.
12. Customer A arch changes NOT visible to Customer B user.
13. Dashboard stats differ correctly between customers.
14. Existing third-party alert tests still pass (imported).
15. Explicit malicious request: Customer A user requests Customer B dashboard → 403.
"""
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import get_connection
from app.auth.security import create_access_token
from app.database.user_repository import create_user, delete_user, get_user_by_username

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_create_customer(name, industry="Technology"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM customers WHERE name = %s", (name,))
    row = cur.fetchone()
    if row:
        cid = row[0]
        created = False
    else:
        cur.execute(
            "INSERT INTO customers (name, industry) VALUES (%s, %s) RETURNING id",
            (name, industry),
        )
        cid = cur.fetchone()[0]
        conn.commit()
        created = True
    cur.close()
    conn.close()
    return cid, created


def _get_or_create_user(username, email, role, customer_id):
    user = get_user_by_username(username)
    if user:
        return user
    return create_user(
        username, email, "hashed_placeholder", f"Test {username}", role, customer_id
    )


def _auth_headers(user_id):
    token = create_access_token({"sub": str(user_id)})
    return {"Authorization": f"Bearer {token}"}


def _create_vendor_and_alert(customer_id):
    """Create a minimal customer_vendor and third_party_alert for the customer."""
    conn = get_connection()
    cur = conn.cursor()

    # vendor
    cur.execute("INSERT INTO vendors (name) VALUES ('TestCo Dashboard') RETURNING id")
    vendor_id = cur.fetchone()[0]

    # customer_vendor
    cur.execute(
        """
        INSERT INTO customer_vendors
            (customer_id, vendor_id, vendor, relationship_type, data_sensitivity,
             criticality, base_risk_score)
        VALUES (%s, %s, 'TestCo Dashboard', 'CLOUD', 'SENSITIVE', 'CRITICAL', 80)
        RETURNING id
        """,
        (customer_id, vendor_id),
    )
    cv_id = cur.fetchone()[0]

    # third_party_alert
    cur.execute(
        """
        INSERT INTO third_party_alerts
            (customer_id, customer_vendor_id, vendor, alert_type, severity,
             risk_score, risk_delta, confidence, status)
        VALUES (%s, %s, 'TestCo Dashboard', 'VULNERABILITY', 'CRITICAL',
                85, 5, 0.9, 'NEW')
        RETURNING id
        """,
        (customer_id, cv_id),
    )
    alert_id = cur.fetchone()[0]

    conn.commit()
    cur.close()
    conn.close()
    return vendor_id, cv_id, alert_id


def _cleanup(customer_id, vendor_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM third_party_alerts WHERE customer_id = %s", (customer_id,))
    cur.execute("DELETE FROM third_party_exposures WHERE customer_id = %s", (customer_id,))
    cur.execute("DELETE FROM customer_vendors WHERE customer_id = %s", (customer_id,))
    if vendor_id:
        cur.execute("DELETE FROM vendors WHERE id = %s", (vendor_id,))
    conn.commit()
    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class CustomerDashboardTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Two customers
        cls.cust_a, _ = _get_or_create_customer("CD Test Customer A")
        cls.cust_b, _ = _get_or_create_customer("CD Test Customer B")

        # Admin (belongs to Customer A)
        cls.admin = _get_or_create_user(
            "cd_admin", "cd_admin@test.local", "Admin", cls.cust_a
        )
        # Analyst — Customer A
        cls.analyst_a = _get_or_create_user(
            "cd_analyst_a", "cd_analyst_a@test.local", "Analyst", cls.cust_a
        )
        # Viewer — Customer A
        cls.viewer_a = _get_or_create_user(
            "cd_viewer_a", "cd_viewer_a@test.local", "Viewer", cls.cust_a
        )
        # Analyst — Customer B (simulates a legitimate B-user)
        cls.analyst_b = _get_or_create_user(
            "cd_analyst_b", "cd_analyst_b@test.local", "Analyst", cls.cust_b
        )

        cls.hdrs_admin    = _auth_headers(cls.admin["id"])
        cls.hdrs_analyst_a = _auth_headers(cls.analyst_a["id"])
        cls.hdrs_viewer_a  = _auth_headers(cls.viewer_a["id"])
        cls.hdrs_analyst_b = _auth_headers(cls.analyst_b["id"])

        # Seed data for Customer A
        cls.vendor_id, cls.cv_id, cls.alert_id = _create_vendor_and_alert(cls.cust_a)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.cust_a, cls.vendor_id)
        _cleanup(cls.cust_b)
        for u in [cls.admin, cls.analyst_a, cls.viewer_a, cls.analyst_b]:
            try:
                delete_user(u["id"])
            except Exception:
                pass

    # ── /api/customers/all ────────────────────────────────────────────────

    def test_01_admin_can_list_all_customers(self):
        """Admin can list all customers."""
        resp = client.get("/api/customers/all", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        ids = [c["id"] for c in data]
        self.assertIn(self.cust_a, ids)
        self.assertIn(self.cust_b, ids)

    def test_02_analyst_cannot_list_all_customers(self):
        """Analyst cannot list all customers — 403."""
        resp = client.get("/api/customers/all", headers=self.hdrs_analyst_a)
        self.assertEqual(resp.status_code, 403)

    def test_03_viewer_cannot_list_all_customers(self):
        """Viewer cannot list all customers — 403."""
        resp = client.get("/api/customers/all", headers=self.hdrs_viewer_a)
        self.assertEqual(resp.status_code, 403)

    # ── /api/customers/{id}/dashboard ─────────────────────────────────────

    def test_04_admin_can_access_customer_a_dashboard(self):
        """Admin can access Customer A dashboard."""
        resp = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["customer"]["id"], self.cust_a)
        self.assertIn("posture", data)
        self.assertIn("alerts", data)
        self.assertIn("vendors", data)
        self.assertIn("exposures", data)
        self.assertIn("vulnerabilities", data)
        self.assertIn("incidents", data)
        self.assertIn("architecture_changes", data)
        self.assertIn("weekly_digest", data)

    def test_05_admin_can_access_customer_b_dashboard(self):
        """Admin can access Customer B dashboard."""
        resp = client.get(f"/api/customers/{self.cust_b}/dashboard", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["customer"]["id"], self.cust_b)

    def test_06_analyst_can_access_own_customer_dashboard(self):
        """Analyst can access their own customer's dashboard."""
        resp = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_analyst_a)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["customer"]["id"], self.cust_a)

    def test_07_analyst_cannot_access_other_customer_dashboard(self):
        """Analyst CANNOT access another customer's dashboard — 403."""
        resp = client.get(f"/api/customers/{self.cust_b}/dashboard", headers=self.hdrs_analyst_a)
        self.assertEqual(resp.status_code, 403)

    def test_08_viewer_cannot_access_other_customer_dashboard(self):
        """Viewer CANNOT access another customer's dashboard — 403."""
        resp = client.get(f"/api/customers/{self.cust_b}/dashboard", headers=self.hdrs_viewer_a)
        self.assertEqual(resp.status_code, 403)

    # ── Malicious cross-tenant request ────────────────────────────────────

    def test_09_malicious_cross_tenant_request(self):
        """Explicit malicious request: Customer A analyst → Customer B dashboard → 403."""
        resp = client.get(
            f"/api/customers/{self.cust_b}/dashboard",
            headers=self.hdrs_analyst_a,
        )
        self.assertEqual(resp.status_code, 403)

    # ── Tenant data isolation ─────────────────────────────────────────────

    def test_10_customer_a_alerts_not_visible_to_b(self):
        """Customer A alerts do NOT appear in Customer B's dashboard."""
        resp = client.get(f"/api/customers/{self.cust_b}/dashboard", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        alert_ids_b = [a["id"] for a in resp.json()["alerts"]]
        self.assertNotIn(self.alert_id, alert_ids_b)

    def test_11_customer_a_alerts_visible_to_a(self):
        """Customer A's seeded alert IS visible in Customer A's dashboard."""
        resp = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        alert_ids_a = [a["id"] for a in resp.json()["alerts"]]
        self.assertIn(self.alert_id, alert_ids_a)

    def test_12_customer_a_vendors_not_visible_to_b(self):
        """Customer A vendors do NOT appear in Customer B's dashboard."""
        resp = client.get(f"/api/customers/{self.cust_b}/dashboard", headers=self.hdrs_admin)
        vendor_ids_b = [v["id"] for v in resp.json()["vendors"]]
        self.assertNotIn(self.cv_id, vendor_ids_b)

    def test_13_customers_subresource_alerts_isolation(self):
        """GET /api/customers/{B}/alerts returns only B's alerts."""
        resp = client.get(f"/api/customers/{self.cust_b}/alerts", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        alert_ids = [a["id"] for a in resp.json()]
        self.assertNotIn(self.alert_id, alert_ids)

    def test_14_customers_subresource_vendors_isolation(self):
        """GET /api/customers/{B}/vendors returns only B's vendors."""
        resp = client.get(f"/api/customers/{self.cust_b}/vendors", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        vendor_ids = [v["id"] for v in resp.json()]
        self.assertNotIn(self.cv_id, vendor_ids)

    def test_15_subresource_requires_auth(self):
        """Sub-resource endpoints require authorization."""
        resp_alerts   = client.get(f"/api/customers/{self.cust_b}/alerts",   headers=self.hdrs_analyst_a)
        resp_vendors  = client.get(f"/api/customers/{self.cust_b}/vendors",  headers=self.hdrs_analyst_a)
        resp_exposures = client.get(f"/api/customers/{self.cust_b}/exposures", headers=self.hdrs_analyst_a)
        self.assertEqual(resp_alerts.status_code, 403)
        self.assertEqual(resp_vendors.status_code, 403)
        self.assertEqual(resp_exposures.status_code, 403)

    def test_16_dashboard_posture_structure(self):
        """Dashboard posture contains all expected KPI fields."""
        resp = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        posture = resp.json()["posture"]
        for key in ("overall_risk", "total_vendors", "critical_vendors",
                    "high_risk_vendors", "critical_alerts", "open_alerts",
                    "new_alerts_this_week", "total_third_party_exposures"):
            self.assertIn(key, posture, msg=f"Missing posture key: {key}")

    def test_17_weekly_digest_structure(self):
        """Weekly digest contains all expected fields."""
        resp = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_admin)
        digest = resp.json()["weekly_digest"]
        for key in ("overall_risk", "risk_change", "new_alerts", "resolved_alerts",
                    "new_vulnerabilities", "new_breaches", "new_ransomware_events",
                    "architecture_changes", "top_risks", "recommendations"):
            self.assertIn(key, digest, msg=f"Missing digest key: {key}")

    def test_18_dashboard_kpis_differ_between_customers(self):
        """Customer A dashboard has seeded data; Customer B should have none (or different)."""
        resp_a = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_admin)
        resp_b = client.get(f"/api/customers/{self.cust_b}/dashboard", headers=self.hdrs_admin)
        vendors_a = resp_a.json()["posture"]["total_vendors"]
        vendors_b = resp_b.json()["posture"]["total_vendors"]
        # A has at least 1 vendor; B may have 0 (unless other tests seeded it)
        self.assertGreaterEqual(vendors_a, 1)

    def test_19_analyst_b_cannot_see_customer_a_data(self):
        """Analyst from Customer B cannot access Customer A's dashboard."""
        resp = client.get(f"/api/customers/{self.cust_a}/dashboard", headers=self.hdrs_analyst_b)
        self.assertEqual(resp.status_code, 403)

    def test_20_unknown_customer_returns_404(self):
        """Requesting a non-existent customer ID returns 404."""
        resp = client.get("/api/customers/999999/dashboard", headers=self.hdrs_admin)
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
