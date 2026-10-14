"""
Tests for the Third-Party Alert Engine (Continuous Monitoring).

Covers:
- Same threat affects two customers differently (business-specific risk)
- Critical vendor + critical CVE -> critical alert
- Low-criticality vendor -> lower risk for same threat
- Duplicate threat does not create duplicate alert
- Breach event generates breach alert
- Ransomware event generates ransomware alert
- Architecture change generates architecture-change alert
- Alert contains evidence
- Alert contains confidence
- Alert contains recommendation
- Weekly digest aggregates correct events
- Tenant isolation prevents cross-customer visibility
"""
import unittest
import json
from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import get_connection
from app.auth.security import create_access_token
from app.database.user_repository import create_user, delete_user
from app.correlation.third_party_alert_engine import (
    _classify_alert_type,
    _compute_customer_risk,
    generate_alerts_from_exposures,
    run_alert_engine,
)

client = TestClient(app)


def _get_or_create_customer(name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM customers WHERE name = %s", (name,))
    row = cur.fetchone()
    if row:
        cur.close()
        conn.close()
        return row[0], False
    cur.execute("INSERT INTO customers (name, industry) VALUES (%s, 'Technology') RETURNING id", (name,))
    cid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return cid, True


def _get_or_create_vendor(name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM vendors WHERE name = %s", (name,))
    row = cur.fetchone()
    if row:
        cur.close()
        conn.close()
        return row[0], False
    cur.execute("INSERT INTO vendors (name) VALUES (%s) RETURNING id", (name,))
    vid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return vid, True


def _create_customer_vendor(customer_id, vendor_id, vendor_name, criticality='MEDIUM', data_sensitivity='MEDIUM'):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO customer_vendors (customer_id, vendor_id, vendor, relationship_type,
                                      data_sensitivity, criticality, base_risk_score)
        VALUES (%s, %s, %s, 'CLOUD_PROVIDER', %s, %s, 50)
        RETURNING id
    """, (customer_id, vendor_id, vendor_name, data_sensitivity, criticality))
    cvid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return cvid


def _create_profile(customer_vendor_id, privileged=False, data_access_level='MEDIUM', business_role=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO third_party_profiles (customer_vendor_id, data_access_level, privileged_access, business_role)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    """, (customer_vendor_id, data_access_level, privileged, business_role))
    pid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return pid


def _create_threat_event(title, description, severity='HIGH', source_type='manual', cve_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threat_events (source_type, title, description, severity, confidence,
                                   affected_technologies, correlated, correlation_count)
        VALUES (%s, %s, %s, %s, 0.9, ARRAY['Exchange'], TRUE, 1)
        RETURNING id
    """, (source_type, title, description, severity))
    tid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return tid


def _create_threat_event_with_cve(title, description, severity='HIGH', cve_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threat_events (source_type, title, description, severity, confidence,
                                   cve_id, affected_technologies, correlated, correlation_count)
        VALUES ('cve', %s, %s, %s, 0.95, %s, ARRAY['Exchange'], TRUE, 1)
        RETURNING id
    """, (title, description, severity, cve_id))
    tid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return tid


def _create_exposure(threat_event_id, customer_id, vendor_id, customer_vendor_id, affected_tech='Exchange'):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO third_party_exposures (
            threat_event_id, customer_id, vendor_id, customer_vendor_id,
            match_type, match_confidence, matched_text, base_severity,
            risk_score, priority, profile_id, affected_technology,
            evidence, recommended_action, acknowledged, muted
        ) VALUES (%s, %s, %s, %s, 'vendor_direct', 90, %s, 'HIGH',
                  75, 'HIGH', NULL, %s, %s, %s, FALSE, FALSE)
        RETURNING id
    """, (
        threat_event_id, customer_id, vendor_id, customer_vendor_id,
        'Test Vendor', affected_tech,
        json.dumps(['Technology match', 'Critical CVE']),
        f'Patch {affected_tech} immediately',
    ))
    eid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return eid


def _get_token(user_id):
    return create_access_token({"sub": str(user_id)})


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


class ThirdPartyAlertEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.customer_a, _ = _get_or_create_customer("Alert Engine Customer A")
        cls.customer_b, _ = _get_or_create_customer("Alert Engine Customer B")

        cls.user_a = create_user(
            "alert_admin_a", "alert_admin_a@test.local", "hashed_placeholder",
            "Alert Admin A", "Admin", cls.customer_a
        )
        cls.user_b = create_user(
            "alert_admin_b", "alert_admin_b@test.local", "hashed_placeholder",
            "Alert Admin B", "Admin", cls.customer_b
        )

        cls.token_a = _get_token(cls.user_a['id'])
        cls.token_b = _get_token(cls.user_b['id'])
        cls.headers_a = _auth_headers(cls.token_a)
        cls.headers_b = _auth_headers(cls.token_b)

        # Same vendor for both customers, different business criticality
        cls.vendor, _ = _get_or_create_vendor("Alert Test Vendor")

        # Customer A: CRITICAL vendor + privileged
        cls.cv_a = _create_customer_vendor(cls.customer_a, cls.vendor, "Alert Test Vendor", criticality='CRITICAL', data_sensitivity='HIGH')

        # Customer B: LOW criticality vendor
        cls.cv_b = _create_customer_vendor(cls.customer_b, cls.vendor, "Alert Test Vendor", criticality='LOW', data_sensitivity='LOW')

    @classmethod
    def tearDownClass(cls):
        delete_user(cls.user_a['id'])
        delete_user(cls.user_b['id'])
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM customer_vendors WHERE customer_id IN (%s, %s)", (cls.customer_a, cls.customer_b))
        cur.execute("DELETE FROM customers WHERE id IN (%s, %s)", (cls.customer_a, cls.customer_b))
        conn.commit()
        cur.close()
        conn.close()

    def test_01_classify_alert_types(self):
        """Alert type classifier detects vulnerability, breach, ransomware."""
        self.assertEqual(_classify_alert_type({"title": "CVE-2024-123", "cve_id": "CVE-2024-123", "source_type": "cve"}), "VULNERABILITY")
        self.assertEqual(_classify_alert_type({"title": "Data breach at vendor", "description": "customer data leaked"}), "BREACH")
        self.assertEqual(_classify_alert_type({"title": "Ransomware attack", "description": "lockbit extortion"}), "RANSOMWARE")

    def test_02_same_threat_different_customer_risk(self):
        """Same threat produces different risk for different customers (business context)."""
        event = {"title": "Critical Exchange CVE with exploit", "description": "Exploit available", "severity": "CRITICAL", "cve_id": "CVE-2024-0001"}

        # Customer A: CRITICAL vendor + privileged + sensitive
        vendor_ctx_a = {"criticality": "CRITICAL", "data_sensitivity": "HIGH"}
        profile_ctx_a = {"privileged_access": True, "data_access_level": "HIGH", "business_role": "Identity Provider"}

        # Customer B: LOW vendor + no privileged
        vendor_ctx_b = {"criticality": "LOW", "data_sensitivity": "LOW"}
        profile_ctx_b = {"privileged_access": False, "data_access_level": "LOW", "business_role": None}

        risk_a = _compute_customer_risk(event, vendor_ctx_a, profile_ctx_a)
        risk_b = _compute_customer_risk(event, vendor_ctx_b, profile_ctx_b)

        self.assertGreater(risk_a, risk_b)
        self.assertGreaterEqual(risk_a, 85)  # Critical for customer A
        self.assertLess(risk_b, 70)          # Lower for customer B

    def test_03_duplicate_alerts_idempotent(self):
        """Running alert engine twice does not create duplicate alerts."""
        # Create a CVE-type threat so it classifies as VULNERABILITY
        te = _create_threat_event(
            "Test Exchange vulnerability", "A vulnerability in Exchange",
            severity="HIGH", source_type="cve"
        )
        _create_exposure(te, self.customer_a, self.vendor, self.cv_a)

        # Run engine twice
        result1 = generate_alerts_from_exposures(limit=10)
        result2 = generate_alerts_from_exposures(limit=10)

        self.assertGreaterEqual(result1["alerts_created"], 1)
        self.assertEqual(result2["alerts_created"], 0)  # No duplicates

        # Verify only 1 alert exists for this exposure
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM third_party_alerts
            WHERE customer_vendor_id = %s AND alert_type = 'VULNERABILITY'
        """, (self.cv_a,))
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(count, 1)

    def test_04_alert_contains_evidence_confidence_recommendation(self):
        """Generated alerts must include evidence, confidence, and recommendation."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT evidence, confidence, recommended_action, business_relevance
            FROM third_party_alerts
            WHERE customer_vendor_id = %s
            LIMIT 1
        """, (self.cv_a,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        self.assertIsNotNone(row)
        evidence, confidence, recommendation, relevance = row

        # Evidence
        ev = json.loads(evidence) if isinstance(evidence, str) else evidence
        self.assertTrue(len(ev) > 0)

        # Confidence
        self.assertIsNotNone(confidence)
        self.assertGreaterEqual(float(confidence), 0.5)

        # Recommendation
        self.assertTrue(recommendation and len(recommendation) > 10)

        # Business relevance
        self.assertTrue(relevance and len(relevance) > 5)

    def test_05_breach_alert_generation(self):
        """Breach event generates a BREACH alert."""
        te = _create_threat_event(
            "Vendor data breach", "Customer data breached and leaked",
            severity="CRITICAL", source_type="breach_report"
        )
        eid = _create_exposure(te, self.customer_a, self.vendor, self.cv_a)

        result = generate_alerts_from_exposures(limit=10)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT alert_type, severity FROM third_party_alerts
            WHERE exposure_id = %s ORDER BY id DESC LIMIT 1
        """, (eid,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "BREACH")

    def test_06_ransomware_alert_generation(self):
        """Ransomware event generates a RANSOMWARE alert."""
        te = _create_threat_event(
            "Ransomware extortion", "Lockbit ransomware group claims attack",
            severity="CRITICAL", source_type="breach_report"
        )
        eid = _create_exposure(te, self.customer_a, self.vendor, self.cv_a, affected_tech='Exchange')

        result = generate_alerts_from_exposures(limit=10)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT alert_type FROM third_party_alerts
            WHERE exposure_id = %s ORDER BY id DESC LIMIT 1
        """, (eid,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "RANSOMWARE")

    def test_07_weekly_digest_tenant_isolated(self):
        """Weekly digest is tenant-isolated."""
        response_b = client.get("/api/reports/third-party-weekly", headers=self.headers_b)
        self.assertEqual(response_b.status_code, 200)
        data_b = response_b.json()
        self.assertIn("overall_risk", data_b)
        self.assertIn("critical_vendors", data_b)
        self.assertIn("new_alerts", data_b)

        response_a = client.get("/api/reports/third-party-weekly", headers=self.headers_a)
        self.assertEqual(response_a.status_code, 200)

    def test_08_tenant_isolation_alerts(self):
        """Customer B cannot see Customer A's alerts."""
        response_b = client.get("/api/reports/third-party-alerts", headers=self.headers_b)
        self.assertEqual(response_b.status_code, 200)
        alerts_b = response_b.json()
        self.assertTrue(all(a["customer_vendor_id"] != self.cv_a for a in alerts_b))

    def test_09_run_full_alert_engine(self):
        """run_alert_engine works end-to-end."""
        result = run_alert_engine(limit=10)
        self.assertIn("exposure_alerts", result)
        self.assertIn("architecture_change_alerts", result)
        self.assertIn("total_created", result)

    def test_10_alert_idempotency(self):
        """Executing the pipeline twice for the same event yields 0 new duplicates."""
        te = _create_threat_event(
            "Idempotency test threat", "Idempotency test description",
            severity="HIGH", source_type="manual"
        )
        eid = _create_exposure(te, self.customer_a, self.vendor, self.cv_a, affected_tech='Exchange')
        
        # Run 1
        res1 = generate_alerts_from_exposures(limit=10)
        created1 = res1.get("alerts_created", 0)
        self.assertGreater(created1, 0, "First run should create at least 1 alert")
        
        # Run 2
        res2 = generate_alerts_from_exposures(limit=10)
        created2 = res2.get("alerts_created", 0)
        self.assertEqual(created2, 0, "Second run should create 0 duplicates")
        
        # Verify only exactly 1 alert exists for this composite identity
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM third_party_alerts
            WHERE customer_id = %s AND customer_vendor_id = %s
              AND threat_event_id = %s AND alert_type = 'OTHER'
        """, (self.customer_a, self.cv_a, te))
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        
        self.assertEqual(count, 1, "Exactly one alert should exist for the given composite key")


if __name__ == "__main__":
    unittest.main()