"""
Tests for Third-Party SOC Alert Engine and Reports API.

Covers:
- Alert creation from exposures
- Vulnerability / breach / ransomware / architecture-change alerts
- Customer-specific severity
- Evidence and confidence generation
- Recommended actions
- Duplicate prevention (idempotency)
- Weekly digest aggregation
- Tenant isolation
- Alert retrieval via reports API
"""
import json
import unittest
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import get_connection
from app.auth.security import create_access_token
from app.database.user_repository import create_user, delete_user
from app.correlation.third_party_alert_engine import (
    generate_alerts_from_exposures,
    generate_alerts_from_architecture_changes,
    generate_alerts_from_external_exposures,
    run_alert_engine,
    _classify_alert_type,
    _compute_customer_risk,
    _build_recommendation,
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
    return vid, False


def _create_customer_vendor(customer_id, vendor_id, vendor_name, criticality='CRITICAL'):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO customer_vendors (customer_id, vendor_id, vendor, relationship_type,
                                      data_sensitivity, criticality, base_risk_score)
        VALUES (%s, %s, %s, 'CLOUD_PROVIDER', 'SENSITIVE', %s, 70)
        RETURNING id
    """, (customer_id, vendor_id, vendor_name, criticality))
    cvid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return cvid


def _create_profile(customer_vendor_id, **kwargs):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO third_party_profiles
            (customer_vendor_id, business_role, data_access_level, privileged_access, criticality)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (customer_vendor_id) DO UPDATE SET
            business_role = EXCLUDED.business_role,
            data_access_level = EXCLUDED.data_access_level,
            privileged_access = EXCLUDED.privileged_access,
            criticality = EXCLUDED.criticality
        RETURNING id
    """, (
        customer_vendor_id,
        kwargs.get('business_role', 'Email Provider'),
        kwargs.get('data_access_level', 'SENSITIVE'),
        kwargs.get('privileged_access', True),
        kwargs.get('criticality', 'CRITICAL'),
    ))
    pid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return pid


def _add_technology(profile_id, technology, version=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO third_party_profile_technologies (profile_id, technology, version, category)
        VALUES (%s, %s, %s, 'Email')
        RETURNING id
    """, (profile_id, technology, version))
    tid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return tid


def _create_threat_event(title, affected_techs=None, severity='CRITICAL', description='', cve_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threat_events
            (source_type, title, description, severity, confidence, affected_technologies,
             cve_id, correlated, correlation_count)
        VALUES ('cve', %s, %s, %s, 0.9, %s, %s, TRUE, 1)
        RETURNING id
    """, (title, description, severity, affected_techs or [], cve_id))
    tid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return tid


def _create_exposure(threat_event_id, customer_id, vendor_id, customer_vendor_id, profile_id,
                     affected_technology='Exchange', risk_score=85):
    conn = get_connection()
    cur = conn.cursor()
    evidence = json.dumps([
        f"{affected_technology} detected in vendor architecture",
        "Critical vendor relationship",
        "Active vulnerability",
    ])
    cur.execute("""
        INSERT INTO third_party_exposures
            (threat_event_id, customer_id, vendor_id, customer_vendor_id,
             match_type, match_confidence, matched_text, base_severity,
             risk_score, priority, profile_id, affected_technology,
             evidence, recommended_action, acknowledged, muted)
        VALUES (%s, %s, %s, %s, 'vendor_direct', 90, 'Microsoft', 'CRITICAL',
                %s, 'CRITICAL', %s, %s, %s, 'Patch Exchange immediately', FALSE, FALSE)
        RETURNING id
    """, (threat_event_id, customer_id, vendor_id, customer_vendor_id,
          risk_score, profile_id, affected_technology, evidence))
    eid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return eid


def _cleanup_alerts(customer_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM third_party_alerts WHERE customer_id = %s", (customer_id,))
    cur.execute("DELETE FROM third_party_exposures WHERE customer_id = %s", (customer_id,))
    conn.commit()
    cur.close()
    conn.close()


def _get_token(user_id):
    return create_access_token({"sub": str(user_id)})


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


class ThirdPartyAlertEngineUnitTests(unittest.TestCase):
    """Unit tests for alert engine helper functions."""

    def test_classify_vulnerability(self):
        event = {"title": "CVE-2024-1234", "cve_id": "CVE-2024-1234", "source_type": "cve"}
        self.assertEqual(_classify_alert_type(event), "VULNERABILITY")

    def test_classify_ransomware(self):
        event = {"title": "LockBit ransomware targets Exchange", "description": "extortion campaign"}
        self.assertEqual(_classify_alert_type(event), "RANSOMWARE")

    def test_classify_breach(self):
        event = {"title": "Data breach at vendor", "description": "customer data compromised"}
        self.assertEqual(_classify_alert_type(event), "BREACH")

    def test_customer_specific_risk_critical_vs_low(self):
        event = {"severity": "CRITICAL", "title": "Exchange CVE", "description": "exploitation reported"}
        vendor_ctx_critical = {"criticality": "CRITICAL", "data_sensitivity": "SENSITIVE"}
        profile_ctx_critical = {"privileged_access": True, "data_access_level": "SENSITIVE", "business_role": "Email"}
        vendor_ctx_low = {"criticality": "LOW", "data_sensitivity": "LOW"}
        profile_ctx_low = {"privileged_access": False, "data_access_level": "LOW", "business_role": None}

        risk_critical = _compute_customer_risk(event, vendor_ctx_critical, profile_ctx_critical)
        risk_low = _compute_customer_risk(event, vendor_ctx_low, profile_ctx_low)
        self.assertGreater(risk_critical, risk_low)

    def test_recommendation_vulnerability(self):
        rec = _build_recommendation("VULNERABILITY", {"cve_id": "CVE-2024-9999"}, "Exchange")
        self.assertIn("CVE-2024-9999", rec)
        self.assertIn("Exchange", rec)

    def test_recommendation_architecture_change(self):
        rec = _build_recommendation("ARCHITECTURE_CHANGE", {}, "Docker")
        self.assertIn("Docker", rec)


class ThirdPartyAlertIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.customer_a, _ = _get_or_create_customer("Alert Test Customer A")
        cls.customer_b, _ = _get_or_create_customer("Alert Test Customer B")

        from app.database.user_repository import get_user_by_username
        cls.user_a = get_user_by_username("alert_admin_a")
        if not cls.user_a:
            cls.user_a = create_user(
                "alert_admin_a", "alert_admin_a@test.local", "hashed_placeholder",
                "Alert Admin A", "Admin", cls.customer_a
            )
        cls.user_b = get_user_by_username("alert_admin_b")
        if not cls.user_b:
            cls.user_b = create_user(
                "alert_admin_b", "alert_admin_b@test.local", "hashed_placeholder",
                "Alert Admin B", "Admin", cls.customer_b
            )
        cls.headers_a = _auth_headers(_get_token(cls.user_a['id']))
        cls.headers_b = _auth_headers(_get_token(cls.user_b['id']))

        cls.vendor_id, _ = _get_or_create_vendor("Microsoft Alert Test")

        cls.cv_a = _create_customer_vendor(cls.customer_a, cls.vendor_id, "Microsoft", criticality='CRITICAL')
        cls.cv_b = _create_customer_vendor(cls.customer_b, cls.vendor_id, "Microsoft", criticality='LOW')

        cls.profile_a = _create_profile(cls.cv_a, privileged_access=True, data_access_level='SENSITIVE')
        cls.profile_b = _create_profile(cls.cv_b, privileged_access=False, data_access_level='LOW', criticality='LOW')

        _add_technology(cls.profile_a, "Microsoft Exchange", "2019")
        _add_technology(cls.profile_b, "Microsoft Exchange", "2019")

    @classmethod
    def tearDownClass(cls):
        _cleanup_alerts(cls.customer_a)
        _cleanup_alerts(cls.customer_b)
        delete_user(cls.user_a['id'])
        delete_user(cls.user_b['id'])
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM third_party_exposures WHERE customer_id IN (%s, %s)", (cls.customer_a, cls.customer_b))
        cur.execute("DELETE FROM customer_vendors WHERE customer_id IN (%s, %s)", (cls.customer_a, cls.customer_b))
        conn.commit()
        cur.close()
        conn.close()

    def setUp(self):
        _cleanup_alerts(self.customer_a)
        _cleanup_alerts(self.customer_b)

    def test_alert_creation_from_exposure(self):
        """Exposure -> Alert pipeline creates a vulnerability alert."""
        event_id = _create_threat_event(
            "Critical Exchange vulnerability",
            affected_techs=["Exchange"],
            severity="CRITICAL",
            cve_id="CVE-2024-TEST-001",
            description="Remote code execution, exploitation reported",
        )
        exposure_id = _create_exposure(
            event_id, self.customer_a, self.vendor_id, self.cv_a, self.profile_a,
            affected_technology="Microsoft Exchange",
        )

        result = generate_alerts_from_exposures(limit=10)
        self.assertGreaterEqual(result["alerts_created"], 1)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT alert_type, severity, vendor, affected_technology, evidence, recommended_action
            FROM third_party_alerts WHERE exposure_id = %s
        """, (exposure_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "VULNERABILITY")
        self.assertEqual(row[2], "Microsoft")
        self.assertEqual(row[3], "Microsoft Exchange")
        self.assertIsNotNone(row[4])
        self.assertIsNotNone(row[5])

    def test_customer_specific_severity(self):
        """Same threat produces higher severity for critical customer vs low-criticality customer."""
        event_id = _create_threat_event(
            "Exchange CVE severity test",
            affected_techs=["Exchange"],
            severity="CRITICAL",
            cve_id="CVE-2024-TEST-002",
        )
        _create_exposure(event_id, self.customer_a, self.vendor_id, self.cv_a, self.profile_a,
                         affected_technology="Microsoft Exchange", risk_score=90)
        _create_exposure(event_id, self.customer_b, self.vendor_id, self.cv_b, self.profile_b,
                         affected_technology="Microsoft Exchange", risk_score=40)

        generate_alerts_from_exposures(limit=100, customer_id=self.customer_a)
        generate_alerts_from_exposures(limit=100, customer_id=self.customer_b)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT risk_score, severity FROM third_party_alerts WHERE customer_id = %s", (self.customer_a,))
        alert_a = cur.fetchone()
        cur.execute("SELECT risk_score, severity FROM third_party_alerts WHERE customer_id = %s", (self.customer_b,))
        alert_b = cur.fetchone()
        cur.close()
        conn.close()

        self.assertIsNotNone(alert_a)
        self.assertIsNotNone(alert_b)
        self.assertGreater(alert_a[0], alert_b[0])

    def test_duplicate_prevention(self):
        """Running alert engine twice does not create duplicate alerts."""
        event_id = _create_threat_event("Duplicate test CVE", cve_id="CVE-2024-DUP")
        _create_exposure(event_id, self.customer_a, self.vendor_id, self.cv_a, self.profile_a)

        r1 = generate_alerts_from_exposures(limit=10)
        r2 = generate_alerts_from_exposures(limit=10)

        self.assertGreaterEqual(r1["alerts_created"], 1)
        self.assertEqual(r2["alerts_created"], 0)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM third_party_alerts
            WHERE customer_id = %s AND threat_event_id = %s
        """, (self.customer_a, event_id))
        alert_count = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(alert_count, 1)

    def test_architecture_change_alert(self):
        """Architecture change produces ARCHITECTURE_CHANGE alert."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO architecture_changes
                (customer_id, customer_vendor_id, profile_id,
                 added_technologies, risk_before, risk_after, risk_delta, risk_impact, reason)
            VALUES (%s, %s, %s, %s, 50, 70, 20, 'HIGH', 'New Docker detected')
            RETURNING id
        """, (
            self.customer_a, self.cv_a, self.profile_a,
            json.dumps([{"technology": "Docker", "version": "24.0"}]),
        ))
        change_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        result = generate_alerts_from_architecture_changes(limit=10)
        self.assertGreaterEqual(result["alerts_created"], 1)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT alert_type, affected_technology FROM third_party_alerts
            WHERE architecture_change_id = %s
        """, (change_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        self.assertEqual(row[0], "ARCHITECTURE_CHANGE")
        self.assertEqual(row[1], "Docker")

    def test_reports_api_tenant_isolation(self):
        """Reports API returns only alerts for authenticated customer."""
        event_id = _create_threat_event("Tenant isolation test", cve_id="CVE-2024-TENANT")
        _create_exposure(event_id, self.customer_a, self.vendor_id, self.cv_a, self.profile_a)
        generate_alerts_from_exposures(limit=10)

        resp_a = client.get("/api/reports/third-party-alerts", headers=self.headers_a)
        resp_b = client.get("/api/reports/third-party-alerts", headers=self.headers_b)

        self.assertEqual(resp_a.status_code, 200)
        self.assertEqual(resp_b.status_code, 200)

        alerts_a = resp_a.json()
        alerts_b = resp_b.json()

        for al in alerts_a:
            self.assertEqual(al.get("vendor"), "Microsoft")
        self.assertEqual(len(alerts_b), 0)

    def test_weekly_digest_api(self):
        """Weekly digest endpoint returns expected structure."""
        event_id = _create_threat_event("Weekly digest test", cve_id="CVE-2024-WEEKLY")
        _create_exposure(event_id, self.customer_a, self.vendor_id, self.cv_a, self.profile_a)
        generate_alerts_from_exposures(limit=10)

        resp = client.get("/api/reports/third-party-weekly", headers=self.headers_a)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        for key in ("period", "overall_risk", "risk_change", "new_alerts",
                    "critical_vendors", "high_risk_vendors", "architecture_changes",
                    "new_vulnerabilities", "top_risks", "recommendations"):
            self.assertIn(key, data)

    def test_run_alert_engine_full(self):
        """Full alert engine runs without error."""
        result = run_alert_engine(limit=10)
        self.assertIn("total_created", result)
        self.assertIn("exposure_alerts", result)
        self.assertIn("architecture_change_alerts", result)
        self.assertIn("external_exposure_alerts", result)


if __name__ == "__main__":
    unittest.main()
