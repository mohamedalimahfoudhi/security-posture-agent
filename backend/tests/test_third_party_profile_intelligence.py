"""
Tests for the Third-Party Profile Intelligence Layer.

Covers:
- Tenant isolation
- Profile CRUD
- Technology mapping
- Threat matching
- Risk calculation (explainable scoring)
- Evidence generation
"""
import unittest
import json
from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import get_connection
from app.auth.security import create_access_token
from app.database.user_repository import create_user, delete_user
from app.risk.third_party_profile_risk import calculate_profile_risk

client = TestClient(app)


def _get_or_create_customer(name):
    """Fetch or create a customer, returns (id, created)."""
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
    """Fetch or create a global vendor, returns (id, created)."""
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


def _create_customer_vendor(customer_id, vendor_id, vendor_name):
    """Create a customer_vendors relationship, returns id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO customer_vendors (customer_id, vendor_id, vendor, relationship_type,
                                      data_sensitivity, criticality, base_risk_score)
        VALUES (%s, %s, %s, 'CLOUD_PROVIDER', 'HIGH', 'CRITICAL', 70)
        RETURNING id
    """, (customer_id, vendor_id, vendor_name))
    cvid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return cvid


def _create_profile(customer_vendor_id, **kwargs):
    """Create (or upsert) a third_party_profile, returns id."""
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
        kwargs.get('business_role', 'Identity Provider'),
        kwargs.get('data_access_level', 'HIGH'),
        kwargs.get('privileged_access', True),
        kwargs.get('criticality', 'CRITICAL'),
    ))
    pid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return pid


def _add_technology(profile_id, technology, version=None):
    """Add a technology to a profile, returns id."""
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


def _add_external_asset(profile_id, value="smtp.example.com", exposure_status="EXPOSED"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO third_party_external_assets (profile_id, asset_type, value, exposure_status)
        VALUES (%s, 'HOST', %s, %s)
        RETURNING id
    """, (profile_id, value, exposure_status))
    aid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return aid


def _create_threat_event(title, affected_techs=None, severity='CRITICAL', description=''):
    """Create a correlated threat_events row, returns id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threat_events
            (source_type, title, description, severity, confidence, affected_technologies,
             correlated, correlation_count)
        VALUES ('cve', %s, %s, %s, 0.9, %s, TRUE, 1)
        RETURNING id
    """, (title, description, severity, affected_techs or []))
    tid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return tid


def _get_token(user_id):
    """Create a JWT for a user."""
    return create_access_token({"sub": str(user_id)})


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


class ThirdPartyProfileIntelligenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Two tenants for isolation tests
        cls.customer_a, _ = _get_or_create_customer("Profile Test Customer A")
        cls.customer_b, _ = _get_or_create_customer("Profile Test Customer B")

        # Users for each tenant
        cls.user_a = create_user(
            "profile_admin_a", "profile_admin_a@test.local", "hashed_placeholder",
            "Profile Admin A", "Admin", cls.customer_a
        )
        cls.user_b = create_user(
            "profile_admin_b", "profile_admin_b@test.local", "hashed_placeholder",
            "Profile Admin B", "Admin", cls.customer_b
        )

        cls.token_a = _get_token(cls.user_a['id'])
        cls.token_b = _get_token(cls.user_b['id'])
        cls.headers_a = _auth_headers(cls.token_a)
        cls.headers_b = _auth_headers(cls.token_b)

        # Vendor
        cls.vendor, _ = _get_or_create_vendor("Exchange Test Vendor")

        # Relationships
        cls.cv_a = _create_customer_vendor(cls.customer_a, cls.vendor['id'] if isinstance(cls.vendor, dict) else cls.vendor, "Exchange Test Vendor")
        cls.cv_b = _create_customer_vendor(cls.customer_b, cls.vendor['id'] if isinstance(cls.vendor, dict) else cls.vendor, "Exchange Test Vendor")

    @classmethod
    def tearDownClass(cls):
        delete_user(cls.user_a['id'])
        delete_user(cls.user_b['id'])
        # Cleanup test customers (delete relationships first to satisfy FK constraints)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM customer_vendors WHERE customer_id IN (%s, %s)", (cls.customer_a, cls.customer_b))
        cur.execute("DELETE FROM customers WHERE id IN (%s, %s)", (cls.customer_a, cls.customer_b))
        conn.commit()
        cur.close()
        conn.close()

    def test_01_profile_create_and_get(self):
        """Profile CRUD: create then GET returns full intelligence payload."""
        pid = _create_profile(self.cv_a, business_role="Identity Provider",
                              data_access_level="HIGH", privileged_access=True,
                              criticality="CRITICAL")

        # Add tech + exposed asset
        tid = _add_technology(pid, "Exchange", "2019")
        aid = _add_external_asset(pid)

        response = client.get(
            f"/api/customers/{self.customer_a}/vendors/{self.cv_a}/profile",
            headers=self.headers_a
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIsNotNone(data['profile'])
        self.assertEqual(data['profile']['business_role'], 'Identity Provider')
        self.assertEqual(data['profile']['privileged_access'], True)
        self.assertEqual(data['profile']['criticality'], 'CRITICAL')
        self.assertGreaterEqual(data['profile']['risk_score'], 0)

        # Technologies / assets included
        tech_names = [t['technology'] for t in data['technologies']]
        self.assertIn('Exchange', tech_names)
        self.assertTrue(len(data['external_assets']) >= 1)

        self.assertIsNotNone(data['risk'])
        self.assertIn('reasons', data['risk'])
        self.assertIn('evidence', data['risk'])

        return pid

    def test_02_tenant_isolation_get(self):
        """Customer B must NOT be able to see Customer A's vendor relationship."""
        response = client.get(
            f"/api/customers/{self.customer_a}/vendors/{self.cv_a}/profile",
            headers=self.headers_b
        )
        self.assertEqual(response.status_code, 403)

    def test_03_technology_add_via_api(self):
        """Technology POST after adding a profile returns an id and refreshed risk."""
        pid = _create_profile(self.cv_a)
        response = client.post(
            f"/api/profiles/{pid}/technologies",
            headers=self.headers_a,
            json={"technology": "Microsoft Exchange", "version": "2016", "category": "Mail"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('id', data)
        self.assertIn('risk', data)
        self.assertIn('reasons', data['risk'])

    def test_04_delete_profile(self):
        """DELETE profile removes the profile and children but not the global vendor."""
        pid = _create_profile(self.cv_b)
        _add_technology(pid, "Exchange 2019")
        _add_external_asset(pid)

        response = client.delete(
            f"/api/customers/{self.customer_b}/vendors/{self.cv_b}/profile",
            headers=self.headers_b
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['deleted'])

        # Verify vendor still exists
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM vendors WHERE id = %s", (self.vendor,))
        vendor_count = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(vendor_count, 1)

        # Verify profile gone
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM third_party_profiles WHERE id = %s", (pid,))
        profile_count = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(profile_count, 0)

    def test_05_threat_matching_and_evidence(self):
        """Threat event matching to profile technology produces evidence and recommended action."""
        # Create a fresh relationship for clean testing
        vendor_clean, _ = _get_or_create_vendor("Evidence Test Vendor")
        cv_clean = _create_customer_vendor(self.customer_a, vendor_clean, "Evidence Test Vendor")
        pid = _create_profile(cv_clean, business_role="Email", privileged_access=False,
                              data_access_level="LOW", criticality="HIGH")
        _add_technology(pid, "Exchange")

        # Create a correlated threat event
        _create_threat_event(
            "Critical Exchange CVE with public exploit",
            affected_techs=["Exchange"],
            severity="CRITICAL",
            description="A critical vulnerability exists in Exchange with a public proof of concept exploit available."
        )

        # Recalculate risk
        result = calculate_profile_risk(pid)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result['risk_score'], 30)  # at least critical CVE on mapped tech
        self.assertIn('reasons', result)

        reasons_lower = " ".join(result['reasons']).lower()
        self.assertIn('vulnerability', reasons_lower)  # critical CVE matched

        # Evidence should include the technology match
        evidence_text = " ".join(result.get('evidence', []))
        self.assertIn('Exchange', evidence_text)

    def test_06_risk_calculation_explainability(self):
        """Risky profile should produce expected reason list."""
        pid = _create_profile(self.cv_a, criticality="CRITICAL",
                              privileged_access=True,
                              data_access_level="HIGH")
        _add_technology(pid, "Exchange")
        _add_external_asset(pid)
        _create_threat_event(
            "Exchange Remote Code Execution with exploit",
            affected_techs=["Exchange"],
            severity="CRITICAL",
            description="Exploit available for this critical RCE in Exchange."
        )

        result = calculate_profile_risk(pid)
        self.assertIsNotNone(result)
        score = result['risk_score']
        self.assertLessEqual(score, 100)

        reasons = result['reasons']
        reasons_text = " ".join(reasons).lower()
        self.assertIn('critical vendor relationship', reasons_text)
        self.assertIn('privileged access', reasons_text)
        self.assertIn('sensitive data access', reasons_text)
        self.assertIn('vulnerability', reasons_text)
        self.assertIn('exploitation', reasons_text)


if __name__ == "__main__":
    unittest.main()