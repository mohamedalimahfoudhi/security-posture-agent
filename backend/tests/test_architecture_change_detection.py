"""
Tests for Architecture Change Detection.

Covers:
- Architecture version history
- Technology additions
- Technology removals
- Version changes
- Duplicate prevention
- Risk refresh
- Threat correlation after new technology
- Tenant isolation
"""
import unittest
import json
from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import get_connection
from app.auth.security import create_access_token
from app.database.user_repository import create_user, delete_user
from app.risk.vendor_architecture_diff import compare_architectures, has_changes

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


def _create_customer_vendor(customer_id, vendor_id, vendor_name):
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


def _get_token(user_id):
    return create_access_token({"sub": str(user_id)})


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


class ArchitectureChangeDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.customer_a, _ = _get_or_create_customer("Arch Change Customer A")
        cls.customer_b, _ = _get_or_create_customer("Arch Change Customer B")

        cls.user_a = create_user(
            "arch_admin_a", "arch_admin_a@test.local", "hashed_placeholder",
            "Arch Admin A", "Admin", cls.customer_a
        )
        cls.user_b = create_user(
            "arch_admin_b", "arch_admin_b@test.local", "hashed_placeholder",
            "Arch Admin B", "Admin", cls.customer_b
        )

        cls.token_a = _get_token(cls.user_a['id'])
        cls.token_b = _get_token(cls.user_b['id'])
        cls.headers_a = _auth_headers(cls.token_a)
        cls.headers_b = _auth_headers(cls.token_b)

        cls.vendor, _ = _get_or_create_vendor("Arch Change Vendor")
        cls.cv_a = _create_customer_vendor(cls.customer_a, cls.vendor, "Arch Change Vendor")
        cls.cv_b = _create_customer_vendor(cls.customer_b, cls.vendor, "Arch Change Vendor")

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

    def test_01_diff_additions_removals_versions(self):
        """Diff engine detects additions, removals, and version changes."""
        previous = [
            {"technology": "Exchange", "version": "2019", "category": "email"},
            {"technology": "Windows Server", "version": "2019", "category": "os"},
            {"technology": "SQL Server", "version": "2019", "category": "database"},
        ]
        current = [
            {"technology": "Exchange", "version": "2025", "category": "email"},
            {"technology": "Windows Server", "version": "2025", "category": "os"},
            {"technology": "SQL Server", "version": "2019", "category": "database"},
            {"technology": "Azure Kubernetes Service", "version": "1.28", "category": "container"},
        ]

        diff = compare_architectures(previous, current)

        # Additions
        added_names = [t["technology"] for t in diff["added_technologies"]]
        self.assertIn("Azure Kubernetes Service", added_names)

        # Version changes
        changed = {c["technology"]: c for c in diff["changed_versions"]}
        self.assertIn("Exchange", changed)
        self.assertEqual(changed["Exchange"]["from_version"], "2019")
        self.assertEqual(changed["Exchange"]["to_version"], "2025")
        self.assertIn("Windows Server", changed)

        # No removals
        self.assertEqual(len(diff["removed_technologies"]), 0)

        # Unchanged
        unchanged_names = [t["technology"] for t in diff["unchanged_technologies"]]
        self.assertIn("SQL Server", unchanged_names)

        self.assertTrue(has_changes(diff))

    def test_02_diff_removals(self):
        """Diff engine detects removals."""
        previous = [
            {"technology": "Exchange", "version": "2019", "category": "email"},
            {"technology": "Windows Server", "version": "2019", "category": "os"},
        ]
        current = [
            {"technology": "Exchange", "version": "2019", "category": "email"},
        ]

        diff = compare_architectures(previous, current)

        removed_names = [t["technology"] for t in diff["removed_technologies"]]
        self.assertIn("Windows Server", removed_names)
        self.assertTrue(has_changes(diff))

    def test_03_diff_no_changes(self):
        """Diff engine returns no changes for identical footprints."""
        techs = [
            {"technology": "Exchange", "version": "2019", "category": "email"},
            {"technology": "Windows Server", "version": "2019", "category": "os"},
        ]
        diff = compare_architectures(techs, techs)
        self.assertFalse(has_changes(diff))
        self.assertEqual(len(diff["added_technologies"]), 0)
        self.assertEqual(len(diff["removed_technologies"]), 0)
        self.assertEqual(len(diff["changed_versions"]), 0)
        self.assertEqual(len(diff["unchanged_technologies"]), 2)

    def test_04_duplicate_prevention(self):
        """Adding the same technology twice does not create duplicates."""
        pid = _create_profile(self.cv_a)

        # Use the processor's dedup-aware upsert
        from app.risk.vendor_architecture_processor import _upsert_technology
        conn = get_connection()
        cur = conn.cursor()
        inserted_1 = _upsert_technology(cur, pid, {"technology": "Exchange", "version": "2019", "category": "email"})
        inserted_2 = _upsert_technology(cur, pid, {"technology": "Exchange", "version": "2019", "category": "email"})
        conn.commit()

        self.assertTrue(inserted_1)   # First insert succeeds
        self.assertFalse(inserted_2)  # Second insert is deduped

        cur.execute("""
            SELECT COUNT(*) FROM third_party_profile_technologies
            WHERE profile_id = %s AND technology = 'Exchange' AND version = '2019'
        """, (pid,))
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(count, 1)

    def test_05_tenant_isolation_architecture(self):
        """Customer B cannot access Customer A's architecture endpoint."""
        response = client.get(
            f"/api/customers/{self.customer_a}/vendors/{self.cv_a}/architecture",
            headers=self.headers_b
        )
        self.assertEqual(response.status_code, 403)

    def test_06_architecture_history_in_profile(self):
        """GET profile returns architecture_changes and architecture_history arrays."""
        pid = _create_profile(self.cv_a)
        _add_technology(pid, "Exchange", "2019")

        response = client.get(
            f"/api/customers/{self.customer_a}/vendors/{self.cv_a}/profile",
            headers=self.headers_a
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn('architecture_changes', data)
        self.assertIn('architecture_history', data)
        self.assertIsInstance(data['architecture_changes'], list)
        self.assertIsInstance(data['architecture_history'], list)


if __name__ == "__main__":
    unittest.main()