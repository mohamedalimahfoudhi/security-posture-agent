"""
Tests for Data Breach Intelligence & Third-Party Exposure Monitoring.

Covers the full pipeline:
  Breach source -> normalized breach -> threat_event -> vendor resolution
  -> customer correlation -> exposure -> risk -> SOC alert -> API -> Graph RAG

Also verifies:
- Source normalization (HIBP, LeakCheck, DataBreach.com)
- Duplicate prevention (idempotency)
- Vendor alias matching
- Customer/vendor correlation
- Exposure creation
- Alert creation
- Tenant isolation (Customer A's breach cannot appear for Customer B)
- API responses (tenant-scoped)
- Scheduler / source failure isolation
- Graph RAG breach context inclusion
"""
import json
import unittest
from datetime import datetime

from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import get_connection
from app.auth.security import create_access_token
from app.database.user_repository import create_user, delete_user, get_user_by_username

from app.threat_intel.sources.hibp import HIBPSource
from app.threat_intel.sources.leakcheck import LeakCheckSource
from app.threat_intel.sources.databreach import DataBreachSource
from app.threat_intel.service import ThreatIntelService
from app.correlation.third_party_correlation import ThirdPartyCorrelationEngine

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

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
        return row[0]
    cur.execute("INSERT INTO vendors (name) VALUES (%s) RETURNING id", (name,))
    vid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return vid


def _create_vendor_alias(vendor_id, alias):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vendor_aliases (vendor_id, alias)
        VALUES (%s, %s)
        ON CONFLICT (alias) DO NOTHING
    """, (vendor_id, alias))
    conn.commit()
    cur.close()
    conn.close()


def _create_customer_vendor(customer_id, vendor_id, vendor_name, criticality='HIGH'):
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


def _insert_breach_event(service, cur, breach_meta):
    """Insert a normalized breach directly via the service's internal method."""
    source_id = breach_meta["source_id"]
    if service._breach_event_exists(cur, source_id):
        return False
    service._insert_breach_event(cur, breach_meta)
    return True


def _query_float(value):
    return float(value) if value is not None else None


# ---------------------------------------------------------------------------
# Unit tests: source normalization
# ---------------------------------------------------------------------------

class BreachSourceNormalizationTests(unittest.TestCase):

    def test_hibp_normalization(self):
        """HIBP breach record normalizes into the unified threat_event schema."""
        source = HIBPSource()
        raw = {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-10-04T00:00:00Z",
            "PwnCount": 152445165,
            "DataClasses": ["Emails", "Passwords", "Password hints"],
            "IsVerified": True,
            "IsSensitive": True,
            "IsFabricated": False,
            "IsRetired": False,
            "IsSpamList": False,
            "Description": "In October 2013, 153 million Adobe accounts were breached.",
        }
        normalized = source.normalize_article(raw)

        self.assertEqual(normalized["source_type"], "breach_report")
        self.assertEqual(normalized["source_id"], "hibp:adobe")
        self.assertEqual(normalized["severity"], "HIGH")  # sensitive -> HIGH
        self.assertIn("Data Breach", normalized["title"])
        self.assertEqual(normalized["threat_type"], "Data Breach")
        self.assertEqual(normalized["raw_metadata"]["severity_source"], "inferred")
        self.assertIn("adobe.com", normalized["affected_vendors"])
        self.assertIn("Emails", normalized["raw_metadata"]["data_classes"])
        self.assertIsInstance(normalized["published_date"], datetime)

    def test_hibp_parse_date_iso(self):
        source = HIBPSource()
        d = source._parse_date("2020-01-15T10:30:00Z")
        self.assertIsNotNone(d)

    def test_hibp_parse_date_plain(self):
        source = HIBPSource()
        d = source._parse_date("2020-01-15")
        self.assertIsNotNone(d)

    def test_leakcheck_normalization(self):
        """LeakCheck breach record normalizes into the unified schema."""
        source = LeakCheckSource()
        raw = {
            "id": "abc123",
            "name": "Globex Systems",
            "domain": "globex.com",
            "description": "Third-party systems breach.",
            "breach_date": "2025-02-28",
            "records": 3500000,
            "data_types": ["Emails", "Passwords"],
        }
        normalized = source.normalize_article(raw)

        self.assertEqual(normalized["source_type"], "breach_report")
        self.assertEqual(normalized["source_id"], "leakcheck:abc123")
        self.assertEqual(normalized["severity"], "HIGH")  # 3.5M records -> HIGH
        self.assertEqual(normalized["raw_metadata"]["severity_source"], "inferred")
        self.assertIn("globex.com", normalized["affected_vendors"])
        self.assertEqual(normalized["confidence"], 0.7)

    def test_databreach_normalization(self):
        """DataBreach.com breach record normalizes into the unified schema."""
        source = DataBreachSource()
        raw = {
            "id": "db-001",
            "name": "Acme Corp Data Leak",
            "organization": "Acme Corp",
            "description": "Customer records exposed.",
            "breach_date": "2025-03-15",
            "records_affected": 125000,
            "data_types": ["Email", "Names", "Phone Numbers"],
        }
        normalized = source.normalize_article(raw)

        self.assertEqual(normalized["source_type"], "breach_report")
        self.assertEqual(normalized["source_id"], "databreach:db-001")
        self.assertEqual(normalized["severity"], "MEDIUM")  # 125k -> MEDIUM
        self.assertEqual(normalized["raw_metadata"]["severity_source"], "inferred")
        self.assertIn("Acme Corp", normalized["affected_vendors"])

    def test_malformed_breach_raises(self):
        """A breach missing both name and id raises ValueError."""
        source = LeakCheckSource()
        with self.assertRaises(ValueError):
            source.normalize_article({})


# ---------------------------------------------------------------------------
# Integration tests: full pipeline
# ---------------------------------------------------------------------------

class DataBreachPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.customer_a, _ = _get_or_create_customer("Breach Customer A")
        cls.customer_b, _ = _get_or_create_customer("Breach Customer B")

        cls.user_a = get_user_by_username("breach_admin_a")
        if not cls.user_a:
            cls.user_a = create_user(
                "breach_admin_a", "breach_admin_a@test.local", "hashed_placeholder",
                "Breach Admin A", "Admin", cls.customer_a
            )
        cls.user_b = get_user_by_username("breach_admin_b")
        if not cls.user_b:
            cls.user_b = create_user(
                "breach_admin_b", "breach_admin_b@test.local", "hashed_placeholder",
                "Breach Admin B", "Admin", cls.customer_b
            )
        cls.headers_a = {"Authorization": f"Bearer {create_access_token({'sub': str(cls.user_a['id'])})}"}
        cls.headers_b = {"Authorization": f"Bearer {create_access_token({'sub': str(cls.user_b['id'])})}"}

        # Vendor: Acme Corp. Customer A uses it; Customer B does not.
        cls.vendor_acme = _get_or_create_vendor("Acme Corp")
        _create_vendor_alias(cls.vendor_acme, "acme corp")
        _create_vendor_alias(cls.vendor_acme, "acme")

        cls.cv_a = _create_customer_vendor(cls.customer_a, cls.vendor_acme, "Acme Corp", criticality='CRITICAL')
        # Customer B uses a DIFFERENT vendor (Globex) - unrelated to Acme breach.

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.customer_a, cls.customer_b)
        delete_user(cls.user_a['id'])
        delete_user(cls.user_b['id'])

    def setUp(self):
        # Clean up breach events and exposures created by prior tests
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM third_party_alerts
            WHERE customer_id IN (%s, %s)
        """, (self.customer_a, self.customer_b))
        cur.execute("""
            DELETE FROM third_party_exposures
            WHERE customer_id IN (%s, %s)
        """, (self.customer_a, self.customer_b))
        cur.execute("""
            DELETE FROM threat_events
            WHERE source_type = 'breach_report'
        """)
        conn.commit()
        cur.close()
        conn.close()

    # ---- Core pipeline ----

    def test_breach_to_exposure_pipeline(self):
        """Breach -> threat_event -> vendor resolution -> customer corr -> exposure."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp",
                "content": "Acme Corp suffered a data breach exposing customer records.",
                "severity": "HIGH",
                "confidence": 0.9,
                "affected_vendors": ["acme corp"],
                "affected_products": [],
                "affected_technologies": [],
                "published_date": datetime(2025, 3, 15),
                "source_url": "https://example.com/breach/acme",
                "source": "test_source",
                "source_id": "unit:acme-breach",
                "raw_metadata": {
                    "data_types": ["Emails", "Passwords"],
                    "severity_source": "inferred",
                },
            }
            self.assertTrue(_insert_breach_event(service, cur, breach))
            conn.commit()
            cur.execute("SELECT id FROM threat_events WHERE source_type='breach_report' ORDER BY id DESC LIMIT 1")
            event_id = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        # Run correlation (uses existing engine)
        result = ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)
        self.assertGreaterEqual(result["exposures_created"], 1)

        # Verify Customer A has an exposure
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT e.customer_id, e.vendor_id, e.risk_score, e.priority
            FROM third_party_exposures e
            WHERE e.threat_event_id = %s
        """, (event_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        customer_ids = {r[0] for r in rows}
        self.assertIn(self.customer_a, customer_ids)
        # Customer B must NOT be correlated (unrelated to Acme)
        self.assertNotIn(self.customer_b, customer_ids)

    def test_duplicate_breach_prevention(self):
        """Repeated ingestion of the same breach source_id does not create duplicates."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Duplicate",
                "content": "test",
                "severity": "MEDIUM",
                "confidence": 0.7,
                "affected_vendors": ["acme corp"],
                "affected_products": [],
                "affected_technologies": [],
                "published_date": datetime(2025, 1, 1),
                "source_url": "https://example.com/dup",
                "source": "test",
                "source_id": "unit:dup-breach",
                "raw_metadata": {"severity_source": "inferred"},
            }
            first = _insert_breach_event(service, cur, breach)
            second = _insert_breach_event(service, cur, breach)
            conn.commit()
        finally:
            cur.close()
            conn.close()

        self.assertTrue(first)
        self.assertFalse(second)  # duplicate detected

    def test_multi_source_duplicate_handling(self):
        """Different sources reporting the same real-world breach are preserved as distinct events."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            # Same vendor but different source-specific source_ids == distinct events
            b1 = {
                "title": "Data Breach: Acme Corp",
                "content": "x", "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "hibp",
                "source_id": "hibp:acme", "raw_metadata": {"severity_source": "inferred"},
            }
            b2 = {
                "title": "Data Breach: Acme Corp",
                "content": "y", "severity": "HIGH", "confidence": 0.7,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://b.com", "source": "leakcheck",
                "source_id": "leakcheck:acme", "raw_metadata": {"severity_source": "inferred"},
            }
            self.assertTrue(_insert_breach_event(service, cur, b1))
            self.assertTrue(_insert_breach_event(service, cur, b2))
            conn.commit()
        finally:
            cur.close()
            conn.close()

    def test_vendor_alias_matching(self):
        """Breach referencing an alias resolves to the canonical vendor."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            # Refer to vendor by alias "acme" (not canonical "Acme Corp")
            breach = {
                "title": "Data Breach: Acme",
                "content": "acme breached",
                "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme"],  # alias
                "affected_products": [], "affected_technologies": [],
                "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:alias-test", "raw_metadata": {"severity_source": "inferred"},
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
            cur.execute("SELECT id FROM threat_events WHERE source_type='breach_report' ORDER BY id DESC LIMIT 1")
            event_id = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        result = ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)
        self.assertGreaterEqual(result["exposures_created"], 1)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT e.customer_id, e.match_type FROM third_party_exposures e
            WHERE e.threat_event_id = %s
        """, (event_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        self.assertTrue(any(r[0] == self.customer_a for r in rows))
        self.assertFalse(any(r[0] == self.customer_b for r in rows))

    def test_unrelated_customers_not_correlated(self):
        """Customer B (no relationship to breached vendor) gets no exposure."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp Only",
                "content": "only acme affected",
                "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:only-acme", "raw_metadata": {"severity_source": "inferred"},
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
            cur.execute("SELECT id FROM threat_events WHERE source_type='breach_report' ORDER BY id DESC LIMIT 1")
            event_id = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)

        conn = get_connection()
        cur = conn.cursor()
        # Customer B has no customer_vendors for Acme, so no exposure for event
        cur.execute("""
            SELECT COUNT(*) FROM third_party_exposures
            WHERE threat_event_id = %s AND customer_id = %s
        """, (event_id, self.customer_b))
        count_b = cur.fetchone()[0]
        cur.close()
        conn.close()

        self.assertEqual(count_b, 0)

    def test_alert_creation_from_breach(self):
        """A significant breach generates a SOC alert via the existing alert engine."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp Critical",
                "content": "data breach compromised customer data at acme corp",
                "severity": "CRITICAL", "confidence": 0.95,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:alert-breach", "raw_metadata": {
                    "data_types": ["Emails", "Credit Cards"], "severity_source": "inferred"
                },
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
        finally:
            cur.close()
            conn.close()

        result = ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)
        self.assertGreaterEqual(result["alerts_created"], 1)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT alert_type, vendor, severity FROM third_party_alerts
            WHERE customer_id = %s
        """, (self.customer_a,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        # "data breach" keyword should classify as BREACH alert
        self.assertTrue(any(r[0] == "BREACH" for r in rows))
        self.assertTrue(any("Acme" in (r[1] or "") for r in rows))

    def test_exposure_idempotency(self):
        """Re-running correlation does not create duplicate exposures."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Idempotent Acme",
                "content": "idempotency test",
                "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:idempotent", "raw_metadata": {"severity_source": "inferred"},
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
            cur.execute("SELECT id FROM threat_events WHERE source_type='breach_report' ORDER BY id DESC LIMIT 1")
            event_id = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        engine = ThirdPartyCorrelationEngine()
        r1 = engine.correlate_unprocessed_events(limit=50)
        r2 = engine.correlate_unprocessed_events(limit=50)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM third_party_exposures
            WHERE threat_event_id = %s AND customer_id = %s
        """, (event_id, self.customer_a))
        count = cur.fetchone()[0]
        cur.close()
        conn.close()

        self.assertEqual(count, 1)  # exactly one exposure despite two correlation runs

    # ---- Tenant isolation + API ----

    def test_api_tenant_isolation_list(self):
        """Customer A sees its breach; Customer B sees nothing."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp Tenant",
                "content": "tenant isolation",
                "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:tenant", "raw_metadata": {"severity_source": "inferred"},
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
        finally:
            cur.close()
            conn.close()

        ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)

        resp_a = client.get("/api/threat-intel/data-breaches", headers=self.headers_a)
        resp_b = client.get("/api/threat-intel/data-breaches", headers=self.headers_b)

        self.assertEqual(resp_a.status_code, 200)
        self.assertEqual(resp_b.status_code, 200)

        data_a = resp_a.json()
        data_b = resp_b.json()

        self.assertGreaterEqual(data_a["total"], 1)
        for b in data_a["breaches"]:
            self.assertIn("Acme", b.get("vendor_name") or "")
        self.assertEqual(data_b["total"], 0)

    def test_api_tenant_isolation_detail(self):
        """Customer A can fetch its breach detail; Customer B gets 404."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp Detail",
                "content": "detail test",
                "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:detail", "raw_metadata": {"severity_source": "inferred"},
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
            cur.execute("SELECT id FROM threat_events WHERE source_type='breach_report' ORDER BY id DESC LIMIT 1")
            event_id = cur.fetchone()[0]
        finally:
            cur.close()
            conn.close()

        ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)

        resp_a = client.get(f"/api/threat-intel/data-breaches/{event_id}", headers=self.headers_a)
        resp_b = client.get(f"/api/threat-intel/data-breaches/{event_id}", headers=self.headers_b)

        self.assertEqual(resp_a.status_code, 200)
        self.assertEqual(resp_b.status_code, 404)  # not correlated to Customer B

    def test_api_summary(self):
        """Summary endpoint returns expected structure, tenant-scoped."""
        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp Summary",
                "content": "summary test",
                "severity": "CRITICAL", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:summary", "raw_metadata": {"severity_source": "inferred"},
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
        finally:
            cur.close()
            conn.close()

        ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)

        resp = client.get("/api/threat-intel/data-breaches/summary", headers=self.headers_a)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for key in ("total_breaches", "critical", "high", "medium", "low",
                    "affected_vendors", "unacknowledged_exposures", "latest_breach_date"):
            self.assertIn(key, data)
        # Correlation ran above and created a correlated breach exposure for
        # Customer A (the summary is tenant-scoped to correlated breaches).
        self.assertGreaterEqual(data["total_breaches"], 1)
        self.assertGreaterEqual(data["critical"], 1)  # breach inserted with CRITICAL severity

    def test_api_requires_auth(self):
        """Unauthenticated data-breach endpoints return 401."""
        resp = client.get("/api/threat-intel/data-breaches")
        self.assertEqual(resp.status_code, 401)
        resp2 = client.get("/api/threat-intel/data-breaches/summary")
        self.assertEqual(resp2.status_code, 401)

    # ---- Scheduler / source failure isolation ----

    def test_source_failure_isolation(self):
        """A failing breach source does not prevent other sources from collecting."""
        service = ThreatIntelService()

        class FailingSource:
            def fetch_articles(self):
                raise RuntimeError("downstream unavailable")

            def __str__(self):
                return "FailingSource"

        # Replace breach_sources with one failing + DataBreach fixture source
        original_sources = service.breach_sources
        service.breach_sources = [FailingSource(), DataBreachSource()]
        try:
            result = service.collect_data_breaches()
            # Expect one error entry and one success (DataBreach fixture works without key)
            self.assertEqual(result["total_errors"], 1)
            self.assertIn("FailingSource", result["sources"])
            self.assertIn("error", result["sources"]["FailingSource"])
            # DataBreachSource fixture path should succeed
            self.assertGreaterEqual(result["sources"]["DataBreachSource"].get("fetched", 0), 1)
        finally:
            service.breach_sources = original_sources

    def test_collect_data_breaches_returns_summary(self):
        """collect_data_breaches returns a structured summary dict."""
        service = ThreatIntelService()
        result = service.collect_data_breaches()
        for key in ("sources", "total_fetched", "total_inserted", "total_duplicates",
                    "total_errors", "last_breach_updated"):
            self.assertIn(key, result)

    # ---- Graph RAG ----

    def test_graph_rag_includes_breach_context(self):
        """Graph RAG customer profile includes breach intelligence for the customer."""
        from app.ai.graph_rag import build_customer_profile

        service = ThreatIntelService()
        conn = get_connection()
        cur = conn.cursor()
        try:
            breach = {
                "title": "Data Breach: Acme Corp RAG",
                "content": "rag breach context",
                "severity": "HIGH", "confidence": 0.9,
                "affected_vendors": ["acme corp"], "affected_products": [],
                "affected_technologies": [], "published_date": datetime(2025, 3, 1),
                "source_url": "https://a.com", "source": "test",
                "source_id": "unit:rag", "raw_metadata": {
                    "data_types": ["Emails"], "severity_source": "inferred"
                },
            }
            _insert_breach_event(service, cur, breach)
            conn.commit()
        finally:
            cur.close()
            conn.close()

        ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=50)

        conn = get_connection()
        cur = conn.cursor()
        try:
            profile = build_customer_profile(cur, self.customer_a, "threat")
        finally:
            cur.close()
            conn.close()

        self.assertIn("Data Breach", profile)
        self.assertIn("Acme", profile)


def _cleanup(customer_a, customer_b):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM third_party_alerts WHERE customer_id IN (%s, %s)", (customer_a, customer_b))
    cur.execute("DELETE FROM third_party_exposures WHERE customer_id IN (%s, %s)", (customer_a, customer_b))
    cur.execute("DELETE FROM threat_events WHERE source_type = 'breach_report'")
    cur.execute("DELETE FROM customer_vendors WHERE customer_id IN (%s, %s)", (customer_a, customer_b))
    conn.commit()
    cur.close()
    conn.close()


if __name__ == "__main__":
    unittest.main()
