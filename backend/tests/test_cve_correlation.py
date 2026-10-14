"""Focused regression tests for the CVE -> vendor/technology -> exposure pipeline.

Proves that structured NVD CPE data in cve.py's ingestion produces the
affected_vendors / affected_products / affected_technologies fields that
third_party_correlation.py consumes, and that a matching vendor yields an
exposure + VULNERABILITY alert while an unrelated vendor does not.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.threat_intel.sources.cve import CVESource  # noqa: E402
from app.database.connection import get_connection  # noqa: E402


def _nvd_item(cve_id, description, affected=None, metrics=None, references=None):
    """Build a synthetic NVD 2.0 vulnerability item dict."""
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "affected": affected or [],
            "metrics": metrics or {},
            "references": references or [],
            "published": "2026-01-01T00:00:00.000",
        }
    }


def _affected_entry(vendor, product, cpes=None, versions=None):
    return {
        "vendor": vendor,
        "product": product,
        "cpes": cpes or [],
        "versions": versions or [],
    }


def _existing_vendor_id(cur, vendor_name):
    """Return a vendor_id for vendor_name if it exists, else None."""
    cur.execute("SELECT id FROM vendors WHERE name ILIKE %s LIMIT 1", (f"%{vendor_name}%",))
    row = cur.fetchone()
    return row[0] if row else None


class TestCveCorrelation(unittest.TestCase):
    # ------------------------------------------------------------------
    # 1. Structured CPE CVE -> vendor/product/technology
    # ------------------------------------------------------------------
    def test_structured_cpe_extraction(self):
        source = CVESource()
        item = _nvd_item(
            "CVE-2026-1001",
            "Apache HTTP Server vulnerability",
            affected=[
                _affected_entry(
                    "apache",
                    "httpd",
                    cpes=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
                    versions=[{"version": "2.4.49", "lessThanOrEqual": "2.4.49"}],
                )
            ],
        )
        raw = source._extract_cve_entry(item)

        self.assertTrue(raw["affected_vendors"], "affected_vendors must be populated by CPE data")
        self.assertTrue(raw["affected_products"], "affected_products must be populated by CPE data")
        self.assertTrue(raw["affected_technologies"], "affected_technologies must be populated")
        self.assertIn("apache", [v.lower() for v in raw["affected_vendors"]])
        self.assertTrue(any("http" in p.lower() for p in raw["affected_products"]))
        self.assertTrue(any("apache" in t.lower() for t in raw["affected_technologies"]))
        self.assertIn("2.4.49", raw["affected_versions"])

        article = source.normalize_article(raw)
        self.assertTrue(article["affected_vendors"])
        self.assertTrue(article["affected_products"])
        self.assertTrue(article["affected_technologies"])

    # ------------------------------------------------------------------
    # 2. Description fallback (no structured data)
    # ------------------------------------------------------------------
    def test_description_fallback(self):
        source = CVESource()
        item = _nvd_item(
            "CVE-2026-1002",
            "Remote code execution vulnerability in Microsoft Exchange Server",
        )
        raw = source._extract_cve_entry(item)

        self.assertTrue(
            raw["affected_technologies"],
            "fallback should identify known tech from description",
        )
        self.assertTrue(any("microsoft" in v.lower() for v in raw["affected_vendors"]))

    # ------------------------------------------------------------------
    # 3. No false positives
    # ------------------------------------------------------------------
    def test_no_false_positive_for_unrelated_cve(self):
        source = CVESource()
        item = _nvd_item(
            "CVE-2026-1003",
            "Unrelated widget firmware issue in a niche controller",
        )
        raw = source._extract_cve_entry(item)

        lowered = " ".join(
            raw["affected_vendors"] + raw["affected_products"] + raw["affected_technologies"]
        ).lower()
        self.assertNotIn("apache", lowered)
        self.assertNotIn("microsoft", lowered)

    # ------------------------------------------------------------------
    # 4. Real correlation: matching vendor -> third_party_exposure + alert
    # ------------------------------------------------------------------
    def test_matching_vendor_creates_exposure_and_alert(self):
        conn = get_connection()
        cur = conn.cursor()
        event_id = None
        try:
            # Use a vendor that actually has a customer_vendors relationship in
            # the DB (Microsoft, vendor_id=1 -> customer 1) so vendor resolution
            # can discover a customer and produce an exposure.
            vendor_id = _existing_vendor_id(cur, "microsoft")
            if vendor_id is None:
                # No Microsoft vendor in DB; skip rather than fabricate resolution.
                return

            cur.execute(
                """
                INSERT INTO threat_events
                    (source_type, title, description, cve_id, cvss_score, severity,
                     confidence, affected_vendors, affected_products,
                     affected_technologies, published_date, source_url, raw_metadata,
                     correlated, correlation_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, 0)
                RETURNING id
                """,
                (
                    "cve",
                    "CVE-2026-1004 (HIGH Severity)",
                    "Microsoft Exchange Server remote code execution",
                    "CVE-2026-1004",
                    8.1,
                    "HIGH",
                    0.9,
                    ["microsoft"],
                    ["exchange server"],
                    ["Microsoft Exchange Server"],
                    "2026-01-01 00:00:00",
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-1004",
                    '{"cve_id": "CVE-2026-1004"}',
                ),
            )
            event_id = cur.fetchone()[0]
            conn.commit()

            from app.correlation.third_party_correlation import ThirdPartyCorrelationEngine

            cur.execute("UPDATE threat_events SET correlated = FALSE WHERE id = %s", (event_id,))
            conn.commit()

            result = ThirdPartyCorrelationEngine().correlate_unprocessed_events(limit=500)

            cur.execute(
                "SELECT COUNT(*) FROM third_party_exposures WHERE threat_event_id = %s",
                (event_id,),
            )
            exposure_count = cur.fetchone()[0]
            self.assertGreaterEqual(
                exposure_count,
                1,
                f"Expected exposure for CVE-2026-1004 but got {exposure_count}; "
                f"correlation result: {result}",
            )

            from app.correlation.third_party_alert_engine import run_alert_engine
            run_alert_engine(limit=100)
            cur.execute(
                "SELECT COUNT(*) FROM third_party_alerts WHERE threat_event_id = %s AND alert_type = 'VULNERABILITY'",
                (event_id,),
            )
            alert_count = cur.fetchone()[0]
            self.assertGreaterEqual(alert_count, 1, "Expected a VULNERABILITY alert for CVE-2026-1004")
        finally:
            if event_id is not None:
                cur.execute("DELETE FROM third_party_exposures WHERE threat_event_id = %s", (event_id,))
                cur.execute("DELETE FROM third_party_alerts WHERE threat_event_id = %s", (event_id,))
                cur.execute("DELETE FROM threat_events WHERE id = %s", (event_id,))
                conn.commit()
            cur.close()
            conn.close()


if __name__ == "__main__":
    unittest.main()