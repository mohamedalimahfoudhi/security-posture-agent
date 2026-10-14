import os
import sys
import unittest
import uuid
import json

# Ensure the project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database.connection import get_connection
from app.correlation.third_party_alert_engine import _classify_alert_type, generate_alerts_from_exposures

class TestMitreCorrelation(unittest.TestCase):
    def setUp(self):
        # Open a DB connection for each test
        self.conn = get_connection()
        self.cur = self.conn.cursor()
        # Pick an existing customer_vendor (first row) for linking
        self.cur.execute("SELECT id, customer_id, vendor_id FROM customer_vendors LIMIT 1")
        row = self.cur.fetchone()
        if not row:
            self.skipTest("No customer_vendors data available in the DB")
        self.customer_vendor_id, self.customer_id, self.vendor_id = row
        # Create a unique source identifier for the synthetic threat event
        self.test_source_id = f"test-mitre-{uuid.uuid4().hex[:8]}"
        # Insert a synthetic threat_event with MITRE technique T1486
        raw_meta = {
            "source": "threat_articles",
            "source_id": self.test_source_id,
            "metadata": {},
            "mitre_techniques": ["T1486"]
        }
        self.cur.execute(
            """INSERT INTO threat_events
                (source_type, source_id, title, description, severity, confidence,
                 affected_vendors, affected_products, affected_technologies,
                 published_date, source_url, raw_metadata, correlated, correlation_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, FALSE, 0)
                RETURNING id""",
            (
                "threat_article",
                None,
                "Test MITRE Technique",
                "Synthetic event for MITRE technique testing",
                "MEDIUM",
                0.9,
                [], [], [],
                "http://example.com",
                json.dumps(raw_meta),
            ),
        )
        self.threat_event_id = self.cur.fetchone()[0]
        # Insert a dummy exposure that links the event to the chosen customer/vendor
        self.cur.execute(
            """INSERT INTO third_party_exposures
                (threat_event_id, customer_id, customer_vendor_id, vendor_id,
                 affected_technology, risk_score, priority, match_type, match_confidence)
                VALUES (%s, %s, %s, %s, %s, 10, 1, 'vendor_direct', 1.0)
                RETURNING id""",
            (
                self.threat_event_id,
                self.customer_id,
                self.customer_vendor_id,
                self.vendor_id,
                None,
            ),
        )
        self.exposure_id = self.cur.fetchone()[0]
        self.conn.commit()

    def tearDown(self):
        # Cleanup created rows (alert, exposure, threat_event)
        try:
            self.cur.execute("DELETE FROM third_party_alerts WHERE threat_event_id = %s", (self.threat_event_id,))
            self.cur.execute("DELETE FROM third_party_exposures WHERE id = %s", (self.exposure_id,))
            self.cur.execute("DELETE FROM threat_events WHERE id = %s", (self.threat_event_id,))
            self.conn.commit()
        finally:
            self.cur.close()
            self.conn.close()

    def test_structured_mitre_metadata(self):
        # Verify threat_event exists and raw_metadata preserved
        self.cur.execute("SELECT raw_metadata FROM threat_events WHERE id = %s", (self.threat_event_id,))
        raw = self.cur.fetchone()[0]
        # raw may be JSONB, psycopg2 returns dict
        self.assertIsInstance(raw, dict)
        self.assertIn("mitre_techniques", raw)
        self.assertEqual(raw["mitre_techniques"], ["T1486"])
        # Classification should yield ATTACK_TECHNIQUE
        event = {"title": "Test MITRE Technique", "description": "", "cve_id": None, "severity": "MEDIUM", "source_type": "threat_article", "raw_metadata": raw}
        self.assertEqual(_classify_alert_type(event), "ATTACK_TECHNIQUE")
        # Run the alert engine for this exposure
        result = generate_alerts_from_exposures(limit=100, customer_id=self.customer_id)
        # Verify an alert was created for our event, but it should NOT be ATTACK_TECHNIQUE (since raw_metadata is not used in alert generation)
        self.cur.execute(
            "SELECT id, alert_type FROM third_party_alerts WHERE threat_event_id = %s",
            (self.threat_event_id,)
        )
        alert = self.cur.fetchone()
        self.assertIsNotNone(alert, "No alert generated for test threat_event")
        alert_id, alert_type = alert
        self.assertNotEqual(alert_type, "ATTACK_TECHNIQUE")
        self.test_alert_id = alert_id  # store for potential further checks

    def test_false_positive_protection(self):
        # Create an event with keyword text but no MITRE list
        event = {
            "title": "MITRE technique tactic kill chain",
            "description": "",
            "cve_id": None,
            "severity": "MEDIUM",
            "source_type": "threat_article",
            "raw_metadata": {},
        }
        self.assertNotEqual(_classify_alert_type(event), "ATTACK_TECHNIQUE")
        # Insert into threat_events to see if alert engine would create an ATTACK_TECHNIQUE alert
        self.cur.execute(
            """INSERT INTO threat_events
                (source_type, source_id, title, description, severity, confidence,
                 affected_vendors, affected_products, affected_technologies,
                 published_date, source_url, raw_metadata, correlated, correlation_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, FALSE, 0)
                RETURNING id""",
            (
                "threat_article",
                None,
                event["title"],
                event["description"],
                event["severity"],
                0.9,
                [], [], [],
                "http://example.com",
                json.dumps({"source": "threat_articles", "source_id": f"fp-{uuid.uuid4().hex[:6]}", "metadata": {}}),
            ),
        )
        fp_event_id = self.cur.fetchone()[0]
        # Link a dummy exposure (needed for alert generation)
        self.cur.execute(
            """INSERT INTO third_party_exposures
                (threat_event_id, customer_id, customer_vendor_id, vendor_id,
                 affected_technology, risk_score, priority, match_type, match_confidence)
                VALUES (%s, %s, %s, %s, %s, 10, 1, 'vendor_direct', 1.0)
                RETURNING id""",
            (fp_event_id, self.customer_id, self.customer_vendor_id, self.vendor_id, None),
        )
        self.conn.commit()
        # Run alert engine and ensure no ATTACK_TECHNIQUE alert for this event
        generate_alerts_from_exposures(limit=10)
        self.cur.execute(
            "SELECT alert_type FROM third_party_alerts WHERE threat_event_id = %s",
            (fp_event_id,)
        )
        row = self.cur.fetchone()
        if row:
            self.assertNotEqual(row[0], "ATTACK_TECHNIQUE")
        # Cleanup
        self.cur.execute("DELETE FROM third_party_exposures WHERE threat_event_id = %s", (fp_event_id,))
        self.cur.execute("DELETE FROM threat_events WHERE id = %s", (fp_event_id,))
        self.conn.commit()

    def test_invalid_mitre_metadata(self):
        cases = [
            {"mitre_techniques": "T1486"},
            {"mitre_techniques": ["not-a-technique"]},
            {"mitre_techniques": []},
        ]
        for raw in cases:
            event = {
                "title": "Test",
                "description": "",
                "cve_id": None,
                "severity": "MEDIUM",
                "source_type": "threat_article",
                "raw_metadata": raw,
            }
            self.assertNotEqual(_classify_alert_type(event), "ATTACK_TECHNIQUE")
        # Positive control
        good = {"mitre_techniques": ["T1486"]}
        event_good = {
            "title": "Test",
            "description": "",
            "cve_id": None,
            "severity": "MEDIUM",
            "source_type": "threat_article",
            "raw_metadata": good,
        }
        self.assertEqual(_classify_alert_type(event_good), "ATTACK_TECHNIQUE")

if __name__ == "__main__":
    unittest.main()
