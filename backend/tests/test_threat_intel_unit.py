import unittest
from datetime import datetime, timezone
from app.threat_intel.sources.hackernews import HackerNewsSource


class ThreatIntelUnitTests(unittest.TestCase):
    def test_normalize_article_with_complete_fields(self):
        source = HackerNewsSource()
        raw_article = {
            "title": "Sample HN Alert",
            "link": "https://thehackernews.com/sample-alert",
            "pubDate": "Tue, 01 Aug 2026 12:00:00 GMT",
            "description": "A sample description for a hacker news alert.",
            "guid": "sample-guid",
            "author": "Threat Team",
            "category": "Cybersecurity",
        }

        normalized = source.normalize_article(raw_article)

        self.assertEqual(normalized["title"], "Sample HN Alert")
        self.assertEqual(normalized["url"], "https://thehackernews.com/sample-alert")
        self.assertEqual(normalized["source"], "The Hacker News")
        self.assertEqual(normalized["threat_type"], None)
        self.assertIn("metadata", normalized)
        self.assertEqual(normalized["metadata"]["guid"], "sample-guid")
        self.assertEqual(normalized["metadata"]["author"], "Threat Team")

        self.assertIsInstance(normalized["published_date"], datetime)
        self.assertEqual(normalized["published_date"].year, 2026)
        self.assertEqual(normalized["published_date"].month, 8)

    def test_normalize_article_ignores_missing_description(self):
        source = HackerNewsSource()
        raw_article = {
            "title": "Missing description",
            "link": "https://thehackernews.com/missing-description",
            "pubDate": "Wed, 02 Aug 2026 13:30:00 GMT",
        }

        normalized = source.normalize_article(raw_article)
        self.assertEqual(normalized["content"], "")
        self.assertEqual(normalized["metadata"]["guid"], None)

    def test_parse_date_returns_none_for_invalid_date(self):
        source = HackerNewsSource()
        self.assertIsNone(source._parse_date("invalid-date-string"))


if __name__ == "__main__":
    unittest.main()
