from datetime import datetime
from email.utils import parsedate_to_datetime
import html
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from app.threat_intel.sources.base import ThreatIntelSource

BLEEPINGCOMPUTER_FEED_URL = "https://www.bleepingcomputer.com/feed/"
SOURCE_NAME = "BleepingComputer"


class BleepingComputerSource(ThreatIntelSource):
    def fetch_articles(self) -> List[Dict[str, Any]]:
        try:
            req = urllib.request.Request(
                BLEEPINGCOMPUTER_FEED_URL,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read()
        except (urllib.error.URLError, ValueError) as exc:
            raise RuntimeError(f"Unable to fetch BleepingComputer RSS feed: {exc}") from exc

        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise RuntimeError(f"Unable to parse BleepingComputer RSS feed XML: {exc}") from exc

        raw_items: List[Dict[str, Any]] = []
        for element in root.iter():
            if element.tag.lower().endswith("item"):
                raw_items.append(self._extract_item(element))

        if not raw_items:
            raise RuntimeError("No items found in BleepingComputer RSS feed")

        return raw_items

    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        title = (raw_article.get("title") or "").strip()
        url = (raw_article.get("link") or "").strip()
        content = raw_article.get("content") or raw_article.get("description") or ""
        published_date = self._parse_date(raw_article.get("pubDate"))
        categories = raw_article.get("categories", [])

        if not url:
            raise ValueError("BleepingComputer article missing URL")

        normalized_content = html.unescape(content).strip() if content else ""

        # Classify threat type based on categories
        threat_type = self._classify_threat_type(categories, title, normalized_content)

        return {
            "title": title or "Untitled Article",
            "url": url,
            "source": SOURCE_NAME,
            "published_date": published_date,
            "content": normalized_content,
            "threat_type": threat_type,
            "metadata": {
                "guid": raw_article.get("guid"),
                "author": raw_article.get("author"),
                "categories": categories,
            },
        }

    def _extract_item(self, item: ET.Element) -> Dict[str, Any]:
        raw_item: Dict[str, Any] = {}
        for child in item:
            tag = child.tag.lower()
            if tag.endswith("title"):
                raw_item["title"] = child.text or ""
            elif tag.endswith("link"):
                raw_item["link"] = child.text or ""
            elif tag.endswith("pubdate"):
                raw_item["pubDate"] = child.text or ""
            elif tag.endswith("description"):
                raw_item["description"] = child.text or ""
            elif tag.endswith("encoded"):
                raw_item["content"] = child.text or ""
            elif tag.endswith("guid"):
                raw_item["guid"] = child.text or ""
            elif tag.endswith("author"):
                raw_item["author"] = child.text or ""
            elif tag.endswith("category"):
                raw_item.setdefault("categories", []).append(child.text or "")
        return raw_item

    def _parse_date(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None

        try:
            dt = parsedate_to_datetime(value)
            if dt and dt.tzinfo is None:
                return dt
            return dt
        except (TypeError, ValueError, IndexError):
            return None

    def _classify_threat_type(self, categories: List[str], title: str, content: str) -> Optional[str]:
        """Classify article into threat type based on categories and content."""
        categories_lower = [c.lower() for c in categories]
        title_lower = title.lower()
        content_lower = content.lower()
        combined_text = f"{title_lower} {content_lower}"

        # Keywords for each threat type
        threat_keywords = {
            "Ransomware": ["ransomware", "ransom", "encryption", "decrypt", "lockbit", "blackcat", "alphv", "conti"],
            "Malware": ["malware", "virus", "trojan", "backdoor", "botnet", "stealer", "infostealer"],
            "Data Breach": ["breach", "leak", "exposed", "stolen", "database", "credentials", "password"],
            "Vulnerability": ["vulnerability", "cve", "flaw", "bug", "patch", "exploit", "zero-day"],
            "Exploit": ["exploit", "attack", "hacked", "compromised", "injection", "rce"],
            "Cyber Attack": ["attack", "hacking", "phishing", "ddos", "campaign", "threat actor"],
            "Security News": ["news", "update", "release", "announcement", "report", "study"],
        }

        # Check categories first
        for category in categories_lower:
            for threat_type, keywords in threat_keywords.items():
                if any(keyword in category for keyword in keywords):
                    return threat_type

        # Check title and content
        for threat_type, keywords in threat_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                return threat_type

        # Default to Security News if no match
        return "Security News"
