from datetime import datetime
from email.utils import parsedate_to_datetime
import html
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from app.threat_intel.sources.base import ThreatIntelSource

HACKERNEWS_FEED_URL = "https://feeds.feedburner.com/TheHackersNews"
SOURCE_NAME = "The Hacker News"


class HackerNewsSource(ThreatIntelSource):
    def fetch_articles(self) -> List[Dict[str, Any]]:
        try:
            with urllib.request.urlopen(HACKERNEWS_FEED_URL, timeout=15) as response:
                body = response.read()
        except (urllib.error.URLError, ValueError) as exc:
            raise RuntimeError(f"Unable to fetch Hacker News RSS feed: {exc}") from exc

        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise RuntimeError(f"Unable to parse Hacker News RSS feed XML: {exc}") from exc

        raw_items: List[Dict[str, Any]] = []
        for element in root.iter():
            if element.tag.lower().endswith("item"):
                raw_items.append(self._extract_item(element))

        if not raw_items:
            raise RuntimeError("No items found in Hacker News RSS feed")

        return raw_items

    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        title = (raw_article.get("title") or "").strip()
        url = (raw_article.get("link") or "").strip()
        content = raw_article.get("content") or raw_article.get("description") or ""
        published_date = self._parse_date(raw_article.get("pubDate"))

        if not url:
            raise ValueError("Hacker News article missing URL")

        normalized_content = html.unescape(content).strip() if content else ""

        return {
            "title": title or "Untitled Article",
            "url": url,
            "source": SOURCE_NAME,
            "published_date": published_date,
            "content": normalized_content,
            "threat_type": None,
            "metadata": {
                "guid": raw_article.get("guid"),
                "author": raw_article.get("author"),
                "categories": raw_article.get("categories", []),
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
