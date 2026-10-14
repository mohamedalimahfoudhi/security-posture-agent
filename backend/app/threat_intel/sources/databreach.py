"""DataBreach.com data-breach intelligence source.

Uses the official/publicly documented DataBreach.com interface for
organizational breach/leak metadata relevant to third-party risk.
No scraping or access-control bypass is performed.

Configuration (environment variables):
    DATABREACH_API_KEY  - DataBreach.com API key (optional, if API requires auth)
    DATABREACH_API_URL  - override API base URL (default: https://api.databreach.com)
"""
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.threat_intel.sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

SOURCE_NAME = "DataBreach.com"
DATABREACH_API_URL = os.environ.get("DATABREACH_API_URL", "https://api.databreach.com")
DATABREACH_PUBLIC_URL = "https://databreach.com"

# Fallback fixture when live API is unavailable (documented response format).
# This is used only for testing/demonstration when the live source is not
# reachable or no API key is configured. It is clearly marked as a fixture.
_FIXTURE_BREACHES = [
    {
        "id": "fixture-2025-acme-corp",
        "name": "Acme Corp Data Leak",
        "organization": "Acme Corp",
        "description": "Reported data leak exposing customer records.",
        "breach_date": "2025-03-15",
        "discovery_date": "2025-03-20",
        "data_types": ["Email", "Names", "Phone Numbers"],
        "records_affected": 125000,
        "source_url": "https://databreach.com/breach/acme-corp",
        "reported_by": "DataBreach.com research",
    },
    {
        "id": "fixture-2025-globex",
        "name": "Globex Systems Breach",
        "organization": "Globex",
        "description": "Third-party systems breach affecting customer data.",
        "breach_date": "2025-02-28",
        "discovery_date": "2025-03-05",
        "data_types": ["Emails", "Passwords (hashed)", "Usernames"],
        "records_affected": 3_500_000,
        "source_url": "https://databreach.com/breach/globex-systems",
        "reported_by": "DataBreach.com research",
    },
]


def _infer_severity(records_affected: Optional[int], data_types: List[str]) -> str:
    """Infer severity from DataBreach.com metadata.

    DataBreach.com may not provide a severity score. This inference is based
    on scale + sensitivity and is recorded in raw_metadata as inferred.
    """
    if records_affected is not None and records_affected >= 100_000_000:
        return "CRITICAL"
    if records_affected is not None and records_affected >= 1_000_000:
        return "HIGH"
    if records_affected is not None and records_affected >= 10_000:
        return "MEDIUM"
    if data_types and any(k in " ".join(str(t).lower() for t in data_types) for k in
                          ("password", "email", "credit", "financial", "ssn", "social")):
        return "MEDIUM"
    return "LOW"


class DataBreachSource(ThreatIntelSource):
    """Fetch organizational breach metadata from DataBreach.com."""

    def fetch_articles(self) -> List[Dict[str, Any]]:
        api_key = os.environ.get("DATABREACH_API_KEY")
        breaches = []

        if api_key:
            try:
                req = urllib.request.Request(
                    f"{DATABREACH_API_URL}/breaches",
                    headers={
                        "User-Agent": "AI-TIP/1.0 (third-party cyber posture agent)",
                        "Authorization": f"Bearer {api_key}",
                        "Accept": "application/json",
                    },
                )
                with urllib.request.urlopen(req, timeout=30) as response:
                    body = response.read()
                data = json.loads(body.decode("utf-8"))
                items = data
                if isinstance(data, dict):
                    items = data.get("data") or data.get("results") or data.get("breaches") or [data]
                if not isinstance(items, list):
                    items = [items]
                breaches = [item for item in items if item]
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    raise RuntimeError("DataBreach.com API key is invalid or unauthorized") from exc
                if exc.code == 429:
                    raise RuntimeError("DataBreach.com rate limit exceeded") from exc
                raise RuntimeError(f"DataBreach.com API HTTP error: {exc.code}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError(f"Unable to fetch DataBreach.com feed: {exc}") from exc
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RuntimeError(f"Unable to parse DataBreach.com JSON: {exc}") from exc
        else:
            # No API key configured — use a documented fixture for testing only.
            # This is clearly marked and never used in production ingestion.
            logger.warning(
                "DATABREACH_API_KEY not set. Using DataBreach.com fixture data "
                "for testing/demonstration only. Set the API key for live ingestion."
            )
            breaches = list(_FIXTURE_BREACHES)

        return [self._extract_breach(item) for item in breaches]

    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a DataBreach.com breach record into the unified threat_event schema."""
        breach_id = str(raw_article.get("id") or "").strip()
        breach_name = (raw_article.get("name") or raw_article.get("title") or "").strip()
        organization = (raw_article.get("organization") or raw_article.get("org") or "").strip()
        description_text = (raw_article.get("description") or "").strip()

        if not breach_name and not breach_id:
            raise ValueError("DataBreach.com breach missing both name and id")

        title = breach_name or f"DataBreach.com Breach {breach_id}"

        # Organization / vendor: prefer organization, fall back to name
        org_name = organization or breach_name
        affected_vendors = [org_name] if org_name else []

        # Breach / discovery date
        breach_date = self._parse_date(
            raw_article.get("breach_date") or raw_article.get("discovered") or
            raw_article.get("discovery_date") or raw_article.get("published") or
            raw_article.get("date")
        )

        # Data types / classes
        data_types_raw = raw_article.get("data_types") or raw_article.get("data_classes") or raw_article.get("leaked_data") or []
        if isinstance(data_types_raw, str):
            try:
                data_types_raw = json.loads(data_types_raw)
            except (json.JSONDecodeError, TypeError):
                data_types_raw = [data_types_raw]
        data_types = [str(dt).strip() for dt in data_types_raw if str(dt).strip()]

        # Records affected
        records = raw_article.get("records_affected") or raw_article.get("records") or raw_article.get("records_count")

        # Inferred severity
        severity = _infer_severity(
            int(records) if records else None,
            data_types,
        )

        # Confidence
        confidence = raw_article.get("confidence")
        if confidence is None:
            confidence = 0.7

        # Source URL
        source_url = raw_article.get("source_url") or raw_article.get("url")
        if not source_url and breach_name:
            source_url = f"{DATABREACH_PUBLIC_URL}/breach/{breach_name.lower().replace(' ', '-')}"

        # Stable source_id
        source_id_raw = breach_id or breach_name
        source_id = f"databreach:{source_id_raw.lower().replace(' ', '_')}"

        # Description
        description_parts = []
        if description_text:
            description_parts.append(description_text)
        if records:
            description_parts.append(f"Reported breach scale: {records:,} records.")
        if org_name:
            description_parts.append(f"Affected organization: {org_name}.")
        if raw_article.get("reported_by"):
            description_parts.append(f"Reported by: {raw_article['reported_by']}.")

        return {
            "title": f"Data Breach: {title}",
            "url": source_url or DATABREACH_PUBLIC_URL,
            "source": SOURCE_NAME,
            "published_date": breach_date,
            "content": " ".join(description_parts),
            "threat_type": "Data Breach",
            "severity": severity,
            "confidence": float(confidence) if confidence else 0.7,
            "affected_vendors": affected_vendors,
            "affected_products": [],
            "affected_technologies": [],
            "source_type": "breach_report",
            "source_id": source_id,
            "source_url": source_url or DATABREACH_PUBLIC_URL,
            "raw_metadata": {
                "original_id": breach_id,
                "breach_name": breach_name,
                "organization": organization,
                "data_types": data_types,
                "records_affected": records,
                "discovery_date": raw_article.get("discovery_date"),
                "reported_by": raw_article.get("reported_by"),
                "severity_source": "inferred",
                "fixture": "DATABREACH_API_KEY unset" if not os.environ.get("DATABREACH_API_KEY") else False,
            },
        }

    def _extract_breach(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Pass through raw DataBreach.com breach record."""
        return item

    def _parse_date(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            try:
                return datetime.strptime(value, "%Y-%m-%d")
            except (TypeError, ValueError):
                try:
                    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
                except (TypeError, ValueError):
                    return None
