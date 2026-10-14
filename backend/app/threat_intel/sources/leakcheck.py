"""LeakCheck data-breach intelligence source.

Uses the official LeakCheck API for organizational breach metadata.
Only breach/event metadata and organizational/domain-level information
are used — no passwords, authentication tokens, or sensitive personal
data are retrieved or stored.

Configuration (environment variables):
    LEAKCHECK_API_KEY  - LeakCheck API key (required)
    LEAKCHECK_API_URL  - override API base URL (default: https://leakcheck.net/api/v2)
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

SOURCE_NAME = "LeakCheck"
LEAKCHECK_API_URL = os.environ.get("LEAKCHECK_API_URL", "https://leakcheck.net/api/v2")
LEAKCHECK_PUBLIC_URL = "https://leakcheck.net"


def _infer_severity(records_count: Optional[int], data_types: List[str]) -> str:
    """Infer severity from LeakCheck breach metadata.

    LeakCheck does not provide a severity score. This is an inferred value
    based on scale and sensitivity. The inferred nature is recorded in
    raw_metadata.
    """
    if records_count is not None and records_count >= 100_000_000:
        return "CRITICAL"
    if records_count is not None and records_count >= 1_000_000:
        return "HIGH"
    if records_count is not None and records_count >= 10_000:
        return "MEDIUM"
    if data_types and any(k in " ".join(str(t).lower() for t in data_types) for k in
                          ("password", "email", "credit", "financial", "ssn", "social")):
        return "MEDIUM"
    return "LOW"


class LeakCheckSource(ThreatIntelSource):
    """Fetch organizational breach metadata from LeakCheck API."""

    def fetch_articles(self) -> List[Dict[str, Any]]:
        api_key = os.environ.get("LEAKCHECK_API_KEY")
        if not api_key:
            logger.info("[LEAKCHECK] LEAKCHECK_API_KEY not configured - source skipped")
            # Return empty list to indicate source is skipped (not failed)
            return []

        try:
            req = urllib.request.Request(
                f"{LEAKCHECK_API_URL}/breaches",
                headers={
                    "User-Agent": "AI-TIP/1.0 (third-party cyber posture agent)",
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise RuntimeError("LeakCheck API key is invalid or unauthorized") from exc
            if exc.code == 429:
                raise RuntimeError("LeakCheck rate limit exceeded") from exc
            raise RuntimeError(f"LeakCheck API HTTP error: {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Unable to fetch LeakCheck breach feed: {exc}") from exc

        try:
            data = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Unable to parse LeakCheck response JSON: {exc}") from exc

        # Handle various response wrappers
        items = data
        if isinstance(data, dict):
            items = data.get("data") or data.get("results") or data.get("breaches") or [data]

        if not isinstance(items, list):
            items = [items]

        return [self._extract_breach(item) for item in items if item]

    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a LeakCheck breach record into the unified threat_event schema."""
        breach_id = str(raw_article.get("id") or raw_article.get("_id") or "").strip()
        breach_name = (raw_article.get("name") or raw_article.get("title") or "").strip()
        domain = (raw_article.get("domain") or raw_article.get("source") or "").strip()
        description_text = (raw_article.get("description") or raw_article.get("info") or "").strip()

        if not breach_name and not breach_id:
            raise ValueError("LeakCheck breach missing both name and id")

        title = breach_name or f"LeakCheck Breach {breach_id}"

        # Organization / vendor: prefer domain, fall back to name
        org_name = domain or breach_name
        affected_vendors = [org_name] if org_name else []

        # Breach / discovery date
        breach_date = self._parse_date(
            raw_article.get("breach_date") or raw_article.get("date") or
            raw_article.get("discovered") or raw_article.get("published")
        )

        # Data types / classes
        data_types_raw = raw_article.get("data_types") or raw_article.get("leaked_data") or raw_article.get("types") or []
        if isinstance(data_types_raw, str):
            try:
                data_types_raw = json.loads(data_types_raw)
            except (json.JSONDecodeError, TypeError):
                data_types_raw = [data_types_raw]
        data_types = [str(dt).strip() for dt in data_types_raw if str(dt).strip()]

        # Records count
        records_count = raw_article.get("records") or raw_article.get("records_count") or raw_article.get("lines")

        # Inferred severity
        severity = _infer_severity(
            int(records_count) if records_count else None,
            data_types,
        )

        # Confidence
        confidence = raw_article.get("confidence")
        if confidence is None:
            confidence = 0.7  # moderate default for LeakCheck

        # Stable source_id
        source_id_raw = breach_id or breach_name
        source_id = f"leakcheck:{source_id_raw.lower().replace(' ', '_')}"

        # Description
        description_parts = []
        if description_text:
            description_parts.append(description_text)
        if records_count:
            description_parts.append(f"Reported breach scale: {records_count:,} records.")
        if org_name:
            description_parts.append(f"Affected organization: {org_name}.")

        return {
            "title": f"Data Breach: {title}",
            "url": f"{LEAKCHECK_PUBLIC_URL}/breach/{breach_name.lower().replace(' ', '-')}" if breach_name else LEAKCHECK_PUBLIC_URL,
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
            "source_url": f"{LEAKCHECK_PUBLIC_URL}/breach/{breach_name.lower().replace(' ', '-')}" if breach_name else LEAKCHECK_PUBLIC_URL,
            "raw_metadata": {
                "original_id": breach_id,
                "breach_name": breach_name,
                "domain": domain,
                "records_count": records_count,
                "data_types": data_types,
                "severity_source": "inferred",
            },
        }

    def _extract_breach(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant fields with safe defaults."""
        return {
            "id": item.get("id") or item.get("_id"),
            "name": item.get("name") or item.get("title"),
            "domain": item.get("domain") or item.get("source"),
            "description": item.get("description") or item.get("info"),
            "breach_date": item.get("breach_date") or item.get("date") or item.get("discovered") or item.get("published"),
            "records": item.get("records") or item.get("records_count") or item.get("lines"),
            "data_types": item.get("data_types") or item.get("leaked_data") or item.get("types"),
            "confidence": item.get("confidence"),
        }

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
