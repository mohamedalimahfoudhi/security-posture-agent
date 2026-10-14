"""Have I Been Pwned (HIBP) data-breach intelligence source.

Uses the official HIBP API v3 (https://haveibeenpwned.com/API/v3).
Breach metadata is used for organizational/third-party risk monitoring —
no passwords, credentials, or sensitive personal data are retrieved or stored.

Configuration (environment variables):
    HIBP_API_KEY    - HIBP API v3 key (required for API access)
    HIBP_BASE_URL   - override base URL (default: https://haveibeenpwned.com/api/v3)
"""
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.threat_intel.sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

SOURCE_NAME = "HIBP"
HIBP_BASE_URL = os.environ.get("HIBP_BASE_URL", "https://haveibeenpwned.com/api/v3")
HIBP_BREACHES_URL = f"{HIBP_BASE_URL}/breaches"

# HIBP breach values -> severity mapping (inferred, clearly distinguished
# from source-provided values via metadata["severity_source"] = "inferred").
HIBP_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _infer_severity(pwn_count: Optional[int], data_classes: List[str], is_sensitive: bool) -> str:
    """Infer a severity from available breach characteristics.

    HIBP does not provide a severity score. This is a best-effort inference
    based on scale + sensitivity. The inferred nature is recorded in
    raw_metadata so consumers can distinguish it from source-provided values.
    """
    if is_sensitive:
        return "HIGH"
    if pwn_count is not None and pwn_count >= 100_000_000:
        return "CRITICAL"
    if pwn_count is not None and pwn_count >= 1_000_000:
        return "HIGH"
    if pwn_count is not None and pwn_count >= 10_000:
        return "MEDIUM"
    if data_classes and any(k in " ".join(data_classes).lower() for k in ("password", "email", "credit", "financial", "ssn", "social")):
        return "MEDIUM"
    return "LOW"


class HIBPSource(ThreatIntelSource):
    """Fetch organizational breach metadata from HIBP API v3."""

    def fetch_articles(self) -> List[Dict[str, Any]]:
        api_key = os.environ.get("HIBP_API_KEY")
        if not api_key:
            logger.info("[HIBP] HIBP_API_KEY not configured - source skipped")
            # Return empty list to indicate source is skipped (not failed)
            return []

        try:
            req = urllib.request.Request(
                HIBP_BREACHES_URL,
                headers={
                    "User-Agent": "AI-TIP/1.0 (third-party cyber posture agent)",
                    "hibp-api-key": api_key,
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise RuntimeError("HIBP API key is invalid or unauthorized") from exc
            if exc.code == 429:
                raise RuntimeError("HIBP rate limit exceeded") from exc
            raise RuntimeError(f"HIBP API HTTP error: {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Unable to fetch HIBP breach feed: {exc}") from exc

        try:
            import json
            data = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Unable to parse HIBP breach feed JSON: {exc}") from exc

        if not isinstance(data, list):
            raise RuntimeError("Unexpected HIBP response format")

        return [self._extract_breach(item) for item in data]

    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize an HIBP breach record into the unified threat_event schema."""
        breach_name = (raw_article.get("Name") or "").strip()
        title = (raw_article.get("Title") or breach_name).strip()
        domain = (raw_article.get("Domain") or "").strip()

        if not breach_name:
            raise ValueError("HIBP breach missing Name")

        # Parse dates
        breach_date = self._parse_date(raw_article.get("BreachDate"))
        added_date = self._parse_date(raw_article.get("AddedDate"))

        # Data classes
        data_classes = [
            str(dc).strip()
            for dc in (raw_article.get("DataClasses") or [])
            if str(dc).strip()
        ]

        # Organization / vendor name: prefer domain, fall back to title
        org_name = domain or title
        affected_vendors = [org_name] if org_name else []
        affected_products = [title] if title and title != org_name else []

        # Inferred severity (HIBP does not provide one)
        pwn_count = raw_article.get("PwnCount")
        is_sensitive = bool(raw_article.get("IsSensitive", False))
        severity = _infer_severity(pwn_count, data_classes, is_sensitive)

        # Confidence: verified breaches are high confidence
        confidence = 0.9 if raw_article.get("IsVerified", False) else 0.6

        # Stable source_id for dedup
        source_id = f"hibp:{breach_name.lower()}"

        # Description
        description_parts = []
        if raw_article.get("Description"):
            description_parts.append(str(raw_article["Description"]).strip())
        if pwn_count is not None:
            description_parts.append(f"Reported compromise scale: {pwn_count:,} records.")
        org_text = f"Affected organization: {org_name}." if org_name else ""
        if org_text:
            description_parts.append(org_text)

        return {
            "title": f"Data Breach: {title}",
            "url": f"https://haveibeenpwned.com/PwnedWebsites#{breach_name}",
            "source": SOURCE_NAME,
            "published_date": breach_date or added_date,
            "content": " ".join(description_parts),
            "threat_type": "Data Breach",
            "severity": severity,
            "confidence": confidence,
            "affected_vendors": affected_vendors,
            "affected_products": affected_products,
            "affected_technologies": [],
            "source_type": "breach_report",
            "source_id": source_id,
            "source_url": f"https://haveibeenpwned.com/PwnedWebsites#{breach_name}",
            "raw_metadata": {
                "breach_name": breach_name,
                "title": title,
                "domain": domain,
                "pwn_count": pwn_count,
                "data_classes": data_classes,
                "is_verified": raw_article.get("IsVerified", False),
                "is_fabricated": raw_article.get("IsFabricated", False),
                "is_sensitive": is_sensitive,
                "is_retired": raw_article.get("IsRetired", False),
                "is_spam_list": raw_article.get("IsSpamList", False),
                "added_date": raw_article.get("AddedDate"),
                "modified_date": raw_article.get("ModifiedDate"),
                "logo_path": raw_article.get("LogoPath"),
                "severity_source": "inferred",
            },
        }

    def _extract_breach(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Pass through raw HIBP breach record (kept for clarity/testing)."""
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
                return None
