from datetime import datetime, timedelta
import html
import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from app.threat_intel.sources.base import ThreatIntelSource

# Reuse the existing technology alias/normalization database.
try:
    from app.ai.technology_patterns import (
        TECHNOLOGY_PATTERNS as _TECH_PATTERNS,
        get_aliases as _get_tech_aliases,
        get_technology_by_name as _get_tech_by_name,
    )
except Exception:  # pragma: no cover - defensive import guard
    _TECH_PATTERNS = []
    _get_tech_aliases = lambda: {}
    _get_tech_by_name = lambda _name: {}

# NVD provides recent CVEs via the JSON 2.0 API. With no date range, the API
# returns the most recently published/modified CVEs (last ~120 days).
NVD_CVE_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE_NAME = "NVD CVE Database"

# Overly-generic alias tokens that would cause false positives if matched in
# a description fallback (e.g. "linux", "java", "php", "ios" appear everywhere).
GENERIC_TECH_TOKENS = {"linux", "java", "php", "ios", "mssql", "f5"}


def _normalize_token(value: str) -> str:
    """Normalize a vendor/product token to a comparable key."""
    if not value:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _cpe_vendor_product(cpe: str):
    """Extract (vendor, product, version) from a cpe:2.3 string when possible."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    vendor = parts[3].replace("_", " ").strip()
    product = parts[4].replace("_", " ").strip()
    version = parts[5]
    if vendor in ("*", "-") or product in ("*", "-"):
        return None
    return vendor, product, version


def _version_texts(affected, cpes):
    """Collect version strings (including ranges) from affected + CPE entries."""
    versions = []
    for entry in affected or []:
        for v in entry.get("versions", []) or []:
            val = v.get("version")
            if val:
                versions.append(val)
            for status, symbol in (("lessThan", "<"), ("lessThanOrEqual", "<=")):
                op_val = v.get(status)
                if op_val:
                    versions.append(f"{symbol} {op_val}")
    for cpe in cpes or []:
        parsed = _cpe_vendor_product(cpe)
        if parsed and parsed[2] not in ("*", "-"):
            versions.append(parsed[2])
    return list(dict.fromkeys(versions))[:20]


class CVESource(ThreatIntelSource):
    def fetch_articles(self) -> List[Dict[str, Any]]:
        # Bound the query to the last 30 days to keep the response small and
        # avoid pulling the full 120-day window on every refresh.
        since = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
        url = f"{NVD_CVE_FEED_URL}?pubStartDate={since}&pubEndDate={datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')}"

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (CTI-Agent)"},
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                body = response.read()
        except (urllib.error.URLError, ValueError) as exc:
            raise RuntimeError(f"Unable to fetch NVD CVE feed: {exc}") from exc

        try:
            data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"Unable to parse NVD CVE feed JSON: {exc}") from exc

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            raise RuntimeError("No CVE entries found in NVD feed")

        raw_items = [self._extract_cve_entry(item) for item in vulnerabilities]
        return raw_items

    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = raw_article.get("id", "").strip()
        description = raw_article.get("description", "").strip()
        published_date = raw_article.get("published_date")
        severity = raw_article.get("severity", "UNKNOWN")
        cvss_score = raw_article.get("cvss_score")

        if not cve_id:
            raise ValueError("CVE entry missing ID")

        normalized_description = html.unescape(description).strip() if description else ""

        affected_vendors = raw_article.get("affected_vendors") or []
        affected_products = raw_article.get("affected_products") or []
        affected_technologies = raw_article.get("affected_technologies") or []
        affected_versions = raw_article.get("affected_versions") or []

        return {
            "title": f"{cve_id} ({severity} Severity)" if severity != "UNKNOWN" else cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source": SOURCE_NAME,
            "published_date": published_date,
            "content": normalized_description,
            "threat_type": "Vulnerability",
            # Top-level structured fields consumed downstream by the correlator.
            "affected_vendors": affected_vendors,
            "affected_products": affected_products,
            "affected_technologies": affected_technologies,
            "affected_versions": affected_versions,
            "metadata": {
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_products": affected_products,
                "affected_vendors": affected_vendors,
                "affected_technologies": affected_technologies,
                "affected_versions": affected_versions,
                "references": raw_article.get("references", []),
            },
        }

    def _extract_cve_entry(self, item: Dict[str, Any]) -> Dict[str, Any]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Severity / CVSS v3.1 (fall back to v2)
        severity = "UNKNOWN"
        cvss_score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if not metric_list:
                continue
            cvss_data = metric_list[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                cvss_score = base_score
            base_severity = cvss_data.get("baseSeverity")
            if base_severity:
                severity = base_severity
            if cvss_score is not None:
                break

        # ---- Structured vendor/product/technology extraction ----
        affected = cve.get("affected", []) or []
        cpes = [c for entry in affected for c in (entry.get("cpes") or [])]

        affected_vendors: list = []
        affected_products: list = []
        affected_technologies: list = []

        # 1. Structured 'affected' entries (authoritative)
        for entry in affected:
            vendor = (entry.get("vendor") or "").replace("_", " ").strip()
            product = (entry.get("product") or "").replace("_", " ").strip()
            if vendor and vendor.lower() not in {v.lower() for v in affected_vendors}:
                affected_vendors.append(vendor)
            if product and product.lower() not in {p.lower() for p in affected_products}:
                affected_products.append(product)

        # 2. CPE strings (authoritative vendor/product source)
        for cpe in cpes:
            parsed = _cpe_vendor_product(cpe)
            if not parsed:
                continue
            vendor, product, _ver = parsed
            if vendor.lower() not in {v.lower() for v in affected_vendors}:
                affected_vendors.append(vendor)
            if product.lower() not in {p.lower() for p in affected_products}:
                affected_products.append(product)

        # 3. Canonical technology names via the existing alias map
        tech_aliases = _get_tech_aliases()
        for product in affected_products:
            canonical = tech_aliases.get(_normalize_token(product)) or tech_aliases.get(product.lower())
            if canonical and canonical not in affected_technologies:
                affected_technologies.append(canonical)

        # 4. Guarded description fallback (only when structured data is empty)
        if not affected_vendors or not affected_technologies:
            self._apply_description_fallback(
                description, affected_vendors, affected_products,
                affected_technologies, tech_aliases,
            )

        affected_vendors = list(dict.fromkeys(affected_vendors))
        affected_products = list(dict.fromkeys(affected_products))
        affected_technologies = list(dict.fromkeys(affected_technologies))
        affected_versions = _version_texts(affected, cpes)

        # References
        references = []
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        # Published date
        published_str = cve.get("published")
        published_date = None
        if published_str:
            try:
                published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except (TypeError, ValueError):
                published_date = None

        return {
            "id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "published_date": published_date,
            "affected_vendors": affected_vendors,
            "affected_products": affected_products,
            "affected_technologies": affected_technologies,
            "affected_versions": affected_versions,
            "references": references,
        }

    def _apply_description_fallback(self, description, affected_vendors, affected_products,
                                    affected_technologies, tech_aliases):
        """Match known technology aliases + vendor names in the description.

        Only adds technologies/vendors that already exist in the curated
        technology_patterns DB — it never invents names from arbitrary words.
        """
        if not description:
            return
        lower = description.lower()

        # 1. Technology aliases (e.g. "apache http server", "sql server")
        for alias, canonical in tech_aliases.items():
            if not alias or len(alias) < 4:
                continue
            if alias in GENERIC_TECH_TOKENS:
                continue
            if alias in lower:
                if canonical not in affected_technologies:
                    affected_technologies.append(canonical)
                if canonical not in affected_products:
                    affected_products.append(canonical)

        # 2. Curated vendor names (e.g. "Microsoft", "Oracle", "Cisco").
        #    Matches the canonical vendor of any known pattern so known-vendor
        #    CVEs (e.g. "Microsoft Exchange Server") resolve even when there is
        #    no technology-alias entry for the exact product.
        matched_vendors = set()
        for entry in _TECH_PATTERNS:
            vendor = (entry.get("vendor") or "").strip()
            if not vendor or vendor.lower() in matched_vendors:
                continue
            vendor_key = vendor.lower()
            if vendor_key in GENERIC_TECH_TOKENS:
                continue
            # Match the human-readable vendor name or its first word(s).
            if vendor_key in lower or vendor.split()[0].lower() in lower:
                if vendor not in affected_vendors:
                    affected_vendors.append(vendor)
                matched_vendors.add(vendor_key)
                # If no explicit technology was found but a vendor matched,
                # surface the vendor's canonical product/technology as well so
                # downstream correlation has something to work with.
                canonical_tech = entry.get("name")
                if not affected_technologies and canonical_tech and canonical_tech not in affected_technologies:
                    affected_technologies.append(canonical_tech)
                if not affected_products and canonical_tech and canonical_tech not in affected_products:
                    affected_products.append(canonical_tech)

    def _parse_date(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
