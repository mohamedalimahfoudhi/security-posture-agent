import re
from typing import Any, Dict, List, Optional

from app.database.assessment_repository import get_assets_for_customer
from app.correlation.asset_cve_matcher import calculate_business_risk


VENDOR_ALIASES = {
    "fortinet": ["fortinet", "fortigate", "fortios", "fortinet inc", "fortinet inc."],
    "cisco": ["cisco", "cisco systems", "cisco systems inc", "cisco systems inc."],
    "microsoft": ["microsoft", "ms", "windows", "azure"],
    "palo alto": ["palo alto", "paloalto", "palo alto networks"],
    "microsoft corporation": ["microsoft", "ms", "windows", "azure"],
}


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).lower().strip()
    text = re.sub(r"[^a-z0-9 _.-]", " ", text)
    return re.sub(r"\s+", " ", text)


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [normalize_text(item) for item in value if normalize_text(item)]
    if isinstance(value, str):
        normalized = normalize_text(value)
        if not normalized:
            return []
        return [item for item in re.split(r"[,;\n]", normalized) if item.strip()]
    return [normalize_text(value)]


def _normalize_vendor_aliases(vendor: str) -> List[str]:
    if not vendor:
        return []
    vendor_norm = normalize_text(vendor)
    for canonical, aliases in VENDOR_ALIASES.items():
        if vendor_norm in aliases:
            return aliases
    return [vendor_norm]


def _match_type_from_fields(fields: List[str]) -> str:
    if not fields:
        return "unknown"
    if "vendor" in fields and "technology" in fields:
        return "vendor+technology"
    return ", ".join(sorted(set(fields)))


def _build_match_text(fields: List[str]) -> str:
    if not fields:
        return "No strong match fields detected"
    return "Matched fields: " + ", ".join(sorted(set(fields)))


def _build_reason(fields: List[str], article: Dict[str, Any], asset: Dict[str, Any]) -> str:
    if not fields:
        return "No strong match criteria identified."
    parts = [f"Match based on {', '.join(sorted(set(fields)))}."]
    if article.get("cves"):
        parts.append("Article contains specific CVEs that align with the affected asset.")
    if asset.get("vendor") and asset.get("technology"):
        parts.append(f"Affected asset vendor is {asset.get('vendor')} and technology is {asset.get('technology')}.")
    return " ".join(parts)


def _derive_matched_value(fields: List[str], asset: Dict[str, Any]) -> str:
    if not fields:
        return ""
    if "technology" in fields:
        return str(asset.get("technology") or "").strip()
    if "vendor" in fields:
        return str(asset.get("vendor") or "").strip()
    if "product" in fields:
        return str(asset.get("technology") or "").strip()
    return ", ".join(fields)


def _score_asset_match(article: Dict[str, Any], asset: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title = normalize_text(article.get("title"))
    summary = normalize_text(article.get("summary"))
    content_text = " ".join([title, summary]).strip()

    article_vendors = _ensure_list(article.get("vendors"))
    article_products = _ensure_list(article.get("products"))
    article_cves = _ensure_list(article.get("cves"))

    asset_vendor = normalize_text(asset.get("vendor"))
    asset_technology = normalize_text(asset.get("technology"))
    asset_version = normalize_text(asset.get("version"))

    vendor_aliases = _normalize_vendor_aliases(asset.get("vendor") or "")

    score = 0
    matched_fields: List[str] = []

    if asset_vendor and asset_vendor in article_vendors:
        score += 40
        matched_fields.append("vendor")

    if asset_technology and asset_technology in article_products:
        score += 30
        matched_fields.append("product")

    if asset_technology and asset_technology in content_text:
        score += 30
        matched_fields.append("technology")

    if asset_vendor and asset_vendor in content_text and "vendor" not in matched_fields:
        score += 20
        matched_fields.append("vendor")

    for alias in vendor_aliases:
        if alias and alias in content_text and alias != asset_vendor and "vendor" not in matched_fields:
            score += 25
            matched_fields.append("vendor")
            break

    if asset_version and asset_version in content_text:
        score += 10
        matched_fields.append("version")

    if article_cves and asset_technology and asset_technology in content_text:
        score += 10
    if article_cves and asset_vendor and asset_vendor in content_text:
        score += 10
    if article_cves and asset_vendor and any(cve in content_text for cve in article_cves):
        score += 5
    if article_cves and asset_technology and any(cve in content_text for cve in article_cves):
        score += 5

    if asset_technology and asset_technology in article_vendors:
        score += 20
        if "technology" not in matched_fields:
            matched_fields.append("technology")

    if asset_vendor and asset_vendor in article_products:
        score += 15
        if "vendor" not in matched_fields:
            matched_fields.append("vendor")

    if score < 25:
        return None

    correlation_score = min(100, int(score))

    asset_result = {
        "internet_exposed": asset.get("internet_exposed", False),
        "criticality": asset.get("criticality") or "MEDIUM",
        "sensitive_data": asset.get("sensitive_data", False),
        "confidence": asset.get("confidence") or 50,
    }
    risk_score, priority = calculate_business_risk(asset_result, correlation_score)

    correlation_details = {
        "article_vendors": article_vendors,
        "article_products": article_products,
        "article_cves": article_cves,
        "asset_vendor": asset_vendor,
        "asset_technology": asset_technology,
        "asset_version": asset_version,
    }

    matched_value = _derive_matched_value(matched_fields, asset)
    reason = _build_reason(matched_fields, article, asset)

    return {
        "asset_id": asset.get("id"),
        "asset_technology": asset.get("technology"),
        "asset_vendor": asset.get("vendor"),
        "asset_version": asset.get("version"),
        "match_type": _match_type_from_fields(matched_fields),
        "match_text": _build_match_text(matched_fields),
        "matched_value": matched_value,
        "reason": reason,
        "correlation_score": correlation_score,
        "risk_score": risk_score,
        "priority": priority,
        "correlation_details": correlation_details,
    }


def match_article_to_assets_for_assets(article: Dict[str, Any], assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for asset in assets:
        scored = _score_asset_match(article, asset)
        if scored:
            matches.append(scored)

    matches.sort(key=lambda match: match["correlation_score"], reverse=True)
    return matches


def match_article_to_assets(customer_id: int, article: Dict[str, Any]) -> List[Dict[str, Any]]:
    assets = get_assets_for_customer(customer_id)
    return match_article_to_assets_for_assets(article, assets)
