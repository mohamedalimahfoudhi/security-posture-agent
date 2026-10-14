"""
External Attack Surface Monitoring.

Detects changes in third-party external assets (domains, subdomains, IPs,
ports, exposed services, certificates, public applications).

Baseline → current observation → diff → risk evaluation → EXTERNAL_EXPOSURE alert.

Design principles:
- Do NOT fabricate scan results.
- If no discovery provider is configured, the system clearly represents that
  monitoring is unavailable (it does not invent assets).
- A provider abstraction allows a real scanner/API to be connected later.
- Changes are only raised as alerts when evidence supports applicability.
- Idempotent: a change that already produced an alert is not re-alerted.
"""
import logging
import os
from typing import Any, Dict, List, Optional

from app.database.connection import get_connection

logger = logging.getLogger(__name__)


class ExternalAssetDiscoveryProvider:
    """Abstract base for external attack-surface discovery providers.

    A concrete provider (e.g. a DNS/HTTP scanner, Censys, Shodan, SecurityTrails)
    would subclass this and return real observations. Without a configured
    provider, monitoring is explicitly unavailable (not faked).
    """

    def is_configured(self) -> bool:
        return False

    def is_enabled(self) -> bool:
        return False

    def discover(self, domain: str) -> List[Dict[str, Any]]:
        """Return a list of observed external assets for a domain.

        Each observation: {asset_type, value, exposure_status}.
        """
        raise NotImplementedError


class DnsBasedDiscoveryProvider(ExternalAssetDiscoveryProvider):
    """Minimal provider that discovers subdomains/IPs from public DNS.

    Uses Python's built-in socket/DNS resolution — no external API key required.
    This is a lightweight, real discovery mechanism (not fabricated). Without
    network access it returns empty and monitoring is "unavailable".
    """

    def __init__(self):
        self._enabled = os.getenv("EXTERNAL_ASM_ENABLED", "true").lower() in ("1", "true", "yes")

    def is_configured(self) -> bool:
        return self._enabled and os.getenv("EXTERNAL_ASM_SOURCE") not in (None, "", "none")

    def is_enabled(self) -> bool:
        return self.is_configured()

    def discover(self, domain: str) -> List[Dict[str, Any]]:
        if not self.is_configured():
            return []
        import socket
        observations = []
        try:
            # A domain's A/AAAA record(s)
            addrinfo = socket.getaddrinfo(domain, None, socket.AF_UNSPEC)
            seen = set()
            for addr in addrinfo:
                # getaddrinfo returns (family, type, proto, canonname, sockaddr)
                ip = addr[4][0] if len(addr) >= 5 and addr[4] else None
                if ip and ip not in seen:
                    seen.add(ip)
                    observations.append({
                        "asset_type": "IP",
                        "value": str(ip),
                        "exposure_status": "EXPOSED",
                    })
            # A subdomain brute force / common names would be added by a
            # real provider. Keep this minimal + real: only resolve the domain.
            if domain and not seen:
                observations.append({
                    "asset_type": "DOMAIN",
                    "value": domain,
                    "exposure_status": "UNKNOWN",
                })
        except Exception as exc:
            logger.warning("[EXTERNAL ASM] DNS discovery failed for %s: %s", domain, exc)
        return observations


# Registry of available providers. Only providers whose requirements are met
# are used. With no provider configured, monitoring is absent (never faked).
_PROVIDERS: List[ExternalAssetDiscoveryProvider] = [
    DnsBasedDiscoveryProvider(),
]


def get_active_provider() -> Optional[ExternalAssetDiscoveryProvider]:
    """Return the first configured/enabled discovery provider, or None."""
    for provider in _PROVIDERS:
        if provider.is_enabled():
            return provider
    return None


def _load_customer_vendor_domains(cur) -> List[Dict[str, Any]]:
    """Return (customer_vendor_id, vendor, customer_id, domain) for each
    external asset already persisted for a customer's third-party profile."""
    cur.execute("""
        SELECT cv.id, cv.vendor, x.value, x.id, cv.customer_id
        FROM third_party_external_assets x
        JOIN third_party_profiles p ON p.id = x.profile_id
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE x.asset_type IN ('DOMAIN', 'HOST', 'SUBDOMAIN')
    """)
    return [
        {"customer_vendor_id": r[0], "vendor": r[1], "value": r[2], "asset_id": r[3], "customer_id": r[4]}
        for r in cur.fetchall()
    ]


def _load_existing_observations(cur, profile_id: int) -> Dict[str, Any]:
    """Load the current persisted asset state (baseline) for a profile."""
    cur.execute("""
        SELECT asset_type, value, exposure_status
        FROM third_party_external_assets
        WHERE profile_id = %s
    """, (profile_id,))
    baseline = {}
    for at, val, status in cur.fetchall():
        baseline.setdefault((at or "UNKNOWN", val or ""), status or "UNKNOWN")
    return baseline


def _persist_observation(cur, profile_id: int, obs: Dict[str, Any], customer_vendor_id: int) -> bool:
    """Persist a new observation if it is not already present. Returns True if new."""
    asset_type = obs.get("asset_type") or "UNKNOWN"
    value = obs.get("value") or ""
    status = obs.get("exposure_status") or "UNKNOWN"
    if not value:
        return False

    cur.execute("""
        SELECT id FROM third_party_external_assets
        WHERE profile_id = %s AND asset_type = %s AND value = %s
    """, (profile_id, asset_type, value))
    if cur.fetchone():
        return False

    cur.execute("""
        INSERT INTO third_party_external_assets (profile_id, asset_type, value, exposure_status, last_seen)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
    """, (profile_id, asset_type, value, status))
    return True


def _raise_exposure_alert(
    cur,
    customer_id: int,
    customer_vendor_id: int,
    profile_id: Optional[int],
    vendor: str,
    asset_type: str,
    asset_value: str,
    status: str,
) -> bool:
    """Create an EXTERNAL_EXPOSURE alert if one does not already exist."""
    if not profile_id:
        return False

    # Idempotency: don't re-alert the same new asset
    cur.execute("""
        SELECT 1 FROM third_party_alerts
        WHERE customer_vendor_id = %s AND alert_type = 'EXTERNAL_EXPOSURE'
          AND affected_technology = %s
        LIMIT 1
    """, (customer_vendor_id, asset_value))
    if cur.fetchone():
        return False

    risk = 60  # Newly discovered external asset is inherently medium-high
    severity = "HIGH"

    evidence = [
        f"External asset discovered: {asset_type} {asset_value}",
        "New observation not present in previous baseline",
    ]
    business_relevance = f"Third-party {vendor} has a newly discovered {asset_type} ({asset_value}) that was not present in the previous baseline."
    recommended_action = f"Validate whether {asset_value} is an authorized, securely configured external service belonging to {vendor}."

    cur.execute("""
        INSERT INTO third_party_alerts (
            customer_id, customer_vendor_id, profile_id,
            vendor, affected_technology, alert_type, severity,
            risk_score, risk_delta, confidence, confidence_reasons,
            evidence, business_relevance, recommended_action,
            status, source_type, created_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, 'EXTERNAL_EXPOSURE', %s,
                  %s, 0, 0.6, %s, %s, %s, %s, 'NEW', 'external_monitoring',
                  CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """, (
        customer_id, customer_vendor_id, profile_id,
        vendor, asset_value, severity,
        risk, "[]", 
        "[]",
        business_relevance, recommended_action,
    ))
    return True


def run_external_asset_monitoring() -> Dict[str, Any]:
    """Run the external attack-surface monitoring pass.

    If no discovery provider is configured, monitoring is explicitly marked
    unavailable (not faked). If a provider is configured, it discovers assets
    for each vendor domain already in the inventory, persists newly observed
    assets, and raises EXTERNAL_EXPOSURE alerts for genuinely new assets.

    Returns a summary dict.
    """
    provider = get_active_provider()
    if provider is None:
        return {
            "monitoring_available": False,
            "reason": "No external attack-surface provider configured. Set EXTERNAL_ASM_SOURCE "
                      "to a supported provider (e.g. dns) to enable discovery.",
            "assets_discovered": 0,
            "changes_detected": 0,
            "alerts_created": 0,
        }

    conn = get_connection()
    cur = conn.cursor()
    discovered = 0
    changes = 0
    alerts_created = 0

    try:
        # Get all persisted DOMAIN/HOST assets across tenant-scoped profiles
        vendor_domains = _load_customer_vendor_domains(cur)

        for vd in vendor_domains:
            profile_id = _load_profile_id_for_asset(cur, vd)
            if not profile_id:
                continue

            # Baseline: current persisted state
            baseline = _load_existing_observations(cur, profile_id)

            # Discover current observations from the provider
            observations = provider.discover(vd["value"])
            for obs in observations:
                key = (obs.get("asset_type") or "UNKNOWN", obs.get("value") or "")
                if not key[1]:
                    continue
                # New observation not in baseline → change detected
                if key not in baseline:
                    if _persist_observation(cur, profile_id, obs, vd["customer_vendor_id"]):
                        discovered += 1
                        changes += 1
                        if _raise_exposure_alert(
                            cur,
                            vd["customer_id"],
                            vd["customer_vendor_id"],
                            profile_id,
                            vd["vendor"],
                            obs.get("asset_type") or "UNKNOWN",
                            obs.get("value") or "",
                            obs.get("exposure_status") or "UNKNOWN",
                        ):
                            alerts_created += 1

        conn.commit()
        return {
            "monitoring_available": True,
            "provider": provider.__class__.__name__,
            "assets_discovered": discovered,
            "changes_detected": changes,
            "alerts_created": alerts_created,
        }
    except Exception:
        conn.rollback()
        logger.exception("[EXTERNAL ASM] Monitoring pass failed")
        raise
    finally:
        cur.close()
        conn.close()


def _load_profile_id_for_asset(cur, vd: Dict[str, Any]) -> Optional[int]:
    """Resolve the profile_id for a persisted external asset."""
    cur.execute("""
        SELECT p.id
        FROM third_party_external_assets x
        JOIN third_party_profiles p ON p.id = x.profile_id
        WHERE x.id = %s
    """, (vd["asset_id"],))
    row = cur.fetchone()
    return row[0] if row else None