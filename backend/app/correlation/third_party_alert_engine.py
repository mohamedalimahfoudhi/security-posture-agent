"""
Third-Party Alert Engine.

Generates analyst-reviewable third-party SOC alerts from:
- third_party_exposures
- threat_events
- architecture_changes
- customer_vendors
- third_party_profiles

Each alert is customer-specific (business relevance + risk score differ per
customer for the same threat), explainable (evidence + confidence reasons),
and idempotent (re-running never creates duplicate alerts).

Alert types:
- VULNERABILITY
- BREACH
- RANSOMWARE
- SECURITY_INCIDENT
- ATTACK_TECHNIQUE
- ARCHITECTURE_CHANGE
- EXTERNAL_EXPOSURE
- OTHER
"""
import json
import logging
from typing import Dict, Any, List, Optional

from app.database.connection import get_connection
from app.notifications import get_email_service

logger = logging.getLogger(__name__)

# Business context weights (customer-specific)
BUSINESS_WEIGHTS = {
    "criticality": {"CRITICAL": 25, "HIGH": 18, "MEDIUM": 10, "LOW": 0},
    "privileged_access": 15,
    "data_access": {"SENSITIVE": 15, "HIGH": 12, "MEDIUM": 8, "LOW": 3, "NONE": 0},
    "business_role": 5,  # if a business role is set
}

# Threat severity base scores
THREAT_BASE = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 25,
    "LOW": 10,
    "UNKNOWN": 15,
}

# Exploitation / ransomware / breach keyword sets
EXPLOIT_KEYWORDS = ["exploit", "exploitation", "exploited", "metasploit", "poc", "proof of concept", "weaponized"]
RANSOMWARE_KEYWORDS = ["ransomware", "extortion", "ransom", "lockbit", "blackcat", "clop", "hive", "conti"]
BREACH_KEYWORDS = ["breach", "data breach", "compromised", "leaked", "exfiltrated", "stolen data", "incident disclosure"]
ATTACK_TECHNIQUE_KEYWORDS = ["attack technique", "tactic", "technique", "mitre", "kill chain", "lateral movement", "privilege escalation"]


def _classify_alert_type(event: Dict[str, Any]) -> str:
    """Classify a threat event into an alert type based on its content."""
    text = " ".join(filter(None, [
        event.get("title") or "",
        event.get("description") or "",
        event.get("cve_id") or "",
    ])).lower()

    # Prefer structured MITRE technique IDs in raw_metadata over keyword heuristics
    try:
        raw = event.get("raw_metadata") or {}
        if isinstance(raw, str):
            raw = json.loads(raw)
        mitre_list = raw.get("mitre_techniques")
    except Exception:
        mitre_list = None

    if isinstance(mitre_list, list) and len(mitre_list) > 0:
        # Optional validation: ensure IDs look like ATT&CK IDs (e.g., TXXXX or TXXXX.XXX)
        if all(isinstance(t, str) and t.upper().startswith("T") and len(t.split(".")[0]) >= 5 for t in mitre_list):
            return "ATTACK_TECHNIQUE"
    # Fallback to existing keyword checks (retain for backward compatibility, but no longer trigger ATTACK_TECHNIQUE)
    if any(k in text for k in RANSOMWARE_KEYWORDS):
        return "RANSOMWARE"
    if any(k in text for k in BREACH_KEYWORDS):
        return "BREACH"
    # NOTE: ATTACK_TECHNIQUE_KEYWORDS removed – no longer triggers based on text
    if event.get("cve_id") or event.get("source_type") == "cve":
        return "VULNERABILITY"
    if event.get("source_type") in ("breach_report", "incident"):
        return "SECURITY_INCIDENT"
    return "OTHER"


def _compute_customer_risk(
    event: Dict[str, Any],
    vendor_ctx: Dict[str, Any],
    profile_ctx: Dict[str, Any],
) -> int:
    """Compute a customer-specific risk score (0-100).

    Combines threat severity with business context:
    - Critical vendor + critical CVE -> high risk
    - Low-criticality vendor + same CVE -> lower risk
    """
    base = THREAT_BASE.get((event.get("severity") or "UNKNOWN").upper(), 15)
    score = base

    # Business context
    crit = (vendor_ctx.get("criticality") or "MEDIUM").upper()
    score += BUSINESS_WEIGHTS["criticality"].get(crit, 10)

    if profile_ctx.get("privileged_access"):
        score += BUSINESS_WEIGHTS["privileged_access"]

    access = (profile_ctx.get("data_access_level") or vendor_ctx.get("data_sensitivity") or "MEDIUM").upper()
    score += BUSINESS_WEIGHTS["data_access"].get(access, 5)

    if profile_ctx.get("business_role"):
        score += BUSINESS_WEIGHTS["business_role"]

    # Threat-specific boosts
    text = " ".join(filter(None, [event.get("title") or "", event.get("description") or ""])).lower()
    if any(k in text for k in EXPLOIT_KEYWORDS):
        score += 15
    if any(k in text for k in RANSOMWARE_KEYWORDS):
        score += 20
    if any(k in text for k in BREACH_KEYWORDS):
        score += 15

    return min(100, score)


def _compute_confidence(
    event: Dict[str, Any],
    exposure: Optional[Dict[str, Any]],
    profile_ctx: Dict[str, Any],
) -> tuple[float, List[str]]:
    """Compute confidence (0-1) and confidence reasons from evidence quality."""
    confidence = 0.5
    reasons = []

    # Exact technology match in profile
    if exposure and exposure.get("affected_technology"):
        confidence += 0.2
        reasons.append("Exact technology match in customer profile")

    # Exact vendor match
    if exposure and exposure.get("match_type") in ("vendor_direct", "alias_resolution"):
        confidence += 0.15
        reasons.append("Exact vendor match")

    # Confirmed CVE
    if event.get("cve_id"):
        confidence += 0.1
        reasons.append("Confirmed CVE identifier")

    # Customer profile confirms technology
    if profile_ctx.get("technologies"):
        reasons.append("Customer profile confirms technology footprint")

    # Exploitation reported
    text = " ".join(filter(None, [event.get("title") or "", event.get("description") or ""])).lower()
    if any(k in text for k in EXPLOIT_KEYWORDS):
        confidence += 0.1
        reasons.append("Exploitation publicly reported")

    # Lower confidence for inferred matches
    if exposure and exposure.get("match_type") == "text_fallback":
        confidence -= 0.15
        reasons.append("Vendor name inferred from text")

    return round(min(1.0, max(0.1, confidence)), 2), reasons


def _build_recommendation(alert_type: str, event: Dict[str, Any], tech: Optional[str]) -> str:
    """Build an explainable recommendation derived from the actual evidence."""
    tech_str = tech or "affected system"

    if alert_type == "VULNERABILITY":
        if event.get("cve_id"):
            return f"Apply patch for {event['cve_id']} on {tech_str} immediately, validate exposure, and monitor exploitation indicators"
        return f"Patch {tech_str} immediately, validate exposure, and monitor exploitation indicators"

    if alert_type == "BREACH":
        return f"Review vendor incident disclosures, determine whether customer data or access is affected, and escalate to the vendor security contact"

    if alert_type == "RANSOMWARE":
        return f"Review third-party connectivity and privileged access, monitor vendor-originated activity, and initiate incident assessment"

    if alert_type == "ATTACK_TECHNIQUE":
        return f"Review whether {tech_str} is exposed to this technique, update detection rules, and validate compensating controls"

    if alert_type == "ARCHITECTURE_CHANGE":
        return f"Review the newly discovered {tech_str} and assess applicable vulnerabilities"

    if alert_type == "EXTERNAL_EXPOSURE":
        return f"Validate the newly exposed service and determine whether it is authorized and securely configured"

    return f"Review {tech_str} exposure and validate security posture"


def _build_business_relevance(alert_type: str, vendor_ctx: Dict[str, Any], profile_ctx: Dict[str, Any], tech: Optional[str]) -> str:
    """Build a customer-specific business relevance description."""
    parts = []
    vendor_name = vendor_ctx.get("vendor") or "Vendor"
    tech_str = tech or "technology"

    if alert_type == "VULNERABILITY":
        parts.append(f"{vendor_name} provides {tech_str} which is affected by a vulnerability")
    elif alert_type == "BREACH":
        parts.append(f"{vendor_name} appears in a publicly reported breach")
    elif alert_type == "RANSOMWARE":
        parts.append(f"{vendor_name} is associated with ransomware/extortion activity")
    elif alert_type == "ARCHITECTURE_CHANGE":
        parts.append(f"{vendor_name} architecture changed with new {tech_str}")
    else:
        parts.append(f"{vendor_name} is affected by a {alert_type.lower().replace('_', ' ')}")

    # Business context
    crit = (vendor_ctx.get("criticality") or "MEDIUM").upper()
    if crit == "CRITICAL":
        parts.append("vendor is business critical")
    elif crit == "HIGH":
        parts.append("vendor is high criticality")

    if profile_ctx.get("privileged_access"):
        parts.append("vendor has privileged access")

    access = (profile_ctx.get("data_access_level") or vendor_ctx.get("data_sensitivity") or "").upper()
    if access in ("SENSITIVE", "HIGH"):
        parts.append("customer uses vendor for sensitive data")

    return "; ".join(parts) + "."


def _alert_exists(cur, customer_id, customer_vendor_id, cve_id, threat_event_id, alert_type) -> bool:
    """Idempotency check: same customer+vendor+CVE/type already alerted.
    
    For CVE alerts: uses (customer_id, customer_vendor_id, cve_id, alert_type)
    For non-CVE alerts: uses (customer_id, customer_vendor_id, threat_event_id, alert_type)
    
    Uses IS NOT DISTINCT FROM to handle NULL values correctly.
    In SQL, NULL != NULL, so we need IS NOT DISTINCT FROM to treat NULL as equal to NULL.
    """
    if cve_id:
        # For CVE alerts, check by CVE (consolidates multiple threat_events with same CVE)
        cur.execute("""
            SELECT 1 FROM third_party_alerts
            WHERE customer_id = %s AND customer_vendor_id = %s
              AND cve_id IS NOT DISTINCT FROM %s AND alert_type = %s
            LIMIT 1
        """, (customer_id, customer_vendor_id, cve_id, alert_type))
    else:
        # For non-CVE alerts, check by threat_event_id (preserves granularity)
        cur.execute("""
            SELECT 1 FROM third_party_alerts
            WHERE customer_id = %s AND customer_vendor_id = %s
              AND threat_event_id IS NOT DISTINCT FROM %s AND alert_type = %s
            LIMIT 1
        """, (customer_id, customer_vendor_id, threat_event_id, alert_type))
    return cur.fetchone() is not None


def _insert_alert(cur, alert: Dict[str, Any]) -> int:
    cur.execute("""
        INSERT INTO third_party_alerts (
            customer_id, customer_vendor_id, profile_id,
            threat_event_id, exposure_id, architecture_change_id,
            vendor, affected_technology, alert_type, severity,
            risk_score, risk_delta, confidence, confidence_reasons,
            evidence, business_relevance, recommended_action,
            status, source_type, cve_id, created_at, updated_at
        ) VALUES (
            %(customer_id)s, %(customer_vendor_id)s, %(profile_id)s,
            %(threat_event_id)s, %(exposure_id)s, %(architecture_change_id)s,
            %(vendor)s, %(affected_technology)s, %(alert_type)s, %(severity)s,
            %(risk_score)s, %(risk_delta)s, %(confidence)s, %(confidence_reasons)s,
            %(evidence)s, %(business_relevance)s, %(recommended_action)s,
            'NEW', %(source_type)s, %(cve_id)s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING id
    """, alert)
    return cur.fetchone()[0]


def _load_vendor_ctx(cur, customer_vendor_id) -> Dict[str, Any]:
    cur.execute("""
        SELECT cv.vendor, cv.criticality, cv.data_sensitivity, cv.relationship_type,
               p.id, p.business_role, p.data_access_level, p.privileged_access
        FROM customer_vendors cv
        LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
        WHERE cv.id = %s
    """, (customer_vendor_id,))
    row = cur.fetchone()
    if not row:
        return {}
    return {
        "vendor": row[0],
        "criticality": row[1],
        "data_sensitivity": row[2],
        "relationship_type": row[3],
        "profile_id": row[4],
        "business_role": row[5],
        "data_access_level": row[6],
        "privileged_access": row[7],
    }


def _load_profile_technologies(cur, profile_id) -> List[str]:
    if not profile_id:
        return []
    cur.execute("SELECT technology FROM third_party_profile_technologies WHERE profile_id = %s", (profile_id,))
    return [r[0] for r in cur.fetchall()]


def generate_alerts_from_exposures(limit: int = 50, customer_id: Optional[int] = None) -> Dict[str, Any]:
    """Generate third-party alerts from unprocessed third_party_exposures.

    Idempotent: skips exposures that already produced an alert.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Find exposures that haven't generated an alert yet
        if customer_id is not None:
            cur.execute("""
                SELECT e.id, e.threat_event_id, e.customer_id, e.customer_vendor_id,
                       e.vendor_id, e.risk_score, e.priority, e.affected_technology,
                       e.evidence, e.recommended_action, e.match_confidence,
                       te.title, te.description, te.cve_id, te.severity, te.source_type, te.raw_metadata
                FROM third_party_exposures e
                JOIN threat_events te ON te.id = e.threat_event_id
                WHERE e.customer_id = %s AND NOT EXISTS (
                    SELECT 1 FROM third_party_alerts a
                    WHERE a.exposure_id = e.id
                )
                ORDER BY e.risk_score DESC
                LIMIT %s
            """, (customer_id, limit))
        else:
            cur.execute("""
                SELECT e.id, e.threat_event_id, e.customer_id, e.customer_vendor_id,
                       e.vendor_id, e.risk_score, e.priority, e.affected_technology,
                       e.evidence, e.recommended_action, e.match_confidence,
                       te.title, te.description, te.cve_id, te.severity, te.source_type, te.raw_metadata
                FROM third_party_exposures e
                JOIN threat_events te ON te.id = e.threat_event_id
                WHERE NOT EXISTS (
                    SELECT 1 FROM third_party_alerts a
                    WHERE a.exposure_id = e.id
                )
                ORDER BY e.risk_score DESC
                LIMIT %s
            """, (limit,))
        rows = cur.fetchall()

        alerts_created = 0
        alerts_skipped = 0
        details = []

        for row in rows:
            (exposure_id, threat_event_id, customer_id, customer_vendor_id, vendor_id,
             risk_score, priority, affected_tech, evidence, rec_action, match_conf,
             title, description, cve_id, severity, source_type, raw_metadata) = row

            event = {
                "title": title,
                "description": description,
                "cve_id": cve_id,
                "severity": severity,
                "source_type": source_type,
            }

            # Load business context
            vendor_ctx = _load_vendor_ctx(cur, customer_vendor_id)
            if not vendor_ctx:
                alerts_skipped += 1
                continue

            profile_id = vendor_ctx.get("profile_id")
            profile_ctx = {
                "privileged_access": vendor_ctx.get("privileged_access", False),
                "data_access_level": vendor_ctx.get("data_access_level"),
                "business_role": vendor_ctx.get("business_role"),
                "technologies": _load_profile_technologies(cur, profile_id),
            }

            # Classify alert type
            alert_type = _classify_alert_type(event)

            # Idempotency check
            if _alert_exists(cur, customer_id, customer_vendor_id, cve_id, threat_event_id, alert_type):
                alerts_skipped += 1
                continue

            # Customer-specific risk
            customer_risk = _compute_customer_risk(event, vendor_ctx, profile_ctx)

            # Confidence
            exposure_ctx = {
                "affected_technology": affected_tech,
                "match_type": "vendor_direct",
            }
            confidence, confidence_reasons = _compute_confidence(event, exposure_ctx, profile_ctx)

            # Evidence
            evidence_list = []
            if isinstance(evidence, str):
                try:
                    evidence_list = json.loads(evidence)
                except (json.JSONDecodeError, TypeError):
                    evidence_list = [evidence]
            elif isinstance(evidence, list):
                evidence_list = evidence

            # Business relevance
            business_relevance = _build_business_relevance(alert_type, vendor_ctx, profile_ctx, affected_tech)

            # Recommendation
            recommended_action = rec_action or _build_recommendation(alert_type, event, affected_tech)

            # Severity from customer risk
            if customer_risk >= 85:
                alert_severity = "CRITICAL"
            elif customer_risk >= 70:
                alert_severity = "HIGH"
            elif customer_risk >= 40:
                alert_severity = "MEDIUM"
            else:
                alert_severity = "LOW"

            alert = {
                "customer_id": customer_id,
                "customer_vendor_id": customer_vendor_id,
                "profile_id": profile_id,
                "threat_event_id": threat_event_id,
                "exposure_id": exposure_id,
                "architecture_change_id": None,
                "vendor": vendor_ctx.get("vendor") or "Unknown",
                "affected_technology": affected_tech,
                "alert_type": alert_type,
                "severity": alert_severity,
                "risk_score": customer_risk,
                "risk_delta": 0,
                "confidence": confidence,
                "confidence_reasons": json.dumps(confidence_reasons),
                "evidence": json.dumps(evidence_list),
                "business_relevance": business_relevance,
                "recommended_action": recommended_action,
                "source_type": "exposure",
                "cve_id": cve_id,
            }

            alert_id = _insert_alert(cur, alert)
            alerts_created += 1
            details.append({
                "alert_id": alert_id,
                "customer_id": customer_id,
                "vendor": alert["vendor"],
                "alert_type": alert_type,
                "risk_score": customer_risk,
                "confidence": confidence,
            })
            
            # Send email notification (non-blocking, doesn't fail alert creation)
            alert_with_id = {**alert, "id": alert_id}
            try:
                email_service = get_email_service()
                if email_service.is_enabled():
                    email_result = email_service.send_alert_notification(
                        alert_with_id, notification_type="new_alert"
                    )
                    logger.info(
                        f"[ALERT ENGINE] Email notification sent for alert {alert_id}: "
                        f"{email_result.get('notifications_sent', 0)} sent, "
                        f"{email_result.get('notifications_failed', 0)} failed"
                    )
            except Exception as e:
                logger.error(f"[ALERT ENGINE] Failed to send email notification for alert {alert_id}: {e}")
                # Email failure should not prevent alert creation

        conn.commit()
        return {
            "alerts_created": alerts_created,
            "alerts_skipped": alerts_skipped,
            "details": details,
        }
    except Exception:
        conn.rollback()
        logger.exception("Third-party alert generation failed")
        raise
    finally:
        cur.close()
        conn.close()


def generate_alerts_from_architecture_changes(limit: int = 50) -> Dict[str, Any]:
    """Generate ARCHITECTURE_CHANGE alerts from unprocessed architecture_changes.

    Idempotent: skips changes that already produced an alert.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT ac.id, ac.customer_id, ac.customer_vendor_id, ac.profile_id,
                   ac.added_technologies, ac.changed_versions, ac.removed_technologies,
                   ac.risk_before, ac.risk_after, ac.risk_delta, ac.risk_impact, ac.reason
            FROM architecture_changes ac
            WHERE NOT EXISTS (
                SELECT 1 FROM third_party_alerts a
                WHERE a.architecture_change_id = ac.id
            )
            ORDER BY ac.created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()

        alerts_created = 0
        alerts_skipped = 0
        details = []

        for row in rows:
            (change_id, customer_id, customer_vendor_id, profile_id,
             added_techs, changed_versions, removed_techs,
             risk_before, risk_after, risk_delta, risk_impact, reason) = row

            vendor_ctx = _load_vendor_ctx(cur, customer_vendor_id)
            if not vendor_ctx:
                alerts_skipped += 1
                continue

            # Parse added technologies
            added_list = []
            if isinstance(added_techs, str):
                try:
                    added_list = json.loads(added_techs)
                except (json.JSONDecodeError, TypeError):
                    added_list = []
            elif isinstance(added_techs, list):
                added_list = added_techs

            if not added_list:
                alerts_skipped += 1
                continue

            # Create one alert per added technology
            for tech in added_list:
                tech_name = tech.get("technology") if isinstance(tech, dict) else str(tech)
                if not tech_name:
                    continue

                # Idempotency: same change + tech already alerted
                cur.execute("""
                    SELECT 1 FROM third_party_alerts
                    WHERE architecture_change_id = %s AND affected_technology = %s
                    LIMIT 1
                """, (change_id, tech_name))
                if cur.fetchone():
                    alerts_skipped += 1
                    continue

                event = {
                    "title": f"Architecture change: new {tech_name}",
                    "description": reason or "New technology discovered in vendor architecture",
                    "cve_id": None,
                    "severity": "MEDIUM",
                    "source_type": "architecture_change",
                }

                profile_ctx = {
                    "privileged_access": vendor_ctx.get("privileged_access", False),
                    "data_access_level": vendor_ctx.get("data_access_level"),
                    "business_role": vendor_ctx.get("business_role"),
                    "technologies": _load_profile_technologies(cur, profile_id),
                }

                # Customer-specific risk
                customer_risk = _compute_customer_risk(event, vendor_ctx, profile_ctx)
                customer_risk = min(100, customer_risk + max(0, risk_delta))

                confidence = 0.7
                confidence_reasons = ["New technology detected in architecture document"]

                evidence = [
                    f"New technology: {tech_name}",
                    f"Risk delta: {risk_delta:+d}",
                ]
                if reason:
                    evidence.append(reason)

                business_relevance = _build_business_relevance("ARCHITECTURE_CHANGE", vendor_ctx, profile_ctx, tech_name)
                recommended_action = _build_recommendation("ARCHITECTURE_CHANGE", event, tech_name)

                if customer_risk >= 85:
                    alert_severity = "CRITICAL"
                elif customer_risk >= 70:
                    alert_severity = "HIGH"
                elif customer_risk >= 40:
                    alert_severity = "MEDIUM"
                else:
                    alert_severity = "LOW"

                alert = {
                    "customer_id": customer_id,
                    "customer_vendor_id": customer_vendor_id,
                    "profile_id": profile_id,
                    "threat_event_id": None,
                    "exposure_id": None,
                    "architecture_change_id": change_id,
                    "vendor": vendor_ctx.get("vendor") or "Unknown",
                    "affected_technology": tech_name,
                    "alert_type": "ARCHITECTURE_CHANGE",
                    "severity": alert_severity,
                    "risk_score": customer_risk,
                    "risk_delta": risk_delta,
                    "confidence": confidence,
                    "confidence_reasons": json.dumps(confidence_reasons),
                    "evidence": json.dumps(evidence),
                    "business_relevance": business_relevance,
                    "recommended_action": recommended_action,
                    "source_type": "architecture_change",
                    "cve_id": None,
                }

                alert_id = _insert_alert(cur, alert)
                alerts_created += 1
                details.append({
                    "alert_id": alert_id,
                    "customer_id": customer_id,
                    "vendor": alert["vendor"],
                    "alert_type": "ARCHITECTURE_CHANGE",
                    "technology": tech_name,
                    "risk_score": customer_risk,
                    "risk_delta": risk_delta,
                })
                
                # Send email notification (non-blocking, doesn't fail alert creation)
                alert_with_id = {**alert, "id": alert_id}
                try:
                    email_service = get_email_service()
                    if email_service.is_enabled():
                        email_result = email_service.send_alert_notification(
                            alert_with_id, notification_type="new_alert"
                        )
                        logger.info(
                            f"[ALERT ENGINE] Email notification sent for alert {alert_id}: "
                            f"{email_result.get('notifications_sent', 0)} sent, "
                            f"{email_result.get('notifications_failed', 0)} failed"
                        )
                except Exception as e:
                    logger.error(f"[ALERT ENGINE] Failed to send email notification for alert {alert_id}: {e}")
                    # Email failure should not prevent alert creation

        conn.commit()
        return {
            "alerts_created": alerts_created,
            "alerts_skipped": alerts_skipped,
            "details": details,
        }
    except Exception:
        conn.rollback()
        logger.exception("Architecture change alert generation failed")
        raise
    finally:
        cur.close()
        conn.close()


def generate_alerts_from_external_exposures(limit: int = 50) -> Dict[str, Any]:
    """Generate EXTERNAL_EXPOSURE alerts from newly exposed external assets.

    Idempotent: skips assets that already produced an alert.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT x.id, x.profile_id, x.asset_type, x.value, x.exposure_status,
                   x.created_at, p.customer_vendor_id, cv.customer_id, cv.vendor
            FROM third_party_external_assets x
            JOIN third_party_profiles p ON p.id = x.profile_id
            JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
            WHERE x.exposure_status ILIKE '%%exposed%%'
              AND NOT EXISTS (
                SELECT 1 FROM third_party_alerts a
                WHERE a.profile_id = x.profile_id
                  AND a.alert_type = 'EXTERNAL_EXPOSURE'
                  AND a.affected_technology = x.value
              )
            ORDER BY x.created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()

        alerts_created = 0
        alerts_skipped = 0
        details = []

        for row in rows:
            (asset_id, profile_id, asset_type, value, exposure_status,
             created_at, customer_vendor_id, customer_id, vendor_name) = row

            vendor_ctx = _load_vendor_ctx(cur, customer_vendor_id)
            if not vendor_ctx:
                alerts_skipped += 1
                continue

            profile_ctx = {
                "privileged_access": vendor_ctx.get("privileged_access", False),
                "data_access_level": vendor_ctx.get("data_access_level"),
                "business_role": vendor_ctx.get("business_role"),
                "technologies": _load_profile_technologies(cur, profile_id),
            }

            event = {
                "title": f"External exposure: {value}",
                "description": f"{asset_type} {value} is externally exposed",
                "cve_id": None,
                "severity": "HIGH",
                "source_type": "external_exposure",
            }

            customer_risk = _compute_customer_risk(event, vendor_ctx, profile_ctx)
            confidence = 0.75
            confidence_reasons = [
                "External asset detected in vendor profile",
                f"Exposure status: {exposure_status}",
            ]

            evidence = [
                f"External {asset_type}: {value}",
                f"Status: {exposure_status}",
            ]
            if profile_ctx.get("privileged_access"):
                evidence.append("Vendor has privileged access")

            business_relevance = _build_business_relevance(
                "EXTERNAL_EXPOSURE", vendor_ctx, profile_ctx, value
            )
            recommended_action = _build_recommendation("EXTERNAL_EXPOSURE", event, value)

            if customer_risk >= 85:
                alert_severity = "CRITICAL"
            elif customer_risk >= 70:
                alert_severity = "HIGH"
            elif customer_risk >= 40:
                alert_severity = "MEDIUM"
            else:
                alert_severity = "LOW"

            alert = {
                "customer_id": customer_id,
                "customer_vendor_id": customer_vendor_id,
                "profile_id": profile_id,
                "threat_event_id": None,
                "exposure_id": None,
                "architecture_change_id": None,
                "vendor": vendor_name or vendor_ctx.get("vendor") or "Unknown",
                "affected_technology": value,
                "alert_type": "EXTERNAL_EXPOSURE",
                "severity": alert_severity,
                "risk_score": customer_risk,
                "risk_delta": 0,
                "confidence": confidence,
                "confidence_reasons": json.dumps(confidence_reasons),
                "evidence": json.dumps(evidence),
                "business_relevance": business_relevance,
                "recommended_action": recommended_action,
                "source_type": "external_exposure",
                "cve_id": None,
            }

            alert_id = _insert_alert(cur, alert)
            alerts_created += 1
            details.append({
                "alert_id": alert_id,
                "customer_id": customer_id,
                "vendor": alert["vendor"],
                "alert_type": "EXTERNAL_EXPOSURE",
                "technology": value,
                "risk_score": customer_risk,
            })
            
            # Send email notification (non-blocking, doesn't fail alert creation)
            alert_with_id = {**alert, "id": alert_id}
            try:
                email_service = get_email_service()
                if email_service.is_enabled():
                    email_result = email_service.send_alert_notification(
                        alert_with_id, notification_type="new_alert"
                    )
                    logger.info(
                        f"[ALERT ENGINE] Email notification sent for alert {alert_id}: "
                        f"{email_result.get('notifications_sent', 0)} sent, "
                        f"{email_result.get('notifications_failed', 0)} failed"
                    )
            except Exception as e:
                logger.error(f"[ALERT ENGINE] Failed to send email notification for alert {alert_id}: {e}")
                # Email failure should not prevent alert creation

        conn.commit()
        return {
            "alerts_created": alerts_created,
            "alerts_skipped": alerts_skipped,
            "details": details,
        }
    except Exception:
        conn.rollback()
        logger.exception("External exposure alert generation failed")
        raise
    finally:
        cur.close()
        conn.close()


def run_alert_engine(limit: int = 100) -> Dict[str, Any]:
    """Run the full alert engine: exposures + architecture changes + external exposures."""
    exposure_result = generate_alerts_from_exposures(limit=limit)
    arch_result = generate_alerts_from_architecture_changes(limit=limit)
    external_result = generate_alerts_from_external_exposures(limit=limit)

    return {
        "exposure_alerts": exposure_result,
        "architecture_change_alerts": arch_result,
        "external_exposure_alerts": external_result,
        "total_created": (
            exposure_result["alerts_created"]
            + arch_result["alerts_created"]
            + external_result["alerts_created"]
        ),
    }