"""
Customer-Centric Dashboard API.

Provides a single aggregated endpoint for viewing a full security posture
dashboard for any customer. Enforces strict RBAC:

  - Admin  → may access any customer_id
  - Analyst / Viewer → may only access their own customer_id → 403 otherwise

Every SQL query is explicitly scoped to the requested customer_id; no tenant
information leaks through global joins.
"""
import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user
from app.database.connection import get_connection

router = APIRouter(prefix="/api/customers", tags=["Customer Dashboard"])


# ---------------------------------------------------------------------------
# Authorization helper
# ---------------------------------------------------------------------------

def _authorize(current_user: dict, customer_id: int) -> None:
    """Raise 403 unless the user is Admin or owns the requested customer."""
    if current_user["role"] == "Admin":
        return
    if current_user["customer_id"] == customer_id:
        return
    raise HTTPException(status_code=403, detail="Not authorized to access this customer")


def _parse_json(value):
    if value is None:
        return []
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return [str(value)] if value else []


# ---------------------------------------------------------------------------
# Helper: weekly digest (reuses identical logic from reports.py, scoped)
# ---------------------------------------------------------------------------

def _weekly_digest(cur, customer_id: int) -> dict:
    now = datetime.now()
    week_start = now - timedelta(days=7)

    cur.execute("""
        SELECT COALESCE(AVG(p.risk_score), 0)
        FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.customer_id = %s
    """, (customer_id,))
    overall_risk = round(cur.fetchone()[0] or 0)

    cur.execute("""
        SELECT COALESCE(AVG(ac.risk_before), 0)
        FROM architecture_changes ac
        WHERE ac.customer_id = %s AND ac.created_at >= %s
    """, (customer_id, week_start))
    risk_before = cur.fetchone()[0] or 0
    risk_change = overall_risk - round(risk_before) if risk_before else 0

    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND created_at >= %s
    """, (customer_id, week_start))
    new_alerts = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND status IN ('RESOLVED', 'ACKNOWLEDGED')
          AND updated_at >= %s
    """, (customer_id, week_start))
    resolved_alerts = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND alert_type = 'VULNERABILITY' AND created_at >= %s
    """, (customer_id, week_start))
    new_vulnerabilities = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND alert_type = 'BREACH' AND created_at >= %s
    """, (customer_id, week_start))
    new_breaches = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND alert_type = 'RANSOMWARE' AND created_at >= %s
    """, (customer_id, week_start))
    new_ransomware = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM architecture_changes
        WHERE customer_id = %s AND created_at >= %s
    """, (customer_id, week_start))
    arch_changes = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM third_party_external_assets x
        JOIN third_party_profiles p ON p.id = x.profile_id
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.customer_id = %s AND x.exposure_status ILIKE '%%exposed%%'
          AND x.created_at >= %s
    """, (customer_id, week_start))
    new_external_exposures = cur.fetchone()[0]

    cur.execute("""
        SELECT cv.vendor, p.risk_score, p.criticality, p.business_role,
               COALESCE(string_agg(DISTINCT t.technology, ', '), '') AS technologies
        FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        LEFT JOIN third_party_profile_technologies t ON t.profile_id = p.id
        WHERE cv.customer_id = %s
        GROUP BY cv.vendor, p.id
        ORDER BY p.risk_score DESC
        LIMIT 5
    """, (customer_id,))
    top_risks = [
        {"vendor": r[0], "risk_score": r[1], "criticality": r[2],
         "business_role": r[3], "technologies": r[4]}
        for r in cur.fetchall()
    ]

    cur.execute("""
        SELECT DISTINCT ON (recommended_action) recommended_action, alert_type, vendor
        FROM third_party_alerts
        WHERE customer_id = %s AND created_at >= %s AND recommended_action IS NOT NULL
        ORDER BY recommended_action, risk_score DESC
        LIMIT 5
    """, (customer_id, week_start))
    recommendations = [
        {"action": r[0], "alert_type": r[1], "vendor": r[2]}
        for r in cur.fetchall()
    ]

    return {
        "period": {"start": week_start.isoformat(), "end": now.isoformat()},
        "overall_risk": overall_risk,
        "risk_change": risk_change,
        "new_alerts": new_alerts,
        "resolved_alerts": resolved_alerts,
        "new_vulnerabilities": new_vulnerabilities,
        "new_breaches": new_breaches,
        "new_ransomware_events": new_ransomware,
        "architecture_changes": arch_changes,
        "new_external_exposures": new_external_exposures,
        "top_risks": top_risks,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# GET /api/customers/{customer_id}/dashboard
# ---------------------------------------------------------------------------

@router.get("/{customer_id}/dashboard")
def customer_dashboard(customer_id: int, current_user: dict = Depends(get_current_user)):
    """
    Aggregated security posture dashboard for a customer.
    Admin: any customer_id. Analyst/Viewer: own customer only.
    """
    _authorize(current_user, customer_id)

    conn = get_connection()
    cur = conn.cursor()

    try:
        # ------------------------------------------------------------------
        # 1. Customer metadata
        # ------------------------------------------------------------------
        cur.execute(
            "SELECT id, name, COALESCE(industry, '') FROM customers WHERE id = %s",
            (customer_id,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Customer not found")
        customer = {"id": row[0], "name": row[1], "industry": row[2]}

        # ------------------------------------------------------------------
        # 2. Posture KPIs
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT COUNT(cv.id),
                   COUNT(cv.id) FILTER (WHERE cv.criticality = 'CRITICAL'),
                   COUNT(cv.id) FILTER (WHERE COALESCE(p.risk_score, cv.base_risk_score, 0) >= 70
                                          AND cv.criticality != 'CRITICAL')
            FROM customer_vendors cv
            LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
            WHERE cv.customer_id = %s
        """, (customer_id,))
        v = cur.fetchone()
        total_vendors = v[0] or 0
        critical_vendors = v[1] or 0
        high_risk_vendors = v[2] or 0

        cur.execute("""
            SELECT COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status = 'NEW'),
                   COUNT(*) FILTER (WHERE status = 'NEW'),
                   COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')
            FROM third_party_alerts
            WHERE customer_id = %s
        """, (customer_id,))
        a = cur.fetchone()
        critical_alerts = a[0] or 0
        open_alerts = a[1] or 0
        new_alerts_week = a[2] or 0

        cur.execute("""
            SELECT COUNT(*) FROM third_party_exposures WHERE customer_id = %s
        """, (customer_id,))
        total_exposures = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT COALESCE(AVG(p.risk_score), 0)
            FROM third_party_profiles p
            JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
            WHERE cv.customer_id = %s
        """, (customer_id,))
        overall_risk = round(cur.fetchone()[0] or 0)

        posture = {
            "overall_risk": overall_risk,
            "total_vendors": total_vendors,
            "critical_vendors": critical_vendors,
            "high_risk_vendors": high_risk_vendors,
            "critical_alerts": critical_alerts,
            "open_alerts": open_alerts,
            "new_alerts_this_week": new_alerts_week,
            "total_third_party_exposures": total_exposures,
        }

        # ------------------------------------------------------------------
        # 3. Third-party SOC alerts (top 50, newest first)
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT id, customer_vendor_id, profile_id, threat_event_id,
                   vendor, affected_technology, alert_type, severity,
                   risk_score, risk_delta, confidence, confidence_reasons,
                   evidence, business_relevance, recommended_action,
                   status, source_type, created_at
            FROM third_party_alerts
            WHERE customer_id = %s
            ORDER BY created_at DESC, risk_score DESC
            LIMIT 50
        """, (customer_id,))
        alerts = [
            {
                "id": r[0], "customer_vendor_id": r[1], "profile_id": r[2],
                "threat_event_id": r[3], "vendor": r[4], "affected_technology": r[5],
                "alert_type": r[6], "severity": r[7], "risk_score": r[8],
                "risk_delta": r[9], "confidence": r[10],
                "confidence_reasons": _parse_json(r[11]),
                "evidence": _parse_json(r[12]),
                "business_relevance": r[13], "recommended_action": r[14],
                "status": r[15], "source_type": r[16],
                "created_at": r[17].isoformat() if r[17] else None,
            }
            for r in cur.fetchall()
        ]

        # ------------------------------------------------------------------
        # 4. Vendors with risk
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT cv.id, cv.vendor, cv.criticality, cv.relationship_type,
                   cv.data_sensitivity, cv.base_risk_score,
                   COALESCE(p.risk_score, cv.base_risk_score, 0) AS effective_risk,
                   p.business_role, p.criticality AS profile_criticality
            FROM customer_vendors cv
            LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
            WHERE cv.customer_id = %s
            ORDER BY effective_risk DESC
        """, (customer_id,))
        vendors = [
            {
                "id": r[0], "vendor": r[1], "criticality": r[2],
                "relationship_type": r[3], "data_sensitivity": r[4],
                "base_risk_score": r[5], "risk_score": r[6],
                "business_role": r[7], "profile_criticality": r[8],
            }
            for r in cur.fetchall()
        ]

        # ------------------------------------------------------------------
        # 5. Third-party exposures (top 25)
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT e.id, cv.vendor, te.title, te.cve_id, te.severity,
                   e.risk_score, e.priority, e.match_type, e.match_confidence,
                   e.matched_text, e.created_at
            FROM third_party_exposures e
            JOIN customer_vendors cv ON cv.id = e.customer_vendor_id
            JOIN threat_events te ON te.id = e.threat_event_id
            WHERE e.customer_id = %s
            ORDER BY e.risk_score DESC, e.created_at DESC
            LIMIT 25
        """, (customer_id,))
        exposures = [
            {
                "id": r[0], "vendor": r[1], "threat_title": r[2], "cve_id": r[3],
                "severity": r[4], "risk_score": r[5], "priority": r[6],
                "match_type": r[7], "confidence": r[8], "affected_technology": r[9],
                "created_at": r[10].isoformat() if r[10] else None,
            }
            for r in cur.fetchall()
        ]

        # ------------------------------------------------------------------
        # 6. Vulnerabilities (VULNERABILITY-type alerts for this customer)
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT id, vendor, affected_technology, severity, risk_score,
                   confidence, status, recommended_action, created_at
            FROM third_party_alerts
            WHERE customer_id = %s AND alert_type = 'VULNERABILITY'
            ORDER BY risk_score DESC, created_at DESC
            LIMIT 25
        """, (customer_id,))
        vulnerabilities = [
            {
                "id": r[0], "vendor": r[1], "technology": r[2], "severity": r[3],
                "risk_score": r[4], "confidence": r[5], "status": r[6],
                "recommended_action": r[7],
                "created_at": r[8].isoformat() if r[8] else None,
            }
            for r in cur.fetchall()
        ]

        # ------------------------------------------------------------------
        # 7. Incidents (BREACH / RANSOMWARE / SECURITY_INCIDENT)
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT id, vendor, affected_technology, alert_type, severity,
                   risk_score, confidence, status, evidence, business_relevance,
                   recommended_action, created_at
            FROM third_party_alerts
            WHERE customer_id = %s
              AND alert_type IN ('BREACH', 'RANSOMWARE', 'SECURITY_INCIDENT')
            ORDER BY risk_score DESC, created_at DESC
            LIMIT 25
        """, (customer_id,))
        incidents = [
            {
                "id": r[0], "vendor": r[1], "technology": r[2], "alert_type": r[3],
                "severity": r[4], "risk_score": r[5], "confidence": r[6],
                "status": r[7], "evidence": _parse_json(r[8]),
                "business_relevance": r[9], "recommended_action": r[10],
                "created_at": r[11].isoformat() if r[11] else None,
            }
            for r in cur.fetchall()
        ]

        # ------------------------------------------------------------------
        # 8. Architecture changes (scoped to this customer only)
        # ------------------------------------------------------------------
        cur.execute("""
            SELECT ac.id, cv.vendor, ac.added_technologies, ac.removed_technologies,
                   ac.risk_before, ac.risk_after, ac.risk_delta,
                   ac.risk_impact, ac.reason, ac.created_at
            FROM architecture_changes ac
            JOIN customer_vendors cv ON cv.id = ac.customer_vendor_id
            WHERE ac.customer_id = %s
            ORDER BY ac.created_at DESC
            LIMIT 20
        """, (customer_id,))
        architecture_changes = [
            {
                "id": r[0], "vendor": r[1],
                "added_technologies": _parse_json(r[2]),
                "removed_technologies": _parse_json(r[3]),
                "risk_before": r[4], "risk_after": r[5], "risk_delta": r[6],
                "risk_impact": r[7], "reason": r[8],
                "created_at": r[9].isoformat() if r[9] else None,
            }
            for r in cur.fetchall()
        ]

        # ------------------------------------------------------------------
        # 9. Weekly digest (reuses existing report logic)
        # ------------------------------------------------------------------
        weekly_digest = _weekly_digest(cur, customer_id)

        return {
            "customer": customer,
            "posture": posture,
            "alerts": alerts,
            "vendors": vendors,
            "exposures": exposures,
            "vulnerabilities": vulnerabilities,
            "incidents": incidents,
            "architecture_changes": architecture_changes,
            "weekly_digest": weekly_digest,
        }

    finally:
        cur.close()
        conn.close()


# ---------------------------------------------------------------------------
# Paginated sub-resource endpoints
# ---------------------------------------------------------------------------

@router.get("/{customer_id}/alerts")
def customer_alerts(
    customer_id: int,
    severity: str = None,
    alert_type: str = None,
    status: str = None,
    vendor: str = None,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """Paginated, filterable third-party alerts for a customer."""
    _authorize(current_user, customer_id)

    conn = get_connection()
    cur = conn.cursor()
    try:
        params = [customer_id]
        filters = ["customer_id = %s"]

        if severity:
            filters.append("severity = %s")
            params.append(severity.upper())
        if alert_type:
            filters.append("alert_type = %s")
            params.append(alert_type.upper())
        if status:
            filters.append("status = %s")
            params.append(status.upper())
        if vendor:
            filters.append("vendor ILIKE %s")
            params.append(f"%{vendor}%")

        where = " AND ".join(filters)
        params.extend([limit, offset])

        cur.execute(f"""
            SELECT id, vendor, affected_technology, alert_type, severity,
                   risk_score, risk_delta, confidence, confidence_reasons,
                   evidence, business_relevance, recommended_action,
                   status, source_type, created_at
            FROM third_party_alerts
            WHERE {where}
            ORDER BY created_at DESC, risk_score DESC
            LIMIT %s OFFSET %s
        """, params)

        return [
            {
                "id": r[0], "vendor": r[1], "affected_technology": r[2],
                "alert_type": r[3], "severity": r[4], "risk_score": r[5],
                "risk_delta": r[6], "confidence": r[7],
                "confidence_reasons": _parse_json(r[8]),
                "evidence": _parse_json(r[9]),
                "business_relevance": r[10], "recommended_action": r[11],
                "status": r[12], "source_type": r[13],
                "created_at": r[14].isoformat() if r[14] else None,
            }
            for r in cur.fetchall()
        ]
    finally:
        cur.close()
        conn.close()


@router.get("/{customer_id}/vendors")
def customer_vendors(customer_id: int, current_user: dict = Depends(get_current_user)):
    """All vendor relationships for a customer with technology dependencies."""
    _authorize(current_user, customer_id)

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT cv.id, cv.vendor_id, cv.vendor, cv.criticality, cv.relationship_type,
                   cv.data_sensitivity, 
                   (SELECT COUNT(*) FROM third_party_exposures e WHERE e.customer_vendor_id = cv.id AND e.acknowledged = FALSE) AS active_exposures,
                   (SELECT COUNT(*) FROM third_party_alerts a WHERE a.customer_vendor_id = cv.id AND a.status = 'NEW') AS active_alerts,
                   (SELECT COUNT(*) FROM assets a WHERE a.customer_id = cv.customer_id AND a.vendor_id = cv.vendor_id) AS technology_count,
                   (SELECT MAX(e.risk_score) FROM third_party_exposures e WHERE e.customer_vendor_id = cv.id AND e.acknowledged = FALSE) AS derived_risk,
                   (SELECT COUNT(*) FROM third_party_alerts a WHERE a.customer_vendor_id = cv.id AND a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')) AS breaches_count,
                   (SELECT MAX(a.created_at) FROM third_party_alerts a WHERE a.customer_vendor_id = cv.id) AS last_intelligence_at,
                   COALESCE(p.risk_score, cv.base_risk_score, 0) AS effective_risk
            FROM customer_vendors cv
            LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
            WHERE cv.customer_id = %s
            ORDER BY effective_risk DESC NULLS LAST, cv.vendor ASC
        """, (customer_id,))
        
        vendors = []
        for r in cur.fetchall():
            # Get technologies for this vendor
            cur.execute("""
                SELECT a.technology, a.version, a.category,
                       (SELECT COUNT(*) FROM third_party_exposures e 
                        WHERE e.customer_vendor_id = %s AND e.matched_text ILIKE '%%' || a.technology || '%%' AND e.acknowledged = FALSE) AS exp_count,
                       (SELECT COUNT(*) FROM third_party_alerts al 
                        WHERE al.customer_vendor_id = %s AND al.affected_technology = a.technology AND al.status = 'NEW') AS alert_count
                FROM assets a
                WHERE a.customer_id = %s AND a.vendor_id = %s
                ORDER BY a.technology
            """, (r[0], r[0], customer_id, r[1]))
            technologies = [
                {
                    "technology": t[0],
                    "version": t[1],
                    "category": t[2],
                    "exposures_count": t[3],
                    "alerts_count": t[4]
                }
                for t in cur.fetchall()
            ]
            
            vendors.append({
                "id": r[0], "vendor_id": r[1], "vendor": r[2], "criticality": r[3],
                "relationship_type": r[4], "data_sensitivity": r[5],
                "exposures_count": r[6], "alerts_count": r[7], "technology_count": r[8],
                "base_risk_score": r[9],
                "risk_score": r[12],
                "breaches_count": r[10],
                "last_intelligence_at": r[11].isoformat() if r[11] else None,
                "technologies": technologies
            })
        return vendors
    finally:
        cur.close()
        conn.close()


@router.get("/{customer_id}/assets")
def customer_assets(
    customer_id: int,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """Paginated assets/technologies for a customer."""
    _authorize(current_user, customer_id)

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT a.id, a.customer_id, a.document_id, a.technology, a.vendor, a.version,
                   a.criticality, a.internet_exposed, a.sensitive_data, a.category,
                   a.confidence, a.created_at, a.updated_at,
                   d.filename as source_document, a.vendor_id,
                   (SELECT COUNT(*) FROM third_party_exposures e 
                    WHERE e.customer_id = %s AND e.matched_text ILIKE '%%' || a.technology || '%%' 
                      AND e.acknowledged = FALSE) AS exposures_count,
                   (SELECT COUNT(*) FROM third_party_alerts al 
                    WHERE al.customer_id = %s AND al.affected_technology = a.technology 
                      AND al.status = 'NEW') AS alerts_count,
                   CASE 
                     WHEN a.criticality = 'CRITICAL' THEN 90
                     WHEN a.criticality = 'HIGH' THEN 70
                     WHEN a.criticality = 'MEDIUM' THEN 40
                     WHEN a.criticality = 'LOW' THEN 20
                     ELSE 0
                   END AS risk_score
            FROM assets a
            LEFT JOIN documents d ON a.document_id = d.id
            WHERE a.customer_id = %s
            ORDER BY a.created_at DESC
            LIMIT %s OFFSET %s
        """, (customer_id, customer_id, customer_id, limit, offset))
        
        assets = []
        for r in cur.fetchall():
            assets.append({
                "id": r[0],
                "customer_id": r[1],
                "document_id": r[2],
                "technology": r[3],
                "vendor": r[4],
                "version": r[5],
                "criticality": r[6],
                "internet_exposed": r[7],
                "sensitive_data": r[8],
                "category": r[9],
                "confidence": r[10],
                "created_at": r[11],
                "updated_at": r[12],
                "source_document": r[13],
                "vendor_id": r[14],
                "exposures_count": r[15],
                "alerts_count": r[16],
                "risk_score": r[17]
            })
        
        cur.execute("""
            SELECT COUNT(*) FROM assets WHERE customer_id = %s
        """, (customer_id,))
        total = cur.fetchone()[0]
        
        return {
            "assets": assets,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    finally:
        cur.close()
        conn.close()


@router.get("/{customer_id}/exposures")
def customer_exposures(
    customer_id: int,
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """Paginated third-party exposures for a customer."""
    _authorize(current_user, customer_id)

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT e.id, cv.vendor, te.title, te.cve_id, te.severity,
                   e.risk_score, e.priority, e.matched_text,
                   e.match_type, e.match_confidence, e.created_at
            FROM third_party_exposures e
            JOIN customer_vendors cv ON cv.id = e.customer_vendor_id
            JOIN threat_events te ON te.id = e.threat_event_id
            WHERE e.customer_id = %s
            ORDER BY e.risk_score DESC, e.created_at DESC
            LIMIT %s OFFSET %s
        """, (customer_id, limit, offset))
        return [
            {
                "id": r[0], "vendor": r[1], "threat_title": r[2], "cve_id": r[3],
                "severity": r[4], "risk_score": r[5], "priority": r[6],
                "affected_technology": r[7], "match_type": r[8],
                "confidence": r[9],
                "created_at": r[10].isoformat() if r[10] else None,
            }
            for r in cur.fetchall()
        ]
    finally:
        cur.close()
        conn.close()
