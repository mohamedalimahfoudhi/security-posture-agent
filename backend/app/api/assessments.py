import json
from fastapi import APIRouter, Depends
from app.auth.deps import get_current_user
from app.database.assessment_repository import get_assessments
from app.database.connection import get_connection
from datetime import datetime, timedelta

router = APIRouter(
    prefix="/api/assessments",
    tags=["Assessments"]
)


@router.get("/")
def read_assessments(current_user: dict = Depends(get_current_user)):
    return get_assessments(current_user["customer_id"])


@router.get("/digest")
def get_weekly_digest(current_user: dict = Depends(get_current_user)):
    """Weekly digest: structured summary of assessments from the last 7 days.
    
    Each item includes evidence/confidence/affected customer/affected third party/
    business relevance/recommended action per the spec output type.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            a.id,
            c.name AS customer,
            ast.vendor,
            ast.technology,
            e.title AS vulnerability,
            a.ai_summary AS threat_summary,
            a.severity,
            a.risk_score,
            a.recommendation,
            a.confidence_score AS confidence,
            a.business_impact AS business_relevance,
            a.affected_third_party,
            a.ransomware_group,
            a.created_at,
            a.hunting_guidance
        FROM assessments a
        JOIN customers c ON a.customer_id = c.id
        LEFT JOIN cve_events e ON a.event_id = e.id
        LEFT JOIN assets ast ON a.asset_id = ast.id
        WHERE a.customer_id = %s AND a.created_at >= NOW() - INTERVAL '7 days'
        ORDER BY a.created_at DESC
    """, (current_user["customer_id"],))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Build structured items
    items = []
    for row in rows:
        recommendations = [row[8]] if row[8] else []

        hunting_guidance = row[14]
        try:
            hunting_guidance = json.loads(hunting_guidance) if isinstance(hunting_guidance, str) else (hunting_guidance or {})
        except (json.JSONDecodeError, TypeError):
            hunting_guidance = {}

        items.append({
            "id": row[0],
            "customer": row[1],
            "vendor": row[2],
            "technology": row[3],
            "vulnerability": row[4],
            "threat_summary": row[5],
            "severity": row[6],
            "risk_score": row[7],
            "recommendations": recommendations,
            "confidence": row[9],
            "business_relevance": row[10],
            "affected_third_party": row[11],
            "ransomware_group": row[12],
            "created_at": row[13],
            "hunting_guidance": hunting_guidance,
        })

    # Summary stats
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in items:
        sev = item["severity"] or "LOW"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "period_start": (datetime.now() - timedelta(days=7)).isoformat(),
        "period_end": datetime.now().isoformat(),
        "total_findings": len(items),
        "severity_breakdown": severity_counts,
        "items": items,
    }


@router.get("/severity-trend")
def get_severity_trend(current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    cur = conn.cursor()

    # Get assessments grouped by hour over the last 24 hours
    # INNER JOIN assets so orphaned/unlinked assessments (deleted assets) are excluded
    cur.execute("""
        SELECT
            EXTRACT(HOUR FROM a.created_at)::int as hour,
            COUNT(*) FILTER (WHERE a.severity = 'CRITICAL') as critical,
            COUNT(*) FILTER (WHERE a.severity = 'HIGH') as high,
            COUNT(*) FILTER (WHERE a.severity = 'MEDIUM') as elevated,
            COUNT(*) FILTER (WHERE a.severity = 'LOW') as low
        FROM assessments a
        INNER JOIN assets ast ON a.asset_id = ast.id
        WHERE a.customer_id = %s AND a.created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY EXTRACT(HOUR FROM a.created_at)
        ORDER BY hour;
    """, (current_user["customer_id"],))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    # If no data, return empty structure
    if not rows:
        return []

    return [
        {
            "time": f"{int(row[0]):02d}:00",
            "critical": row[1] or 0,
            "high": row[2] or 0,
            "elevated": row[3] or 0,
            "low": row[4] or 0
        }
        for row in rows
    ]
