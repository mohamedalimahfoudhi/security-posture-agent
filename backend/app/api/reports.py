"""
Third-Party Weekly Posture Digest.

Summarizes the previous 7 days of third-party risk posture for a customer:
- Overall risk + change
- Critical/high-risk vendors
- New/resolved alerts
- New vulnerabilities/breaches/ransomware events
- Architecture changes
- New external exposures
- Top risks + recommendations
"""
import json
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user
from app.database.connection import get_connection
from app.ai.ollama_client import ask_mistral

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Reports"])


def generate_digest_summary(digest_data):
    """Generate AI analysis for weekly digest using real data."""
    
    # Build context from real digest data
    context_parts = []
    
    # Severity breakdown
    if digest_data.get("critical_vendors"):
        context_parts.append(f"CRITICAL RISK VENDORS: {', '.join([v['vendor'] for v in digest_data['critical_vendors'][:5]])}")
    if digest_data.get("high_risk_vendors"):
        context_parts.append(f"HIGH RISK VENDORS: {', '.join([v['vendor'] for v in digest_data['high_risk_vendors'][:5]])}")
    
    if digest_data.get("new_vulnerabilities", 0) > 0:
        context_parts.append(f"NEW VULNERABILITIES: {digest_data['new_vulnerabilities']}")
    if digest_data.get("new_breaches", 0) > 0:
        context_parts.append(f"NEW BREACHES: {digest_data['new_breaches']}")
    if digest_data.get("new_ransomware_events", 0) > 0:
        context_parts.append(f"NEW RANSOMWARE EVENTS: {digest_data['new_ransomware_events']}")
    
    if digest_data.get("architecture_changes", 0) > 0:
        context_parts.append(f"ARCHITECTURE CHANGES: {digest_data['architecture_changes']}")
    if digest_data.get("new_external_exposures", 0) > 0:
        context_parts.append(f"NEW EXTERNAL EXPOSURES: {digest_data['new_external_exposures']}")
    
    if digest_data.get("new_alerts", 0) > 0:
        context_parts.append(f"NEW ALERTS: {digest_data['new_alerts']}")
    
    # Top risks with specific vendors
    if digest_data.get("top_risks"):
        top_risks = digest_data["top_risks"][:3]
        for risk in top_risks:
            context_parts.append(f"HIGH RISK: {risk['vendor']} (score: {risk['risk_score']}, role: {risk.get('business_role', 'unknown')}, tech: {risk.get('technologies', 'N/A')})")
    
    # Recommendations with specific actions
    if digest_data.get("recommendations"):
        for rec in digest_data["recommendations"][:3]:
            context_parts.append(f"RECOMMENDATION: {rec.get('action', 'N/A')} for {rec.get('vendor', 'N/A')} ({rec.get('alert_type', 'N/A')})")
    
    context = "\n".join(context_parts) if context_parts else "No significant events this week."
    
    prompt = f"""You are a cybersecurity analyst specializing in third-party risk management. Analyze the following weekly digest data and generate an executive summary, prioritized recommendations, and forward-looking risk outlook.

WEEKLY DIGEST DATA:
{context}

REQUIREMENTS:
1. Return ONLY valid JSON with exactly these three fields: executive_summary, recommendations, future_outlook
2. executive_summary MUST be a plain string (not an object, not an array)
3. recommendations MUST be a flat array of strings (not an array of objects)
4. Every recommendation MUST be a plain string (not an object)
5. future_outlook MUST be a plain string (not an object, not an array)
6. NO nested objects anywhere
7. NO nested arrays anywhere
8. NO markdown JSON wrapper (no ```json ... ```)
9. NO additional fields beyond the three required

CRITICAL GROUNDING RULES:

Use ONLY facts explicitly present in THIS WEEK'S DATA.

Do not infer trends that are not represented by the provided numbers.

Do not claim something increased/decreased unless the data explicitly contains a comparison or trend supporting that statement.

Do not invent industries, sectors, vendor criticality, affected assets, attack targets, geographic regions, threat actors, or motivations.

If the data says there was 1 ransomware event, say there was 1 ransomware event. Do NOT describe it as an increase unless a prior-period comparison is provided.

If the data does not identify an industry, do not name an industry.

If the data does not identify critical vendors, do not call vendors critical.

Every factual claim must be directly traceable to the supplied weekly data.

Use the EXACT numbers from the data. If the data shows 12 new alerts, say 12 new alerts. Do not round or approximate numbers unless explicitly stated.

When the data is sparse, explicitly acknowledge that it is sparse rather than filling the gap with assumptions.

Every recommendation MUST reference at least one concrete item from the supplied weekly data when such an item exists.

Do not generate generic recommendations such as:
- improve security
- patch systems
- monitor threats
- review access controls

unless the supplied data specifically supports that recommendation.

Do NOT invent vendor names that are not present in the supplied data. If the data only mentions AWS, do not invent TechSolutions, AcmeCorp, or any other vendor name not in the source data.

FORMAT EXAMPLES ONLY — DO NOT COPY THESE. Generate recommendations from THIS WEEK'S REAL DATA.

Example executive_summary: "This week recorded 12 new alerts, including 6 new vulnerabilities and 3 breach events. Five AWS-related vulnerability recommendations were generated. Overall risk is 0 for this period with no critical or high-risk vendors identified."

Example recommendations: ["Apply patch for CVE-2021-1234 on affected system immediately, validate exposure, and monitor exploitation indicators for AWS (VULNERABILITY)", "Apply patch for CVE-2023-19764 on affected system immediately, validate exposure, and monitor exploitation indicators for AWS (VULNERABILITY)", "Apply patch for CVE-2023-26817 on affected system immediately, validate exposure, and monitor exploitation indicators for AWS (VULNERABILITY)"]

Example future_outlook: "Based on this week's data showing 1 ransomware event and 6 new vulnerabilities, continue monitoring for similar patterns. No specific trend is evident from the current week's metrics alone."

CRITICAL: The examples above are FORMAT EXAMPLES ONLY. You MUST generate your own content based on the ACTUAL data provided above. Do NOT copy the example text. Do NOT use placeholder text like [REAL VENDOR] or [REAL CVE]. Use the actual vendor names, actual alert types, and actual data from the context above.

Return JSON only:
{{
  "executive_summary": "your plain string summary here",
  "recommendations": ["your plain string recommendation 1", "your plain string recommendation 2", "your plain string recommendation 3"],
  "future_outlook": "your plain string outlook here"
}}"""
    
    try:
        result = ask_mistral(prompt, timeout=120)
        ai_response = result.get("response", "")
        
        # Parse and validate
        parsed = json.loads(ai_response)
        
        # Validate structure
        if not isinstance(parsed, dict):
            raise ValueError("Response is not a dictionary")
        
        if "executive_summary" not in parsed or "recommendations" not in parsed or "future_outlook" not in parsed:
            raise ValueError("Missing required fields")
        
        if not isinstance(parsed["executive_summary"], str):
            raise ValueError("executive_summary must be a string")
        
        if not isinstance(parsed["recommendations"], list):
            raise ValueError("recommendations must be an array")
        
        for rec in parsed["recommendations"]:
            if not isinstance(rec, str):
                raise ValueError("Each recommendation must be a string")
        
        if not isinstance(parsed["future_outlook"], str):
            raise ValueError("future_outlook must be a string")
        
        # Validate factual grounding - reject unsupported placeholders
        text_to_check = parsed["executive_summary"] + " " + parsed["future_outlook"] + " " + " ".join(parsed["recommendations"])
        forbidden_patterns = ["[REAL", "[INSERT", "<TBD>", "example", "placeholder"]

        for pattern in forbidden_patterns:
            if pattern in text_to_check:
                raise ValueError(f"Response contains unsupported placeholder pattern: {pattern}")

        return parsed

    except Exception as e:
        logger.error(f"Error generating digest summary: {e}")
        # Return fallback structure
        return {
            "executive_summary": "Unable to generate AI summary this week.",
            "recommendations": ["Review weekly alerts manually", "Monitor critical vendors", "Check for new vulnerabilities"],
            "future_outlook": "Continue monitoring for emerging threats."
        }


def _parse_json_field(value):
    if value is None:
        return []
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value if isinstance(value, list) else [str(value)]


@router.get("/third-party-alerts")
def list_third_party_alerts(current_user: dict = Depends(get_current_user)):
    """List third-party alerts for the current customer (tenant-isolated)."""
    customer_id = current_user["customer_id"]
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, customer_vendor_id, profile_id, threat_event_id,
               vendor, affected_technology, alert_type, severity,
               risk_score, risk_delta, confidence, confidence_reasons,
               evidence, business_relevance, recommended_action,
               status, source_type, created_at
        FROM third_party_alerts
        WHERE customer_id = %s
        ORDER BY created_at DESC, risk_score DESC
        LIMIT 100
    """, (customer_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return [
        {
            "id": r[0],
            "customer_vendor_id": r[1],
            "profile_id": r[2],
            "threat_event_id": r[3],
            "vendor": r[4],
            "affected_technology": r[5],
            "alert_type": r[6],
            "severity": r[7],
            "risk_score": r[8],
            "risk_delta": r[9],
            "confidence": r[10],
            "confidence_reasons": _parse_json_field(r[11]),
            "evidence": _parse_json_field(r[12]),
            "business_relevance": r[13],
            "recommended_action": r[14],
            "status": r[15],
            "source_type": r[16],
            "created_at": r[17].isoformat() if r[17] else None,
        }
        for r in rows
    ]


@router.get("/intelligence-dashboard")
def intelligence_dashboard(current_user: dict = Depends(get_current_user)):
    """Aggregate data for intelligence dashboard with real, traceable data."""
    customer_id = current_user["customer_id"]
    now = datetime.now()
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    conn = get_connection()
    cur = conn.cursor()

    # 1. Alerts by day and severity (last 7 days)
    cur.execute("""
        SELECT 
            DATE(created_at) as day,
            risk_level as severity,
            COUNT(*) as count
        FROM alerts
        WHERE customer_id = %s AND created_at >= %s
        GROUP BY DATE(created_at), risk_level
        ORDER BY day DESC, severity
    """, (customer_id, week_start))
    alerts_by_day = [
        {"day": r[0].isoformat() if r[0] else None, "severity": r[1], "count": r[2]}
        for r in cur.fetchall()
    ]

    # 2. Ransomware groups from third_party_incidents (using group_name column)
    # Get Top 8 + aggregate remaining as "Other"
    cur.execute("""
        SELECT 
            group_name,
            COUNT(*) as count
        FROM third_party_incidents
        WHERE customer_id = %s AND group_name IS NOT NULL
        GROUP BY group_name
        ORDER BY count DESC
    """, (customer_id,))
    all_groups = cur.fetchall()
    
    ransomware_groups = []
    other_count = 0
    
    for i, (group_name, count) in enumerate(all_groups):
        if i < 8:
            ransomware_groups.append({"group": group_name, "count": count})
        else:
            other_count += count
    
    if other_count > 0:
        ransomware_groups.append({"group": "Other", "count": other_count})

    # 3. Countries from third_party_incidents raw_payload
    cur.execute("""
        SELECT 
            raw_payload->>'country' as country,
            COUNT(*) as count
        FROM third_party_incidents
        WHERE customer_id = %s AND raw_payload->>'country' IS NOT NULL
        GROUP BY raw_payload->>'country'
        ORDER BY count DESC
        LIMIT 10
    """, (customer_id,))
    countries = [
        {"country": r[0], "count": r[1]}
        for r in cur.fetchall()
    ]

    # 4. Recent assessments with aggregated MITRE techniques
    cur.execute("""
        SELECT 
            a.id,
            a.event_id,
            a.created_at,
            a.severity,
            a.confidence_score,
            STRING_AGG(at.technique_id, ', ' ORDER BY at.technique_id) as techniques
        FROM assessments a
        LEFT JOIN assessment_techniques at ON a.id = at.assessment_id
        WHERE a.customer_id = %s
        GROUP BY a.id, a.event_id, a.created_at, a.severity, a.confidence_score
        ORDER BY a.created_at DESC
        LIMIT 10
    """, (customer_id,))
    recent_assessments = []
    for r in cur.fetchall():
        recent_assessments.append({
            "id": r[0],
            "event_id": r[1],
            "created_at": r[2].isoformat() if r[2] else None,
            "severity": r[3],
            "confidence_score": r[4],
            "techniques": r[5]  # Aggregated technique IDs as comma-separated string
        })

    # 5. Confidence trend (last 30 days) - using assessments table as specified
    cur.execute("""
        SELECT 
            DATE(created_at) as day,
            AVG(confidence_score) as avg_confidence,
            COUNT(*) as count
        FROM assessments
        WHERE customer_id = %s AND created_at >= %s AND confidence_score IS NOT NULL
        GROUP BY DATE(created_at)
        ORDER BY day DESC
    """, (customer_id, month_start))
    confidence_trend = [
        {"day": r[0].isoformat() if r[0] else None, "avg_confidence": float(r[1]) if r[1] else None, "count": r[2]}
        for r in cur.fetchall()
    ]

    cur.close()
    conn.close()

    return {
        "alerts_by_day": alerts_by_day,
        "ransomware_groups": ransomware_groups,
        "countries": countries,
        "recent_assessments": recent_assessments,
        "confidence_trend": confidence_trend,
    }


@router.get("/third-party-weekly")
def third_party_weekly_digest(current_user: dict = Depends(get_current_user)):
    """Summarize the previous 7 days of third-party posture with cached AI analysis."""
    customer_id = current_user["customer_id"]
    now = datetime.now()
    week_start = now - timedelta(days=7)
    
    # Normalize dates to DATE for cache lookup
    period_start_date = week_start.date()
    period_end_date = now.date()

    conn = get_connection()
    cur = conn.cursor()

    # Check for cached summary first
    cur.execute("""
        SELECT executive_summary, recommendations, future_outlook, generated_at
        FROM weekly_digest_summaries
        WHERE customer_id = %s AND period_start = %s AND period_end = %s
    """, (customer_id, period_start_date, period_end_date))
    cached_summary = cur.fetchone()

    # Build digest data (needed for both cache miss and AI generation)
    # 1. Overall risk: average of current profile risk scores
    cur.execute("""
        SELECT COALESCE(AVG(p.risk_score), 0), COUNT(p.id)
        FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.customer_id = %s
    """, (customer_id,))
    row = cur.fetchone()
    overall_risk = round(row[0] or 0)
    profile_count = row[1] or 0

    # 2. Risk change: compare current avg vs avg 7 days ago (via architecture_changes risk_before)
    cur.execute("""
        SELECT COALESCE(AVG(ac.risk_before), 0)
        FROM architecture_changes ac
        WHERE ac.customer_id = %s AND ac.created_at >= %s
    """, (customer_id, week_start))
    risk_before = cur.fetchone()[0] or 0
    risk_change = overall_risk - round(risk_before) if risk_before else 0

    # 3. Critical / high-risk vendors
    cur.execute("""
        SELECT cv.vendor, p.risk_score, p.criticality
        FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.customer_id = %s AND p.risk_score >= 85
        ORDER BY p.risk_score DESC
    """, (customer_id,))
    critical_vendors = [
        {"vendor": r[0], "risk_score": r[1], "criticality": r[2]}
        for r in cur.fetchall()
    ]

    cur.execute("""
        SELECT cv.vendor, p.risk_score, p.criticality
        FROM third_party_profiles p
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.customer_id = %s AND p.risk_score >= 70 AND p.risk_score < 85
        ORDER BY p.risk_score DESC
    """, (customer_id,))
    high_risk_vendors = [
        {"vendor": r[0], "risk_score": r[1], "criticality": r[2]}
        for r in cur.fetchall()
    ]

    # 4. New alerts this week
    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND created_at >= %s
    """, (customer_id, week_start))
    new_alerts = cur.fetchone()[0]

    # 5. Resolved alerts this week
    cur.execute("""
        SELECT COUNT(*) FROM third_party_alerts
        WHERE customer_id = %s AND status IN ('RESOLVED', 'ACKNOWLEDGED')
          AND updated_at >= %s
    """, (customer_id, week_start))
    resolved_alerts = cur.fetchone()[0]

    # 6. New vulnerabilities / breaches / ransomware
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

    # 7. Architecture changes this week
    cur.execute("""
        SELECT COUNT(*) FROM architecture_changes
        WHERE customer_id = %s AND created_at >= %s
    """, (customer_id, week_start))
    architecture_changes = cur.fetchone()[0]

    # 8. New external exposures
    cur.execute("""
        SELECT COUNT(*) FROM third_party_external_assets x
        JOIN third_party_profiles p ON p.id = x.profile_id
        JOIN customer_vendors cv ON cv.id = p.customer_vendor_id
        WHERE cv.customer_id = %s AND x.exposure_status ILIKE '%%exposed%%'
          AND x.created_at >= %s
    """, (customer_id, week_start))
    new_external_exposures = cur.fetchone()[0]

    # 9. Top risks (highest risk vendors with reasons)
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
    top_risks = []
    for r in cur.fetchall():
        top_risks.append({
            "vendor": r[0],
            "risk_score": r[1],
            "criticality": r[2],
            "business_role": r[3],
            "technologies": r[4],
        })

    # 10. Recommendations (from top alerts)
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

    digest_data = {
        "period": {
            "start": week_start.isoformat(),
            "end": now.isoformat(),
        },
        "overall_risk": overall_risk,
        "risk_change": risk_change,
        "critical_vendors": critical_vendors,
        "high_risk_vendors": high_risk_vendors,
        "new_alerts": new_alerts,
        "resolved_alerts": resolved_alerts,
        "new_vulnerabilities": new_vulnerabilities,
        "new_breaches": new_breaches,
        "new_ransomware_events": new_ransomware,
        "architecture_changes": architecture_changes,
        "new_external_exposures": new_external_exposures,
        "top_risks": top_risks,
        "recommendations": recommendations,
    }

    # Handle AI summary (cache hit or generate new)
    ai_summary = None
    if cached_summary:
        # Return cached summary
        ai_summary = {
            "executive_summary": cached_summary[0],
            "recommendations": json.loads(cached_summary[1]) if isinstance(cached_summary[1], str) else cached_summary[1],
            "future_outlook": cached_summary[2],
            "generated_at": cached_summary[3].isoformat() if cached_summary[3] else None
        }
    else:
        # Generate new summary
        logger.info(f"No cached summary found for customer {customer_id}, period {period_start_date} to {period_end_date}. Generating new AI analysis...")
        new_summary = generate_digest_summary(digest_data)
        
        # Store in cache
        cur.execute("""
            INSERT INTO weekly_digest_summaries 
            (customer_id, period_start, period_end, executive_summary, recommendations, future_outlook)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (customer_id, period_start, period_end) DO UPDATE SET
                executive_summary = EXCLUDED.executive_summary,
                recommendations = EXCLUDED.recommendations,
                future_outlook = EXCLUDED.future_outlook,
                generated_at = CURRENT_TIMESTAMP
        """, (
            customer_id,
            period_start_date,
            period_end_date,
            new_summary["executive_summary"],
            json.dumps(new_summary["recommendations"]),
            new_summary["future_outlook"]
        ))
        conn.commit()
        
        ai_summary = {
            "executive_summary": new_summary["executive_summary"],
            "recommendations": new_summary["recommendations"],
            "future_outlook": new_summary["future_outlook"],
            "generated_at": now.isoformat()
        }

    cur.close()
    conn.close()

    return {
        **digest_data,
        "ai_summary": ai_summary
    }


@router.post("/third-party-weekly/regenerate")
def regenerate_digest_summary(current_user: dict = Depends(get_current_user)):
    """Regenerate AI summary for current week (admin only)."""
    if current_user.get("role") != "Admin":
        raise HTTPException(status_code=403, detail="Only admins can regenerate summaries")
    
    customer_id = current_user["customer_id"]
    now = datetime.now()
    week_start = now - timedelta(days=7)
    
    period_start_date = week_start.date()
    period_end_date = now.date()

    conn = get_connection()
    cur = conn.cursor()

    # Delete existing cached summary
    cur.execute("""
        DELETE FROM weekly_digest_summaries
        WHERE customer_id = %s AND period_start = %s AND period_end = %s
    """, (customer_id, period_start_date, period_end_date))
    
    conn.commit()
    cur.close()
    conn.close()

    # Call the regular digest endpoint which will regenerate
    return third_party_weekly_digest(current_user)


@router.get("/customers/{customer_id}/data-breaches")
def get_customer_data_breaches(customer_id: int, current_user: dict = Depends(get_current_user)):
    """Get data breaches correlated with customer's ecosystem (tenant-isolated)."""
    # Verify customer access
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot access other customers' data")

    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Get customer's vendors and technologies for correlation
        cur.execute("""
            SELECT DISTINCT cv.vendor, t.technology
            FROM customer_vendors cv
            LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
            LEFT JOIN third_party_profile_technologies t ON t.profile_id = p.id
            WHERE cv.customer_id = %s
        """, (customer_id,))
        customer_ecosystem = cur.fetchall()
        
        customer_vendors = set(row[0] for row in customer_ecosystem if row[0])
        customer_technologies = set(row[1] for row in customer_ecosystem if row[1])
        
        # Get breach alerts joined with threat_events
        cur.execute("""
            SELECT a.id, a.customer_vendor_id, a.threat_event_id,
                   a.vendor, a.affected_technology, a.alert_type, a.severity,
                   a.risk_score, a.confidence, a.evidence, a.business_relevance,
                   a.recommended_action, a.status, a.created_at,
                   t.title, t.description, t.published_date, t.source_url
            FROM third_party_alerts a
            LEFT JOIN threat_events t ON a.threat_event_id = t.id
            WHERE a.customer_id = %s AND a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')
            ORDER BY a.created_at DESC, a.risk_score DESC
        """, (customer_id,))
        
        breach_rows = cur.fetchall()
        
        # Correlate with customer ecosystem
        breaches = []
        for row in breach_rows:
            breach_vendor = row[3]
            breach_tech = row[4]
            
            # Determine if breach matches customer ecosystem
            customer_impact = False
            match_reason = None
            matched_vendor_id = None
            matched_technology_id = None
            
            # Check vendor match via customer_vendors table
            if breach_vendor:
                cur.execute("""
                    SELECT cv.id, cv.vendor_id FROM customer_vendors cv
                    WHERE cv.customer_id = %s AND LOWER(cv.vendor) = LOWER(%s)
                    LIMIT 1
                """, (customer_id, breach_vendor))
                vendor_match = cur.fetchone()
                if vendor_match:
                    customer_impact = True
                    matched_vendor_id = vendor_match[0]
                    match_reason = f"Vendor {breach_vendor} is in customer ecosystem"
            
            # Check technology match via assets table
            if not customer_impact and breach_tech:
                cur.execute("""
                    SELECT a.id FROM assets a
                    WHERE a.customer_id = %s AND LOWER(a.technology) = LOWER(%s)
                    LIMIT 1
                """, (customer_id, breach_tech))
                tech_match = cur.fetchone()
                if tech_match:
                    customer_impact = True
                    matched_technology_id = tech_match[0]
                    match_reason = f"Technology {breach_tech} is in customer ecosystem"
            
            # Also check threat_events affected_technologies/affected_products
            if not customer_impact and row[2]:
                cur.execute("""
                    SELECT affected_vendors, affected_products, affected_technologies
                    FROM threat_events WHERE id = %s
                """, (row[2],))
                te_row = cur.fetchone()
                if te_row:
                    affected_vendors = te_row[0] or []
                    affected_products = te_row[1] or []
                    affected_technologies = te_row[2] or []
                    
                    # Check against customer vendors
                    for cv_name in customer_vendors:
                        for av in affected_vendors:
                            if cv_name and av and str(cv_name).lower() == str(av).lower():
                                customer_impact = True
                                match_reason = f"Vendor {cv_name} affected by breach"
                                break
                        if customer_impact:
                            break
                    
                    # Check against customer technologies
                    if not customer_impact:
                        for ct_name in customer_technologies:
                            for at in list(affected_products) + list(affected_technologies):
                                if ct_name and at and str(ct_name).lower() == str(at).lower():
                                    customer_impact = True
                                    match_reason = f"Technology {ct_name} affected by breach"
                                    break
                            if customer_impact:
                                break
            
            title = row[14] or f"Data Breach affecting {breach_vendor or 'Unknown Vendor'}"
            
            breaches.append({
                "id": row[0],
                "customer_vendor_id": row[1],
                "threat_event_id": row[2],
                "vendor_name": breach_vendor,
                "technology_name": breach_tech,
                "alert_type": row[5],
                "severity": row[6],
                "risk_score": row[7],
                "confidence": row[8],
                "evidence": _parse_json_field(row[9]),
                "business_relevance": row[10],
                "recommended_action": row[11],
                "status": row[12],
                "created_at": row[13].isoformat() if row[13] else None,
                "customer_impact": customer_impact,
                "match_reason": match_reason,
                "matched_vendor_id": matched_vendor_id,
                "matched_technology_id": matched_technology_id,
                "title": title,
                "description": row[15],
                "published_at": row[16].isoformat() if row[16] else (row[13].isoformat() if row[13] else None),
                "source_url": row[17]
            })
        
        # Calculate summary statistics
        summary = {
            "total": len(breaches),
            "critical": sum(1 for b in breaches if b["severity"] == "CRITICAL"),
            "high": sum(1 for b in breaches if b["severity"] == "HIGH"),
            "medium": sum(1 for b in breaches if b["severity"] == "MEDIUM"),
            "low": sum(1 for b in breaches if b["severity"] == "LOW"),
            "matched": sum(1 for b in breaches if b["customer_impact"])
        }
        
        return {
            "breaches": breaches,
            "summary": summary
        }
        
    finally:
        cur.close()
        conn.close()


@router.get("/customers/{customer_id}/data-breaches/{breach_id}")
def get_data_breach_detail(customer_id: int, breach_id: int, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific data breach (tenant-isolated)."""
    # Verify customer access
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot access other customers' data")

    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Get breach details joined with threat_events
        cur.execute("""
            SELECT a.id, a.customer_vendor_id, a.threat_event_id,
                   a.vendor, a.affected_technology, a.alert_type, a.severity,
                   a.risk_score, a.confidence, a.evidence, a.business_relevance,
                   a.recommended_action, a.status, a.created_at,
                   t.title, t.description, t.published_date, t.source_url
            FROM third_party_alerts a
            LEFT JOIN threat_events t ON a.threat_event_id = t.id
            WHERE a.customer_id = %s AND a.id = %s AND a.alert_type IN ('BREACH', 'SECURITY_INCIDENT')
        """, (customer_id, breach_id))
        
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Breach not found")
            
        # Get customer ecosystem for correlation context
        cur.execute("""
            SELECT DISTINCT cv.vendor, t.technology
            FROM customer_vendors cv
            LEFT JOIN third_party_profiles p ON p.customer_vendor_id = cv.id
            LEFT JOIN third_party_profile_technologies t ON t.profile_id = p.id
            WHERE cv.customer_id = %s
        """, (customer_id,))
        customer_ecosystem = cur.fetchall()
        
        customer_vendors = set(r[0] for r in customer_ecosystem if r[0])
        customer_technologies = set(r[1] for r in customer_ecosystem if r[1])
        
        breach_vendor = row[3]
        breach_tech = row[4]
        
        customer_impact = False
        match_reason = None
        
        if breach_vendor and breach_vendor in customer_vendors:
            customer_impact = True
            match_reason = f"Vendor {breach_vendor} is in customer ecosystem"
        elif breach_tech and breach_tech in customer_technologies:
            customer_impact = True
            match_reason = f"Technology {breach_tech} is in customer ecosystem"
            
        title = row[14] or f"Data Breach affecting {breach_vendor or 'Unknown Vendor'}"
        
        return {
            "id": row[0],
            "customer_vendor_id": row[1],
            "threat_event_id": row[2],
            "vendor_name": breach_vendor,
            "technology_name": breach_tech,
            "alert_type": row[5],
            "severity": row[6],
            "risk_score": row[7],
            "confidence": row[8],
            "evidence": _parse_json_field(row[9]),
            "business_relevance": row[10],
            "recommended_action": row[11],
            "status": row[12],
            "created_at": row[13].isoformat() if row[13] else None,
            "customer_impact": customer_impact,
            "match_reason": match_reason,
            "title": title,
            "description": row[15],
            "published_at": row[16].isoformat() if row[16] else (row[13].isoformat() if row[13] else None),
            "source_url": row[17]
        }
        
    finally:
        cur.close()
        conn.close()