from app.database.connection import get_connection
import json


def calculate_escalation_recommendation(risk_level, asset_criticality, internet_exposed, sensitive_data):
    """
    Derive escalation recommendation based on risk_level and asset characteristics.
    
    Returns: (escalation_label, reason_string)
    
    Logic:
    - ESCALATE_IMMEDIATELY: CRITICAL risk, or HIGH risk + CRITICAL asset with exposure/sensitive data
    - ESCALATE_SOON: HIGH risk, or HIGH criticality + HIGH risk asset with exposure
    - MONITOR: MEDIUM risk (default safe baseline)
    - NO_ACTION_NEEDED: LOW risk
    """
    
    if not risk_level:
        return "MONITOR", "No risk level specified"
    
    risk_level_upper = risk_level.upper()
    criticality_upper = asset_criticality.upper() if asset_criticality else "UNKNOWN"
    
    # ESCALATE_IMMEDIATELY conditions
    if risk_level_upper == "CRITICAL":
        return "ESCALATE_IMMEDIATELY", "Critical risk level detected"
    
    if risk_level_upper == "HIGH" and criticality_upper == "CRITICAL":
        if internet_exposed or sensitive_data:
            return "ESCALATE_IMMEDIATELY", "High risk + critical asset with exposure/sensitive data"
    
    # ESCALATE_SOON conditions
    if risk_level_upper == "HIGH":
        if criticality_upper == "HIGH" and internet_exposed:
            return "ESCALATE_SOON", "High risk on high-criticality internet-exposed asset"
        else:
            return "ESCALATE_SOON", "High risk level detected"
    
    # NO_ACTION_NEEDED conditions
    if risk_level_upper == "LOW":
        return "NO_ACTION_NEEDED", "Low risk level"
    
    if criticality_upper == "LOW":
        return "NO_ACTION_NEEDED", "Asset criticality is low"
    
    # Default: MONITOR (safe baseline for MEDIUM and unknown cases)
    return "MONITOR", "Medium risk - monitoring recommended"


def save_applicability_alert(alert: dict) -> dict:
    """Persist a generated applicability alert in the database.

    This uses the existing alerts table if available; otherwise it falls back to a
    lightweight in-memory-like behavior by returning the alert payload.
    """
    try:
        conn = get_connection()
        cur = conn.cursor()

        # Prevent duplicate alerts
        cur.execute(
            """
            SELECT id
            FROM alerts
            WHERE customer_id=%s
            AND title=%s
            AND asset_id IS NOT DISTINCT FROM %s
            """,
            (alert.get("customer_id"), alert.get("title"), alert.get("asset_id"))
        )
        existing = cur.fetchone()
        if existing:
            alert_id = existing[0]
            cur.close()
            conn.close()
            alert["stored_alert_id"] = alert_id
            alert["id"] = alert_id
            return alert

        cur.execute(
            """
            INSERT INTO alerts
            (
                customer_id,
                event_id,
                title,
                asset_id,
                asset_technology,
                asset_vendor,
                asset_version,
                asset_criticality,
                asset_internet_exposed,
                asset_sensitive_data,
                risk_score,
                risk_level,
                confidence_score,
                evidence,
                ai_summary,
                business_impact,
                recommendation,
                remediation_steps,
                status,
                escalation_recommendation
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                alert.get("customer_id"),
                alert.get("event_id"),
                alert.get("title"),
                alert.get("asset_id"),
                alert.get("asset_technology"),
                alert.get("asset_vendor"),
                alert.get("asset_version"),
                alert.get("asset_criticality"),
                alert.get("asset_internet_exposed"),
                alert.get("asset_sensitive_data"),
                alert.get("risk_score"),
                alert.get("risk_level"),
                alert.get("confidence_score"),
                json.dumps(alert.get("evidence") or []),
                alert.get("ai_summary"),
                alert.get("business_impact"),
                alert.get("recommendation"),
                json.dumps(alert.get("remediation_steps") or []),
                alert.get("status", "NEW"),
                calculate_escalation_recommendation(
                    alert.get("risk_level"),
                    alert.get("asset_criticality"),
                    alert.get("asset_internet_exposed"),
                    alert.get("asset_sensitive_data")
                )[0],  # Take only the label, not the reason
            ),
        )

        alert_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        alert["stored_alert_id"] = alert_id
        alert["id"] = alert_id
        return alert
    except Exception as exc:
        print(f"ALERT STORE ERROR: {repr(exc)}")
        alert["stored_alert_id"] = None
        alert["storage_error"] = str(exc)
        return alert
