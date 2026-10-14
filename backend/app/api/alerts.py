import logging
from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user, require_roles
from pydantic import BaseModel
from app.database.connection import get_connection
from app.notifications import get_email_service
import psycopg2.extras

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"]
)


@router.get("/")
def read_alerts(current_user: dict = Depends(get_current_user)):
    """Return alerts stored in the third_party_alerts table."""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT id, customer_id, customer_vendor_id, threat_event_id, vendor, affected_technology,
               alert_type, severity, risk_score, confidence, status, created_at, updated_at, recommended_action
        FROM third_party_alerts
        WHERE customer_id = %s
        ORDER BY created_at DESC
    """, (current_user["customer_id"],))
    
    alerts = cursor.fetchall()
    conn.close()
    
    results = []
    for alert in alerts:
        results.append({
            "id": alert.get("id"),
            "customer": alert.get("customer_id"),
            "title": f"{alert.get('vendor')} - {alert.get('alert_type')}",
            "event": alert.get("alert_type"),
            "risk_level": alert.get("severity"),
            "risk_score": alert.get("risk_score"),
            "confidence_score": alert.get("confidence"),
            "status": alert.get("status"),
            "created_at": alert.get("created_at"),
            "updated_at": alert.get("updated_at"),
            "escalation_recommendation": alert.get("recommended_action"),
            "alert_type": alert.get("alert_type"),
            "asset_vendor": alert.get("vendor"),
        })

    return results


class AlertStatusUpdate(BaseModel):
    status: str


@router.get("/{alert_id}")
def read_alert_detail(alert_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT * FROM third_party_alerts
        WHERE id = %s AND customer_id = %s
    """, (alert_id, current_user["customer_id"]))
    
    alert = cursor.fetchone()
    
    if not alert:
        cursor.execute("""
            SELECT * FROM alerts
            WHERE id = %s AND customer_id = %s
        """, (alert_id, current_user["customer_id"]))
        alert = cursor.fetchone()
        conn.close()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        # Format legacy alert from alerts table
        evidence_val = alert.get("evidence")
        if isinstance(evidence_val, str):
            try:
                import json
                evidence_list = json.loads(evidence_val)
            except Exception:
                evidence_list = [evidence_val]
        elif isinstance(evidence_val, list):
            evidence_list = evidence_val
        else:
            evidence_list = ["Asset vulnerability match"]

        alert["confidence_score"] = alert.get("confidence_score") or 80
        alert["analysis"] = {
            "evidence": evidence_list,
            "business_impact": alert.get("business_impact") or "Not specified",
        }
        alert["asset"] = {
            "vendor": alert.get("asset_vendor") or alert.get("vendor") or "Not specified"
        }
        return alert

    conn.close()
    
    # Map for frontend compatibility
    alert["title"] = alert.get("title") or f"{alert.get('vendor')} - {alert.get('alert_type')}"
    alert["risk_level"] = alert.get("severity") or alert.get("risk_level")
    alert["asset_vendor"] = alert.get("vendor") or alert.get("asset_vendor")
    alert["escalation_recommendation"] = alert.get("recommended_action") or alert.get("escalation_recommendation")
    return alert



@router.get("/{alert_id}/notifications")
def read_alert_notifications(alert_id: int, current_user: dict = Depends(get_current_user)):
    """Get email notification history for a specific alert."""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Verify alert belongs to user's customer
    cursor.execute("""
        SELECT customer_id FROM third_party_alerts
        WHERE id = %s
    """, (alert_id,))

    
    alert = cursor.fetchone()
    
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if alert["customer_id"] != current_user["customer_id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Cannot access notifications for another customer's alert")
    
    # Get notifications for third-party alerts
    cursor.execute("""
        SELECT id, alert_id, recipient_email, recipient_name, notification_type, 
               status, sent_at, delivered_at, failure_reason, created_at
        FROM alert_email_notifications
        WHERE alert_id = %s AND alert_source = 'third_party_alert'
        ORDER BY created_at DESC
    """, (alert_id,))
    
    notifications = cursor.fetchall()
    conn.close()
    
    return {
        "alert_id": alert_id,
        "notifications": notifications
    }


@router.patch("/{alert_id}/status")
def patch_alert_status(alert_id: int, update: AlertStatusUpdate, current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Statuses actually supported by the third_party_alerts table
    allowed_statuses = {"NEW", "ACKNOWLEDGED", "IN_PROGRESS", "MITIGATED", "RESOLVED", "DISMISSED"}
    if update.status not in allowed_statuses:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed values: {', '.join(sorted(allowed_statuses))}"
        )
    
    # Get current status before update
    cursor.execute("""
        SELECT * FROM third_party_alerts
        WHERE id = %s AND customer_id = %s
    """, (alert_id, current_user["customer_id"]))
    
    old_alert = cursor.fetchone()
    
    if not old_alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    
    old_status = old_alert.get("status")
    
    # Update status
    cursor.execute("""
        UPDATE third_party_alerts
        SET status = %s, updated_at = CURRENT_TIMESTAMP
        WHERE id = %s AND customer_id = %s
        RETURNING *
    """, (update.status, alert_id, current_user["customer_id"]))
    
    alert = cursor.fetchone()
    conn.commit()
    conn.close()
    
    # Send email notification for status change (non-blocking)
    if old_status != update.status:
        try:
            email_service = get_email_service()
            if email_service.is_enabled():
                notification_type = "resolution" if update.status in ("MITIGATED", "RESOLVED") else "status_change"
                email_result = email_service.send_alert_notification(
                    alert, notification_type=notification_type
                )
                logger.info(
                    f"[ALERTS API] Email notification sent for status change on alert {alert_id}: "
                    f"{email_result.get('notifications_sent', 0)} sent, "
                    f"{email_result.get('notifications_failed', 0)} failed"
                )
        except Exception as e:
            logger.error(f"[ALERTS API] Failed to send email notification for status change on alert {alert_id}: {e}")
            # Email failure should not prevent status update
    
    return alert
