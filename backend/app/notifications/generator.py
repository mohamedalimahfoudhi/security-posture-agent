import os
from app.database.connection import get_connection
from app.notifications.email_service import get_email_service
from app.notifications.sender import send_notification_email
import psycopg2.extras


def generate_and_send_notification(alert_id: int, alert_data: dict) -> dict:
    """Generate and send notification for CRITICAL/HIGH alerts via unified EmailService.
    
    Only processes CRITICAL or HIGH risk level alerts.
    
    Args:
        alert_id: The ID of the alert
        alert_data: Dictionary containing alert data
        
    Returns:
        dict with send results
    """
    # Only process CRITICAL or HIGH alerts
    if alert_data.get("risk_level") not in {"CRITICAL", "HIGH"}:
        print(f"[NOTIFICATION] Alert {alert_id} has risk level {alert_data.get('risk_level')}, skipping notification")
        return None
    
    # Auto-send notification via unified EmailService
    try:
        email_svc = get_email_service()
        alert_dict = alert_data.copy()
        alert_dict.setdefault("id", alert_id)
        
        result = email_svc.send_alert_notification(alert_dict, notification_type="vulnerability_applicability")
        status_str = "sent" if result.get("notifications_sent", 0) > 0 else "skipped"
        print(f"[NOTIFICATION] Notification processed for alert {alert_id}: {status_str}")
        return {
            "alert_id": alert_id,
            "status": status_str,
            "recipients": [r.get("recipient") for r in result.get("results", [])],
            "message": result.get("message", "Processed via EmailService")
        }
    except Exception as e:
        print(f"[NOTIFICATION] Failed to process notification for alert {alert_id}: {e}")
        return {
            "alert_id": alert_id,
            "status": "error",
            "error": str(e)
        }
