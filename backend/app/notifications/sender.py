import os
from dotenv import load_dotenv
import resend
from app.database.connection import get_connection
import psycopg2.extras

# Load environment variables from .env file
load_dotenv()


def enrich_alert_data(alert_id: int, alert_data: dict) -> dict:
    """Enrich alert_data with actual database values if fields are missing.
    
    Checks both alerts and third_party_alerts tables to populate missing fields.
    
    Args:
        alert_id: The ID of the alert
        alert_data: Dictionary containing alert data
        
    Returns:
        dict with enriched alert data
    """
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Check alerts table first
    cursor.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
    alert = cursor.fetchone()

    # Check third_party_alerts table
    cursor.execute("SELECT * FROM third_party_alerts WHERE id = %s", (alert_id,))
    tp_alert = cursor.fetchone()

    cursor.close()
    conn.close()

    # Merge data, preferring non-None values
    enriched = alert_data.copy()

    if alert:
        def _fill(key, db_key=None):
            db_key = db_key or key
            val = enriched.get(key)
            if not val or str(val).strip() in ("", "None", "Not specified"):
                enriched[key] = alert.get(db_key) or "Not specified"
        _fill("title");              enriched.setdefault("title", "Security Alert")
        _fill("asset_technology");   _fill("asset_vendor")
        _fill("business_impact");    _fill("recommendation")
        _fill("escalation_recommendation"); _fill("ai_summary")
        # Also surface as vendor/technology for the shared email builder
        enriched.setdefault("vendor", enriched.get("asset_vendor"))
        enriched.setdefault("affected_technology", enriched.get("asset_technology"))

    if tp_alert:
        def _fill_tp(key, tp_key):
            val = enriched.get(key)
            if not val or str(val).strip() in ("", "None", "Not specified"):
                enriched[key] = tp_alert.get(tp_key) or enriched.get(key, "Not specified")
        _fill_tp("vendor",              "vendor")
        _fill_tp("asset_vendor",        "vendor")
        _fill_tp("affected_technology", "affected_technology")
        _fill_tp("asset_technology",    "affected_technology")
        _fill_tp("business_impact",     "business_relevance")
        _fill_tp("recommendation",      "recommended_action")
        if tp_alert.get("cve_id"):
            enriched["cve_id"] = tp_alert["cve_id"]

        # Fetch threat event details if available — use a fresh connection
        if tp_alert.get("threat_event_id"):
            conn2 = get_connection()
            cur2 = conn2.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                cur2.execute("SELECT * FROM threat_events WHERE id = %s", (tp_alert["threat_event_id"],))
                threat_event = cur2.fetchone()
                if threat_event:
                    enriched["threat_title"]     = threat_event.get("title")
                    enriched["threat_description"] = threat_event.get("description")
                    enriched["threat_type"]      = threat_event.get("threat_type")
                    enriched["attack_technique"] = threat_event.get("attack_technique")
            finally:
                cur2.close()
                conn2.close()

        # Fetch CVE event details if available
        if alert and alert.get("event_id"):
            conn3 = get_connection()
            cur3 = conn3.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                cur3.execute("SELECT * FROM cve_events WHERE id = %s", (alert["event_id"],))
                cve_event = cur3.fetchone()
                if cve_event:
                    enriched["cve_title"]      = cve_event.get("title")
                    enriched["cve_description"] = cve_event.get("description")
                    enriched["cve_cvss_score"]  = cve_event.get("cvss_score")
                    enriched["cve_severity"]    = cve_event.get("severity")
            finally:
                cur3.close()
                conn3.close()

    return enriched


def check_notification_exists(alert_id: int, recipient_email: str) -> bool:
    """Check if a notification already exists for the alert.
    
    Uses notification_drafts table since alert_email_notifications has
    a foreign key constraint to third_party_alerts.id, but the Resend path
    uses alerts from the alerts table.
    
    Args:
        alert_id: The ID of the alert
        recipient_email: The recipient email address (unused in current schema)
        
    Returns:
        bool: True if notification exists, False otherwise
    """
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT id FROM notification_drafts
        WHERE alert_id = %s
        AND status = 'sent'
        LIMIT 1
    """, (alert_id,))
    
    exists = cursor.fetchone() is not None
    cursor.close()
    conn.close()
    
    return exists


def send_notification_email(alert_id: int, alert_data: dict) -> dict:
    """Send notification email via Resend API to configured recipients.
    
    Auto-sends for CRITICAL/HIGH alerts if recipients are configured.
    Uses Resend's sandbox sender (onboarding@resend.dev) for testing.
    
    Args:
        alert_id: The ID of the alert
        alert_data: Dictionary containing alert data
        
    Returns:
        dict with send results including status, recipients, and Resend response
    """
    # Get Resend API credentials
    resend.api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("RESEND_FROM", "onboarding@resend.dev")
    
    # Enrich alert_data from database if fields are missing
    alert_data = enrich_alert_data(alert_id, alert_data)
    
    if not resend.api_key:
        print(f"[NOTIFICATION] RESEND_API_KEY not configured, skipping send")
        # Log skipped notification
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("""
            INSERT INTO notification_drafts (alert_id, subject, body, status)
            VALUES (%s, %s, %s, 'skipped-no-api-key')
            RETURNING id
        """, (alert_id, "Skipped - No API key configured", "RESEND_API_KEY not configured in .env"))
        
        conn.commit()
        conn.close()
        
        return {
            "alert_id": alert_id,
            "status": "skipped-no-api-key",
            "recipients": [],
            "message": "RESEND_API_KEY not configured, notification skipped"
        }
    
    # Get notification recipients for the customer
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT id, name, email
        FROM notification_recipients
        WHERE customer_id = %s
    """, (alert_data.get("customer_id"),))
    
    recipients = cursor.fetchall()
    
    if not recipients:
        # Safety gate: no recipients configured, skip sending
        print(f"[NOTIFICATION] No recipients configured for customer {alert_data.get('customer_id')}, skipping send")
        
        # Log skipped notification
        cursor.execute("""
            INSERT INTO notification_drafts (alert_id, subject, body, status)
            VALUES (%s, %s, %s, 'skipped-no-recipients')
            RETURNING id
        """, (alert_id, "Skipped - No recipients configured", "No recipients configured for this customer"))
        
        conn.commit()
        conn.close()
        
        return {
            "alert_id": alert_id,
            "status": "skipped-no-recipients",
            "recipients": [],
            "message": "No recipients configured, notification skipped"
        }
    
    # Filter out already-notified recipients (do NOT mutate while iterating)
    recipient_emails = [
        r["email"] for r in recipients
        if not check_notification_exists(alert_id, r["email"])
    ]

    if not recipient_emails:
        print(f"[NOTIFICATION] All recipients already notified for alert {alert_id}")
        conn.close()
        return {
            "alert_id": alert_id,
            "status": "skipped-duplicate",
            "recipients": [],
            "message": "All recipients already notified for this alert"
        }
    
    # Generate HTML email content
    subject, html_body = generate_html_email(alert_data)
    
    try:
        # Send email using Resend
        params = {
            "from": from_email,
            "to": recipient_emails,
            "subject": subject,
            "html": html_body,
        }
        
        response = resend.Emails.send(params)
        
        print(f"[NOTIFICATION] Email sent successfully via Resend to {recipient_emails}")
        print(f"[NOTIFICATION] Resend response: {response}")
        
        # Log successful notification in notification_drafts
        cursor.execute("""
            INSERT INTO notification_drafts (alert_id, subject, body, status)
            VALUES (%s, %s, %s, 'sent')
            RETURNING id
        """, (alert_id, subject, html_body))
        
        draft_id = cursor.fetchone()['id']
        
        # Update with sent timestamp
        cursor.execute("""
            UPDATE notification_drafts
            SET sent_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (draft_id,))
        
        conn.commit()
        conn.close()
        
        return {
            "alert_id": alert_id,
            "status": "sent",
            "recipients": recipient_emails,
            "resend_id": response.get("id"),
            "resend_response": response,
            "message": "Email sent successfully"
        }
        
    except Exception as e:
        print(f"[NOTIFICATION] Failed to send email: {e}")
        
        # Log failed notification
        cursor.execute("""
            INSERT INTO notification_drafts (alert_id, subject, body, status)
            VALUES (%s, %s, %s, 'failed')
            RETURNING id
        """, (alert_id, subject, f"Failed to send: {str(e)}"))
        
        conn.commit()
        conn.close()
        
        return {
            "alert_id": alert_id,
            "status": "failed",
            "recipients": recipient_emails,
            "error": str(e),
            "message": "Failed to send email"
        }


def generate_html_email(alert_data: dict) -> tuple:
    """Generate HTML email content from alert data.
    
    Returns:
        tuple of (subject, html_body)
    """
    # Extract relevant fields with proper fallbacks
    title = alert_data.get("title") or "Security Alert"
    asset_technology = alert_data.get("asset_technology") or "Not specified"
    asset_vendor = alert_data.get("asset_vendor") or "Not specified"
    risk_level = alert_data.get("risk_level") or "UNKNOWN"
    business_impact = alert_data.get("business_impact") or "Not specified"
    recommendation = alert_data.get("recommendation") or "Not specified"
    escalation_recommendation = alert_data.get("escalation_recommendation") or "Not specified"
    ai_summary = alert_data.get("ai_summary") or "Not specified"
    cve_id = alert_data.get("cve_id")
    threat_title = alert_data.get("threat_title")
    threat_description = alert_data.get("threat_description")
    threat_type = alert_data.get("threat_type")
    attack_technique = alert_data.get("attack_technique")
    
    # Generate subject line with CVE context if available
    if cve_id and asset_vendor != "Not specified" and asset_technology != "Not specified":
        subject = f"[{risk_level}] {asset_vendor} — {asset_technology} — {cve_id}"
    elif cve_id and asset_vendor != "Not specified":
        subject = f"[{risk_level}] {asset_vendor} — {cve_id}"
    elif cve_id:
        subject = f"[{risk_level}] Security Alert — {cve_id}"
    elif asset_technology != "Not specified" and asset_vendor != "Not specified":
        subject = f"[{risk_level}] Security Alert: {asset_technology} by {asset_vendor}"
    elif asset_vendor != "Not specified":
        subject = f"[{risk_level}] Security Alert: {asset_vendor}"
    elif asset_technology != "Not specified":
        subject = f"[{risk_level}] Security Alert: {asset_technology}"
    else:
        subject = f"[{risk_level}] Security Alert"
    
    # Severity color mapping
    severity_colors = {
        'CRITICAL': '#E2483C',
        'HIGH': '#D65A3C',
        'MEDIUM': '#D9B23D',
        'LOW': '#4C8C63',
    }
    severity_color = severity_colors.get(risk_level, '#E39307')
    
    # Ember-bright color from tailwind config
    ember_bright = '#E39307'
    
    # Generate HTML body with inline CSS
    html_body = f"""
    <html>
    <body style="margin: 0; padding: 20px; font-family: Arial, sans-serif; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <!-- Header -->
            <div style="background-color: {ember_bright}; padding: 20px; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: bold;">Security Posture Agent</h1>
                <p style="margin: 5px 0 0 0; color: #ffffff; opacity: 0.9; font-size: 14px;">Security Alert Notification</p>
            </div>
            
            <!-- Severity Badge -->
            <div style="padding: 20px;">
                <div style="display: inline-block; background-color: {severity_color}; color: #ffffff; padding: 8px 16px; border-radius: 4px; font-weight: bold; font-size: 14px; margin-bottom: 20px;">
                    {risk_level} SEVERITY
                </div>
                
                <!-- Alert Title -->
                <h2 style="margin: 0 0 10px 0; color: #333333; font-size: 18px; font-weight: bold;">{title}</h2>
                
                <!-- Affected Third Party -->
                <p style="margin: 0 0 20px 0; color: #666666; font-size: 14px;">
                    <strong>Affected Technology:</strong> {asset_technology}<br>
                    <strong>Vendor:</strong> {asset_vendor}
                </p>
                
                <!-- Attack Summary -->
                <div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin-bottom: 20px; border-left: 4px solid {severity_color};">
                    <h3 style="margin: 0 0 10px 0; color: #333333; font-size: 16px; font-weight: bold;">Attack Summary</h3>
                    <p style="margin: 0; color: #666666; font-size: 14px; line-height: 1.5;">{threat_description if threat_description else ai_summary}</p>
                </div>
                
                {f'''<!-- Threat Intelligence -->
                <div style="margin-bottom: 20px;">
                    <h3 style="margin: 0 0 10px 0; color: #333333; font-size: 16px; font-weight: bold;">Threat Intelligence</h3>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 10px;">
                        {f'<tr><td style="padding: 8px; border-bottom: 1px solid #e0e0e0; color: #666666; font-size: 14px;"><strong>CVE:</strong></td><td style="padding: 8px; border-bottom: 1px solid #e0e0e0; color: #333333; font-size: 14px;">{cve_id}</td></tr>' if cve_id else ''}
                        {f'<tr><td style="padding: 8px; border-bottom: 1px solid #e0e0e0; color: #666666; font-size: 14px;"><strong>Threat Type:</strong></td><td style="padding: 8px; border-bottom: 1px solid #e0e0e0; color: #333333; font-size: 14px;">{threat_type or "Not specified"}</td></tr>' if threat_type else ''}
                        {f'<tr><td style="padding: 8px; border-bottom: 1px solid #e0e0e0; color: #666666; font-size: 14px;"><strong>Attack Technique:</strong></td><td style="padding: 8px; border-bottom: 1px solid #e0e0e0; color: #333333; font-size: 14px;">{attack_technique or "Not specified"}</td></tr>' if attack_technique else ''}
                    </table>
                </div>
                ''' if cve_id or threat_type or attack_technique else ''}
                
                <!-- Business Impact -->
                <div style="margin-bottom: 20px;">
                    <h3 style="margin: 0 0 10px 0; color: #333333; font-size: 16px; font-weight: bold;">Business Impact</h3>
                    <p style="margin: 0; color: #666666; font-size: 14px; line-height: 1.5;">{business_impact}</p>
                </div>
                
                <!-- Recommended Actions -->
                <div style="margin-bottom: 20px;">
                    <h3 style="margin: 0 0 10px 0; color: #333333; font-size: 16px; font-weight: bold;">Recommended Actions</h3>
                    <ul style="margin: 0; padding-left: 20px; color: #666666; font-size: 14px; line-height: 1.5;">
                        <li>{recommendation}</li>
                        <li><strong>Escalation:</strong> {escalation_recommendation}</li>
                    </ul>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #f5f5f5; padding: 15px 20px; border-radius: 0 0 8px 8px; border-top: 1px solid #e0e0e0;">
                <p style="margin: 0; color: #999999; font-size: 12px; text-align: center;">
                    This is an automated notification from Security Posture Agent.<br>
                    Generated on {alert_data.get('created_at', 'Unknown date')}
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return subject, html_body
