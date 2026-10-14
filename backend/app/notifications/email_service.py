"""
Email Notification Service for Security Alerts.

Primary transport: Resend (when RESEND_API_KEY is set).
Fallback transport: SMTP (when SMTP_HOST/USER/PASSWORD are set).
If neither is configured, notifications are skipped and logged.

Integrates with alert_email_notifications table for per-recipient delivery tracking.
"""
import logging
import os
import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import psycopg2.extras
from dotenv import load_dotenv

from app.database.connection import get_connection

load_dotenv()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTML email builder
# ---------------------------------------------------------------------------

def _build_subject(alert: Dict[str, Any]) -> str:
    """Build a descriptive subject line using real alert fields."""
    severity  = (alert.get("severity") or alert.get("risk_level") or "ALERT").upper()
    vendor    = _safe(alert, "vendor", "asset_vendor")
    tech      = _safe(alert, "affected_technology", "asset_technology")
    cve_id    = alert.get("cve_id")

    if vendor and tech and cve_id:
        return f"[{severity}] {vendor} — {tech} — {cve_id}"
    if vendor and cve_id:
        return f"[{severity}] {vendor} — {cve_id}"
    if cve_id:
        return f"[{severity}] Security Alert — {cve_id}"
    if vendor and tech:
        return f"[{severity}] Security Alert: {tech} by {vendor}"
    if vendor:
        return f"[{severity}] Security Alert: {vendor}"
    if tech:
        return f"[{severity}] Security Alert: {tech}"
    return f"[{severity}] Security Alert"


def _safe(d: Dict[str, Any], *keys: str, default: str = "") -> str:
    """Return first non-None/non-empty value among the given keys."""
    for k in keys:
        v = d.get(k)
        if v and str(v).strip() and str(v).strip().lower() not in ("none", "null", "not specified"):
            return str(v).strip()
    return default


def _row(label: str, value: str) -> str:
    if not value:
        return ""
    return (
        f'<tr><td style="padding:6px 10px;color:#888;font-size:13px;white-space:nowrap;'
        f'vertical-align:top"><strong>{label}</strong></td>'
        f'<td style="padding:6px 10px;color:#333;font-size:13px">{value}</td></tr>'
    )


def build_html_email(alert: Dict[str, Any]) -> tuple[str, str]:
    """Return (subject, html_body) built entirely from real alert data."""
    subject = _build_subject(alert)

    severity     = (alert.get("severity") or alert.get("risk_level") or "UNKNOWN").upper()
    title        = _safe(alert, "title") or subject
    vendor       = _safe(alert, "vendor", "asset_vendor") or "Not specified"
    tech         = _safe(alert, "affected_technology", "asset_technology") or "Not specified"
    cve_id       = _safe(alert, "cve_id")
    threat_type  = _safe(alert, "threat_type", "alert_type")
    attack_tech  = _safe(alert, "attack_technique")
    summary      = _safe(alert, "ai_summary", "threat_description", "description", "business_relevance")
    impact       = _safe(alert, "business_impact", "business_relevance") or "Not specified"
    recom        = _safe(alert, "recommendation", "recommended_action") or "Not specified"
    escalation   = _safe(alert, "escalation_recommendation") or "Not specified"
    created_at   = alert.get("created_at", "")

    severity_color = {
        "CRITICAL": "#E2483C",
        "HIGH":     "#D65A3C",
        "MEDIUM":   "#D9B23D",
        "LOW":      "#4C8C63",
    }.get(severity, "#E39307")

    header_color = "#E39307"

    rows = "".join(filter(None, [
        _row("Vendor:",            vendor if vendor != "Not specified" else ""),
        _row("Technology:",        tech   if tech   != "Not specified" else ""),
        _row("CVE:",               cve_id),
        _row("Threat Type:",       threat_type),
        _row("Attack Technique:",  attack_tech),
    ]))

    html = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:20px;font-family:Arial,sans-serif;background:#f5f5f5">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)">
    <div style="background:{header_color};padding:20px;border-radius:8px 8px 0 0">
      <h1 style="margin:0;color:#fff;font-size:22px">AI-TIP Security Alert</h1>
      <p style="margin:4px 0 0;color:#fff;opacity:.9;font-size:13px">Automated threat notification</p>
    </div>
    <div style="padding:24px">
      <span style="display:inline-block;background:{severity_color};color:#fff;padding:6px 14px;border-radius:4px;font-weight:bold;font-size:13px;margin-bottom:16px">
        {severity} SEVERITY
      </span>
      <h2 style="margin:0 0 16px;color:#222;font-size:17px">{title}</h2>

      {"<table style='width:100%;border-collapse:collapse;margin-bottom:20px'>" + rows + "</table>" if rows else ""}

      {"<div style='background:#f9f9f9;padding:14px;border-radius:4px;border-left:4px solid " + severity_color + ";margin-bottom:20px'><h3 style='margin:0 0 8px;color:#333;font-size:15px'>Attack Summary</h3><p style='margin:0;color:#555;font-size:13px;line-height:1.6'>" + summary + "</p></div>" if summary else ""}

      <div style="margin-bottom:20px">
        <h3 style="margin:0 0 8px;color:#333;font-size:15px">Business Impact</h3>
        <p style="margin:0;color:#555;font-size:13px;line-height:1.6">{impact}</p>
      </div>

      <div style="margin-bottom:20px">
        <h3 style="margin:0 0 8px;color:#333;font-size:15px">Recommended Actions</h3>
        <p style="margin:0;color:#555;font-size:13px;line-height:1.6">{recom}</p>
        {"<p style='margin:8px 0 0;color:#555;font-size:13px'><strong>Escalation:</strong> " + escalation + "</p>" if escalation != "Not specified" else ""}
      </div>
    </div>
    <div style="background:#f5f5f5;padding:12px 20px;border-radius:0 0 8px 8px;border-top:1px solid #e0e0e0">
      <p style="margin:0;color:#999;font-size:11px;text-align:center">
        Automated notification from AI-TIP · Generated {created_at}
      </p>
    </div>
  </div>
</body>
</html>"""

    return subject, html


# ---------------------------------------------------------------------------
# Email service — Resend-first, SMTP fallback
# ---------------------------------------------------------------------------

class EmailService:
    """Service for sending alert email notifications with delivery tracking.

    Uses Resend when RESEND_API_KEY is configured, falls back to SMTP.
    """

    def __init__(self):
        load_dotenv()

        # Resend config (primary)
        self._resend_api_key = os.getenv("RESEND_API_KEY", "").strip()
        self._resend_from    = os.getenv("RESEND_FROM", "onboarding@resend.dev").strip()

        # SMTP config (fallback)
        self.smtp_host     = os.getenv("SMTP_HOST", "").strip()
        self.smtp_port     = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user     = os.getenv("SMTP_USER", "").strip()
        self.smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
        self.smtp_from     = os.getenv("SMTP_FROM", "noreply@ai-tip.local").strip()
        self.smtp_use_tls  = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
        self._test_mode = (
            os.getenv("AI_TIP_TEST_MODE", "").lower() in {"1", "true", "yes"}
            or "unittest" in sys.modules
        )

        self._use_resend = bool(self._resend_api_key)
        self._use_smtp   = bool(self.smtp_host and self.smtp_user and self.smtp_password)

        if self._use_resend:
            logger.info("[EMAIL SERVICE] Resend transport configured.")
        elif self._use_smtp:
            logger.info("[EMAIL SERVICE] SMTP transport configured.")
        else:
            logger.warning(
                "[EMAIL SERVICE] No transport configured. "
                "Set RESEND_API_KEY or SMTP_HOST/SMTP_USER/SMTP_PASSWORD."
            )

    def is_enabled(self) -> bool:
        return self._use_resend or self._use_smtp

    # ------------------------------------------------------------------
    # Recipient resolution (tenant-isolated)
    # ------------------------------------------------------------------

    def _get_recipients_for_customer(self, customer_id: int) -> List[Dict[str, Any]]:
        conn = get_connection()
        cur  = conn.cursor()
        try:
            cur.execute("""
                SELECT id, name, email, customer_id
                FROM notification_recipients
                WHERE customer_id = %s
                ORDER BY name
            """, (customer_id,))
            rows = cur.fetchall()
            return [{"id": r[0], "name": r[1], "email": r[2], "customer_id": r[3]} for r in rows]
        finally:
            cur.close()
            conn.close()

    # ------------------------------------------------------------------
    # Duplicate protection (per alert × recipient × notification_type)
    # ------------------------------------------------------------------

    def _check_notification_exists(
        self, alert_id: int, recipient_email: str, notification_type: str,
        alert_source: str = "third_party_alert",
    ) -> bool:
        conn = get_connection()
        cur  = conn.cursor()
        try:
            cur.execute("""
                SELECT 1 FROM alert_email_notifications
                WHERE alert_id = %s AND alert_source = %s
                  AND recipient_email = %s AND notification_type = %s
                LIMIT 1
            """, (alert_id, alert_source, recipient_email, notification_type))
            return cur.fetchone() is not None
        finally:
            cur.close()
            conn.close()

    # ------------------------------------------------------------------
    # Notification record management (alert_email_notifications table)
    # ------------------------------------------------------------------

    def _create_notification_record(
        self,
        alert_id: int,
        recipient_email: str,
        recipient_name: Optional[str],
        notification_type: str,
        status: str,
        sent_at: Optional[str] = None,
        failure_reason: Optional[str] = None,
        alert_source: str = "third_party_alert",
    ) -> int:
        conn = get_connection()
        cur  = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO alert_email_notifications (
                    alert_id, alert_source, recipient_email, recipient_name, notification_type,
                    status, sent_at, failure_reason, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING id
            """, (
                alert_id, alert_source, recipient_email, recipient_name,
                notification_type, status, sent_at, failure_reason,
            ))
            notification_id = cur.fetchone()[0]
            conn.commit()
            return notification_id
        except Exception as e:
            conn.rollback()
            logger.error(f"[EMAIL SERVICE] Failed to create notification record: {e}")
            raise
        finally:
            cur.close()
            conn.close()

    def _update_notification_record(
        self, notification_id: int, status: str,
        sent_at: Optional[str], failure_reason: Optional[str]
    ):
        conn = get_connection()
        cur  = conn.cursor()
        try:
            cur.execute("""
                UPDATE alert_email_notifications
                SET status = %s, sent_at = %s, failure_reason = %s
                WHERE id = %s
            """, (status, sent_at, failure_reason, notification_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"[EMAIL SERVICE] Failed to update notification record {notification_id}: {e}")
        finally:
            cur.close()
            conn.close()

    # ------------------------------------------------------------------
    # Transport implementations
    # ------------------------------------------------------------------

    def _send_via_resend(
        self, to_emails: List[str], subject: str, html: str
    ) -> tuple[bool, Optional[str]]:
        """Send via Resend API. Returns (success, failure_reason)."""
        if self._test_mode:
            logger.info("[EMAIL SERVICE] Test mode: Resend delivery suppressed")
            return False, "External email delivery disabled in test mode"
        try:
            import resend
            resend.api_key = self._resend_api_key
            response = resend.Emails.send({
                "from": self._resend_from,
                "to":   to_emails,
                "subject": subject,
                "html": html,
            })
            logger.info(f"[EMAIL SERVICE] Resend OK -> id={response.get('id')} to={to_emails}")
            return True, None
        except Exception as e:
            logger.error(f"[EMAIL SERVICE] Resend failed: {e}")
            return False, str(e)

    def _send_via_smtp(
        self, to_email: str, subject: str, body: str
    ) -> tuple[bool, Optional[str]]:
        """Send via SMTP. Returns (success, failure_reason)."""
        if self._test_mode:
            logger.info("[EMAIL SERVICE] Test mode: SMTP delivery suppressed")
            return False, "External email delivery disabled in test mode"
        try:
            msg = MIMEMultipart("alternative")
            msg["From"]    = self.smtp_from
            msg["To"]      = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as srv:
                if self.smtp_use_tls:
                    srv.starttls()
                srv.login(self.smtp_user, self.smtp_password)
                srv.send_message(msg)

            logger.info(f"[EMAIL SERVICE] SMTP OK -> {to_email}")
            return True, None
        except Exception as e:
            logger.error(f"[EMAIL SERVICE] SMTP failed: {e}")
            return False, str(e)

    # ------------------------------------------------------------------
    # Public API — send_alert_notification
    # ------------------------------------------------------------------

    def send_alert_notification(
        self,
        alert: Dict[str, Any],
        notification_type: str = "new_alert",
    ) -> Dict[str, Any]:
        """Send email notification for an alert to all configured recipients.

        Supports both the alerts table schema (asset_vendor, asset_technology)
        and the third_party_alerts schema (vendor, affected_technology).

        Args:
            alert: Alert dict (from either alerts or third_party_alerts).
            notification_type: 'new_alert', 'escalation', 'status_change', 'resolution'.

        Returns:
            Summary dict with counts of sent/failed notifications.
        """
        alert_id    = alert.get("id")
        customer_id = alert.get("customer_id")
        alert_source = "third_party_alert" if alert.get("alert_type") else "alert"

        if not alert_id or not customer_id:
            logger.error("[EMAIL SERVICE] Alert missing id or customer_id")
            return {"success": False, "error": "Invalid alert data"}

        if not self.is_enabled():
            logger.warning("[EMAIL SERVICE] No transport configured — skipping notification")
            return {
                "success": True,
                "alert_id": alert_id,
                "recipients_count": 0,
                "notifications_sent": 0,
                "notifications_failed": 0,
                "message": "No email transport configured",
            }

        recipients = self._get_recipients_for_customer(customer_id)
        if not recipients:
            logger.info(f"[EMAIL SERVICE] No recipients for customer {customer_id}")
            return {
                "success": True,
                "alert_id": alert_id,
                "recipients_count": 0,
                "notifications_sent": 0,
                "notifications_failed": 0,
                "message": "No recipients configured",
            }

        # Build email once (shared subject/body for all recipients)
        subject, html = build_html_email(alert)

        notifications_sent   = 0
        notifications_failed = 0
        results              = []

        if self._use_resend:
            # Resend: batch-send to non-duplicate recipients, then record per-recipient
            new_recipients = [
                r for r in recipients
                if not self._check_notification_exists(alert_id, r["email"], notification_type, alert_source)
            ]

            if not new_recipients:
                logger.info(f"[EMAIL SERVICE] All recipients already notified: alert={alert_id}")
                return {
                    "success": True,
                    "alert_id": alert_id,
                    "recipients_count": len(recipients),
                    "notifications_sent": 0,
                    "notifications_failed": 0,
                    "message": "Duplicate — all recipients already notified",
                }

            to_emails = [r["email"] for r in new_recipients]
            success, failure_reason = self._send_via_resend(to_emails, subject, html)
            sent_at = datetime.now(timezone.utc).isoformat() if success else None
            status  = "sent" if success else "failed"

            for r in new_recipients:
                try:
                    self._create_notification_record(
                        alert_id=alert_id,
                        recipient_email=r["email"],
                        recipient_name=r.get("name"),
                        notification_type=notification_type,
                        status=status,
                        sent_at=sent_at,
                        failure_reason=failure_reason,
                        alert_source=alert_source,
                    )
                except Exception:
                    pass

                if success:
                    notifications_sent += 1
                    results.append({"recipient": r["email"], "status": "sent"})
                else:
                    notifications_failed += 1
                    results.append({"recipient": r["email"], "status": "failed", "error": failure_reason})

        else:
            # SMTP: send per-recipient
            for r in recipients:
                if self._check_notification_exists(alert_id, r["email"], notification_type, alert_source):
                    logger.info(f"[EMAIL SERVICE] Skipping duplicate: alert={alert_id} to={r['email']}")
                    continue

                notification_id = self._create_notification_record(
                    alert_id=alert_id,
                    recipient_email=r["email"],
                    recipient_name=r.get("name"),
                    notification_type=notification_type,
                    status="pending",
                    alert_source=alert_source,
                )

                success, failure_reason = self._send_via_smtp(r["email"], subject, html)
                sent_at = datetime.now(timezone.utc).isoformat() if success else None
                status  = "sent" if success else "failed"

                self._update_notification_record(notification_id, status, sent_at, failure_reason)

                if success:
                    notifications_sent += 1
                    results.append({"recipient": r["email"], "notification_id": notification_id, "status": "sent"})
                else:
                    notifications_failed += 1
                    results.append({"recipient": r["email"], "notification_id": notification_id, "status": "failed", "error": failure_reason})

        return {
            "success": True,
            "alert_id": alert_id,
            "recipients_count": len(recipients),
            "notifications_sent": notifications_sent,
            "notifications_failed": notifications_failed,
            "results": results,
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get or create the global EmailService singleton."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
