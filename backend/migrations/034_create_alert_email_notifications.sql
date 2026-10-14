-- Migration 034: Alert Email Notifications
--
-- Tracks email notification history for third-party alerts.
-- Each record represents an email sent to a specific recipient for an alert,
-- including delivery status and failure reasons.

CREATE TABLE IF NOT EXISTS alert_email_notifications (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES third_party_alerts(id) ON DELETE CASCADE,
    recipient_email VARCHAR(255) NOT NULL,
    recipient_name VARCHAR(255),
    notification_type VARCHAR(50) NOT NULL,  -- new_alert, escalation, status_change, resolution, other
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, sent, delivered, failed
    sent_at TIMESTAMP,
    delivered_at TIMESTAMP,
    failure_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alert_email_notifications_alert ON alert_email_notifications(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_email_notifications_status ON alert_email_notifications(status);
CREATE INDEX IF NOT EXISTS idx_alert_email_notifications_recipient ON alert_email_notifications(recipient_email);
CREATE INDEX IF NOT EXISTS idx_alert_email_notifications_sent_at ON alert_email_notifications(sent_at DESC);

COMMENT ON TABLE alert_email_notifications IS 'Email notification history for third-party alerts with delivery tracking';
COMMENT ON COLUMN alert_email_notifications.notification_type IS 'Type: new_alert, escalation, status_change, resolution, other';
COMMENT ON COLUMN alert_email_notifications.status IS 'Status: pending, sent, delivered, failed';
COMMENT ON COLUMN alert_email_notifications.failure_reason IS 'Error message if email delivery failed';
