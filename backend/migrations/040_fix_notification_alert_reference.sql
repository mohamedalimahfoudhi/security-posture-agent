-- Migration 040: notifications can originate from either alerts table.
-- A foreign key to only third_party_alerts rejected valid base-alert records.

ALTER TABLE alert_email_notifications
    ADD COLUMN IF NOT EXISTS alert_source VARCHAR(30) NOT NULL DEFAULT 'third_party_alert';

ALTER TABLE alert_email_notifications
    DROP CONSTRAINT IF EXISTS alert_email_notifications_alert_id_fkey;

ALTER TABLE alert_email_notifications
    DROP CONSTRAINT IF EXISTS alert_email_notifications_alert_source_check;

ALTER TABLE alert_email_notifications
    ADD CONSTRAINT alert_email_notifications_alert_source_check
    CHECK (alert_source IN ('alert', 'third_party_alert'));

CREATE INDEX IF NOT EXISTS idx_alert_email_notifications_source_alert
    ON alert_email_notifications(alert_source, alert_id);
