-- Notification Recipients table
CREATE TABLE IF NOT EXISTS notification_recipients (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Notification Drafts table
CREATE TABLE IF NOT EXISTS notification_drafts (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    subject VARCHAR(500) NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_notification_recipients_customer ON notification_recipients(customer_id);
CREATE INDEX IF NOT EXISTS idx_notification_drafts_alert ON notification_drafts(alert_id);
CREATE INDEX IF NOT EXISTS idx_notification_drafts_status ON notification_drafts(status);
