-- Migration 002: Extend alerts schema for SOC investigation workflow

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS title TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_id INTEGER;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_technology TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_vendor TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_version TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_criticality TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_internet_exposed BOOLEAN;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS asset_sensitive_data BOOLEAN;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS risk_score INTEGER;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS confidence_score INTEGER;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '[]'::jsonb;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS ai_summary TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS business_impact TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS recommendation TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS remediation_steps JSONB DEFAULT '[]'::jsonb;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE alerts
    ALTER COLUMN status SET DEFAULT 'NEW';

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_alerts_updated_at ON alerts;
CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
