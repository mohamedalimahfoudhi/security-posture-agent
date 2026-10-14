-- Migration 005: Add escalation_recommendation column to alerts
-- Derived from risk_level and asset characteristics by save_applicability_alert()

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS escalation_recommendation VARCHAR
    DEFAULT NULL;

-- Backfill existing rows using the same logic as calculate_escalation_recommendation():
-- CRITICAL risk -> ESCALATE_IMMEDIATELY
-- HIGH risk + (critical asset with inet/sensitive) -> ESCALATE_IMMEDIATELY
-- HIGH risk -> ESCALATE_SOON
-- LOW risk OR low criticality -> NO_ACTION_NEEDED
-- All other (MEDIUM, unknowns) -> MONITOR

UPDATE alerts
SET escalation_recommendation = CASE
    WHEN UPPER(risk_level) = 'CRITICAL' THEN 'ESCALATE_IMMEDIATELY'
    WHEN UPPER(risk_level) = 'HIGH'
         AND UPPER(COALESCE(asset_criticality, '')) = 'CRITICAL'
         AND (asset_internet_exposed = TRUE OR asset_sensitive_data = TRUE)
        THEN 'ESCALATE_IMMEDIATELY'
    WHEN UPPER(risk_level) = 'HIGH' THEN 'ESCALATE_SOON'
    WHEN UPPER(risk_level) = 'LOW' THEN 'NO_ACTION_NEEDED'
    WHEN UPPER(COALESCE(asset_criticality, '')) = 'LOW' THEN 'NO_ACTION_NEEDED'
    ELSE 'MONITOR'
END
WHERE escalation_recommendation IS NULL
   OR escalation_recommendation = 'MONITOR';
