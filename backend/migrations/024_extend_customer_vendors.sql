-- Migration 024: Extend customer_vendors with business context fields.
--
-- Purely additive. All existing columns and their values are preserved.
-- New columns provide per-customer-vendor business context for risk scoring.

ALTER TABLE customer_vendors
    ADD COLUMN IF NOT EXISTS sla_penalty_risk INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS regulatory_flags TEXT[],
    ADD COLUMN IF NOT EXISTS base_risk_score INTEGER DEFAULT 50,
    ADD COLUMN IF NOT EXISTS incident_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_incident_date TIMESTAMP;

COMMENT ON COLUMN customer_vendors.sla_penalty_risk IS '0-100 score of financial/operational impact if vendor SLA is breached';
COMMENT ON COLUMN customer_vendors.regulatory_flags IS 'Array of regulatory frameworks: GDPR, SOX, HIPAA, PCI-DSS etc.';
COMMENT ON COLUMN customer_vendors.base_risk_score IS '0-100 inherent risk score of this vendor for this customer';
COMMENT ON COLUMN customer_vendors.incident_count IS 'Cumulative count of past security incidents involving this vendor for this customer';
COMMENT ON COLUMN customer_vendors.last_incident_date IS 'Timestamp of the most recent security incident involving this vendor';
