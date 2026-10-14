-- Migration 026: Neutral third_party_exposures model.
--
-- An exposure is a row recording that a threat_event affects the relationship
-- between a customer and a vendor. This is the neutral data model from which
-- alerts, digests, and notifications are derived as views/filters.
--
-- Alerts  = recent, unacknowledged exposures with risk_score >= threshold
-- Digests = aggregated exposures (daily/weekly summary)
-- Notifications = exposures matching notification_rule filters
--
-- Purely additive. No existing tables modified.

CREATE TABLE IF NOT EXISTS third_party_exposures (
    id SERIAL PRIMARY KEY,
    -- Core relationship
    threat_event_id INTEGER NOT NULL REFERENCES threat_events(id) ON DELETE CASCADE,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    customer_vendor_id INTEGER REFERENCES customer_vendors(id) ON DELETE SET NULL,
    -- Match metadata
    match_type VARCHAR(30) NOT NULL,             -- vendor_direct, technology_asset, product_match, alias_resolution, cve_match
    match_confidence INTEGER NOT NULL DEFAULT 50,-- 0-100
    matched_text TEXT,                           -- The text that triggered the match
    -- Risk scoring components
    base_severity VARCHAR(10) DEFAULT 'UNKNOWN', -- From threat_event.severity
    cvss_score NUMERIC(3,1),                     -- From threat_event.cvss_score
    asset_exposure_factor INTEGER DEFAULT 0,     -- Sum of exposed asset flags (internet_exposed, sensitive_data)
    vendor_criticality VARCHAR(10),              -- From customer_vendors.criticality
    vendor_base_risk INTEGER DEFAULT 50,         -- From customer_vendors.base_risk_score
    sla_penalty_risk INTEGER DEFAULT 0,          -- From customer_vendors.sla_penalty_risk
    regulatory_flags TEXT[],                     -- From customer_vendors.regulatory_flags
    incident_history_factor INTEGER DEFAULT 0,   -- Derived from customer_vendors.incident_count
    -- Computed risk
    risk_score INTEGER NOT NULL DEFAULT 0,       -- 0-100 final computed risk
    risk_factors JSONB DEFAULT '{}'::jsonb,      -- Breakdown: {base: N, exposure: N, vendor: N, sla: N, incident: N}
    priority VARCHAR(10) DEFAULT 'MEDIUM',       -- CRITICAL/HIGH/MEDIUM/LOW based on risk_score
    -- SOC guidance (structured)
    soc_guidance JSONB DEFAULT '{}'::jsonb,      -- {contain: [], hunt: [], remediate: [], notify: []}
    -- State management (for alert view)
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMP,
    muted BOOLEAN DEFAULT FALSE,                 -- Suppress from alert views without deleting
    resolution_notes TEXT,
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tp_exposures_threat ON third_party_exposures (threat_event_id);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_customer ON third_party_exposures (customer_id);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_vendor ON third_party_exposures (vendor_id);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_risk ON third_party_exposures (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_priority ON third_party_exposures (priority);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_unacknowledged ON third_party_exposures (acknowledged, muted)
    WHERE acknowledged = FALSE AND muted = FALSE;
CREATE INDEX IF NOT EXISTS idx_tp_exposures_created ON third_party_exposures (created_at DESC);

COMMENT ON TABLE third_party_exposures IS 'Records that a threat_event affects the relationship between a customer and a vendor. This is the neutral data model for alerts, digests, and notifications.';
COMMENT ON COLUMN third_party_exposures.match_type IS 'How the vendor was matched: vendor_direct, technology_asset, product_match, alias_resolution, cve_match';
COMMENT ON COLUMN third_party_exposures.risk_score IS '0-100 computed risk combining base severity, asset exposure, vendor context, and incident history';
COMMENT ON COLUMN third_party_exposures.risk_factors IS 'JSON breakdown: {base: N, exposure: N, vendor: N, sla: N, incident: N}';
COMMENT ON COLUMN third_party_exposures.soc_guidance IS 'Structured SOC actions: {contain: [], hunt: [], remediate: [], notify: []}';
COMMENT ON COLUMN third_party_exposures.muted IS 'Suppress from alert views without deleting (for known false positives)';
