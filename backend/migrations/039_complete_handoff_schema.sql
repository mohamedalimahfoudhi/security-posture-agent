-- Migration 039: complete schema elements required by the current application.
--
-- The original demo dump contained ransomware/breach incidents and additional
-- assessment intelligence fields, but the clean schema snapshot did not.  This
-- migration makes fresh schema installs match the application contract.

CREATE TABLE IF NOT EXISTS third_party_incidents (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    incident_type VARCHAR(50) NOT NULL CHECK (incident_type IN ('ransomware', 'breach')),
    victim VARCHAR(255) NOT NULL,
    group_name VARCHAR(255),
    disclosure_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_name VARCHAR(100) NOT NULL,
    source_url TEXT,
    raw_payload JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (source_name, victim, disclosure_date)
);

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS third_party_incident_id INTEGER REFERENCES third_party_incidents(id),
    ADD COLUMN IF NOT EXISTS hunting_guidance JSONB,
    ADD COLUMN IF NOT EXISTS technology VARCHAR(255),
    ADD COLUMN IF NOT EXISTS vendor VARCHAR(255),
    ADD COLUMN IF NOT EXISTS threat_summary TEXT,
    ADD COLUMN IF NOT EXISTS exploitation_risk VARCHAR(20),
    ADD COLUMN IF NOT EXISTS recommendations TEXT,
    ADD COLUMN IF NOT EXISTS intel_source VARCHAR(100),
    ADD COLUMN IF NOT EXISTS intel_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS confidence INTEGER,
    ADD COLUMN IF NOT EXISTS business_relevance TEXT,
    ADD COLUMN IF NOT EXISTS evidence JSONB;

CREATE INDEX IF NOT EXISTS idx_third_party_incidents_customer
    ON third_party_incidents(customer_id);
CREATE INDEX IF NOT EXISTS idx_third_party_incidents_disclosure
    ON third_party_incidents(disclosure_date DESC);
