-- Migration 031: Architecture change detection events.
--
-- Records structured changes when a new architecture document is uploaded
-- for the same customer/vendor, enabling SOC visibility into technology
-- additions, removals, and version changes.
--
-- Purely additive. No existing columns modified.

CREATE TABLE IF NOT EXISTS architecture_changes (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    customer_vendor_id INTEGER NOT NULL REFERENCES customer_vendors(id) ON DELETE CASCADE,
    profile_id INTEGER REFERENCES third_party_profiles(id) ON DELETE SET NULL,
    previous_document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
    current_document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
    added_technologies JSONB DEFAULT '[]'::jsonb,
    removed_technologies JSONB DEFAULT '[]'::jsonb,
    changed_versions JSONB DEFAULT '[]'::jsonb,
    added_services JSONB DEFAULT '[]'::jsonb,
    removed_services JSONB DEFAULT '[]'::jsonb,
    risk_before INTEGER DEFAULT 0,
    risk_after INTEGER DEFAULT 0,
    risk_delta INTEGER DEFAULT 0,
    risk_impact VARCHAR(20) DEFAULT 'NONE',  -- NONE, LOW, MEDIUM, HIGH, CRITICAL
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_arch_changes_customer ON architecture_changes (customer_id);
CREATE INDEX IF NOT EXISTS idx_arch_changes_vendor ON architecture_changes (customer_vendor_id);
CREATE INDEX IF NOT EXISTS idx_arch_changes_created ON architecture_changes (created_at DESC);

COMMENT ON TABLE architecture_changes IS 'Structured record of architecture document changes for a customer-vendor relationship';
COMMENT ON COLUMN architecture_changes.added_technologies IS 'JSON array of {technology, version, category} added in the new architecture';
COMMENT ON COLUMN architecture_changes.removed_technologies IS 'JSON array of {technology, version, category} removed in the new architecture';
COMMENT ON COLUMN architecture_changes.changed_versions IS 'JSON array of {technology, from_version, to_version} version changes';
COMMENT ON COLUMN architecture_changes.risk_delta IS 'Change in profile risk score (positive = increased risk)';