-- Migration 018: Add global vendors entity table.
--
-- Purely additive. Does NOT touch existing customer_vendors.vendor / assets.vendor
-- VARCHAR columns. This table is the canonical source of truth for a vendor
-- identity. All existing read paths (APIs/frontend) continue to use the VARCHAR
-- columns untouched.

CREATE TABLE IF NOT EXISTS vendors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,          -- canonical vendor display name
    category VARCHAR(50),                       -- cloud_provider, security_tools, database, etc.
    base_risk_score INT DEFAULT 0,              -- vendor-level risk (not customer-specific)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vendors_name ON vendors (name);
