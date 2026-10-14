-- Migration 019: Add vendor_aliases mapping table.
--
-- Maps free-text vendor string variants (as they appear across assets,
-- customer_vendors, assessments, alerts and threat intel) to a canonical
-- vendor_id. Purely additive.

CREATE TABLE IF NOT EXISTS vendor_aliases (
    id SERIAL PRIMARY KEY,
    vendor_id INT REFERENCES vendors(id) ON DELETE CASCADE,
    alias VARCHAR(255) NOT NULL UNIQUE,         -- normalized alias string
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vendor_aliases_vendor ON vendor_aliases (vendor_id);
CREATE INDEX IF NOT EXISTS idx_vendor_aliases_alias ON vendor_aliases (alias);
