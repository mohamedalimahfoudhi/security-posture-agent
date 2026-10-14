-- Migration 020: Add nullable vendor_id FK columns to customer_vendors and assets.
--
-- Purely additive. The existing VARCHAR vendor columns are kept unchanged and
-- remain authoritative for all current read paths. vendor_id is backfilled by
-- apply_020_backfill_vendor_id.py using the vendor_aliases resolution. Rows that
-- cannot be resolved to a canonical vendor keep vendor_id = NULL and are
-- unaffected.

ALTER TABLE customer_vendors
    ADD COLUMN IF NOT EXISTS vendor_id INT REFERENCES vendors(id);

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS vendor_id INT REFERENCES vendors(id);

CREATE INDEX IF NOT EXISTS idx_customer_vendors_vendor_id ON customer_vendors (vendor_id);
CREATE INDEX IF NOT EXISTS idx_assets_vendor_id ON assets (vendor_id);
