-- Migration 017: Add missing columns to customer_vendors used by the vendors API.
-- The vendors API (backend/app/api/vendors.py) and repository.get_customer_vendors()
-- reference technology and criticality, which were not present in the base schema
-- or migration 007. Add them safely with ADD COLUMN IF NOT EXISTS.
--
-- Preserves existing data; only additive changes.

ALTER TABLE customer_vendors
    ADD COLUMN IF NOT EXISTS technology VARCHAR(255);

ALTER TABLE customer_vendors
    ADD COLUMN IF NOT EXISTS criticality VARCHAR(50);
