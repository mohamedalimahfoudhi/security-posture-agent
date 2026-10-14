-- Migration 037: Add unique constraint on (customer_id, vendor_id) in customer_vendors
-- This prevents duplicate customer-vendor relationships at the database level

-- First, ensure no existing duplicates
-- This should return 0 rows if the application-level duplicate prevention worked
SELECT customer_id, vendor_id, COUNT(*) as count
FROM customer_vendors
GROUP BY customer_id, vendor_id
HAVING COUNT(*) > 1;

-- If the above returns any rows, we need to resolve them before adding the constraint
-- For now, assuming no duplicates exist based on our audit

-- Add the unique constraint
ALTER TABLE customer_vendors
ADD CONSTRAINT customer_vendors_customer_vendor_unique
UNIQUE (customer_id, vendor_id);

-- Verify the constraint was added
SELECT conname
FROM pg_constraint
WHERE conrelid = 'customer_vendors'::regclass
  AND contype = 'u';
