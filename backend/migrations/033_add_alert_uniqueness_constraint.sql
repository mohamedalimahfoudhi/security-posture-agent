-- Migration 033: Add uniqueness constraint to prevent duplicate third-party alerts.
--
-- This constraint prevents duplicate alerts based on the natural key:
-- customer_id, customer_vendor_id, threat_event_id, alert_type
--
-- Uses IS NOT DISTINCT FROM to handle NULL values correctly.
-- This matches the idempotency check in third_party_alert_engine.py.

DO $$
BEGIN
    -- Step 1: Clean up existing duplicate alerts with NULL threat_event_id
    -- Keep the oldest alert for each (customer_id, customer_vendor_id, alert_type) group
    DELETE FROM third_party_alerts a
    USING (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY customer_id, customer_vendor_id, alert_type
            ORDER BY created_at ASC
        ) as rn
        FROM third_party_alerts
        WHERE threat_event_id IS NULL
    ) ranked
    WHERE a.id = ranked.id AND ranked.rn > 1;

    -- Step 2: Clean up existing duplicate alerts with non-NULL threat_event_id
    DELETE FROM third_party_alerts a
    USING (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY customer_id, customer_vendor_id, threat_event_id, alert_type
            ORDER BY created_at ASC
        ) as rn
        FROM third_party_alerts
        WHERE threat_event_id IS NOT NULL
    ) ranked
    WHERE a.id = ranked.id AND ranked.rn > 1;

    -- Step 3: Drop existing partial index if it exists (for safety)
    DROP INDEX IF EXISTS idx_tp_alerts_threat;

    -- Step 4: Create unique constraint using a partial index approach
    -- This allows NULL values to be treated as equal for uniqueness
    CREATE UNIQUE INDEX idx_tp_alerts_unique 
    ON third_party_alerts (customer_id, customer_vendor_id, alert_type)
    WHERE threat_event_id IS NULL;

    -- Step 5: Create unique constraint for alerts with threat_event_id
    CREATE UNIQUE INDEX idx_tp_alerts_unique_with_threat
    ON third_party_alerts (customer_id, customer_vendor_id, threat_event_id, alert_type)
    WHERE threat_event_id IS NOT NULL;

    -- Comment on the constraint
    COMMENT ON INDEX idx_tp_alerts_unique IS 'Prevents duplicate alerts with NULL threat_event_id (customer, vendor, alert_type)';
    COMMENT ON INDEX idx_tp_alerts_unique_with_threat IS 'Prevents duplicate alerts with threat_event_id (customer, vendor, threat, alert_type)';
END $$;
