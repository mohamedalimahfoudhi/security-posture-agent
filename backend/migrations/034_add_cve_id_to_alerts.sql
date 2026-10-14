-- Migration 034: Add cve_id column to third_party_alerts for CVE-based consolidation
--
-- This change allows alerts to be consolidated by CVE instead of threat_event_id.
-- Multiple threat_events with the same CVE will now produce a single alert.

DO $$
BEGIN
    -- Step 1: Add cve_id column
    ALTER TABLE third_party_alerts ADD COLUMN IF NOT EXISTS cve_id VARCHAR(50);
    
    -- Step 2: Populate cve_id from threat_events for existing alerts
    UPDATE third_party_alerts a
    SET cve_id = te.cve_id
    FROM threat_events te
    WHERE a.threat_event_id = te.id AND te.cve_id IS NOT NULL;
    
    -- Step 3: Clean up existing duplicates by CVE (BEFORE creating index)
    -- Keep the oldest alert for each (customer_id, customer_vendor_id, cve_id, alert_type) group
    DELETE FROM third_party_alerts a
    USING (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY customer_id, customer_vendor_id, cve_id, alert_type
            ORDER BY created_at ASC
        ) as rn
        FROM third_party_alerts
        WHERE cve_id IS NOT NULL
    ) ranked
    WHERE a.id = ranked.id AND ranked.rn > 1;
    
    -- Clean up duplicates for non-CVE alerts (keep by threat_event_id)
    DELETE FROM third_party_alerts a
    USING (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY customer_id, customer_vendor_id, threat_event_id, alert_type
            ORDER BY created_at ASC
        ) as rn
        FROM third_party_alerts
        WHERE cve_id IS NULL AND threat_event_id IS NOT NULL
    ) ranked
    WHERE a.id = ranked.id AND ranked.rn > 1;
    
    -- Step 4: Drop old unique indexes
    DROP INDEX IF EXISTS idx_tp_alerts_unique;
    DROP INDEX IF EXISTS idx_tp_alerts_unique_with_threat;
    
    -- Step 5: Create new unique indexes based on cve_id
    -- For alerts with CVE: unique by (customer_id, customer_vendor_id, cve_id, alert_type)
    CREATE UNIQUE INDEX idx_tp_alerts_unique_cve
    ON third_party_alerts (customer_id, customer_vendor_id, cve_id, alert_type)
    WHERE cve_id IS NOT NULL;
    
    -- For alerts without CVE: unique by (customer_id, customer_vendor_id, threat_event_id, alert_type)
    CREATE UNIQUE INDEX idx_tp_alerts_unique_no_cve
    ON third_party_alerts (customer_id, customer_vendor_id, threat_event_id, alert_type)
    WHERE cve_id IS NULL;
    
    -- Comment on the new indexes
    COMMENT ON INDEX idx_tp_alerts_unique_cve IS 'Prevents duplicate alerts with same CVE (customer, vendor, CVE, alert_type)';
    COMMENT ON INDEX idx_tp_alerts_unique_no_cve IS 'Prevents duplicate alerts without CVE (customer, vendor, threat_event, alert_type)';
    
END $$;
