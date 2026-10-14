-- Migration 041: synchronize the alert CVE consolidation fields with the
-- authoritative fresh-install schema.  Migration 034 introduced this logic,
-- but the original schema snapshot omitted it.

ALTER TABLE third_party_alerts
    ADD COLUMN IF NOT EXISTS cve_id VARCHAR(50);

UPDATE third_party_alerts a
SET cve_id = te.cve_id
FROM threat_events te
WHERE a.threat_event_id = te.id
  AND a.cve_id IS NULL
  AND te.cve_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tp_alerts_unique_cve
    ON third_party_alerts(customer_id, customer_vendor_id, cve_id, alert_type)
    WHERE cve_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tp_alerts_unique_no_cve
    ON third_party_alerts(customer_id, customer_vendor_id, threat_event_id, alert_type)
    WHERE cve_id IS NULL;
