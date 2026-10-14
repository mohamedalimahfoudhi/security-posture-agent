-- Migration 006: Add affected_third_party and ransomware_group to assessments
-- These are populated only for ThirdPartyIncident intel_type (incident_id path).
-- Left NULL for CVE/NVD assessments.

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS affected_third_party TEXT;

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS ransomware_group TEXT;

-- Backfill from third_party_incidents for existing rows
UPDATE assessments a
SET
    affected_third_party = i.victim,
    ransomware_group     = i.group_name
FROM third_party_incidents i
WHERE a.third_party_incident_id = i.id
  AND a.affected_third_party IS NULL;
