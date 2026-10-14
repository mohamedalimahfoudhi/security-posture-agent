-- Migration 029: Add profile intelligence columns to third_party_exposures.
--
-- Extends the exposure model to link a threat event to a specific
-- third-party profile technology, storing evidence and recommended action.
--
-- Purely additive. No existing columns modified.

ALTER TABLE third_party_exposures
    ADD COLUMN IF NOT EXISTS profile_id INTEGER REFERENCES third_party_profiles(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS affected_technology VARCHAR(255),
    ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS recommended_action TEXT;

CREATE INDEX IF NOT EXISTS idx_tp_exposures_profile ON third_party_exposures (profile_id);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_technology ON third_party_exposures (affected_technology);

COMMENT ON COLUMN third_party_exposures.profile_id IS 'Third-party profile (customer-specific vendor context) that this exposure affects';
COMMENT ON COLUMN third_party_exposures.affected_technology IS 'The specific technology (from third_party_profile_technologies) matched to the threat';
COMMENT ON COLUMN third_party_exposures.evidence IS 'Array of evidence strings explaining why this exposure was created';
COMMENT ON COLUMN third_party_exposures.recommended_action IS 'Recommended SOC action for this exposure';