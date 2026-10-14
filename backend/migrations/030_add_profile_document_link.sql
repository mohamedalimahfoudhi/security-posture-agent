-- Migration 030: Add architecture document link to third_party_profiles.
--
-- Links a third-party profile to the uploaded architecture document
-- whose technologies/services were extracted and mapped into the profile.
--
-- Purely additive. No existing columns modified.

ALTER TABLE third_party_profiles
    ADD COLUMN IF NOT EXISTS document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tp_profiles_document ON third_party_profiles (document_id);

COMMENT ON COLUMN third_party_profiles.document_id IS 'Architecture document whose technologies/services were extracted and mapped into this profile';