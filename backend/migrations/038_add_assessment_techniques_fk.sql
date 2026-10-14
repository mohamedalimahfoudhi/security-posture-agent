-- Migration 038: Add foreign key constraints to assessment_techniques
-- Root cause fix: assessment_techniques had no referential integrity,
-- allowing orphaned records when assessments were deleted or when
-- AI extraction produced technique IDs not in the local dataset.

-- Step 1: Add UNIQUE constraint on attack_techniques.technique_id
-- (required before it can be referenced by a foreign key)
ALTER TABLE attack_techniques
ADD CONSTRAINT attack_techniques_technique_id_unique
UNIQUE (technique_id);

-- Step 2: Add foreign key from assessment_techniques.assessment_id -> assessments.id
ALTER TABLE assessment_techniques
ADD CONSTRAINT fk_assessment_techniques_assessment_id
FOREIGN KEY (assessment_id)
REFERENCES assessments (id)
ON DELETE CASCADE;

-- Step 3: Add foreign key from assessment_techniques.technique_id -> attack_techniques.technique_id
ALTER TABLE assessment_techniques
ADD CONSTRAINT fk_assessment_techniques_technique_id
FOREIGN KEY (technique_id)
REFERENCES attack_techniques (technique_id)
ON DELETE CASCADE;
