CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tactics VARCHAR(255),
    embedding JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS assessment_techniques (
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    technique_id VARCHAR(50) REFERENCES attack_techniques(technique_id),
    similarity_score FLOAT NOT NULL,
    PRIMARY KEY (assessment_id, technique_id)
);
