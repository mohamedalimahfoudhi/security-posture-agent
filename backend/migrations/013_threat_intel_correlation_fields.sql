ALTER TABLE threat_correlations
ADD COLUMN IF NOT EXISTS matched_value TEXT,
ADD COLUMN IF NOT EXISTS reason TEXT,
ADD COLUMN IF NOT EXISTS severity VARCHAR(50),
ADD COLUMN IF NOT EXISTS confidence FLOAT,
ADD COLUMN IF NOT EXISTS recommendation TEXT;

CREATE INDEX IF NOT EXISTS idx_threat_correlations_severity ON threat_correlations(severity);
CREATE INDEX IF NOT EXISTS idx_threat_correlations_confidence ON threat_correlations(confidence);
