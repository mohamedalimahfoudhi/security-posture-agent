-- Migration 025: Unified threat_event abstraction.
--
-- threat_event is the canonical representation of any security-relevant event:
-- CVE (cve_events), threat article (threat_articles), breach/incident, or
-- manual SOC entry. All vendor correlation and scoring sits atop this table.
--
-- Existing tables (cve_events, threat_articles) are unchanged. A view or
-- materialized feed may merge them into threat_events for the correlation
-- engine to consume identically regardless of source type.
--
-- Purely additive. No existing tables modified.

CREATE TABLE IF NOT EXISTS threat_events (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(30) NOT NULL,          -- cve, threat_article, breach_report, manual
    source_id INTEGER,                         -- FK to source table (cve_events.id, threat_articles.id, NULL for manual)
    title TEXT NOT NULL,
    description TEXT,
    cve_id VARCHAR(20),                        -- CVE identifier if applicable (e.g. CVE-2025-12345)
    cvss_score NUMERIC(3,1),                   -- CVSS v3 score 0.0-10.0 (NULL for non-CVE events)
    severity VARCHAR(10) DEFAULT 'UNKNOWN',    -- CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    confidence DOUBLE PRECISION DEFAULT 0.0,   -- AI confidence in the event 0.0-1.0
    -- Extracted metadata (normalized)
    affected_vendors TEXT[],                    -- Array of canonical vendor names extracted from the event
    affected_products TEXT[],                   -- Array of product names extracted
    affected_technologies TEXT[],               -- Array of technology names extracted
    iocs JSONB,                                -- Indicators of compromise: {ips: [], domains: [], hashes: [], urls: []}
    -- Timelines
    published_date TIMESTAMP,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Source reference
    source_url TEXT,
    raw_metadata JSONB DEFAULT '{}'::jsonb,    -- Original source data preserved
    -- Processing state
    correlated BOOLEAN DEFAULT FALSE,           -- Has vendor/technology correlation been run?
    correlation_count INTEGER DEFAULT 0,        -- Number of correlated vendor-customer pairs
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_events_source ON threat_events (source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_severity ON threat_events (severity);
CREATE INDEX IF NOT EXISTS idx_threat_events_cve ON threat_events (cve_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_published ON threat_events (published_date DESC);
CREATE INDEX IF NOT EXISTS idx_threat_events_vendors ON threat_events USING GIN (affected_vendors);
CREATE INDEX IF NOT EXISTS idx_threat_events_products ON threat_events USING GIN (affected_products);

COMMENT ON TABLE threat_events IS 'Unified security event abstraction for vendor correlation. CVEs, threat articles, breach reports, and manual entries are all represented here.';
COMMENT ON COLUMN threat_events.source_type IS 'Origin type: cve, threat_article, breach_report, manual';
COMMENT ON COLUMN threat_events.source_id IS 'Primary key in the source-specific table (cve_events.id, threat_articles.id)';
COMMENT ON COLUMN threat_events.affected_vendors IS 'Canonical vendor names extracted/normalized from the event';
COMMENT ON COLUMN threat_events.affected_products IS 'Product names extracted from the event';
COMMENT ON COLUMN threat_events.affected_technologies IS 'Technology names extracted from the event';
COMMENT ON COLUMN threat_events.iocs IS 'Indicators of compromise: {ips: [], domains: [], hashes: [], urls: []}';
COMMENT ON COLUMN threat_events.correlated IS 'Whether vendor/technology correlation has been run for this event';
