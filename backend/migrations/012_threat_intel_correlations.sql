CREATE TABLE IF NOT EXISTS threat_correlations (
    id SERIAL PRIMARY KEY,
    article_id INTEGER REFERENCES threat_articles(id),
    customer_id INTEGER REFERENCES customers(id),
    asset_id INTEGER REFERENCES assets(id),
    match_type VARCHAR(100),
    match_text TEXT,
    correlation_score INTEGER,
    risk_score INTEGER,
    priority VARCHAR(20),
    correlation_details JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_correlations_customer ON threat_correlations(customer_id);
CREATE INDEX IF NOT EXISTS idx_threat_correlations_article ON threat_correlations(article_id);
CREATE INDEX IF NOT EXISTS idx_threat_correlations_asset ON threat_correlations(asset_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_correlations_article_asset_customer ON threat_correlations(article_id, customer_id, asset_id);
