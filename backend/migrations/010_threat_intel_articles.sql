CREATE TABLE IF NOT EXISTS threat_articles (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    source VARCHAR(100) NOT NULL,
    published_date TIMESTAMP,
    content TEXT,
    threat_type VARCHAR(100),
    metadata JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_articles_published_date ON threat_articles (published_date);
