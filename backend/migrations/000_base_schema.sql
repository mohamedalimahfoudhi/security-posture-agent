-- Base Schema for AI-TIP
-- Creates core tables before running migrations

-- Customers table
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CVE Events table
CREATE TABLE IF NOT EXISTS cve_events (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    cvss_score DECIMAL(5,2),
    severity VARCHAR(20),
    published_date TIMESTAMP,
    source_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    event_id INTEGER REFERENCES cve_events(id),
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'NEW',
    title TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Assessments table
CREATE TABLE IF NOT EXISTS assessments (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    event_id INTEGER REFERENCES cve_events(id),
    asset_id INTEGER,
    risk_score INTEGER,
    severity VARCHAR(20),
    confidence_score INTEGER,
    ai_summary TEXT,
    business_impact TEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Customer Vendors table
CREATE TABLE IF NOT EXISTS customer_vendors (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    vendor VARCHAR(255) NOT NULL,
    relationship_type VARCHAR(100),
    data_sensitivity VARCHAR(50),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default customer
INSERT INTO customers (name, industry) 
VALUES ('Demo Customer', 'Technology')
ON CONFLICT DO NOTHING;
