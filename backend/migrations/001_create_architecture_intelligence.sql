-- Architecture Intelligence Migration
-- Creates tables for document upload and asset extraction

-- Documents table to track uploaded files
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    filename VARCHAR(255) NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    file_size INTEGER NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    upload_status VARCHAR(50) DEFAULT 'pending',
    extraction_status VARCHAR(50) DEFAULT 'pending',
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    error_message TEXT
);

-- Assets table for extracted technologies
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    document_id INTEGER REFERENCES documents(id),
    technology VARCHAR(255) NOT NULL,
    vendor VARCHAR(255),
    version VARCHAR(100),
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    internet_exposed BOOLEAN DEFAULT FALSE,
    sensitive_data BOOLEAN DEFAULT FALSE,
    category VARCHAR(100),
    operating_system VARCHAR(255),
    database VARCHAR(255),
    cloud_provider VARCHAR(255),
    web_server VARCHAR(255),
    firewall VARCHAR(255),
    virtualization VARCHAR(255),
    programming_language VARCHAR(255),
    framework VARCHAR(255),
    security_tools VARCHAR(255),
    network_devices VARCHAR(255),
    confidence INTEGER DEFAULT 80,
    extraction_metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_assets_customer ON assets(customer_id);
CREATE INDEX IF NOT EXISTS idx_assets_technology ON assets(technology);
CREATE INDEX IF NOT EXISTS idx_assets_vendor ON assets(vendor);
CREATE INDEX IF NOT EXISTS idx_assets_document ON assets(document_id);
CREATE INDEX IF NOT EXISTS idx_documents_customer ON documents(customer_id);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(upload_status, extraction_status);

-- Add trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
