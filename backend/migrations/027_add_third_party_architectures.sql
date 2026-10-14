CREATE TABLE IF NOT EXISTS third_party_architectures (
    id SERIAL PRIMARY KEY,
    customer_vendor_id INTEGER NOT NULL REFERENCES customer_vendors(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    business_purpose TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS architecture_technologies (
    id SERIAL PRIMARY KEY,
    architecture_id INTEGER NOT NULL REFERENCES third_party_architectures(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    technology_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    role VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (architecture_id, technology_name, version)
);

CREATE TABLE IF NOT EXISTS architecture_services (
    id SERIAL PRIMARY KEY,
    architecture_id INTEGER NOT NULL REFERENCES third_party_architectures(id) ON DELETE CASCADE,
    service_name VARCHAR(255) NOT NULL,
    description TEXT,
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE third_party_exposures
    ADD COLUMN IF NOT EXISTS architecture_id INTEGER REFERENCES third_party_architectures(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tpa_customer_vendor ON third_party_architectures(customer_vendor_id);
CREATE INDEX IF NOT EXISTS idx_arch_technologies_architecture ON architecture_technologies(architecture_id);
CREATE INDEX IF NOT EXISTS idx_arch_services_architecture ON architecture_services(architecture_id);
CREATE INDEX IF NOT EXISTS idx_tp_exposures_architecture ON third_party_exposures(architecture_id);
