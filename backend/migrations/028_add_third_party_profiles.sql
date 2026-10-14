CREATE TABLE IF NOT EXISTS third_party_profiles (
    id SERIAL PRIMARY KEY,
    customer_vendor_id INTEGER NOT NULL UNIQUE REFERENCES customer_vendors(id) ON DELETE CASCADE,
    business_role VARCHAR(255),
    description TEXT,
    data_access_level VARCHAR(50),
    privileged_access BOOLEAN NOT NULL DEFAULT FALSE,
    criticality VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS third_party_profile_technologies (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES third_party_profiles(id) ON DELETE CASCADE,
    technology VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    category VARCHAR(100),
    source VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS third_party_profile_services (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES third_party_profiles(id) ON DELETE CASCADE,
    service_name VARCHAR(255) NOT NULL,
    service_type VARCHAR(100),
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS third_party_external_assets (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES third_party_profiles(id) ON DELETE CASCADE,
    asset_type VARCHAR(50) NOT NULL,
    value VARCHAR(512) NOT NULL,
    exposure_status VARCHAR(50) DEFAULT 'UNKNOWN',
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_third_party_profiles_relationship ON third_party_profiles(customer_vendor_id);
CREATE INDEX IF NOT EXISTS idx_tp_profile_technologies_profile ON third_party_profile_technologies(profile_id);
CREATE INDEX IF NOT EXISTS idx_tp_profile_services_profile ON third_party_profile_services(profile_id);
CREATE INDEX IF NOT EXISTS idx_tp_external_assets_profile ON third_party_external_assets(profile_id);
