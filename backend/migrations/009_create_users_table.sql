-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'Viewer',
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert demo users
-- Admin user
INSERT INTO users (username, email, hashed_password, full_name, role, customer_id, is_active)
VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$xm2LOLFix24WQuBMyiNxU.FvOPFZlDnSsybZp3KmiT2K.JBxww9ui',
    'Demo Admin',
    'Admin',
    1,
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- Analyst user
INSERT INTO users (username, email, hashed_password, full_name, role, customer_id, is_active)
VALUES (
    'analyst',
    'analyst@example.com',
    '$2b$12$fhh.hv28nRqajqlz/aq.o.9CxLx0q8YMkbCNi7450ifVO3H.al9UW',
    'Demo Analyst',
    'Analyst',
    1,
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- Viewer user
INSERT INTO users (username, email, hashed_password, full_name, role, customer_id, is_active)
VALUES (
    'viewer',
    'viewer@example.com',
    '$2b$12$hcNOUShUhr.oWil0vSDTk.yfFRX208gpGUvLt2rG.B7Iq742MN0MS',
    'Demo Viewer',
    'Viewer',
    1,
    TRUE
) ON CONFLICT (email) DO NOTHING;
