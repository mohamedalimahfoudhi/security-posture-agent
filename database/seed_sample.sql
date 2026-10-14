-- Sample seed data for Security Posture Agent
-- This file contains fake/demo data only for development and testing purposes
-- DO NOT use this in production environments

-- Insert demo customer
INSERT INTO customers (name, industry) VALUES ('Demo Customer', 'Technology');

-- Insert demo users (passwords are bcrypt hashes)
-- IMPORTANT: Change these passwords immediately after setup!
-- admin@example.com / ChangeMe123!
-- analyst@example.com / ChangeMe123!
-- viewer@example.com / ChangeMe123!
INSERT INTO users (username, email, hashed_password, full_name, role, customer_id, is_active) VALUES
('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7xqYqN.5Wm', 'Demo Administrator', 'Admin', 1, TRUE),
('analyst', 'analyst@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7xqYqN.5Wm', 'Demo Analyst', 'Analyst', 1, TRUE),
('viewer', 'viewer@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7xqYqN.5Wm', 'Demo Viewer', 'Viewer', 1, TRUE);

-- Insert demo vendor
INSERT INTO vendors (name, category, base_risk_score) VALUES ('Sample Vendor', 'Cloud Services', 72);

-- Insert demo customer-vendor relationship
INSERT INTO customer_vendors (customer_id, vendor_id, vendor, relationship_type, data_sensitivity, criticality, base_risk_score)
VALUES (1, 1, 'Sample Vendor', 'Cloud Hosting', 'HIGH', 'HIGH', 75);
