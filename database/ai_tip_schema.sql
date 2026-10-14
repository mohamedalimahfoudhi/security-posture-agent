-- AI-TIP Database Schema
-- 
-- This file contains the complete database schema for the AI-TIP platform.
-- To initialize a fresh database:
--   createdb ai_tip
--   psql -U postgres -d ai_tip -f database/ai_tip_schema.sql
--
-- After importing, configure your backend .env file with the database connection details.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Function: update_updated_at_column()
-- Automatically updates updated_at timestamp on row modification
--

CREATE OR REPLACE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

SET default_tablespace = '';
SET default_table_access_method = heap;

--
-- Table: customers
--

CREATE TABLE public.customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: users
--

CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'Viewer',
    customer_id INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: cve_events
--

CREATE TABLE public.cve_events (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    cvss_score NUMERIC(5,2),
    severity VARCHAR(20),
    published_date TIMESTAMP WITHOUT TIME ZONE,
    source_url TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: alerts
--

CREATE TABLE public.alerts (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    event_id INTEGER,
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'NEW',
    title TEXT,
    asset_id INTEGER,
    asset_technology TEXT,
    asset_vendor TEXT,
    asset_version TEXT,
    asset_criticality TEXT,
    asset_internet_exposed BOOLEAN,
    asset_sensitive_data BOOLEAN,
    risk_score INTEGER,
    confidence_score INTEGER,
    evidence JSONB DEFAULT '[]'::jsonb,
    ai_summary TEXT,
    business_impact TEXT,
    recommendation TEXT,
    remediation_steps JSONB DEFAULT '[]'::jsonb,
    escalation_recommendation VARCHAR,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: assessments
--

CREATE TABLE public.assessments (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    event_id INTEGER,
    asset_id INTEGER,
    risk_score INTEGER,
    severity VARCHAR(20),
    confidence_score INTEGER,
    ai_summary TEXT,
    business_impact TEXT,
    recommendation TEXT,
    affected_third_party TEXT,
    ransomware_group TEXT,
    third_party_incident_id INTEGER,
    hunting_guidance JSONB,
    technology VARCHAR(255),
    vendor VARCHAR(255),
    threat_summary TEXT,
    exploitation_risk VARCHAR(20),
    recommendations TEXT,
    intel_source VARCHAR(100),
    intel_type VARCHAR(50),
    confidence INTEGER,
    business_relevance TEXT,
    evidence JSONB,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_incidents
--

CREATE TABLE public.third_party_incidents (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    incident_type VARCHAR(50) NOT NULL CHECK (incident_type IN ('ransomware', 'breach')),
    victim VARCHAR(255) NOT NULL,
    group_name VARCHAR(255),
    disclosure_date TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_name VARCHAR(100) NOT NULL,
    source_url TEXT,
    raw_payload JSONB,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (source_name, victim, disclosure_date)
);

--
-- Table: customer_vendors
--

CREATE TABLE public.customer_vendors (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    vendor VARCHAR(255) NOT NULL,
    relationship_type VARCHAR(100),
    data_sensitivity VARCHAR(50),
    notes TEXT,
    technology VARCHAR(255),
    criticality VARCHAR(50),
    vendor_id INTEGER,
    sla_penalty_risk INTEGER DEFAULT 0,
    regulatory_flags TEXT[],
    base_risk_score INTEGER DEFAULT 50,
    incident_count INTEGER DEFAULT 0,
    last_incident_date TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: documents
--

CREATE TABLE public.documents (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    filename VARCHAR(255) NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    file_size INTEGER NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    upload_status VARCHAR(50) DEFAULT 'pending',
    extraction_status VARCHAR(50) DEFAULT 'pending',
    uploaded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITHOUT TIME ZONE,
    error_message TEXT
);

--
-- Table: assets
--

CREATE TABLE public.assets (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    document_id INTEGER,
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
    vendor_id INTEGER,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: attack_techniques
--

CREATE TABLE public.attack_techniques (
    technique_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tactics VARCHAR(255),
    embedding JSONB NOT NULL
);

--
-- Table: assessment_techniques
--

CREATE TABLE public.assessment_techniques (
    assessment_id INTEGER NOT NULL,
    technique_id VARCHAR(50) NOT NULL,
    similarity_score REAL NOT NULL,
    PRIMARY KEY (assessment_id, technique_id)
);

--
-- Table: knowledge_chunks
--

CREATE TABLE public.knowledge_chunks (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(50) NOT NULL,
    source_id INTEGER NOT NULL,
    customer_id INTEGER NOT NULL,
    content_text TEXT NOT NULL,
    embedding JSONB NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_type, source_id)
);

--
-- Table: threat_articles
--

CREATE TABLE public.threat_articles (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    url TEXT UNIQUE NOT NULL,
    source VARCHAR(100) NOT NULL,
    published_date TIMESTAMP WITHOUT TIME ZONE,
    content TEXT,
    threat_type VARCHAR(100),
    metadata JSONB DEFAULT '{}'::jsonb,
    summary TEXT,
    severity VARCHAR(50),
    vendors JSONB DEFAULT '[]'::jsonb,
    products JSONB DEFAULT '[]'::jsonb,
    cves JSONB DEFAULT '[]'::jsonb,
    malware JSONB DEFAULT '[]'::jsonb,
    threat_actors JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    attack_scenario TEXT,
    technical_impact TEXT,
    exploitation_context TEXT,
    affected_technologies JSONB DEFAULT '[]'::jsonb,
    customer_relevance TEXT,
    recommendation TEXT,
    confidence DOUBLE PRECISION,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: threat_correlations
--

CREATE TABLE public.threat_correlations (
    id SERIAL PRIMARY KEY,
    article_id INTEGER,
    customer_id INTEGER,
    asset_id INTEGER,
    match_type VARCHAR(100),
    match_text TEXT,
    correlation_score INTEGER,
    risk_score INTEGER,
    priority VARCHAR(20),
    correlation_details JSONB DEFAULT '{}'::jsonb,
    matched_value TEXT,
    reason TEXT,
    severity VARCHAR(50),
    confidence DOUBLE PRECISION,
    recommendation TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(article_id, customer_id, asset_id)
);

--
-- Table: chat_messages
--

CREATE TABLE public.chat_messages (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    customer_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    response TEXT NOT NULL,
    conversation_id UUID,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: notification_recipients
--

CREATE TABLE public.notification_recipients (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: notification_drafts
--

CREATE TABLE public.notification_drafts (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER,
    subject VARCHAR(500) NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'draft',
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP WITHOUT TIME ZONE
);

--
-- Table: vendors
--

CREATE TABLE public.vendors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    category VARCHAR(50),
    base_risk_score INTEGER DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: vendor_aliases
--

CREATE TABLE public.vendor_aliases (
    id SERIAL PRIMARY KEY,
    vendor_id INTEGER,
    alias VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: threat_events
--

CREATE TABLE public.threat_events (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(30) NOT NULL,
    source_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    cve_id VARCHAR(20),
    cvss_score NUMERIC(3,1),
    severity VARCHAR(10) DEFAULT 'UNKNOWN',
    confidence DOUBLE PRECISION DEFAULT 0.0,
    affected_vendors TEXT[],
    affected_products TEXT[],
    affected_technologies TEXT[],
    iocs JSONB,
    published_date TIMESTAMP WITHOUT TIME ZONE,
    detected_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_url TEXT,
    raw_metadata JSONB DEFAULT '{}'::jsonb,
    correlated BOOLEAN DEFAULT FALSE,
    correlation_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_exposures
--

CREATE TABLE public.third_party_exposures (
    id SERIAL PRIMARY KEY,
    threat_event_id INTEGER NOT NULL,
    customer_id INTEGER NOT NULL,
    vendor_id INTEGER NOT NULL,
    customer_vendor_id INTEGER,
    match_type VARCHAR(30) NOT NULL,
    match_confidence INTEGER DEFAULT 50,
    matched_text TEXT,
    base_severity VARCHAR(10) DEFAULT 'UNKNOWN',
    cvss_score NUMERIC(3,1),
    asset_exposure_factor INTEGER DEFAULT 0,
    vendor_criticality VARCHAR(10),
    vendor_base_risk INTEGER DEFAULT 50,
    sla_penalty_risk INTEGER DEFAULT 0,
    regulatory_flags TEXT[],
    incident_history_factor INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0 NOT NULL,
    risk_factors JSONB DEFAULT '{}'::jsonb,
    priority VARCHAR(10) DEFAULT 'MEDIUM',
    soc_guidance JSONB DEFAULT '{}'::jsonb,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INTEGER,
    acknowledged_at TIMESTAMP WITHOUT TIME ZONE,
    muted BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    profile_id INTEGER,
    affected_technology VARCHAR(255),
    evidence JSONB DEFAULT '[]'::jsonb,
    recommended_action TEXT,
    architecture_id INTEGER,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_profiles
--

CREATE TABLE public.third_party_profiles (
    id SERIAL PRIMARY KEY,
    customer_vendor_id INTEGER UNIQUE NOT NULL,
    business_role VARCHAR(255),
    description TEXT,
    data_access_level VARCHAR(50),
    privileged_access BOOLEAN NOT NULL DEFAULT FALSE,
    criticality VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    risk_score INTEGER DEFAULT 0 NOT NULL,
    document_id INTEGER,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_profile_technologies
--

CREATE TABLE public.third_party_profile_technologies (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL,
    technology VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    category VARCHAR(100),
    source VARCHAR(100),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_profile_services
--

CREATE TABLE public.third_party_profile_services (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    service_type VARCHAR(100),
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_external_assets
--

CREATE TABLE public.third_party_external_assets (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    value VARCHAR(512) NOT NULL,
    exposure_status VARCHAR(50) DEFAULT 'UNKNOWN',
    last_seen TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_architectures
--

CREATE TABLE public.third_party_architectures (
    id SERIAL PRIMARY KEY,
    customer_vendor_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    business_purpose TEXT,
    risk_score INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: architecture_technologies
--

CREATE TABLE public.architecture_technologies (
    id SERIAL PRIMARY KEY,
    architecture_id INTEGER NOT NULL,
    asset_id INTEGER,
    technology_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    role VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (architecture_id, technology_name, version)
);

--
-- Table: architecture_services
--

CREATE TABLE public.architecture_services (
    id SERIAL PRIMARY KEY,
    architecture_id INTEGER NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    description TEXT,
    criticality VARCHAR(20) DEFAULT 'MEDIUM',
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: architecture_changes
--

CREATE TABLE public.architecture_changes (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    customer_vendor_id INTEGER NOT NULL,
    profile_id INTEGER,
    previous_document_id INTEGER,
    current_document_id INTEGER,
    added_technologies JSONB DEFAULT '[]'::jsonb,
    removed_technologies JSONB DEFAULT '[]'::jsonb,
    changed_versions JSONB DEFAULT '[]'::jsonb,
    added_services JSONB DEFAULT '[]'::jsonb,
    removed_services JSONB DEFAULT '[]'::jsonb,
    risk_before INTEGER DEFAULT 0,
    risk_after INTEGER DEFAULT 0,
    risk_delta INTEGER DEFAULT 0,
    risk_impact VARCHAR(20) DEFAULT 'NONE',
    reason TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: third_party_alerts
--

CREATE TABLE public.third_party_alerts (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    customer_vendor_id INTEGER NOT NULL,
    profile_id INTEGER,
    threat_event_id INTEGER,
    exposure_id INTEGER,
    architecture_change_id INTEGER,
    cve_id VARCHAR(50),
    vendor VARCHAR(255) NOT NULL,
    affected_technology VARCHAR(255),
    alert_type VARCHAR(40) NOT NULL,
    severity VARCHAR(20) DEFAULT 'MEDIUM' NOT NULL,
    risk_score INTEGER DEFAULT 0 NOT NULL,
    risk_delta INTEGER DEFAULT 0 NOT NULL,
    confidence DOUBLE PRECISION DEFAULT 0.5 NOT NULL,
    confidence_reasons JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '[]'::jsonb,
    business_relevance TEXT,
    recommended_action TEXT,
    status VARCHAR(20) DEFAULT 'NEW' NOT NULL,
    source_type VARCHAR(30),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Table: weekly_digest_summaries
--

CREATE TABLE public.weekly_digest_summaries (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    executive_summary TEXT NOT NULL,
    recommendations JSONB NOT NULL,
    future_outlook TEXT NOT NULL,
    generated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(customer_id, period_start, period_end)
);

--
-- Table: alert_email_notifications
--

CREATE TABLE public.alert_email_notifications (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER NOT NULL,
    alert_source VARCHAR(30) NOT NULL DEFAULT 'third_party_alert'
        CHECK (alert_source IN ('alert', 'third_party_alert')),
    recipient_email VARCHAR(255) NOT NULL,
    recipient_name VARCHAR(255),
    notification_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
    sent_at TIMESTAMP WITHOUT TIME ZONE,
    delivered_at TIMESTAMP WITHOUT TIME ZONE,
    failure_reason TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

--
-- Foreign Keys
--

ALTER TABLE public.users
    ADD CONSTRAINT users_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;

ALTER TABLE public.alerts
    ADD CONSTRAINT alerts_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id),
    ADD CONSTRAINT alerts_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.cve_events(id);

ALTER TABLE public.assessments
    ADD CONSTRAINT assessments_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id),
    ADD CONSTRAINT assessments_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.cve_events(id),
    ADD CONSTRAINT assessments_third_party_incident_id_fkey FOREIGN KEY (third_party_incident_id) REFERENCES public.third_party_incidents(id);

ALTER TABLE public.third_party_incidents
    ADD CONSTRAINT third_party_incidents_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;

ALTER TABLE public.customer_vendors
    ADD CONSTRAINT customer_vendors_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id),
    ADD CONSTRAINT customer_vendors_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id),
    ADD CONSTRAINT customer_vendors_customer_vendor_unique UNIQUE (customer_id, vendor_id);

ALTER TABLE public.documents
    ADD CONSTRAINT documents_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);

ALTER TABLE public.assets
    ADD CONSTRAINT assets_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id),
    ADD CONSTRAINT assets_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id),
    ADD CONSTRAINT assets_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id);

ALTER TABLE public.assessment_techniques
    ADD CONSTRAINT assessment_techniques_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES public.assessments(id) ON DELETE CASCADE,
    ADD CONSTRAINT assessment_techniques_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.attack_techniques(technique_id);

ALTER TABLE public.knowledge_chunks
    ADD CONSTRAINT knowledge_chunks_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);

ALTER TABLE public.threat_correlations
    ADD CONSTRAINT threat_correlations_article_id_fkey FOREIGN KEY (article_id) REFERENCES public.threat_articles(id),
    ADD CONSTRAINT threat_correlations_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id),
    ADD CONSTRAINT threat_correlations_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);

ALTER TABLE public.chat_messages
    ADD CONSTRAINT chat_messages_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE,
    ADD CONSTRAINT chat_messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE public.notification_recipients
    ADD CONSTRAINT notification_recipients_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);

ALTER TABLE public.notification_drafts
    ADD CONSTRAINT notification_drafts_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id);

ALTER TABLE public.vendor_aliases
    ADD CONSTRAINT vendor_aliases_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE;

ALTER TABLE public.third_party_exposures
    ADD CONSTRAINT third_party_exposures_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE,
    ADD CONSTRAINT third_party_exposures_customer_vendor_id_fkey FOREIGN KEY (customer_vendor_id) REFERENCES public.customer_vendors(id) ON DELETE SET NULL,
    ADD CONSTRAINT third_party_exposures_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE,
    ADD CONSTRAINT third_party_exposures_threat_event_id_fkey FOREIGN KEY (threat_event_id) REFERENCES public.threat_events(id) ON DELETE CASCADE,
    ADD CONSTRAINT third_party_exposures_acknowledged_by_fkey FOREIGN KEY (acknowledged_by) REFERENCES public.users(id) ON DELETE SET NULL,
    ADD CONSTRAINT third_party_exposures_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.third_party_profiles(id) ON DELETE SET NULL,
    ADD CONSTRAINT third_party_exposures_architecture_id_fkey FOREIGN KEY (architecture_id) REFERENCES public.third_party_architectures(id) ON DELETE SET NULL;

ALTER TABLE public.third_party_profiles
    ADD CONSTRAINT third_party_profiles_customer_vendor_id_fkey FOREIGN KEY (customer_vendor_id) REFERENCES public.customer_vendors(id) ON DELETE CASCADE,
    ADD CONSTRAINT third_party_profiles_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE SET NULL;

ALTER TABLE public.third_party_profile_technologies
    ADD CONSTRAINT third_party_profile_technologies_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.third_party_profiles(id) ON DELETE CASCADE;

ALTER TABLE public.third_party_profile_services
    ADD CONSTRAINT third_party_profile_services_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.third_party_profiles(id) ON DELETE CASCADE;

ALTER TABLE public.third_party_external_assets
    ADD CONSTRAINT third_party_external_assets_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.third_party_profiles(id) ON DELETE CASCADE;

ALTER TABLE public.third_party_architectures
    ADD CONSTRAINT third_party_architectures_customer_vendor_id_fkey FOREIGN KEY (customer_vendor_id) REFERENCES public.customer_vendors(id) ON DELETE CASCADE;

ALTER TABLE public.architecture_technologies
    ADD CONSTRAINT architecture_technologies_architecture_id_fkey FOREIGN KEY (architecture_id) REFERENCES public.third_party_architectures(id) ON DELETE CASCADE,
    ADD CONSTRAINT architecture_technologies_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE SET NULL;

ALTER TABLE public.architecture_services
    ADD CONSTRAINT architecture_services_architecture_id_fkey FOREIGN KEY (architecture_id) REFERENCES public.third_party_architectures(id) ON DELETE CASCADE;

ALTER TABLE public.architecture_changes
    ADD CONSTRAINT architecture_changes_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE,
    ADD CONSTRAINT architecture_changes_customer_vendor_id_fkey FOREIGN KEY (customer_vendor_id) REFERENCES public.customer_vendors(id) ON DELETE CASCADE,
    ADD CONSTRAINT architecture_changes_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.third_party_profiles(id) ON DELETE SET NULL,
    ADD CONSTRAINT architecture_changes_previous_document_id_fkey FOREIGN KEY (previous_document_id) REFERENCES public.documents(id) ON DELETE SET NULL,
    ADD CONSTRAINT architecture_changes_current_document_id_fkey FOREIGN KEY (current_document_id) REFERENCES public.documents(id) ON DELETE SET NULL;

ALTER TABLE public.third_party_alerts
    ADD CONSTRAINT third_party_alerts_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE,
    ADD CONSTRAINT third_party_alerts_customer_vendor_id_fkey FOREIGN KEY (customer_vendor_id) REFERENCES public.customer_vendors(id) ON DELETE CASCADE,
    ADD CONSTRAINT third_party_alerts_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.third_party_profiles(id) ON DELETE SET NULL,
    ADD CONSTRAINT third_party_alerts_threat_event_id_fkey FOREIGN KEY (threat_event_id) REFERENCES public.threat_events(id) ON DELETE SET NULL,
    ADD CONSTRAINT third_party_alerts_exposure_id_fkey FOREIGN KEY (exposure_id) REFERENCES public.third_party_exposures(id) ON DELETE SET NULL,
    ADD CONSTRAINT third_party_alerts_architecture_change_id_fkey FOREIGN KEY (architecture_change_id) REFERENCES public.architecture_changes(id) ON DELETE SET NULL;

ALTER TABLE public.weekly_digest_summaries
    ADD CONSTRAINT weekly_digest_summaries_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;

--
-- Indexes
--

CREATE INDEX idx_assets_customer ON public.assets(customer_id);
CREATE INDEX idx_assets_technology ON public.assets(technology);
CREATE INDEX idx_assets_vendor ON public.assets(vendor);
CREATE INDEX idx_assets_document ON public.assets(document_id);
CREATE INDEX idx_assets_vendor_id ON public.assets(vendor_id);

CREATE INDEX idx_documents_customer ON public.documents(customer_id);
CREATE INDEX idx_documents_status ON public.documents(upload_status, extraction_status);

CREATE INDEX idx_threat_articles_published_date ON public.threat_articles(published_date);
CREATE INDEX idx_threat_articles_processed ON public.threat_articles(processed);
CREATE INDEX idx_threat_articles_confidence ON public.threat_articles(confidence);

CREATE INDEX idx_threat_correlations_customer ON public.threat_correlations(customer_id);
CREATE INDEX idx_threat_correlations_article ON public.threat_correlations(article_id);
CREATE INDEX idx_threat_correlations_asset ON public.threat_correlations(asset_id);
CREATE INDEX idx_threat_correlations_severity ON public.threat_correlations(severity);
CREATE INDEX idx_threat_correlations_confidence ON public.threat_correlations(confidence);

CREATE INDEX idx_chat_messages_user_customer ON public.chat_messages(user_id, customer_id);
CREATE INDEX idx_chat_messages_created_at ON public.chat_messages(created_at);
CREATE INDEX idx_chat_messages_conversation_id ON public.chat_messages(conversation_id);
CREATE INDEX idx_chat_messages_user_conv ON public.chat_messages(user_id, customer_id, conversation_id);

CREATE INDEX idx_notification_recipients_customer ON public.notification_recipients(customer_id);
CREATE INDEX idx_notification_drafts_alert ON public.notification_drafts(alert_id);
CREATE INDEX idx_notification_drafts_status ON public.notification_drafts(status);

CREATE INDEX idx_vendors_name ON public.vendors(name);
CREATE INDEX idx_vendor_aliases_vendor ON public.vendor_aliases(vendor_id);
CREATE INDEX idx_vendor_aliases_alias ON public.vendor_aliases(alias);
CREATE INDEX idx_customer_vendors_vendor_id ON public.customer_vendors(vendor_id);
CREATE INDEX idx_third_party_incidents_customer ON public.third_party_incidents(customer_id);
CREATE INDEX idx_third_party_incidents_disclosure ON public.third_party_incidents(disclosure_date DESC);

CREATE INDEX idx_threat_events_source ON public.threat_events(source_type, source_id);
CREATE INDEX idx_threat_events_severity ON public.threat_events(severity);
CREATE INDEX idx_threat_events_cve ON public.threat_events(cve_id);
CREATE INDEX idx_threat_events_published ON public.threat_events(published_date DESC);
CREATE INDEX idx_threat_events_vendors ON public.threat_events USING GIN (affected_vendors);
CREATE INDEX idx_threat_events_products ON public.threat_events USING GIN (affected_products);

CREATE INDEX idx_tp_exposures_threat ON public.third_party_exposures(threat_event_id);
CREATE INDEX idx_tp_exposures_customer ON public.third_party_exposures(customer_id);
CREATE INDEX idx_tp_exposures_vendor ON public.third_party_exposures(vendor_id);
CREATE INDEX idx_tp_exposures_risk ON public.third_party_exposures(risk_score DESC);
CREATE INDEX idx_tp_exposures_priority ON public.third_party_exposures(priority);
CREATE INDEX idx_tp_exposures_unacknowledged ON public.third_party_exposures(acknowledged, muted)
    WHERE acknowledged = FALSE AND muted = FALSE;
CREATE INDEX idx_tp_exposures_created ON public.third_party_exposures(created_at DESC);
CREATE INDEX idx_tp_exposures_profile ON public.third_party_exposures(profile_id);
CREATE INDEX idx_tp_exposures_technology ON public.third_party_exposures(affected_technology);
CREATE INDEX idx_tp_exposures_architecture ON public.third_party_exposures(architecture_id);

CREATE INDEX idx_third_party_profiles_relationship ON public.third_party_profiles(customer_vendor_id);
CREATE INDEX idx_tp_profiles_document ON public.third_party_profiles(document_id);
CREATE INDEX idx_tp_profile_technologies_profile ON public.third_party_profile_technologies(profile_id);
CREATE INDEX idx_tp_profile_services_profile ON public.third_party_profile_services(profile_id);
CREATE INDEX idx_tp_external_assets_profile ON public.third_party_external_assets(profile_id);

CREATE INDEX idx_tpa_customer_vendor ON public.third_party_architectures(customer_vendor_id);
CREATE INDEX idx_arch_technologies_architecture ON public.architecture_technologies(architecture_id);
CREATE INDEX idx_arch_services_architecture ON public.architecture_services(architecture_id);
CREATE INDEX idx_arch_changes_customer ON public.architecture_changes(customer_id);
CREATE INDEX idx_arch_changes_vendor ON public.architecture_changes(customer_vendor_id);
CREATE INDEX idx_arch_changes_created ON public.architecture_changes(created_at DESC);

CREATE INDEX idx_tp_alerts_customer ON public.third_party_alerts(customer_id);
CREATE INDEX idx_tp_alerts_vendor ON public.third_party_alerts(customer_vendor_id);
CREATE INDEX idx_tp_alerts_type ON public.third_party_alerts(alert_type);
CREATE INDEX idx_tp_alerts_severity ON public.third_party_alerts(severity);
CREATE INDEX idx_tp_alerts_created ON public.third_party_alerts(created_at DESC);
CREATE INDEX idx_tp_alerts_status ON public.third_party_alerts(status);
CREATE INDEX idx_tp_alerts_threat ON public.third_party_alerts(threat_event_id);
CREATE UNIQUE INDEX idx_tp_alerts_unique_cve
    ON public.third_party_alerts(customer_id, customer_vendor_id, cve_id, alert_type)
    WHERE cve_id IS NOT NULL;
CREATE UNIQUE INDEX idx_tp_alerts_unique_no_cve
    ON public.third_party_alerts(customer_id, customer_vendor_id, threat_event_id, alert_type)
    WHERE cve_id IS NULL;

CREATE INDEX idx_weekly_digest_summaries_customer_period ON public.weekly_digest_summaries(customer_id, period_start, period_end);
CREATE INDEX idx_alert_email_notifications_alert ON public.alert_email_notifications(alert_id);
CREATE INDEX idx_alert_email_notifications_status ON public.alert_email_notifications(status);
CREATE INDEX idx_alert_email_notifications_recipient ON public.alert_email_notifications(recipient_email);
CREATE INDEX idx_alert_email_notifications_sent_at ON public.alert_email_notifications(sent_at DESC);

--
-- Triggers
--

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON public.assets
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON public.alerts
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Comments
--

COMMENT ON TABLE public.third_party_exposures IS 'Records that a threat_event affects the relationship between a customer and a vendor. This is the neutral data model for alerts, digests, and notifications.';
COMMENT ON COLUMN public.third_party_exposures.match_type IS 'How the vendor was matched: vendor_direct, technology_asset, product_match, alias_resolution, cve_match';
COMMENT ON COLUMN public.third_party_exposures.risk_score IS '0-100 computed risk combining base severity, asset exposure, vendor context, and incident history';
COMMENT ON COLUMN public.third_party_exposures.risk_factors IS 'JSON breakdown: {base: N, exposure: N, vendor: N, sla: N, incident: N}';
COMMENT ON COLUMN public.third_party_exposures.soc_guidance IS 'Structured SOC actions: {contain: [], hunt: [], remediate: [], notify: []}';
COMMENT ON COLUMN public.third_party_exposures.muted IS 'Suppress from alert views without deleting (for known false positives)';
COMMENT ON COLUMN public.third_party_exposures.profile_id IS 'Third-party profile (customer-specific vendor context) that this exposure affects';
COMMENT ON COLUMN public.third_party_exposures.affected_technology IS 'The specific technology (from third_party_profile_technologies) matched to the threat';
COMMENT ON COLUMN public.third_party_exposures.evidence IS 'Array of evidence strings explaining why this exposure was created';
COMMENT ON COLUMN public.third_party_exposures.recommended_action IS 'Recommended SOC action for this exposure';

COMMENT ON TABLE public.third_party_alerts IS 'Analyst-reviewable third-party alerts generated by the continuous monitoring layer';
COMMENT ON COLUMN public.third_party_alerts.alert_type IS 'VULNERABILITY, BREACH, RANSOMWARE, SECURITY_INCIDENT, ATTACK_TECHNIQUE, ARCHITECTURE_CHANGE, EXTERNAL_EXPOSURE, OTHER';
COMMENT ON COLUMN public.third_party_alerts.risk_score IS 'Customer-specific risk score (0-100) combining threat severity + business context';
COMMENT ON COLUMN public.third_party_alerts.business_relevance IS 'Human-readable description of why this threat matters for this customer';
COMMENT ON COLUMN public.third_party_alerts.recommended_action IS 'Explainable SOC action derived from actual evidence';

COMMENT ON TABLE public.threat_events IS 'Unified security event abstraction for vendor correlation. CVEs, threat articles, breach reports, and manual entries are all represented here.';
COMMENT ON COLUMN public.threat_events.source_type IS 'Origin type: cve, threat_article, breach_report, manual';
COMMENT ON COLUMN public.threat_events.source_id IS 'Primary key in the source-specific table (cve_events.id, threat_articles.id)';
COMMENT ON COLUMN public.threat_events.affected_vendors IS 'Canonical vendor names extracted/normalized from the event';
COMMENT ON COLUMN public.threat_events.affected_products IS 'Product names extracted from the event';
COMMENT ON COLUMN public.threat_events.affected_technologies IS 'Technology names extracted from the event';
COMMENT ON COLUMN public.threat_events.iocs IS 'Indicators of compromise: {ips: [], domains: [], hashes: [], urls: []}';
COMMENT ON COLUMN public.threat_events.correlated IS 'Whether vendor/technology correlation has been run for this event';

COMMENT ON TABLE public.customer_vendors IS 'Business relationships between customers and their third-party vendors';
COMMENT ON COLUMN public.customer_vendors.sla_penalty_risk IS '0-100 score of financial/operational impact if vendor SLA is breached';
COMMENT ON COLUMN public.customer_vendors.regulatory_flags IS 'Array of regulatory frameworks: GDPR, SOX, HIPAA, PCI-DSS etc.';
COMMENT ON COLUMN public.customer_vendors.base_risk_score IS '0-100 inherent risk score of this vendor for this customer';
COMMENT ON COLUMN public.customer_vendors.incident_count IS 'Cumulative count of past security incidents involving this vendor for this customer';
COMMENT ON COLUMN public.customer_vendors.last_incident_date IS 'Timestamp of the most recent security incident involving this vendor';

COMMENT ON TABLE public.architecture_changes IS 'Structured record of architecture document changes for a customer-vendor relationship';
COMMENT ON COLUMN public.architecture_changes.added_technologies IS 'JSON array of {technology, version, category} added in the new architecture';
COMMENT ON COLUMN public.architecture_changes.removed_technologies IS 'JSON array of {technology, version, category} removed in the new architecture';
COMMENT ON COLUMN public.architecture_changes.changed_versions IS 'JSON array of {technology, from_version, to_version} version changes';
COMMENT ON COLUMN public.architecture_changes.risk_delta IS 'Change in profile risk score (positive = increased risk)';

COMMENT ON TABLE public.alert_email_notifications IS 'Email notification history for third-party alerts with delivery tracking';
COMMENT ON COLUMN public.alert_email_notifications.notification_type IS 'Type: new_alert, escalation, status_change, resolution, other';
COMMENT ON COLUMN public.alert_email_notifications.status IS 'Status: pending, sent, delivered, failed';
COMMENT ON COLUMN public.alert_email_notifications.failure_reason IS 'Error message if email delivery failed';

COMMENT ON COLUMN public.third_party_profiles.document_id IS 'Architecture document whose technologies/services were extracted and mapped into this profile';

--
-- Seed Data
--

-- Insert default customer
INSERT INTO public.customers (name, industry) 
VALUES ('Demo Customer', 'Technology')
ON CONFLICT DO NOTHING;

-- Note: Demo users are NOT included in this schema dump.
-- After importing this schema, create users through the application
-- or use the backend's user creation endpoints.
-- This avoids shipping password hashes and credentials in the repository.
