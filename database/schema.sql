-- =============================================================================
-- AI SOC Copilot - PostgreSQL Core Schema DDL
-- Target: PostgreSQL 15+ / Supabase
-- =============================================================================

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'analyst', -- 'analyst', 'admin'
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. EVENTS TABLE (Canonical Normalized Telemetry)
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(64) NOT NULL, -- e.g. 'suricata', 'wazuh', 'zeek', 'auth_log', 'simulator'
    host VARCHAR(128),
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(32),
    event_type VARCHAR(64) NOT NULL, -- e.g. 'failed_login', 'port_scan', 'command_exec', 'web_request'
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. ALERTS TABLE
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM', -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'
    detection_rule VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. INCIDENTS TABLE
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'
    summary TEXT,
    confidence FLOAT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 5. INCIDENT_ALERTS JUNCTION TABLE
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

-- 6. AI_ANALYSES TABLE
CREATE TABLE IF NOT EXISTS ai_analyses (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    attack_type VARCHAR(128),
    severity VARCHAR(32),
    confidence FLOAT,
    explanation TEXT,
    evidence JSONB,
    recommendations JSONB,
    mitre_techniques JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 7. THREAT_INTELLIGENCE CACHE TABLE
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(64) NOT NULL, -- 'ip', 'domain', 'hash'
    source VARCHAR(64) NOT NULL, -- 'virustotal', 'abuseipdb'
    reputation VARCHAR(64),
    risk_score INTEGER,
    raw_result JSONB,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_indicator_source UNIQUE (indicator, source)
);

-- 8. MITRE_TECHNIQUES TABLE
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(32) UNIQUE NOT NULL, -- e.g. 'T1110', 'T1046'
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tactic VARCHAR(128) NOT NULL
);

-- 9. AUDIT_LOGS TABLE
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(128) NOT NULL,
    target_type VARCHAR(64),
    target_id VARCHAR(64),
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- INDEXES FOR HIGH-PERFORMANCE SOC QUERIES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_destination_ip ON events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip ON alerts(destination_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence(indicator);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
