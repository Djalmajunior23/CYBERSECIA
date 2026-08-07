-- CyberSec AI Ecosystem — Database Initialization
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    alert JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    assigned_to VARCHAR(100),
    mttr_seconds INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(100) NOT NULL,
    agent_id VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target VARCHAR(255),
    authorization VARCHAR(50),
    outcome VARCHAR(50),
    integrity_hash VARCHAR(64),
    previous_hash VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip VARCHAR(45) UNIQUE NOT NULL,
    hostname VARCHAR(255),
    mac VARCHAR(17),
    os VARCHAR(255),
    asset_class VARCHAR(50),
    criticality VARCHAR(20),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id),
    cve_id VARCHAR(50),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),
    cisa_kev BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'open',
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    remediated_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id VARCHAR(50),
    source VARCHAR(255),
    evidence_type VARCHAR(50),
    hash_sha256 VARCHAR(64),
    chain_of_custody JSONB,
    acquired_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
