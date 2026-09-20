-- ============================================================
-- SentinelX Database Schema
-- PostgreSQL 18
-- ============================================================

-- ============================================================
-- 1. ROLES
-- ============================================================

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 2. USERS
-- ============================================================

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id BIGINT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ,

    CONSTRAINT fk_users_role
        FOREIGN KEY (role_id)
        REFERENCES roles(id)
        ON DELETE RESTRICT
);

-- ============================================================
-- Initial RBAC Roles
-- ============================================================

INSERT INTO roles (name, description)
VALUES
    ('ADMIN', 'Full platform administration access'),
    ('SOC_ANALYST', 'Security monitoring and incident investigation access'),
    ('SECURITY_ENGINEER', 'Security configuration and engineering access'),
    ('VIEWER', 'Read-only security dashboard access');
    -- ============================================================
-- 3. ASSETS
-- ============================================================

CREATE TABLE assets (
    id BIGSERIAL PRIMARY KEY,

    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    mac_address MACADDR,

    asset_type VARCHAR(50) NOT NULL,
    operating_system VARCHAR(100),

    criticality VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_asset_criticality
        CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

-- Index for fast asset lookup by IP address
CREATE INDEX idx_assets_ip_address
    ON assets(ip_address);

-- Index for filtering assets by criticality
CREATE INDEX idx_assets_criticality
    ON assets(criticality);
    -- ============================================================
-- 4. NETWORK FLOWS
-- ============================================================

CREATE TABLE network_flows (
    id BIGSERIAL PRIMARY KEY,

    source_asset_id BIGINT NOT NULL,
    destination_asset_id BIGINT NOT NULL,

    source_port INTEGER,
    destination_port INTEGER,

    protocol VARCHAR(20) NOT NULL,

    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,

    packets BIGINT NOT NULL DEFAULT 0,

    duration DOUBLE PRECISION,

    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_network_flows_source_asset
        FOREIGN KEY (source_asset_id)
        REFERENCES assets(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_network_flows_destination_asset
        FOREIGN KEY (destination_asset_id)
        REFERENCES assets(id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_network_flows_source_port
        CHECK (source_port IS NULL OR source_port BETWEEN 0 AND 65535),

    CONSTRAINT chk_network_flows_destination_port
        CHECK (destination_port IS NULL OR destination_port BETWEEN 0 AND 65535),

    CONSTRAINT chk_network_flows_bytes_sent
        CHECK (bytes_sent >= 0),

    CONSTRAINT chk_network_flows_bytes_received
        CHECK (bytes_received >= 0),

    CONSTRAINT chk_network_flows_packets
        CHECK (packets >= 0),

    CONSTRAINT chk_network_flows_duration
        CHECK (duration IS NULL OR duration >= 0)
);

-- Index for time-based security analysis
CREATE INDEX idx_network_flows_timestamp
    ON network_flows(timestamp);

-- Index for source asset investigation
CREATE INDEX idx_network_flows_source_asset
    ON network_flows(source_asset_id);

-- Index for destination asset investigation
CREATE INDEX idx_network_flows_destination_asset
    ON network_flows(destination_asset_id);
    -- ============================================================
-- SECURITY EVENTS
-- ============================================================

CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,

    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',

    source_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    destination_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,

    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,

    protocol VARCHAR(20),

    description TEXT,

    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_security_event_severity
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

-- Index for fast security event investigation
CREATE INDEX idx_security_events_type
    ON security_events(event_type);

CREATE INDEX idx_security_events_severity
    ON security_events(severity);

CREATE INDEX idx_security_events_detected_at
    ON security_events(detected_at);

CREATE INDEX idx_security_events_source_asset
    ON security_events(source_asset_id);

CREATE INDEX idx_security_events_destination_asset
    ON security_events(destination_asset_id);
    -- ============================================================
-- ML PREDICTIONS
-- ============================================================

CREATE TABLE ml_predictions (
    id BIGSERIAL PRIMARY KEY,

    network_flow_id BIGINT REFERENCES network_flows(id) ON DELETE SET NULL,

    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),

    prediction VARCHAR(100) NOT NULL,
    confidence NUMERIC(5,4),

    risk_score NUMERIC(5,2),

    predicted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_ml_prediction_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),

    CONSTRAINT chk_ml_prediction_risk_score
        CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100))
);

-- Index for finding predictions belonging to a network flow
CREATE INDEX idx_ml_predictions_network_flow
    ON ml_predictions(network_flow_id);

-- Index for filtering predictions by type
CREATE INDEX idx_ml_predictions_prediction
    ON ml_predictions(prediction);

-- Index for investigating high-risk predictions
CREATE INDEX idx_ml_predictions_risk_score
    ON ml_predictions(risk_score);

-- Index for time-based ML analysis
CREATE INDEX idx_ml_predictions_predicted_at
    ON ml_predictions(predicted_at);
    -- ============================================================
-- SECURITY ALERTS
-- ============================================================

CREATE TABLE alerts (
    id BIGSERIAL PRIMARY KEY,

    security_event_id BIGINT
        REFERENCES security_events(id)
        ON DELETE SET NULL,

    ml_prediction_id BIGINT
        REFERENCES ml_predictions(id)
        ON DELETE SET NULL,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',

    risk_score NUMERIC(5,2),

    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,

    CONSTRAINT chk_alert_severity
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    CONSTRAINT chk_alert_status
        CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),

    CONSTRAINT chk_alert_risk_score
        CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100))
);

-- Index for filtering alerts by severity
CREATE INDEX idx_alerts_severity
    ON alerts(severity);

-- Index for dashboard filtering by status
CREATE INDEX idx_alerts_status
    ON alerts(status);

-- Index for investigating recent alerts
CREATE INDEX idx_alerts_created_at
    ON alerts(created_at);

-- Index for linking alerts to security events
CREATE INDEX idx_alerts_security_event
    ON alerts(security_event_id);

-- Index for linking alerts to ML predictions
CREATE INDEX idx_alerts_ml_prediction
    ON alerts(ml_prediction_id);
    -- ============================================================
-- SECURITY INCIDENTS
-- ============================================================

CREATE TABLE incidents (
    id BIGSERIAL PRIMARY KEY,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',

    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',

    assigned_to BIGINT
        REFERENCES users(id)
        ON DELETE SET NULL,

    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,

    resolution_notes TEXT,

    CONSTRAINT chk_incident_severity
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    CONSTRAINT chk_incident_status
        CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'))
);

-- Index for filtering incidents by severity
CREATE INDEX idx_incidents_severity
    ON incidents(severity);

-- Index for SOC dashboard status filtering
CREATE INDEX idx_incidents_status
    ON incidents(status);

-- Index for assigned analyst lookup
CREATE INDEX idx_incidents_assigned_to
    ON incidents(assigned_to);

-- Index for recent incident investigation
CREATE INDEX idx_incidents_detected_at
    ON incidents(detected_at);
    -- ============================================================
-- THREAT INTELLIGENCE INDICATORS
-- ============================================================

CREATE TABLE threat_indicators (
    id BIGSERIAL PRIMARY KEY,

    indicator_type VARCHAR(30) NOT NULL,
    indicator_value VARCHAR(500) NOT NULL,

    threat_type VARCHAR(100),

    confidence VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',

    source VARCHAR(255),

    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_indicator_type
        CHECK (indicator_type IN ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL')),

    CONSTRAINT chk_indicator_confidence
        CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH'))
);

-- Fast lookup when investigating an indicator
CREATE INDEX idx_threat_indicators_value
    ON threat_indicators(indicator_value);

-- Filter indicators by type
CREATE INDEX idx_threat_indicators_type
    ON threat_indicators(indicator_type);

-- Filter active indicators
CREATE INDEX idx_threat_indicators_active
    ON threat_indicators(is_active);

-- Track recently observed indicators
CREATE INDEX idx_threat_indicators_last_seen
    ON threat_indicators(last_seen);
    CREATE TABLE mitre_techniques (
    id BIGSERIAL PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL UNIQUE,
    technique_name VARCHAR(255) NOT NULL,
    tactic VARCHAR(100),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mitre_techniques_technique_id
ON mitre_techniques(technique_id);

CREATE INDEX idx_mitre_techniques_tactic
ON mitre_techniques(tactic);
CREATE TABLE alert_mitre_techniques (
    alert_id BIGINT NOT NULL,
    technique_id BIGINT NOT NULL,
    confidence NUMERIC(5,4),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (alert_id, technique_id),

    CONSTRAINT fk_alert_mitre_alert
        FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_alert_mitre_technique
        FOREIGN KEY (technique_id)
        REFERENCES mitre_techniques(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_alert_mitre_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

CREATE INDEX idx_alert_mitre_technique
ON alert_mitre_techniques(technique_id);
CREATE TABLE incident_alerts (
    incident_id BIGINT NOT NULL,
    alert_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (incident_id, alert_id),

    CONSTRAINT fk_incident_alert_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_alert_alert
        FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_incident_alerts_alert
ON incident_alerts(alert_id);
CREATE TABLE event_threat_indicators (
    event_id BIGINT NOT NULL,
    indicator_id BIGINT NOT NULL,
    match_type VARCHAR(50),
    confidence NUMERIC(5,4),
    matched_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (event_id, indicator_id),

    CONSTRAINT fk_event_indicator_event
        FOREIGN KEY (event_id)
        REFERENCES security_events(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_event_indicator_indicator
        FOREIGN KEY (indicator_id)
        REFERENCES threat_indicators(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_event_indicator_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

CREATE INDEX idx_event_threat_indicators_indicator
ON event_threat_indicators(indicator_id);
CREATE TABLE attack_sequences (
    id BIGSERIAL PRIMARY KEY,
    source_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    sequence_name VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    confidence NUMERIC(5,4),
    risk_score NUMERIC(5,2),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_attack_sequence_status
        CHECK (status IN ('ACTIVE', 'COMPLETED', 'ABORTED')),

    CONSTRAINT chk_attack_sequence_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),

    CONSTRAINT chk_attack_sequence_risk_score
        CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)),

    CONSTRAINT chk_attack_sequence_time
        CHECK (end_time IS NULL OR end_time >= start_time)
);

CREATE INDEX idx_attack_sequences_source_asset
ON attack_sequences(source_asset_id);

CREATE INDEX idx_attack_sequences_status
ON attack_sequences(status);

CREATE INDEX idx_attack_sequences_start_time
ON attack_sequences(start_time);

CREATE INDEX idx_attack_sequences_risk_score
ON attack_sequences(risk_score);
CREATE TABLE attack_sequence_events (
    sequence_id BIGINT NOT NULL,
    event_id BIGINT NOT NULL,
    sequence_order INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (sequence_id, event_id),

    CONSTRAINT fk_sequence_event_sequence
        FOREIGN KEY (sequence_id)
        REFERENCES attack_sequences(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_sequence_event_event
        FOREIGN KEY (event_id)
        REFERENCES security_events(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_sequence_event_order
        CHECK (sequence_order > 0),

    CONSTRAINT uq_sequence_event_order
        UNIQUE (sequence_id, sequence_order)
);

CREATE INDEX idx_attack_sequence_events_event
ON attack_sequence_events(event_id);

CREATE INDEX idx_attack_sequence_events_order
ON attack_sequence_events(sequence_id, sequence_order);
CREATE TABLE risk_scores (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT REFERENCES alerts(id) ON DELETE CASCADE,
    incident_id BIGINT REFERENCES incidents(id) ON DELETE CASCADE,
    sequence_id BIGINT REFERENCES attack_sequences(id) ON DELETE CASCADE,
    score NUMERIC(5,2) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    scoring_method VARCHAR(100),
    explanation TEXT,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_risk_score_value
        CHECK (score >= 0 AND score <= 100),

    CONSTRAINT chk_risk_level
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX idx_risk_scores_alert
ON risk_scores(alert_id);

CREATE INDEX idx_risk_scores_incident
ON risk_scores(incident_id);

CREATE INDEX idx_risk_scores_sequence
ON risk_scores(sequence_id);

CREATE INDEX idx_risk_scores_score
ON risk_scores(score);

CREATE INDEX idx_risk_scores_calculated_at
ON risk_scores(calculated_at);
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id BIGINT,
    ip_address INET,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user
ON audit_logs(user_id);

CREATE INDEX idx_audit_logs_action
ON audit_logs(action);

CREATE INDEX idx_audit_logs_resource
ON audit_logs(resource_type, resource_id);

CREATE INDEX idx_audit_logs_created_at
ON audit_logs(created_at);

