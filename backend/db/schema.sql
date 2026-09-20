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