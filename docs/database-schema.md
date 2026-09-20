# SentinelX Database Schema

## 1. Purpose

The SentinelX database is the persistent source of truth for the platform.

It stores users, assets, network activity, security events, alerts, incidents, machine learning predictions, threat intelligence, MITRE ATT&CK mappings, attack sequences, risk assessments, and audit records.

The database is designed to support:

- Security monitoring
- Event correlation
- Threat detection
- ML-based analysis
- Incident investigation
- Risk scoring
- Threat intelligence
- Security auditing
- Historical security analytics

## 2. Database Technology

SentinelX uses PostgreSQL as its primary relational database.

### Why PostgreSQL?

PostgreSQL provides:

- Strong relational data modelling
- Primary and foreign key constraints
- ACID transactions
- Complex SQL queries
- Aggregations
- Common Table Expressions (CTEs)
- Window functions
- JSON/JSONB support
- Indexing
- Reliable transactional storage

These capabilities are useful for security analytics and historical event investigation.

## 3. Entity Overview

The main entities in the SentinelX database are:

1. Users
2. Roles
3. Assets
4. Network Flows
5. Security Events
6. Alerts
7. Incidents
8. ML Predictions
9. Threat Indicators
10. MITRE ATT&CK Techniques
11. Attack Sequences
12. Risk Scores
13. Audit Logs

## 4. Entity Relationships

High-level relationship:

                    ┌──────────┐
                    │  Roles   │
                    └────┬─────┘
                         │
                         │ 1:N
                         ▼
                    ┌──────────┐
                    │  Users   │
                    └────┬─────┘
                         │
                         │ 1:N
                         ▼
                    ┌─────────────┐
                    │ Audit Logs  │
                    └─────────────┘


┌──────────┐
│  Assets  │
└────┬─────┘
     │
     ├───────────────┐
     │               │
     │ 1:N           │ 1:N
     ▼               ▼
Network Flows   Attack Sequences
     │
     ▼
Security Events
     │
     ├───────────────┐
     │               │
     │ 1:N           │ 1:N
     ▼               ▼
   Alerts       ML Predictions
     │
     ▼
 Incidents

Security Events
     │
     ├──────► Risk Scores
     │
     ├──────► Threat Indicators
     │
     └──────► MITRE ATT&CK Techniques

## 5. Table Definitions

## 5.1 roles

Stores the roles used for Role-Based Access Control (RBAC).

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| name | VARCHAR | Unique role name |
| description | TEXT | Role description |
| created_at | TIMESTAMP | Creation timestamp |

### Example Roles

ADMIN
SOC_ANALYST
SECURITY_ENGINEER
VIEWER

### Relationship

roles 1 ─────── N users

One role can be assigned to multiple users.

## 5.2 users

Stores authenticated platform users.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| username | VARCHAR | Unique username |
| email | VARCHAR | Unique email |
| password_hash | VARCHAR | Securely hashed password |
| role_id | BIGINT | Foreign key to roles |
| is_active | BOOLEAN | Account status |
| created_at | TIMESTAMP | Account creation time |
| last_login | TIMESTAMP | Last successful login |

### Security

Plaintext passwords must never be stored.

Passwords will be securely hashed before persistence.

## 5.3 assets

Represents hosts and devices monitored by SentinelX.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| ip_address | INET | IP address |
| hostname | VARCHAR | Hostname |
| mac_address | MACADDR | MAC address |
| asset_type | VARCHAR | Server, workstation, router, etc. |
| operating_system | VARCHAR | Detected operating system |
| criticality | VARCHAR | Asset importance |
| created_at | TIMESTAMP | First registration |
| updated_at | TIMESTAMP | Last update |

### Example

IP: 10.0.0.15
Hostname: server-01
OS: Linux
Type: Server
Criticality: HIGH

## 5.4 network_flows

Stores summarized network communication.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| source_asset_id | BIGINT | Source asset |
| destination_asset_id | BIGINT | Destination asset |
| source_port | INTEGER | Source port |
| destination_port | INTEGER | Destination port |
| protocol | VARCHAR | TCP, UDP, ICMP, etc. |
| bytes_sent | BIGINT | Bytes sent |
| bytes_received | BIGINT | Bytes received |
| packets | BIGINT | Number of packets |
| duration | DOUBLE PRECISION | Flow duration |
| timestamp | TIMESTAMP | Flow timestamp |

### Purpose

Network flow data forms an important input for feature engineering and machine learning.

Example:

Source: 10.0.0.15
Destination: 10.0.0.20
Protocol: TCP
Destination Port: 22
Packets: 145
Bytes: 23840
Duration: 2.31 seconds

## 5.5 security_events

Represents meaningful security-related observations.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| asset_id | BIGINT | Related asset |
| event_type | VARCHAR | Type of security event |
| severity | VARCHAR | Event severity |
| description | TEXT | Event details |
| source | VARCHAR | Detection source |
| status | VARCHAR | Event status |
| timestamp | TIMESTAMP | Detection time |

### Possible Event Types

PORT_SCAN
BRUTE_FORCE
ANOMALOUS_TRAFFIC
SUSPICIOUS_LOGIN
MALWARE_INDICATOR
DNS_ANOMALY
UNUSUAL_CONNECTION

## 5.6 alerts

Represents security events that require analyst attention.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| security_event_id | BIGINT | Related security event |
| risk_score | NUMERIC | Calculated risk score |
| severity | VARCHAR | Alert severity |
| status | VARCHAR | Open, acknowledged, resolved |
| created_at | TIMESTAMP | Alert creation time |
| resolved_at | TIMESTAMP | Resolution time |

### Important Concept

A security event is not necessarily an alert.

Example:

1000 network events
        ↓
Detection Engine
        ↓
20 suspicious events
        ↓
10 analyst-worthy alerts

This separation prevents excessive alert noise.

## 5.7 incidents

Groups related alerts into an investigation.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| title | VARCHAR | Incident title |
| description | TEXT | Incident description |
| severity | VARCHAR | Incident severity |
| status | VARCHAR | Incident status |
| assigned_to | BIGINT | Assigned analyst |
| created_at | TIMESTAMP | Creation time |
| resolved_at | TIMESTAMP | Resolution time |

### Example

Incident #42
Possible SSH Brute Force Attack

    ├── Alert #101
    ├── Alert #104
    ├── Alert #108
    └── Alert #111

## 5.8 ml_predictions

Stores outputs generated by ML models.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| security_event_id | BIGINT | Related security event |
| model_name | VARCHAR | Model identifier |
| prediction | VARCHAR | Model prediction |
| confidence | NUMERIC | Prediction confidence |
| anomaly_score | NUMERIC | Anomaly score |
| created_at | TIMESTAMP | Prediction time |

### Example

Model: isolation_forest_v1
Prediction: suspicious
Confidence: 0.91
Anomaly Score: 0.94

Keeping predictions separately allows model performance and historical predictions to be analysed later.

## 5.9 threat_indicators

Stores indicators associated with known or suspected threats.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| indicator_type | VARCHAR | IP, domain, URL, hash, etc. |
| indicator_value | TEXT | Indicator value |
| source | VARCHAR | Intelligence source |
| confidence | NUMERIC | Intelligence confidence |
| first_seen | TIMESTAMP | First observation |
| last_seen | TIMESTAMP | Most recent observation |

### Possible Indicator Types

IP
DOMAIN
URL
HASH
EMAIL

## 5.10 mitre_techniques

Stores MITRE ATT&CK technique information used for behaviour mapping.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| technique_id | VARCHAR | ATT&CK technique identifier |
| name | VARCHAR | Technique name |
| tactic | VARCHAR | Associated tactic |
| description | TEXT | Technique description |

### Purpose

Detected behaviours can be mapped to relevant MITRE ATT&CK techniques to provide security context and improve analyst investigation.

## 5.11 attack_sequences

Represents temporal sequences of related suspicious activity.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| asset_id | BIGINT | Related asset |
| sequence_start | TIMESTAMP | Sequence start |
| sequence_end | TIMESTAMP | Sequence end |
| current_stage | VARCHAR | Current attack stage |
| status | VARCHAR | Sequence status |

### Example

Recon
  ↓
Scanning
  ↓
Brute Force
  ↓
Suspicious Login
  ↓
Lateral Activity

This structure supports future temporal analysis and attack progression modelling.

## 5.12 risk_scores

Stores historical risk calculations.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| security_event_id | BIGINT | Related event |
| score | NUMERIC | Numeric risk score |
| risk_level | VARCHAR | Risk category |
| calculation_version | VARCHAR | Risk algorithm version |
| created_at | TIMESTAMP | Calculation time |

### Example

Score: 91
Risk Level: HIGH
Calculation Version: v1

The calculation version allows historical scores to remain explainable when the risk algorithm changes.

## 5.13 audit_logs

Stores security-relevant actions performed inside the platform.

### Columns

| Column | Type | Description |
|---|---|---|
| id | BIGSERIAL | Primary key |
| user_id | BIGINT | User performing the action |
| action | VARCHAR | Action performed |
| resource | VARCHAR | Resource type |
| resource_id | BIGINT | Affected resource |
| ip_address | INET | Request source |
| timestamp | TIMESTAMP | Action timestamp |

### Example

User: SOC_ANALYST
Action: RESOLVE_ALERT
Resource: ALERT
Resource ID: 102

Audit logs provide accountability and support security investigations.

## 6. Primary Keys and Foreign Keys

Primary keys uniquely identify records.

Foreign keys establish relationships between entities.

Important relationships:

users.role_id → roles.id

network_flows.source_asset_id → assets.id

network_flows.destination_asset_id → assets.id

security_events.asset_id → assets.id

alerts.security_event_id → security_events.id

ml_predictions.security_event_id → security_events.id

risk_scores.security_event_id → security_events.id

incidents.assigned_to → users.id

audit_logs.user_id → users.id

attack_sequences.asset_id → assets.id

## 7. Data Flow Through the Database

The expected security-data lifecycle is:

Network Traffic
      ↓
Network Flow
      ↓
Feature Engineering
      ↓
Detection Engine
      ↓
Security Event
      ↓
 ┌────┼───────────────┐
 ↓    ↓               ↓
 ML   Risk        Threat Intel
 ↓    ↓               ↓
 └────┼───────────────┘
      ↓
    Alert
      ↓
   Incident
      ↓
 Analyst Investigation
      ↓
  Resolution
      ↓
  Audit Log

## 8. SQL Analytics

The database will support security analytics using PostgreSQL features such as:

- SELECT
- WHERE
- ORDER BY
- GROUP BY
- HAVING
- JOIN
- CTE
- CASE
- Window Functions
- ROW_NUMBER
- RANK
- DENSE_RANK
- LAG
- LEAD
- Conditional Aggregation
- Date/Time Analysis
- Running Totals
- Moving Windows

Example analytical questions:

### High-risk hosts

Which hosts generated the most high-risk events?

### Alert trends

How many alerts were generated per hour?

### Attack bursts

Did a host generate an unusual number of events within a short time window?

### Analyst workload

Which analysts currently have the highest number of unresolved incidents?

### Temporal behaviour

What events occurred immediately before a suspicious login?

These queries will later become real backend/dashboard features.

## 9. Indexing Strategy

Security data can grow quickly, so indexes will be added to frequently queried columns.

Potential indexes include:

- assets.ip_address
- network_flows.timestamp
- network_flows.source_asset_id
- network_flows.destination_asset_id
- security_events.timestamp
- security_events.asset_id
- security_events.severity
- alerts.status
- alerts.created_at
- threat_indicators.indicator_value
- audit_logs.timestamp

Indexes will be added based on actual query patterns rather than blindly indexing every column.

## 10. Security Considerations

The database layer will follow security best practices:

- Passwords stored only as secure hashes
- Parameterized queries
- Least-privilege database users
- Foreign key constraints
- Input validation at the API layer
- Sensitive configuration stored outside source code
- Database credentials stored using environment variables/secrets
- Audit logging for security-sensitive actions
- Restricted database network access
- Regular backups in production environments

## 11. Design Principles

The SentinelX database follows these principles:

### Separation of concerns

Users, network data, detections, ML predictions, alerts, and incidents are represented separately.

### Referential integrity

Foreign keys maintain valid relationships.

### Auditability

Security decisions and analyst actions should remain traceable.

### Historical analysis

Security events and ML predictions are persisted for future analysis.

### Scalability

Indexes and appropriate relational modelling will support increasing event volume.

### Explainability

Risk scores and ML predictions retain contextual information required for investigation.

## 12. Future Extensions

The schema may later be extended with:

- Detection rules
- API keys
- Notification channels
- Threat intelligence feeds
- Model versions
- Feature versions
- Dataset metadata
- Investigation notes
- File/hash analysis
- User sessions
- Notification history
- Model evaluation metrics

These will only be introduced when they provide a concrete requirement for the platform.