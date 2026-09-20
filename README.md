# SentinelX

> AI-Powered Network Security & Threat Intelligence Platform

SentinelX is a defensive cybersecurity platform designed to monitor network behaviour, detect suspicious activity, analyse security events, and assist security analysts with AI-powered threat detection and risk assessment.

## Problem Statement

Modern networks generate a large volume of network traffic and security events. Manually analysing this activity makes it difficult to identify abnormal behaviour, correlate related events, and respond to emerging threats quickly.

SentinelX addresses this problem by combining network telemetry, rule-based detection, machine learning, threat intelligence, MITRE ATT&CK mapping, and a security operations dashboard into a unified platform.

## Core Objectives

- Monitor and analyse network activity
- Extract meaningful features from network traffic
- Detect anomalous and potentially malicious behaviour
- Classify suspicious network activity using machine learning
- Correlate related security events
- Assign risk scores to detected activity
- Map detected behaviour to MITRE ATT&CK techniques
- Provide real-time security alerts
- Provide an investigation dashboard for security analysts
- Maintain an auditable history of security events and incidents

## High-Level Architecture

```text
Network Traffic / PCAP / Zeek
            │
            ▼
    Data Ingestion Layer
            │
            ▼
    Feature Engineering
            │
            ▼
  Detection & ML Pipeline
            │
            ▼
 Risk & Event Correlation
            │
       ┌────┴────┐
       ▼         ▼
 Threat Intel  MITRE ATT&CK
       │         │
       └────┬────┘
            ▼
       PostgreSQL
            │
            ▼
       Backend APIs
            │
            ▼
      React Dashboard