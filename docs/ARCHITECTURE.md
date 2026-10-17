# AI SOC Copilot – Architecture Specification

## 1. System Overview

AI SOC Copilot is an intelligent, full-stack Security Operations Center (SOC) assistant designed to ingest security events, detect malicious activity using deterministic rules, correlate alerts into incidents, enrich indicators with threat intelligence, and provide explainable AI-guided investigation via Google Gemini.

---

## 2. High-Level Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Security Log Sources                            │
│  (Suricata EVE, Wazuh, Zeek, Linux Auth, Apache/Nginx, Event Simulator)│
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Raw logs / HTTP Ingestion
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend Layer                           │
│  ┌───────────────────────┐             ┌────────────────────────────┐  │
│  │ Ingestion & Parsers   │             │ Rule-Based Detection Engine│  │
│  │ Normalization Engine  │────────────►│ (Brute Force, Port Scan,   │  │
│  └──────────┬────────────┘             │  Web Attacks, Cmd Exec)    │  │
│             │                          └─────────────┬──────────────┘  │
│             │ Stored Events                          │ Generated Alerts│
│             ▼                                        ▼                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   Incident Correlation Engine                    │  │
│  │         (Aggregates alerts into kill-chain incidents)            │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                  PostgreSQL Relational Storage                   │  │
│  │  (Users, Events, Alerts, Incidents, MITRE, ThreatIntel, Audits)  │  │
│  └──────────────────┬───────────────────────────────▲───────────────┘  │
│                     │ Controlled                     │ Read-only       │
│                     │ Parameters                     │ Tool Results    │
│                     ▼                                │                 │
│  ┌──────────────────────────────────────────────────┴───────────────┐  │
│  │                    AI Engine (Google Gemini)                     │  │
│  │  ┌────────────────────┐ ┌───────────────────┐ ┌───────────────┐  │  │
│  │  │ Alert Analyzer     │ │ Incident Narrator │ │ Copilot Chat  │  │  │
│  │  └────────────────────┘ └───────────────────┘ └───────────────┘  │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │ AI Insights & Recommendations    │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              Human-in-the-Loop Response Controller               │  │
│  │         (Simulated Action Approval & Audit Trail Logging)        │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
└─────────────────────────────────────┼──────────────────────────────────┘
                                      │ REST API (JSON)
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   React + Vite + Tailwind Frontend                     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌────────────┐  │
│  │ SOC Dashboard │ │ Alert Details │ │ Incident View │ │ AI Copilot │  │
│  └───────────────┘ └───────────────┘ └───────────────┘ └────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture & Data Flow

### 3.1 Log Ingestion & Normalization
- Security logs arrive via `POST /api/logs/upload` or streaming endpoints (`/api/ingest/suricata`, `/api/ingest/wazuh`, `/api/ingest/zeek`).
- **File Type Detector** identifies file encoding and structure.
- **Format-Specific Parsers** extract timestamps, IPs, ports, protocols, user accounts, and payloads.
- **Normalizer** transforms diverse logs into the canonical `EVENT` schema.
- Raw logs are stored alongside structured fields to preserve forensic integrity.

### 3.2 Deterministic Detection Engine
- Operates on normalized events before any AI invocation.
- Applies deterministic threshold and signature rules (e.g., failed logins > 5 in 60 seconds = T1110 Brute Force).
- Produces normalized `ALERT` records linked to the triggering events.
- Guarantees detection repeatability without relying on non-deterministic LLM behavior.

### 3.3 Incident Correlation
- Aggregates temporally and spatially related alerts sharing common source IPs, destination hosts, or subnets.
- Maps activity across the Cyber Kill Chain (Reconnaissance → Scanning → Credential Access → Execution → Exfiltration).
- Links alerts into `INCIDENT` records.

### 3.4 Threat Intelligence
- Queries external reputation APIs (VirusTotal, AbuseIPDB).
- Caches results in the `threat_intelligence` table with TTL to prevent quota exhaustion.
- Gracefully handles missing API keys without disrupting core SOC operations.

### 3.5 AI Engine (Google Gemini)
- Never accesses the database directly.
- Receives sanitized, structured context via FastAPI service methods.
- Invokes controlled backend tools (e.g., `get_alert`, `get_related_events`, `get_ip_reputation`, `get_mitre_technique`) to retrieve ground truth data.
- Outputs structured JSON analyses with calibrated confidence levels, observable evidence, and non-destructive recommendations.

### 3.6 Human-in-the-Loop & Audit Logging
- Destructive and containment actions (IP block, host isolation, credential revocation) require explicit analyst confirmation.
- Every analyst decision and system state change is written to `audit_logs`.

---

## 4. Security & Isolation Boundaries

1. **Frontend Isolation**: Frontend communicates strictly via authenticated REST APIs with CORS protection. No direct database or external API credentials exist on the client.
2. **AI Boundary**: Google Gemini receives only explicit telemetry payloads through parameterized backend functions. Shell commands and direct SQL execution are prohibited.
3. **Database Security**: PostgreSQL connection uses parameterized SQLAlchemy queries, preventing SQL injection. Role-based access control segregates Analyst and Admin permissions.
