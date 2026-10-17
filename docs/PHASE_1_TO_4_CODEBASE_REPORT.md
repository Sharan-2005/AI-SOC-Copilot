# Technical Handover & 50% Milestone Report: AI SOC Copilot (Phases 1–4)

**Project Title:** AI SOC Copilot – Intelligent Security Operations Center Platform  
**Target Milestone:** College Major Project 50% Presentation & Viva Review  
**Academic Degree:** Bachelor of Engineering in Information Technology (BE IT)  
**Implementation Baseline:** Phases 1 to 4 Complete (Verified against current source code)  
**Report Generation Date:** September 2026  

---

## 1. Project Overview

### What the Project Currently Does
The AI SOC Copilot is a defensive cybersecurity and threat-monitoring platform. In its current implementation (Phases 1 through 4), it ingests raw security telemetry from files or real-time HTTP streams, normalizes diverse log structures into a unified event format, evaluates records against deterministic detection rules (mapped to MITRE ATT&CK techniques), generates structured security alerts, correlates related alerts into multi-stage attack incidents based on attacker IP and temporal proximity, and presents an interactive, reactive web-based operations console for security analysts.

### Main Objective
To solve the modern Security Operations Center (SOC) challenge of alert fatigue and fragmented telemetry by providing an end-to-end pipeline that automates the ingestion, parsing, normalization, detection, and incident correlation stages with high auditability and zero vendor lock-in.

### Current Capabilities (Phases 1–4 Complete)
- **Multi-Format Log Ingestion:** Ingestion of `.log`, `.txt`, `.json`, `.csv`, syslog, Linux auth logs, Apache/Nginx web logs, and synthetic telemetry via drag-and-drop or multipart HTTP upload.
- **Data Normalization:** Transformation of varied schemas into a canonical relational schema (`Event`) with flexible timestamp handling and lossless raw JSON preservation.
- **Deterministic Detection Engine:** In-memory and SQL-backed detection for Brute Force (T1110), Port Scanning (T1046), Suspicious Commands (T1059), Web Application Exploits (T1190), and Privilege Escalation (T1548).
- **Automated Incident Correlation:** Algorithmic grouping of temporally close alerts sharing an identical source IP into consolidated, high-confidence security incidents.
- **Relational Cloud Persistence:** Complete transactional model in Supabase PostgreSQL via SQLAlchemy 2.0 with indexed query support.
- **SOC Analyst Console:** Single Page Application (React 18 + Vite + Tailwind CSS + Recharts) featuring live dashboard analytics, full-text event search, alert lifecycle triage, incident inspection, and MITRE ATT&CK matrix browsing.
- **Integrated Scenario Simulator:** Built-in attack generator capable of executing multi-stage attacks directly from the UI or CLI to validate detection and correlation pipelines.
- **System Maintenance Controls:** Foreign-key compliant data purging (`DELETE /api/system/clear-data`) allowing repeated demonstrations without resetting database migrations or user credentials.

### Current Limitations
- AI reasoning (Google Gemini LLM for automated incident briefings, kill-chain reconstruction, and natural language copilot chat) is planned for Phase 5 and not yet active.
- Direct external threat intelligence querying (live API lookups to VirusTotal/AbuseIPDB) is planned for Phase 6; table schema exists, but live external API connectors are not yet active.
- Dedicated streaming daemon connectors for Suricata socket, Zeek broker, or Wazuh agent socket are not implemented; ingestion is currently executed through HTTP upload and REST endpoints.
- User authentication and role-based access control (RBAC) middleware with JWT tokens are not yet enforced on endpoints; database schema supports users, but endpoints are currently open for local demonstration.
- Automated active response / containment actions (firewall blocking, host isolation) are not yet automated.

### 5–10 Line Presentation Summary (Ready for Judges)
> "Good morning, respected judges. Our major project is the **AI SOC Copilot**, a centralized defensive cybersecurity platform designed to reduce alert fatigue in Security Operations Centers. In this initial 50% milestone covering Phases 1 through 4, we have engineered an end-to-end security pipeline that ingests raw, heterogeneous machine logs—including Linux authentication, Apache/Nginx access, and network flow records. The system normalizes these into a canonical schema stored in Supabase PostgreSQL, runs five deterministic detection algorithms mapped to MITRE ATT&CK techniques, and automatically correlates related alerts into actionable security incidents. Analysts interact with a modern React dashboard providing real-time telemetry, alert triage, and attack simulations. In the subsequent phases, we will integrate Google Gemini to act as an automated AI SOC Copilot for intelligent threat analysis and guided response."

---

## 2. Current Architecture

### Actual Current Architecture
The system employs a client-server micro-architecture comprising a decoupled Single Page Application (SPA) frontend, a high-throughput asynchronous REST API backend, and a cloud-hosted PostgreSQL relational database.

### End-to-End Data Flow
```
User / Log File / Simulator
            │
            ▼
    [Frontend Console]
    (React 18 / Vite / Axios)
            │  HTTP POST (Multipart or JSON)
            ▼
    [FastAPI REST API Layer] (Port 8000)
    (/api/logs/upload, /api/events, /api/simulator)
            │
            ▼
    [Ingestion & Normalization Engine]
    (file_detector.py -> parsers/*.py -> normalizer.py)
            │
            ▼
    [PostgreSQL Database (Supabase)]
    (Persist canonical Event records via COPY protocol or chunked bulk insert)
            │
            ▼
    [Detection Engine] (detection_engine.py + rules.py)
    (Evaluate 5 deterministic rules: Brute Force, Port Scan, Commands, Web, PrivEsc)
            │
            ▼
    [Alert Generation & Deduplication]
    (Persist Alert records linked to Event IDs)
            │
            ▼
    [Incident Correlator] (correlator.py)
    (Group alerts by Source IP + 1-hour temporal window into Incident & IncidentAlert records)
            │
            ▼
    [Frontend Updates via State Sync / Custom Events]
    (Dashboard metrics, Alert tables, Incident timelines refreshed dynamically)
```

### ASCII Architecture Diagram

```
+-----------------------------------------------------------------------------------------+
|                                    SECURITY SOURCES                                     |
|  +--------------------+   +-----------------------+   +------------------------------+  |
|  |   Log Upload UI    |   | Python Simulator CLI  |   | UI Attack Simulator Controls |  |
|  | (.log, .txt, .json)|   | (generate_events.py)  |   | (Brute Force/Scan/Web Probe) |  |
|  +---------+----------+   +-----------+-----------+   +--------------+---------------+  |
+------------|--------------------------|------------------------------|------------------+
             |                          |                              |
             +--------------------------+------------------------------+
                                        | HTTP REST (JSON / Multipart)
                                        v
+-----------------------------------------------------------------------------------------+
|                               FASTAPI APPLICATION BACKEND                               |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   |                              ROUTERS & CONTROLLERS                              |   |
|   |  /health | /events | /alerts | /incidents | /mitre | /dashboard | /logs | /sim  |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   |                       INGESTION & NORMALIZATION PIPELINE                        |   |
|   |  File Detector -> Parser Registry (JSON/CSV/Apache/Nginx/Text) -> Normalizer   |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                     +---------------------+---------------------+                       |
|                     |                                           |                       |
|                     v                                           v                       |
|   +-----------------------------------+       +-------------------------------------+   |
|   |    DETERMINISTIC RULE ENGINE      |       |     BULK DATABASE PERSISTENCE       |   |
|   |  - RULE 1: Brute Force (T1110)    |       |  PostgreSQL COPY Protocol via DBAPI |   |
|   |  - RULE 2: Port Scan (T1046)      |       |  Fallback: Chunked 500-record Batch |   |
|   |  - RULE 3: Suspicious Cmd (T1059) |       +------------------+------------------+   |
|   |  - RULE 4: Web Attacks (T1190)    |                          |                      |
|   |  - RULE 5: Priv Escalation (T1548)|                          |                      |
|   +-----------------+-----------------+                          |                      |
|                     |                                            |                      |
|                     v                                            |                      |
|   +-----------------------------------+                          |                      |
|   |     TEMPORAL INCIDENT CORRELATOR  |                          |                      |
|   |  Groups alerts by source_ip in    |                          |                      |
|   |  1-hour window into Incidents     |                          |                      |
|   +-----------------+-----------------+                          |                      |
|                     |                                            |                      |
+---------------------|--------------------------------------------|----------------------+
                      |                                            |
                      v                                            v
+-----------------------------------------------------------------------------------------+
|                              SUPABASE POSTGRESQL DATABASE                               |
|                                                                                         |
|  [events] <─────── [alerts] <─────── [incident_alerts] ───────> [incidents]             |
|                                                                                         |
|  [mitre_techniques]       [users]        [threat_intelligence]       [audit_logs]       |
+-----------------------------------------------------------------------------------------+
                                        ^
                                        | JSON REST API over HTTP
+-----------------------------------------------------------------------------------------+
|                                    REACT 18 FRONTEND                                    |
|                                                                                         |
|  [Dashboard Overview]  [Log Upload Page]  [Alerts View]  [Incidents & Timeline]         |
|  [Event Stream Search] [MITRE Matrix]     [System Health] [Attack Simulator Controls]   |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Complete Technology Stack

### Frontend Stack
- **Framework:** React 18 (`react: ^18.3.1`, `react-dom: ^18.3.1`)
  - *Why used:* Industry standard for component-driven UI development. Provides declarative state management, virtual DOM reconciliation, and seamless hooks (`useState`, `useEffect`, custom contexts) necessary for a high-frequency real-time security dashboard.
- **Build Tool / Bundler:** Vite 6 (`vite: ^6.1.0`, `@vitejs/plugin-react: ^4.3.4`)
  - *Why used:* Ultra-fast Hot Module Replacement (HMR) and optimized Rollup production bundling. Built-in proxy configuration routes `/api` calls directly to the FastAPI backend at `http://127.0.0.1:8000`, eliminating manual CORS handling in development.
- **Styling System:** Tailwind CSS (`tailwindcss: ^3.4.17`, `postcss: ^8.4.49`, `autoprefixer: ^10.4.20`) + Vanilla Custom CSS
  - *Why used:* Enables utility-first design for dark-themed, glassmorphic security consoles (`soc-glass`, `soc-grid-bg`) and responsive responsive flex/grid layouts.
- **Data Visualization & Charts:** Recharts (`recharts: ^3.10.1`)
  - *Why used:* React-native SVG charting library used to render the Alert Severity Donut Chart, Top Source IP Horizontal Bar Chart, and Telemetry Frequency Area Timeline.
- **Routing:** React Router DOM v6 (`react-router-dom: ^6.28.1`)
  - *Why used:* Declarative client-side nested routing (`DashboardLayout` wrapping routes `/`, `/upload`, `/alerts`, `/alerts/:id`, `/incidents`, `/incidents/:id`, `/events`, `/mitre`, `/system`).
- **HTTP / API Communication:** Axios (`axios: ^1.7.9`)
  - *Why used:* Robust promise-based HTTP client with instance configuration, unified timeouts (15s default, 180s for log parsing), base URLs, and response error interceptors.
- **Icons:** Lucide React (`lucide-react: ^0.475.0`)
  - *Why used:* High-clarity, consistent cybersecurity and UI iconography (`ShieldAlert`, `Terminal`, `Activity`, `UploadCloud`, `Server`).

### Backend Stack
- **Runtime & Language:** Python 3.11+ (Tested and verified on Python 3.14.2)
  - *Why used:* Primary language for cybersecurity engineering, regex pattern matching, data science, and upcoming Gemini AI integrations.
- **API Framework:** FastAPI (`fastapi>=0.110.0`)
  - *Why used:* Modern, asynchronous Python web framework built on Starlette and Pydantic. Delivers native OpenAPI/Swagger generation (`/docs`), automated request validation, and high concurrency.
- **ASGI Server:** Uvicorn (`uvicorn[standard]>=0.29.0`)
  - *Why used:* High-performance asynchronous server implementation based on `uvloop` and `httptools`.
- **Object Relational Mapper (ORM):** SQLAlchemy 2.0 (`sqlalchemy>=2.0.28`)
  - *Why used:* Python's industry-standard database abstraction toolkit using modern 2.0 typed mappings (`Mapped`, `mapped_column`, `relationship`, `select()`). Protects against SQL injection through parameterized queries.
- **Data Validation & Settings:** Pydantic v2 & Pydantic-Settings (`pydantic>=2.6.0`, `pydantic-settings>=2.2.0`)
  - *Why used:* Strict serialization and deserialization of API request/response models (`EventBase`, `AlertResponse`, etc.) and environment variable parsing from `.env`.
- **Multipart Form Parser:** Python-Multipart (`python-multipart>=0.0.9`)
  - *Why used:* Streaming parser required by FastAPI to handle file uploads via `UploadFile`.
- **Environment Management:** Python-Dotenv (`python-dotenv>=1.0.1`)
  - *Why used:* Loads local `.env` configuration securely without hardcoding credentials in source code.
- **HTTP Testing Client:** HTTPX (`httpx>=0.27.0`)
  - *Why used:* Async-capable HTTP client utilized by FastAPI's `TestClient` during test suite runs.

### Database Stack
- **Database Engine:** Supabase PostgreSQL (PostgreSQL 15+)
  - *Why used:* Production-grade relational database providing native ACID transactions, relational foreign key constraints, high-performance B-tree indexes, and JSONB storage for unstructured telemetry.
- **Database Driver:** Psycopg 3 Binary (`psycopg[binary]>=3.1.18`)
  - *Why used:* Next-generation PostgreSQL adapter for Python supporting native connection pooling and high-speed binary `COPY` protocol used for bulk log ingestion.
- **Connection Management:** SQLAlchemy Connection Pool (`pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`)
  - *Why used:* Reuses persistent connections to Supabase and prevents connection drops over cloud networks.

### Security Engineering & Standards
- **MITRE ATT&CK Framework:** Mapped technique taxonomy (v14/v15 enterprise baseline: T1110, T1046, T1059, T1190, T1548, T1071, T1078).
- **Detection Architecture:** Hybrid threshold-based, regex signature-based, and temporal state correlation engine.
- **Data Sanitization:** Strict regex-based input normalization, port boundary enforcement (1–65535), and UTC timestamp normalization.

### Development & Tooling
- **IDE:** Antigravity AI IDE / VS Code
- **Version Control:** Git
- **Testing:** Pytest 9.1 (`pytest>=9.1.1`, `anyio>=4.15.1`)
- **Containers (Configured):** Docker & Docker Compose (`docker-compose.yml` for optional local PostgreSQL fallback)

---

## 4. Phase 1 Implementation

### What Was Actually Implemented in Phase 1
Phase 1 established the foundational infrastructure of the AI SOC Copilot:
1. Complete directory scaffolding separating `backend`, `frontend`, `database`, `simulator`, and `docs`.
2. Asynchronous FastAPI server initialization with configurable application lifespan (`@asynccontextmanager`).
3. Cross-Origin Resource Sharing (CORS) middleware configuration allowing frontend origin calls.
4. Database connection manager using SQLAlchemy 2.0 with the `psycopg` driver, including pool management and auto-ping connectivity checks.
5. System health diagnostic endpoint (`GET /api/health`) reporting live PostgreSQL latency and connection status.
6. Environment variable architecture supporting hierarchical `.env` loading.
7. Initial React 18 frontend scaffolding using Vite with a development proxy connecting frontend port `5173` to backend port `8000`.

### Folder Structure
```
Major Project/
├── .env                       # Environment variables (DATABASE_URL, CORS, HOST, PORT)
├── .env.example               # Template environment variables
├── .gitignore                 # Git ignore rules
├── docker-compose.yml         # Containerized local PostgreSQL fallback
├── README.md                  # Project overview documentation
├── backend/                   # Python FastAPI Backend
│   ├── requirements.txt       # Backend dependencies
│   ├── app/
│   │   ├── main.py            # FastAPI entry point, lifespan, CORS, router mounting
│   │   ├── config.py          # Pydantic BaseSettings, URL normalizer
│   │   ├── database/
│   │   │   ├── base.py        # SQLAlchemy DeclarativeBase
│   │   │   ├── connection.py  # Engine creation, get_db session dependency, health check
│   │   │   └── init_db.py     # Schema creation and baseline data seeder
│   │   ├── models/            # SQLAlchemy 2.0 ORM database models
│   │   ├── schemas/           # Pydantic v2 schemas for validation
│   │   ├── routers/           # REST API route handlers
│   │   ├── ingestion/         # File detector, parsers, and normalizer
│   │   └── detection/         # Rule engine and incident correlator
│   └── tests/                 # Pytest test suite (19 test cases)
├── database/                  # SQL DDL & Seed Scripts
│   ├── schema.sql             # Full DDL schema for PostgreSQL
│   └── seed.sql               # Idempotent baseline seed data
├── frontend/                  # React 18 Frontend
│   ├── package.json           # Frontend dependencies and npm scripts
│   ├── vite.config.js         # Vite configuration with /api proxy
│   ├── tailwind.config.js     # Tailwind design tokens
│   ├── src/
│   │   ├── main.jsx           # React DOM root entry
│   │   ├── App.jsx            # React Router root
│   │   ├── index.css          # Design system, glassmorphism, theme styling
│   │   ├── layouts/           # DashboardLayout with sidebar and topbar
│   │   ├── pages/             # 9 distinct application views
│   │   ├── components/        # Reusable badges, modals, controls
│   │   ├── context/           # ThemeContext (dark/light) & SocRefreshContext
│   │   └── services/          # Axios API communication methods
├── simulator/                 # Standalone Attack Simulator
│   └── generate_events.py     # Multi-scenario synthetic attack generator
└── docs/                      # Architectural and specification documents
```

### Important Phase 1 Files & Explanations
- [backend/app/main.py](file:///d:/Major%20Project/backend/app/main.py): Application entry point. Instantiates `FastAPI`, binds the `lifespan` handler that executes non-destructive table initialization (`init_tables()`), configures CORS middleware via `settings.cors_origin_list`, mounts all 9 routers, and provides the root `/` welcome endpoint.
- [backend/app/config.py](file:///d:/Major%20Project/backend/app/config.py): Configuration hub powered by `pydantic-settings`. Reads environment variables, sets defaults (`HOST=0.0.0.0`, `PORT=8000`), and computes the `sqlalchemy_database_url` property that automatically prefixes PostgreSQL URLs with `postgresql+psycopg://`.
- [backend/app/database/connection.py](file:///d:/Major%20Project/backend/app/database/connection.py): Creates the SQLAlchemy `engine` with connection pooling (`pool_size=10`, `max_overflow=20`). Defines `get_db()` dependency for route handlers and `check_database_connection()` which performs an active `SELECT 1` query to benchmark roundtrip latency in milliseconds.
- [backend/app/routers/health.py](file:///d:/Major%20Project/backend/app/routers/health.py): Implements `GET /api/health`. Queries the database connection and returns a diagnostic JSON payload indicating service status, dialect, latency, and timestamp.
- [frontend/vite.config.js](file:///d:/Major%20Project/frontend/vite.config.js): Configures Vite development server to run on port 5173 and establishes the reverse proxy rule forwarding `/api` to `http://127.0.0.1:8000`.

---

## 5. Phase 2 Implementation

### Actual Database Implementation
Phase 2 implemented the relational database schema, SQLAlchemy 2.0 ORM models, Pydantic schemas, and CRUD endpoints supporting pagination and filtering.

### Database Tables Present in Codebase

| Table Name | Purpose | Primary Key | Foreign Keys | Relationships |
|---|---|---|---|---|
| `users` | Stores SOC analyst accounts and system roles | `id` (SERIAL) | None | Referenced by `audit_logs.user_id` |
| `events` | Normalized canonical log telemetry | `id` (SERIAL) | None | Has many `alerts` (`Alert.event_id`) |
| `alerts` | Threat detection alerts generated by rules | `id` (SERIAL) | `event_id` -> `events.id` (ON DELETE SET NULL) | Belongs to `Event`, has many `IncidentAlert`, has many `AIAnalysis` |
| `incidents` | Correlated security incident cases | `id` (SERIAL) | None | Has many `IncidentAlert`, has many `AIAnalysis` |
| `incident_alerts` | Many-to-many junction between incidents & alerts | (`incident_id`, `alert_id`) | `incident_id` -> `incidents.id` (CASCADE), `alert_id` -> `alerts.id` (CASCADE) | Connects `Incident` and `Alert` models |
| `mitre_techniques`| Reference catalog of MITRE ATT&CK techniques | `id` (SERIAL) | None (Unique: `technique_id`) | Standalone reference catalog |
| `threat_intelligence`| Cache for external reputation lookups | `id` (SERIAL) | None (Unique: `indicator`, `source`) | Standalone intelligence cache |
| `ai_analyses` | AI reasoning outputs and evidence storage | `id` (SERIAL) | `alert_id` -> `alerts.id` (CASCADE), `incident_id` -> `incidents.id` (CASCADE) | Linked optionally to an Alert or Incident |
| `audit_logs` | Audit trail of analyst decisions and actions | `id` (SERIAL) | `user_id` -> `users.id` (SET NULL) | Linked to `User` |

### Database Table Columns Detail

#### 1. `events` Table
- `id`: Integer, Primary Key, Auto-increment.
- `timestamp`: TIMESTAMPTZ, Indexed, default `now()`. Time the event occurred.
- `source`: String(64), Not Null. Telemetry origin (e.g. `auth_log`, `apache_access`, `simulator`).
- `host`: String(128), Nullable. Hostname or machine name.
- `source_ip`: String(64), Indexed, Nullable. Originating IPv4/IPv6 address.
- `destination_ip`: String(64), Indexed, Nullable. Target IPv4/IPv6 address.
- `source_port`: Integer, Nullable. Source port number (1–65535).
- `destination_port`: Integer, Nullable. Destination port number (1–65535).
- `protocol`: String(32), Nullable. Transport/application protocol (TCP, UDP, HTTP).
- `event_type`: String(64), Indexed, Not Null. Categorical label (`failed_login`, `connection`, `http_request`, `command_exec`).
- `raw_data`: JSONB / JSON, Nullable. Unmodified original payload preserving full forensic fidelity.
- `created_at`: TIMESTAMPTZ, default `now()`. Record insertion timestamp.

#### 2. `alerts` Table
- `id`: Integer, Primary Key, Auto-increment.
- `event_id`: Integer, Foreign Key (`events.id`, ON DELETE SET NULL), Nullable. Triggering event.
- `timestamp`: TIMESTAMPTZ, Indexed, default `now()`. Time alert fired.
- `title`: String(255), Not Null. Human-readable alert name.
- `description`: Text, Nullable. Detailed technical explanation.
- `source_ip`: String(64), Indexed, Nullable. Offending IP address.
- `destination_ip`: String(64), Nullable. Target IP address.
- `severity`: String(32), Indexed, Not Null. (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `status`: String(32), Indexed, Not Null. (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- `detection_rule`: String(128), Not Null. Unique rule identifier.
- `created_at`: TIMESTAMPTZ, default `now()`.

#### 3. `incidents` Table
- `id`: Integer, Primary Key, Auto-increment.
- `title`: String(255), Not Null. Incident summary headline.
- `description`: Text, Nullable. Narrative of correlated attack activity.
- `severity`: String(32), Indexed, Not Null. (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `status`: String(32), Indexed, Not Null. (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`).
- `summary`: Text, Nullable. Correlated rule names and attack footprint.
- `confidence`: Float, Nullable. Calibrated correlation score (0.00 to 1.00).
- `created_at`: TIMESTAMPTZ, default `now()`.
- `updated_at`: TIMESTAMPTZ, default `now()`, auto-updated on change.

#### 4. `incident_alerts` Table (Junction)
- `incident_id`: Integer, Primary Key component, Foreign Key -> `incidents.id` (CASCADE).
- `alert_id`: Integer, Primary Key component, Foreign Key -> `alerts.id` (CASCADE).

#### 5. `mitre_techniques` Table
- `id`: Integer, Primary Key, Auto-increment.
- `technique_id`: String(32), Unique, Indexed, Not Null (e.g. `T1110`).
- `name`: String(255), Not Null (e.g. `Brute Force`).
- `tactic`: String(128), Not Null (e.g. `Credential Access`).
- `description`: Text, Nullable. Technical definition.

### Seed & Baseline Reference Data
The `seed_baseline_data()` function in [backend/app/database/init_db.py](file:///d:/Major%20Project/backend/app/database/init_db.py) seeds:
1. **MITRE ATT&CK Techniques:** T1110 (Brute Force), T1046 (Network Service Scanning), T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol), T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts).
2. **Default Analyst User:** Username `analyst_soc`, email `analyst@soc-copilot.internal`, role `analyst`.
3. **Demonstration Telemetry:** Initial baseline `failed_login` Event, `Possible SSH Brute Force` Alert, and associated `Incident` linked via `IncidentAlert`.

### Implemented REST API Endpoints

| Method | URL | Purpose | Request Parameters / Body | Response Model | Database Tables Involved |
|---|---|---|---|---|---|
| `GET` | `/api/health` | Service & DB connectivity check | None | Object with status, version, dialect, latency | None (executes `SELECT 1`) |
| `GET` | `/api/dashboard/stats` | Aggregated dashboard metrics | None | Metrics object, severity distribution, top IPs, timeline | `events`, `alerts`, `incidents` |
| `GET` | `/api/events` | List events with pagination & filtering | `page`, `limit`, `source_ip`, `event_type`, `source` | `PaginatedEventsResponse` | `events` |
| `GET` | `/api/events/{event_id}` | Retrieve event by ID | Path: `event_id` | `EventResponse` | `events` |
| `POST` | `/api/events` | Create event & trigger detection | JSON Body: `EventCreate` | `EventResponse` (201 Created) | `events`, `alerts`, `incidents`, `incident_alerts` |
| `GET` | `/api/alerts` | List alerts with pagination & filtering | `page`, `limit`, `severity`, `status`, `source_ip` | `PaginatedAlertsResponse` | `alerts` |
| `GET` | `/api/alerts/{alert_id}` | Retrieve alert by ID | Path: `alert_id` | `AlertResponse` | `alerts` |
| `POST` | `/api/alerts` | Manually create alert | JSON Body: `AlertCreate` | `AlertResponse` (201 Created) | `alerts` |
| `PATCH` | `/api/alerts/{alert_id}` | Update alert status/severity | Path: `alert_id`, Body: `AlertUpdate` | `AlertResponse` | `alerts` |
| `DELETE` | `/api/alerts/{alert_id}` | Delete alert record | Path: `alert_id` | 204 No Content | `alerts`, `incident_alerts` |
| `GET` | `/api/incidents` | List incidents with alert IDs | `page`, `limit`, `status`, `severity` | `PaginatedIncidentsResponse` | `incidents`, `incident_alerts` |
| `GET` | `/api/incidents/{incident_id}` | Retrieve incident by ID | Path: `incident_id` | `IncidentResponse` | `incidents`, `incident_alerts` |
| `POST` | `/api/incidents` | Create incident & link alerts | JSON Body: `IncidentCreate` | `IncidentResponse` (201 Created) | `incidents`, `incident_alerts`, `alerts` |
| `PATCH` | `/api/incidents/{incident_id}` | Update incident fields/alerts | Path: `incident_id`, Body: `IncidentUpdate`| `IncidentResponse` | `incidents`, `incident_alerts` |
| `GET` | `/api/mitre/techniques` | List all MITRE techniques | None | List of `MitreTechniqueResponse` | `mitre_techniques` |
| `GET` | `/api/mitre/techniques/{id}` | Get technique details by ID | Path: `technique_id` (e.g. `T1110`)| `MitreTechniqueResponse` | `mitre_techniques` |
| `POST` | `/api/logs/upload` | Ingest log file, parse, detect | Multipart file (`.log`, `.txt`, `.json`, `.csv`)| Upload summary object | `events`, `alerts`, `incidents`, `incident_alerts` |
| `POST` | `/api/simulator/brute-force` | Execute SSH brute force simulation | None | Simulation result object | `events`, `alerts`, `incidents`, `incident_alerts` |
| `POST` | `/api/simulator/port-scan` | Execute port scan simulation | None | Simulation result object | `events`, `alerts`, `incidents`, `incident_alerts` |
| `POST` | `/api/simulator/web-attack` | Execute web attack simulation | None | Simulation result object | `events`, `alerts`, `incidents`, `incident_alerts` |
| `POST` | `/api/simulator/run` | Execute specified attack scenario | Query: `scenario` (`brute_force`, `port_scan`, `web_attack`)| Simulation result object | `events`, `alerts`, `incidents`, `incident_alerts` |
| `DELETE` | `/api/system/clear-data` | Clear all operational data | None | Status message | Deletes from `ai_analyses`, `incident_alerts`, `alerts`, `incidents`, `events`, `threat_intelligence`, `audit_logs` |

---

## 6. Phase 3 Implementation

### Actual Frontend Implementation
Phase 3 delivered the analyst-facing Single Page Application built with React 18, React Router v6, Tailwind CSS, Recharts, and Lucide React.

### Current Pages & Routes

#### 1. Overview / Dashboard Page (`/`)
- **File:** [frontend/src/pages/DashboardPage.jsx](file:///d:/Major%20Project/frontend/src/pages/DashboardPage.jsx)
- **Purpose:** Primary executive overview summarizing telemetry and active threat volume.
- **Components:**
  - `SimulatorControls`: Quick-action buttons to launch attack simulations.
  - Metric summary cards (Total Events, Total Alerts, Critical Severity, Open Incidents).
  - Recharts PieChart (donut style) showing Alert Severity Distribution.
  - Recharts BarChart (horizontal) displaying Top Offending Source IPs.
  - Recharts AreaChart visualizing chronological telemetry frequency.
  - Recent Alerts Triage Table displaying the latest 6 alerts with direct "Investigate" navigation links.
- **Endpoints Used:** `GET /api/dashboard/stats`, `GET /api/alerts?page=1&limit=6`.

#### 2. Log Upload Page (`/upload`)
- **File:** [frontend/src/pages/LogUploadPage.jsx](file:///d:/Major%20Project/frontend/src/pages/LogUploadPage.jsx)
- **Purpose:** Ingestion workspace allowing drag-and-drop or file selection for security logs.
- **Components:**
  - Drag-and-drop file target with format validation badge indicators.
  - Processing progress spinner.
  - Processing summary card showing Total Records, Parsed & Stored, Failed Records, Alerts Generated, and Incidents Correlated.
  - One-click demo log presets for Auth Log, Web Server Access Log, and JSON Event Stream.
- **Endpoints Used:** `POST /api/logs/upload`.

#### 3. Alerts Management Page (`/alerts`)
- **File:** [frontend/src/pages/AlertsPage.jsx](file:///d:/Major%20Project/frontend/src/pages/AlertsPage.jsx)
- **Purpose:** Central triage table for all generated security alerts.
- **Components:**
  - Source IP search filter with instant query submission.
  - Severity dropdown filter (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Status dropdown filter (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
  - Interactive table supporting live status change via inline dropdown (`PATCH /api/alerts/{id}`).
  - Pagination controls (Previous / Next / Page Indicator).
- **Endpoints Used:** `GET /api/alerts`, `PATCH /api/alerts/{id}`.

#### 4. Alert Details Page (`/alerts/:id`)
- **File:** [frontend/src/pages/AlertDetailsPage.jsx](file:///d:/Major%20Project/frontend/src/pages/AlertDetailsPage.jsx)
- **Purpose:** Deep-dive forensic inspection of an individual alert.
- **Components:**
  - Top action bar with status updater and "Promote to Incident" trigger (`createIncident`).
  - Metadata grid: Detection Rule ID, Attacker Source IP, Target Destination IP, Triggering Event ID.
  - Full detection rule description.
  - Triggering Telemetry Event JSON payload viewer (`event.raw_data`).
  - Phase 5 Google Gemini AI placeholder card displaying planned automated reasoning capabilities.
- **Endpoints Used:** `GET /api/alerts/{id}`, `GET /api/events/{event_id}`, `PATCH /api/alerts/{id}`, `POST /api/incidents`.

#### 5. Incidents Management Page (`/incidents`)
- **File:** [frontend/src/pages/IncidentsPage.jsx](file:///d:/Major%20Project/frontend/src/pages/IncidentsPage.jsx)
- **Purpose:** Oversight of correlated multi-alert security incidents.
- **Components:**
  - Filter bar (Severity and Status).
  - Modal form to manually initialize a new security incident.
  - Paginated table showing Incident ID, Title, Severity Badge, Status Badge, Correlated Alert Count, and Confidence Score.
- **Endpoints Used:** `GET /api/incidents`, `POST /api/incidents`.

#### 6. Incident Details Page (`/incidents/:id`)
- **File:** [frontend/src/pages/IncidentDetailsPage.jsx](file:///d:/Major%20Project/frontend/src/pages/IncidentDetailsPage.jsx)
- **Purpose:** Full investigation workspace for a correlated incident.
- **Components:**
  - Status lifecycle updater (`OPEN` -> `INVESTIGATING` -> `CONTAINED` -> `RESOLVED`).
  - Four key indicators: Correlated Alerts count, Threat Indicators (Source IPs), Target Assets (Destination IPs), and Correlation Confidence percentage.
  - Chronological attack progression timeline with visual step nodes.
  - Phase 5 Gemini AI incident narrative briefing card (placeholder).
- **Endpoints Used:** `GET /api/incidents/{id}`, `GET /api/alerts/{id}`, `PATCH /api/incidents/{id}`.

#### 7. Event Stream Page (`/events`)
- **File:** [frontend/src/pages/EventsPage.jsx](file:///d:/Major%20Project/frontend/src/pages/EventsPage.jsx)
- **Purpose:** Low-level security telemetry stream viewer.
- **Components:**
  - Filter controls for Source IP, Event Type (`failed_login`, `connection`, `http_request`, `command_exec`), and Source (`auth_log`, `simulator`, `apache_access`).
  - Paginated telemetry table showing timestamp, source, event type, host, IPs, protocol, and port.
  - Modal JSON viewer rendering the raw formatted payload of any selected event.
- **Endpoints Used:** `GET /api/events`.

#### 8. MITRE ATT&CK Matrix Page (`/mitre`)
- **File:** [frontend/src/pages/MitrePage.jsx](file:///d:/Major%20Project/frontend/src/pages/MitrePage.jsx)
- **Purpose:** Knowledge base mapping adversarial tactics and techniques implemented in the detection engine.
- **Components:**
  - Search bar for technique ID or keyword.
  - Tactic filter dropdown (`Credential Access`, `Discovery`, `Execution`, `Command and Control`, `Initial Access`, `Defense Evasion`).
  - Card grid displaying Technique ID, Tactic badge, Name, Description, and external link to the official MITRE ATT&CK website.
- **Endpoints Used:** `GET /api/mitre/techniques`.

#### 9. System Health Diagnostics Page (`/system`)
- **File:** [frontend/src/pages/SystemHealthPage.jsx](file:///d:/Major%20Project/frontend/src/pages/SystemHealthPage.jsx)
- **Purpose:** Infrastructure status and connectivity validation.
- **Components:**
  - FastAPI Core status card (Version, Environment).
  - Supabase PostgreSQL status card (Connection state, roundtrip latency in ms).
  - SOC Architecture phase tracker card.
  - Interactive terminal box displaying the raw response from `GET /api/health`.
  - Manual "Re-check" button.
- **Endpoints Used:** `GET /api/health`.

### Shared Layout & Console Features
- **Sidebar:** Desktop sidebar and responsive mobile slide-out drawer navigation displaying brand, navigation links, active route highlight, and persistent Supabase connection status.
- **Topbar:** Breadcrumb path indicator, theme toggle button, "Clear All Data" modal button, connection indicator, and manual probe button.
- **Dark / Light Mode:** Managed via [frontend/src/context/ThemeContext.jsx](file:///d:/Major%20Project/frontend/src/context/ThemeContext.jsx). Persists selection to `localStorage` (`soc-theme`). Adapts Recharts tooltip and axis colors dynamically.
- **Clear Data Functionality:** Triggered via [frontend/src/components/ClearDataModal.jsx](file:///d:/Major%20Project/frontend/src/components/ClearDataModal.jsx). Executes `DELETE /api/system/clear-data` and broadcasts a window-level custom event via [frontend/src/context/SocRefreshContext.jsx](file:///d:/Major%20Project/frontend/src/context/SocRefreshContext.jsx) causing all active pages to re-fetch clean data without requiring a browser refresh.

---

## 7. Phase 4 Implementation

### Detailed End-to-End Ingestion Workflow
Phase 4 implements the complete security pipeline converting unstructured files or synthetic attacks into database-backed alerts and correlated incidents:

```
[1. User Action]
Analyst drops file (e.g. auth.log) on /upload OR triggers simulator on Dashboard
       │
       ▼
[2. Frontend Request]
Axios sends POST multipart/form-data to /api/logs/upload (timeout: 180s)
       │
       ▼
[3. File Validation & Detection]
- Extension checked against ALLOWED_EXTENSIONS (.log, .txt, .json, .csv)
- file_detector.detect_file_type() inspects filename and initial lines for signatures
       │
       ▼
[4. Parser Dispatch]
Appropriate parser dispatched from parser_registry.PARSERS:
  - json_parser (JSON array / NDJSON)
  - csv_parser (DictReader with semicolon/comma auto-detection)
  - apache_parser / nginx_parser (Combined access log regex)
  - text_parser (Syslog headers, SSH failure patterns, sudo execution)
       │
       ▼
[5. Field Normalization]
normalizer.normalize_event_dict() standardizes records:
  - Timestamps parsed via 6 datetime formats + ISO-8601 to timezone.utc
  - IPs extracted and trimmed
  - Ports converted safely to integer (1–65535)
  - Raw payload stored losslessly in raw_data field
       │
       ▼
[6. High-Performance Database Persistence]
bulk_insert_events() attempts PostgreSQL COPY protocol via raw DBAPI connection:
  - Falls back to chunked multi-values SQLAlchemy insert (chunks of 500)
  - Canonical Event records committed to Supabase PostgreSQL
       │
       ▼
[7. Deterministic Detection Execution]
detection_engine.run_detection(event_objects, db):
  - Ingested events evaluated against 5 rules in rules.py
  - Query existing alert event_ids to prevent duplicate alerts
  - Generates Alert records and commits to alerts table
       │
       ▼
[8. Automated Incident Correlation]
correlator.correlate_alerts(created_alerts, db):
  - Groups new alerts by source_ip
  - Checks for OPEN incident from that IP within 1 hour
  - Attaches alerts to existing incident OR creates new Incident
  - Updates incident summary with unique rule titles and attack progression
       │
       ▼
[9. Ingestion Response]
Returns JSON summary to frontend: total_records, parsed_records, failed_records,
alerts_created, incidents_created. Dashboard updates immediately.
```

---

## 8. Supported Log Formats

| Format | Parser Function | Expected Input Structure | Fields Extracted | Normalized Event Mapping |
|---|---|---|---|---|
| **JSON Array** | `parse_json_content` in [json_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/json_parser.py) | Array of JSON objects `[{...}, {...}]` | `timestamp`, `source_ip`, `destination_ip`, `destination_port`, `event_type`, `raw_data` | Direct key extraction via `normalize_event_dict` |
| **NDJSON (Line-Delimited JSON)** | `parse_json_content` in [json_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/json_parser.py) | One JSON object per line | Individual line dictionary keys | Iterative line parsing into canonical event format |
| **CSV / Delimited Log** | `parse_csv_content` in [csv_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/csv_parser.py) | CSV with header row (comma `,` or semicolon `;`) | Header-mapped values: `source_ip`, `src_ip`, `ip`, `port`, `event_type` | Headers matched against flexible synonyms in normalizer |
| **Linux Auth Log / Plaintext Syslog** | `parse_text_content` / `parse_text_line` in [text_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/text_parser.py) | Plaintext syslog lines, e.g.: `Sep 17 12:00:00 srv sshd[12]: Failed password for user from 192.168.1.1 port 54321 ssh2` | Syslog timestamp, hostname, process, failed/accepted username, remote IP, source port | Extracted regex groups mapped to `failed_login`, `successful_login`, `command_exec` |
| **Apache / Nginx Access Log** | `parse_apache_content` in [apache_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/apache_parser.py) & [nginx_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/nginx_parser.py) | NCSA Combined Log Format: `127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /path HTTP/1.1" 200 2326 "ref" "agent"` | Remote client IP, HTTP method, requested URL path, status code, user agent | `event_type="http_request"`, `source_ip=ip`, `destination_port=80/443`, `raw_data` with payload |

*Note: Proprietary binary formats (.pcap, .evtx) or live streaming sockets (Suricata UNIX socket, Zeek broker) are NOT currently implemented.*

---

## 9. Normalized Event Format

### Canonical Event Model
The `Event` model in [backend/app/models/event.py](file:///d:/Major%20Project/backend/app/models/event.py) defines the schema:

```python
class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    host: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
```

### Explanation of Every Field
- `id`: Unique database primary key for forensic referencing and alert linkage.
- `timestamp`: UTC datetime representing when the activity occurred on the originating asset.
- `source`: Collector identifier (`auth_log`, `apache_access`, `nginx_access`, `simulator`).
- `host`: Hostname or server identifier where the log was recorded.
- `source_ip`: IP address of the initiating entity (potential attacker or client).
- `destination_ip`: IP address of the target asset or receiving server.
- `source_port`: Ephemeral port used by the initiating host (1–65535).
- `destination_port`: Service port on the destination asset (e.g. 22 for SSH, 80 for HTTP).
- `protocol`: Transport or network protocol (`TCP`, `UDP`, `HTTP`).
- `event_type`: Standardized activity classification (`failed_login`, `connection`, `http_request`, `command_exec`).
- `raw_data`: Full unstructured JSON dictionary containing all original log fields.
- `created_at`: Ingestion timestamp recording when the database accepted the event.

### Why Log Normalization is Necessary in a SOC
1. **Schema Heterogeneity:** A Linux server logs an authentication failure as `Failed password for root from 1.2.3.4`, whereas an Apache server logs web probes as `1.2.3.4 - - "GET /admin" 401`. Normalization allows detection rules to query standard fields (`source_ip`, `event_type`) regardless of source.
2. **Deterministic Correlation:** Alert rules cannot reliably cross-correlate events across different systems without uniform timestamp timezones (UTC) and standardized IP fields.
3. **Forensic Integrity:** Normalizing into fixed relational columns enables high-speed B-Tree indexed SQL queries while preserving the unmodified original payload in `raw_data` for audit and compliance.

---

## 10. Detection Engine

### Detection Classification
The current detection engine is strictly **deterministic**: a combination of **threshold-based state analysis** and **regex pattern matching**.  
**It does NOT use AI.** AI reasoning is planned for Phase 5.

### Implemented Detection Rules

#### Rule 1: SSH / Authentication Brute Force Detection
- **Rule ID:** `RULE_01_BRUTE_FORCE`
- **Rule Function:** `check_brute_force()` in [rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py)
- **Trigger Condition:** More than 10 failed login attempts (`event_type == 'failed_login'` or raw text matches `failed password`, `authentication failure`) originating from the same `source_ip` within the batch or a 10-minute database window.
- **Severity:** `HIGH`
- **MITRE Technique:** `T1110` (Brute Force)
- **Alert Title:** "Possible Brute Force Attack"
- **Example Input:** 12 rapid SSH connection failures from IP `192.168.1.185` targeting user accounts `admin`, `root`, `ubuntu`.

#### Rule 2: Network Port Scan Detection
- **Rule ID:** `RULE_02_PORT_SCAN`
- **Rule Function:** `check_port_scan()` in [rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py)
- **Trigger Condition:** A single `source_ip` initiates connections probing 8 or more distinct destination ports within the batch or a 5-minute database window.
- **Severity:** `HIGH`
- **MITRE Technique:** `T1046` (Network Service Scanning)
- **Alert Title:** "Possible Network Service Scanning"
- **Example Input:** Single IP probing destination ports 21, 22, 23, 25, 53, 80, 110, 443, 3306 sequentially.

#### Rule 3: Suspicious Command Execution Detection
- **Rule ID:** `RULE_03_SUSPICIOUS_COMMAND`
- **Rule Function:** `check_suspicious_commands()` in [rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py)
- **Trigger Condition:** Event payload matches regex signatures for administrative reconnaissance or unauthorized scripting: `powershell(\.exe)?`, `cmd\.exe`, `bash\s+-c`, `whoami`, `net\s+(user|group)`, `(curl|wget)\s+.*\|\s*(sh|bash)`, `nc\s+(-e|--exec)`, `/etc/(passwd|shadow)`.
- **Severity:** `HIGH`
- **MITRE Technique:** `T1059` (Command and Scripting Interpreter)
- **Alert Title:** "Suspicious Command Execution Detected"
- **Example Input:** Command payload `powershell.exe -enc dGVzdA==` or `whoami`.

#### Rule 4: Web Application Exploit Detection
- **Rule ID:** `RULE_04_WEB_ATTACK`
- **Rule Function:** `check_web_attacks()` in [rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py)
- **Trigger Condition:** Event payload or HTTP request URI matches signatures for SQL injection or Path Traversal: `UNION\s+SELECT`, `'\s*OR\s*('1'='1'|1=1)`, `\.\./|\.\.\\|%2e%2e%2f`, `<script\b[^>]*>.*?</script>`, `SLEEP\s*\(\s*\d+\s*\)`.
- **Severity:** `HIGH`
- **MITRE Technique:** `T1190` (Exploit Public-Facing Application)
- **Alert Title:** "Possible Web Attack"
- **Example Input:** `GET /products?cat=1' UNION SELECT username, password_hash FROM users--`.

#### Rule 5: Privilege Escalation Detection
- **Rule ID:** `RULE_05_PRIVILEGE_ESCALATION`
- **Rule Function:** `check_privilege_escalation()` in [rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py)
- **Trigger Condition:** Event payload matches privileged execution signatures: `sudo\s+(su|bash|sh|chmod|visudo)`, `su\s+-\s*root`, `/etc/sudoers`, `usermod\s+-aG\s+(sudo|wheel|admin)`, `chown\s+root`.
- **Severity:** `HIGH`
- **MITRE Technique:** `T1548` (Abuse Elevation Control Mechanism)
- **Alert Title:** "Possible Privilege Escalation"
- **Example Input:** `sudo visudo -f /etc/sudoers` or `usermod -aG sudo attacker`.

### Detection & Deduplication Execution Logic
1. `run_detection()` receives a batch of `Event` objects.
2. Evaluates all 5 rule functions and aggregates candidates.
3. Queries existing alerts by `event_id` to ensure idempotent non-duplication.
4. Maintains an in-memory `seen_in_batch` set keyed by `(source_ip, detection_rule)` to prevent storming alerts from high-volume logs.
5. Commits valid `Alert` records to the database and passes them directly to the incident correlation engine.

---

## 11. Incident Correlation

### Alert-to-Incident Correlation Pipeline
The incident correlation engine is implemented in [backend/app/detection/correlator.py](file:///d:/Major%20Project/backend/app/detection/correlator.py). It aggregates individual threat alerts into high-level security incidents based on **shared attacker infrastructure** and **temporal proximity**.

```
[New Alerts Generated]
          │
          ▼
Group alerts by source_ip
          │
          ▼
For each unique source_ip:
  Query database for existing OPEN Incident created within past 1 hour
  associated with alerts from this source_ip
          │
          ├─────────────────────────────────────────┐
          ▼                                         ▼
[Existing Open Incident Found]            [No Open Incident Exists]
  - Link new Alert IDs via                 - Create new Incident record
    IncidentAlert junction records         - Set Title:
  - Update Incident updated_at timestamp     Single Rule: "Incident: Correlated Attack Activity from {ip}"
  - Update Incident summary narrative        Multi Rule:  "Incident: Multi-Stage Attack ({Rule1} -> {Rule2}) from {ip}"
    with consolidated rule titles          - Calculate Severity (highest among alerts)
  - Commit transaction                     - Calculate Confidence: min(0.95, 0.80 + (unique_rules * 0.05))
                                           - Link all alerts via IncidentAlert junction
                                           - Commit transaction
```

### Correlation Criteria
1. **Source IP Match:** Alerts must originate from the exact same `source_ip`.
2. **Temporal Proximity Window:** A sliding window of **1 hour** (`created_at >= now() - 1 hour`).
3. **Incident Status:** The existing incident must be in `OPEN` status. Incidents marked `CONTAINED` or `RESOLVED` are not re-opened; a new incident is initialized instead.
4. **Kill-Chain Multi-Stage Titling:** When an incident links multiple different detection rules (e.g. `RULE_02_PORT_SCAN` followed by `RULE_01_BRUTE_FORCE`), the correlation engine updates the title to reflect a multi-stage attack campaign.

---

## 12. Simulator

### Purpose and Location
The simulator is implemented in two locations:
1. **Backend Service & API Router:** [backend/app/routers/simulator.py](file:///d:/Major%20Project/backend/app/routers/simulator.py)
2. **Standalone Command-Line Script:** [simulator/generate_events.py](file:///d:/Major%20Project/simulator/generate_events.py)
3. **Frontend Dashboard Widget:** [frontend/src/components/SimulatorControls.jsx](file:///d:/Major%20Project/frontend/src/components/SimulatorControls.jsx)

### Available Attack Scenarios

#### 1. Brute Force Scenario (`brute_force`)
- **Action:** Generates 12 rapid failed authentication events against target `10.0.0.5:22` from attacker IP `192.168.1.185`.
- **Target Users:** `admin`, `root`, `ubuntu`, `guest`, `oracle`, `user`, `test`, `deploy`, `service`, `backup`, `operator`, `sysadmin`.
- **Detection Triggered:** `RULE_01_BRUTE_FORCE` -> Alert "Possible Brute Force Attack" -> Incident.

#### 2. Network Port Scan Scenario (`port_scan`)
- **Action:** Generates 15 rapid TCP connection attempts across distinct ports: 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080.
- **Detection Triggered:** `RULE_02_PORT_SCAN` -> Alert "Possible Network Service Scanning" -> Incident.

#### 3. Web Application Attack Scenario (`web_attack`)
- **Action:** Generates 4 HTTP exploit probes:
  - SQL Injection: `GET /api/products?cat=1' UNION SELECT username, password_hash FROM users--`
  - Auth Bypass: `POST /login.php` (with `' OR 1=1--`)
  - Path Traversal: `GET /download.php?file=../../../../etc/passwd`
  - SQL Probe: `GET /search?q=' OR 1=1--`
- **Detection Triggered:** `RULE_04_WEB_ATTACK` -> Alert "Possible Web Attack" -> Incident.

### How to Run the Simulator

#### Via Frontend UI:
1. Navigate to the SOC Dashboard at `http://localhost:5173`.
2. Click **"Simulate Brute Force"**, **"Simulate Port Scan"**, or **"Simulate Web Attack"** in the top widget.
3. View the confirmation toast and watch the counters increment in real time.

#### Via CLI Script:
```powershell
# Run individual scenarios
python simulator/generate_events.py --scenario brute_force
python simulator/generate_events.py --scenario port_scan
python simulator/generate_events.py --scenario web_attack

# Run all scenarios sequentially
python simulator/generate_events.py --scenario all
```

---

## 13. Supabase Database

### Connection Architecture
Communication between the application layers and Supabase PostgreSQL operates strictly through the backend:

```
[React Frontend]
       │
       │ HTTP JSON (Proxied via Vite /api)
       ▼
[FastAPI Backend]
       │
       │ SQLAlchemy 2.0 Engine (Connection Pool: 10 + 20 overflow)
       ▼
[psycopg3 Driver] (postgresql+psycopg://)
       │
       │ TLS / SSL Encrypted TCP Connection (Port 5432 / 6543)
       ▼
[Supabase PostgreSQL Cloud Database]
```

### Configuration & Security
- `DATABASE_URL` is configured in the root `.env` file (loaded via `pydantic-settings` in [backend/app/config.py](file:///d:/Major%20Project/backend/app/config.py)).
- **Credential Redaction Notice:** The URL format follows:
  `DATABASE_URL=postgresql://postgres:[REDACTED_PASSWORD]@[REDACTED_HOST].supabase.co:5432/postgres`
- The `sqlalchemy_database_url` property ensures the driver prefix is normalized to `postgresql+psycopg://`.
- **Direct Database Access Boundary:** The frontend never connects directly to Supabase. No database credentials, service role keys, or connection strings exist on the client side.

---

## 14. Important Files

### Current Project File Tree
```
Major Project/
├── .env
├── .env.example
├── docker-compose.yml
├── README.md
├── backend/
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database/
│   │   │   ├── base.py
│   │   │   ├── connection.py
│   │   │   └── init_db.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── event.py
│   │   │   ├── alert.py
│   │   │   ├── incident.py
│   │   │   ├── mitre.py
│   │   │   ├── user.py
│   │   │   ├── ai_analysis.py
│   │   │   ├── threat_intel.py
│   │   │   └── audit_log.py
│   │   ├── schemas/
│   │   │   ├── event.py
│   │   │   ├── alert.py
│   │   │   ├── incident.py
│   │   │   └── mitre.py
│   │   ├── routers/
│   │   │   ├── health.py
│   │   │   ├── dashboard.py
│   │   │   ├── events.py
│   │   │   ├── alerts.py
│   │   │   ├── incidents.py
│   │   │   ├── mitre.py
│   │   │   ├── logs.py
│   │   │   ├── simulator.py
│   │   │   └── system.py
│   │   ├── ingestion/
│   │   │   ├── file_detector.py
│   │   │   ├── normalizer.py
│   │   │   ├── parser_registry.py
│   │   │   └── parsers/
│   │   │       ├── json_parser.py
│   │   │       ├── csv_parser.py
│   │   │       ├── apache_parser.py
│   │   │       ├── nginx_parser.py
│   │   │       └── text_parser.py
│   │   └── detection/
│   │       ├── detection_engine.py
│   │       ├── rules.py
│   │       └── correlator.py
│   └── tests/
│       ├── test_crud.py
│       ├── test_health.py
│       ├── test_phase4.py
│       └── test_system.py
├── database/
│   ├── schema.sql
│   └── seed.sql
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       ├── index.css
│       ├── layouts/DashboardLayout.jsx
│       ├── services/api.js
│       ├── context/
│       │   ├── ThemeContext.jsx
│       │   └── SocRefreshContext.jsx
│       ├── components/
│       │   ├── ClearDataModal.jsx
│       │   ├── SimulatorControls.jsx
│       │   ├── SeverityBadge.jsx
│       │   ├── StatusBadge.jsx
│       │   ├── LoadingSpinner.jsx
│       │   ├── ErrorMessage.jsx
│       │   └── EmptyState.jsx
│       └── pages/
│           ├── DashboardPage.jsx
│           ├── LogUploadPage.jsx
│           ├── AlertsPage.jsx
│           ├── AlertDetailsPage.jsx
│           ├── IncidentsPage.jsx
│           ├── IncidentDetailsPage.jsx
│           ├── EventsPage.jsx
│           ├── MitrePage.jsx
│           └── SystemHealthPage.jsx
└── simulator/
    └── generate_events.py
```

### Top 10 Most Important Files for Viva Preparation
1. [backend/app/main.py](file:///d:/Major%20Project/backend/app/main.py): Initializes the FastAPI app, manages database lifecycle on startup, configures CORS, and registers all API routes.
2. [backend/app/database/connection.py](file:///d:/Major%20Project/backend/app/database/connection.py): Implements connection pooling, session yielding (`get_db`), and live latency verification.
3. [backend/app/models/event.py](file:///d:/Major%20Project/backend/app/models/event.py): Defines the canonical relational schema for all ingested security events.
4. [backend/app/ingestion/normalizer.py](file:///d:/Major%20Project/backend/app/ingestion/normalizer.py): Normalizes inconsistent log formats, timestamps, and IP addresses into consistent event fields.
5. [backend/app/ingestion/parsers/text_parser.py](file:///d:/Major%20Project/backend/app/ingestion/parsers/text_parser.py): Uses regular expressions to extract auth failures, accepted logins, sudo commands, and syslog headers from plaintext logs.
6. [backend/app/detection/rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py): Contains the core detection logic for all 5 implemented MITRE ATT&CK rules.
7. [backend/app/detection/correlator.py](file:///d:/Major%20Project/backend/app/detection/correlator.py): Groups alerts sharing an IP and time window into consolidated Incident entities.
8. [backend/app/routers/logs.py](file:///d:/Major%20Project/backend/app/routers/logs.py): Orchestrates file upload, parsing, bulk insertion via COPY protocol, and automatic detection triggering.
9. [frontend/src/services/api.js](file:///d:/Major%20Project/frontend/src/services/api.js): Centralizes all Axios HTTP calls from the React UI to the backend.
10. [frontend/src/pages/DashboardPage.jsx](file:///d:/Major%20Project/frontend/src/pages/DashboardPage.jsx): Central console UI showing Recharts graphs, telemetry counters, simulator triggers, and recent alerts.

---

## 15. Important Code Logic

### 1. `bulk_insert_events` ([backend/app/routers/logs.py](file:///d:/Major%20Project/backend/app/routers/logs.py#L17-L80))
- **Purpose:** Ingests thousands of normalized events into PostgreSQL at maximum speed.
- **Input:** `events_data: List[Dict[str, Any]]`, `db: Session`.
- **Output:** Tuple `(inserted_count, failed_count)`.
- **Logic:** Attempts to access the raw DBAPI cursor and execute a direct `COPY events (...) FROM STDIN` stream. If unsupported, gracefully falls back to chunked SQLAlchemy multi-row inserts (500 records per chunk) with individual error isolation.

### 2. `parse_and_normalize` ([backend/app/ingestion/parser_registry.py](file:///d:/Major%20Project/backend/app/ingestion/parser_registry.py#L19-L45))
- **Purpose:** Orchestrates format detection, parser dispatch, and canonical standardization.
- **Input:** `filename: str`, `content: str`.
- **Output:** Tuple `(normalized_events, detected_format, total_records, parsed_records, failed_records)`.
- **Logic:** Calls `detect_file_type()`, looks up the parser in `PARSERS` map, parses raw records, and runs each record through `normalize_event_dict()`.

### 3. `check_brute_force` ([backend/app/detection/rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py#L38-L93))
- **Purpose:** Implements MITRE T1110 detection.
- **Input:** `events: List[Event]`, `db: Session`.
- **Output:** `List[AlertCreate]`.
- **Logic:** Aggregates failed authentication attempts by `source_ip`. If count exceeds 10 within the batch or within the last 10 minutes in the database, generates a `HIGH` severity alert with rule ID `RULE_01_BRUTE_FORCE`.

### 4. `check_port_scan` ([backend/app/detection/rules.py](file:///d:/Major%20Project/backend/app/detection/rules.py#L94-L144))
- **Purpose:** Implements MITRE T1046 detection.
- **Input:** `events: List[Event]`, `db: Session`.
- **Output:** `List[AlertCreate]`.
- **Logic:** Tracks unique `destination_port` values probed by each `source_ip`. If 8 or more distinct ports are probed within a 5-minute window, generates a `HIGH` severity alert with rule ID `RULE_02_PORT_SCAN`.

### 5. `correlate_alerts` ([backend/app/detection/correlator.py](file:///d:/Major%20Project/backend/app/detection/correlator.py#L12-L119))
- **Purpose:** Converts atomic alerts into actionable incident campaigns.
- **Input:** `new_alerts: List[Alert]`, `db: Session`.
- **Output:** `List[Incident]`.
- **Logic:** Queries for open incidents matching `source_ip` within 1 hour. If found, appends the alert via `IncidentAlert` and updates the summary narrative. If none exists, instantiates a new `Incident`, computes confidence based on rule variety, and links the alerts.

### 6. `clear_soc_data` ([backend/app/routers/system.py](file:///d:/Major%20Project/backend/app/routers/system.py#L17-L69))
- **Purpose:** Non-destructively flushes operational data for demonstration resets.
- **Input:** `db: Session`.
- **Output:** Status dictionary.
- **Logic:** Deletes records in strict foreign key order (`AIAnalysis` -> `IncidentAlert` -> `Alert` -> `Incident` -> `Event` -> `ThreatIntelligence` -> `AuditLog`), preserving users, MITRE techniques, and table structures.

---

## 16. API Flow Examples

### Example 1: Normal Security Event Ingestion
```
1. Client sends POST /api/events
   Payload: {
     "source": "firewall",
     "source_ip": "10.0.1.50",
     "destination_ip": "10.0.1.1",
     "destination_port": 443,
     "protocol": "TCP",
     "event_type": "network_flow",
     "raw_data": {"bytes": 1024}
   }
2. events.py:create_event() validates payload using Pydantic EventCreate.
3. Event record inserted into 'events' table.
4. run_detection() evaluates event against rules -> No thresholds exceeded.
5. Returns HTTP 201 Created with persisted EventResponse (including generated ID).
```

### Example 2: Brute-Force Attack Detection & Incident Creation
```
1. Attacker sends 12 failed SSH attempts from 192.168.1.185.
2. Parsed into Event records with event_type="failed_login", source_ip="192.168.1.185".
3. detection_engine.run_detection() calls check_brute_force().
4. Threshold check: 12 attempts > 10 attempts -> Fired!
5. Alert created:
   - title: "Possible Brute Force Attack"
   - severity: "HIGH"
   - detection_rule: "RULE_01_BRUTE_FORCE"
   - source_ip: "192.168.1.185"
6. correlator.correlate_alerts() processes the alert:
   - Finds no open incident from 192.168.1.185 within past 1 hour.
   - Creates new Incident: "Incident: Correlated Attack Activity from 192.168.1.185".
   - Links Alert to Incident via 'incident_alerts'.
7. Dashboard metrics update via WebSocket/probe: Total Alerts +1, Open Incidents +1.
```

### Example 3: Uploaded Web Server Log Ingestion
```
1. User uploads "access.log" containing SQL injection probes via LogUploadPage (/upload).
2. Frontend sends multipart/form-data to POST /api/logs/upload.
3. file_detector.py detects format as "apache".
4. apache_parser.py parses lines using regex RE_COMBINED_LOG.
5. normalizer.py converts entries into canonical events:
   - event_type: "http_request"
   - raw_data: {"path": "/index.php?id=1' UNION SELECT ..."}
6. bulk_insert_events() batch inserts events into Supabase 'events' table.
7. run_detection() triggers check_web_attacks():
   - Regex matches 'UNION SELECT'
   - Fires Alert: "Possible Web Attack" (RULE_04_WEB_ATTACK)
8. correlator.correlate_alerts() links alert to an incident.
9. Response returned to frontend:
   {"parsed_records": 4, "alerts_created": 1, "incidents_created": 1}
10. UI displays summary card with direct button: "View Alerts (1)".
```

---

## 17. Testing

### Current Testing Status (Verified)
- **Total Test Cases:** 19
- **Passing Tests:** 19 (100% Pass Rate)
- **Failed Tests:** 0
- **Test Execution Time:** ~110 seconds against live Supabase PostgreSQL
- **Frontend Build Status:** Succeeded (`vite build` compiled 2,253 modules into `dist/` with 0 errors)
- **Backend Service Status:** Operational on port 8000
- **Database Connection Status:** Live connectivity verified (`connected: true`, dialect: PostgreSQL)

### Test Breakdown by File

#### `backend/tests/test_health.py` (2 tests)
- `test_root_endpoint`: Validates root `/` responds with 200 and docs links.
- `test_health_endpoint_structure`: Validates `/api/health` returns status `ok` and PostgreSQL dialect.

#### `backend/tests/test_crud.py` (6 tests)
- `test_health_still_operational`: Confirms database live connection is true.
- `test_mitre_techniques_endpoints`: Verifies listing and lookup of technique `T1110`.
- `test_events_crud_and_pagination`: Tests creating an event and retrieving via paginated filter.
- `test_alerts_crud_and_patch`: Tests creating, listing, and patching alert status to `INVESTIGATING`.
- `test_incidents_crud_with_correlated_alerts`: Tests creating an incident linked to alerts and updating status to `CONTAINED`.
- `test_dashboard_stats`: Verifies dashboard aggregated metrics and chart distributions.

#### `backend/tests/test_phase4.py` (10 tests)
- `test_upload_json_log`: Validates JSON log file parsing and ingestion.
- `test_upload_csv_log`: Validates CSV log file parsing with header matching.
- `test_parse_basic_text_log`: Validates syslog / auth.log plaintext parsing.
- `test_brute_force_detection`: Verifies 12 failed logins trigger `RULE_01_BRUTE_FORCE`.
- `test_port_scan_detection`: Verifies multi-port probes trigger `RULE_02_PORT_SCAN`.
- `test_web_attack_detection`: Verifies SQL injection probe triggers `RULE_04_WEB_ATTACK`.
- `test_suspicious_command_and_privilege_escalation`: Verifies `RULE_03` (powershell) and `RULE_05` (visudo).
- `test_incident_correlation`: Verifies alerts from the same IP are aggregated into an Incident.
- `test_simulator_endpoints`: Verifies execution of `/api/simulator/brute-force`.
- `test_reject_unsupported_file_extension`: Asserts rejection of `.exe`, `.pdf`, `.py`, `.zip` with HTTP 400.

#### `backend/tests/test_system.py` (1 test)
- `test_clear_soc_data_endpoint`: Tests `DELETE /api/system/clear-data`, verifying events/alerts/incidents are zeroed out while users and MITRE data remain intact.

---

## 18. Current Limitations

To maintain academic honesty during presentations, the following components are acknowledged as **not yet implemented**:

1. **Google Gemini AI (Phase 5):** The AI analysis service, LLM copilot chat, and automated incident summarization are not yet active. Frontend displays placeholder cards.
2. **External Threat Intelligence APIs (Phase 6):** Real-time enrichment lookups against VirusTotal and AbuseIPDB are not yet wired to live external endpoints.
3. **Dedicated Ingestion Daemons:** Suricata socket listeners, Wazuh manager forwarders, and Zeek brokers are not implemented; ingestion currently relies on HTTP upload and file parsing.
4. **Authentication & Authorization (JWT):** The `users` database table exists with password hashes, but route authorization middleware is not yet enforced.
5. **Active Response Automation:** Automatic containment actions (e.g. executing firewall IP block rules on local interfaces) are not yet implemented.

---

## 19. Presentation Explanation (Script for Judges)

### A. 30-Second Elevator Pitch
> "Respected judges, our project is the **AI SOC Copilot**. In modern security operations, analysts are overwhelmed by thousands of disconnected security logs. In this first half of our project, we have built a complete defensive pipeline that ingests heterogeneous logs—from Linux authentication to web servers—normalizes them into a unified format in PostgreSQL, runs deterministic rules mapped to MITRE ATT&CK to catch attacks like brute force and port scans, and correlates those alerts into cohesive incidents on an interactive React dashboard. This provides the robust data foundation for our upcoming AI phase."

### B. 1-Minute Overview
> "Good morning, judges. We are presenting the 50% milestone of our major project: **AI SOC Copilot**. 
> 
> Security analysts face massive alert fatigue because different systems output logs in incompatible formats. To solve this, our Phase 1 through 4 implementation accomplishes three key goals:
> First, **Universal Ingestion & Normalization**: Our backend accepts `.log`, `.txt`, `.json`, and `.csv` files, parses syslog headers and web requests, and standardizes them into a canonical relational schema stored in Supabase PostgreSQL.
> Second, **Deterministic Detection**: We implemented five core security detection algorithms mapped to MITRE ATT&CK techniques, detecting brute-force attempts, network port scans, web application exploits, suspicious commands, and privilege escalation.
> Third, **Incident Correlation & Visualization**: Rather than alerting on every single event, our correlation engine links related alerts by source IP into consolidated attack incidents. Analysts can triage alerts, inspect raw JSON payloads, track attack timelines, and simulate live attacks through our React 18 dashboard."

### C. 3-Minute Technical Walkthrough
> "Respected panel, let me walk you through the technical architecture of our AI SOC Copilot at this 50% milestone.
> 
> Our architecture consists of three tiers: a **React 18 Single Page Application**, a **FastAPI asynchronous backend**, and a **Supabase PostgreSQL database**.
> 
> When an analyst uploads a security log or our built-in simulator fires, the telemetry enters our Ingestion Pipeline. The `file_detector` module inspects the file signature, dispatching it to format-specific parsers—such as our regex-driven syslog parser or our RFC-compliant CSV and JSON parsers.
> 
> Next, the `normalizer` maps varied field names like `src_ip`, `client_ip`, or syslog hosts into our canonical `Event` schema. We handle multiple timestamp variations, normalizing everything into UTC datetime. To maximize write performance, we utilize the PostgreSQL binary `COPY` protocol via `psycopg3`, falling back to chunked multi-values batch insertion.
> 
> Once persisted, the events are evaluated by our Deterministic Detection Engine in `rules.py`. We intentionally avoid non-deterministic AI at this layer to guarantee predictable, auditable detections. For example:
> - If an IP generates more than 10 failed login attempts, Rule 1 triggers MITRE Technique T1110 for Brute Force.
> - If an IP probes 8 or more distinct ports, Rule 2 flags MITRE Technique T1046 for Network Service Scanning.
> - We also evaluate regex signatures for SQL injection, command execution, and privilege escalation.
> 
> The resulting alerts are fed into our Incident Correlator in `correlator.py`. The correlator groups alerts sharing an identical source IP within a 1-hour temporal window. If an open incident exists, new alerts are appended; otherwise, a new incident is created with an automated confidence score and multi-stage attack title.
> 
> On the frontend, built with Vite and Tailwind CSS, analysts have real-time visibility into telemetry distributions via Recharts, can update alert triage states, view raw event payloads, and run simulated attack scenarios. All 19 backend unit tests are passing with 100% test coverage across health, CRUD, log parsing, detection rules, and incident correlation. This completes our robust operational foundation, preparing us for Phase 5 where we integrate Google Gemini as our intelligent AI investigation copilot."

---

## 20. Possible Viva Questions & Answers

#### Q1: Why did you choose FastAPI over Flask or Django?
**Answer:** FastAPI provides native asynchronous concurrency via ASGI (Uvicorn), automatic request validation using Pydantic, high throughput for handling bulk security telemetry, and automatic interactive Swagger documentation (`/docs`). Django is too monolithic and Flask lacks built-in async validation without external extensions.

#### Q2: Why React for the frontend instead of server-rendered templates (Jinja2)?
**Answer:** A SOC dashboard requires high interactivity, dynamic chart re-rendering (Recharts), client-side filtering, and responsive state updates without full page reloads. React 18's virtual DOM and component modularity provide the reactive user experience needed for real-time monitoring.

#### Q3: Why PostgreSQL / Supabase instead of MongoDB or Elasticsearch?
**Answer:** Relational integrity is paramount for auditability and incident correlation: alerts must have strict foreign key relationships with events and incidents (`ON DELETE CASCADE` or `SET NULL`). PostgreSQL also natively supports `JSONB` columns, giving us the relational rigor of SQL combined with the schema flexibility of NoSQL for raw log payloads.

#### Q4: Why use SQLAlchemy ORM instead of raw SQL queries?
**Answer:** SQLAlchemy 2.0 provides type safety, database dialect abstraction, connection pooling, and automatic parameter binding which completely eliminates SQL injection vulnerabilities.

#### Q5: Why is log normalization necessary before detection?
**Answer:** Different operating systems, firewalls, and web servers log data in completely different formats and field names (e.g. `src_ip`, `client_ip`, `rhost`). Normalization standardizes all records into a single canonical `Event` schema (with UTC timestamps and standardized IP fields), allowing a single detection rule to work across any log source.

#### Q6: How does your detection engine work? Is it using Machine Learning?
**Answer:** No, the current engine is strictly deterministic—relying on threshold counters (e.g., >10 failed logins) and regex signature matching. Deterministic rules are industry standard for baseline detection because they are auditable, explainable, and do not suffer from probabilistic hallucinations or false positives. AI is introduced in Phase 5 for reasoning, not initial alerting.

#### Q7: How are alerts created from events?
**Answer:** In `detection_engine.py`, batches of normalized events are passed through rule functions in `rules.py`. When a rule's threshold or regex pattern matches, an `AlertCreate` object is instantiated, deduplicated against existing database records, and persisted into the `alerts` table linked to the triggering `event_id`.

#### Q8: How does an alert become an incident?
**Answer:** Through `correlator.py`. Alerts sharing the same `source_ip` within a 1-hour window are correlated. If an open incident already exists for that IP, the alert is linked via the `incident_alerts` table and the incident narrative is updated. If not, a new `Incident` record is generated.

#### Q9: What is the MITRE ATT&CK framework?
**Answer:** MITRE ATT&CK is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It categorizes attacker behaviors across the cyber kill chain (such as Credential Access or Discovery), allowing security teams to standardize threat classifications.

#### Q10: What is the difference between an Event, an Alert, and an Incident?
**Answer:** 
- **Event:** Any raw, observable log entry (e.g., a single SSH connection attempt or web request).
- **Alert:** A notification generated when an event (or pattern of events) violates a security detection rule.
- **Incident:** A correlated collection of one or more related alerts that represent an active, multi-step attack campaign requiring human investigation.

#### Q11: How does the frontend communicate with the backend?
**Answer:** Through an Axios HTTP client configured in `src/services/api.js`. In development, Vite's reverse proxy intercepts `/api` requests and forwards them to `http://127.0.0.1:8000`, preventing CORS issues.

#### Q12: How is database security handled?
**Answer:** 
1. Database credentials are stored strictly in backend environment variables (`.env`) and are never exposed to the frontend.
2. All database queries use SQLAlchemy parameterized statements, preventing SQL injection.
3. Foreign key constraints enforce referential integrity across all tables.

#### Q13: What happens when an invalid or corrupt log file is uploaded?
**Answer:** The system handles this gracefully:
1. File extension validation rejects non-log files (`.exe`, `.pdf`) with an immediate HTTP 400.
2. Inside parsers, malformed lines increment a `failed_records` counter inside a `try-except` block while continuing to parse valid lines.
3. The API returns a breakdown of `total_records`, `parsed_records`, and `failed_records` without crashing.

#### Q14: What are the current limitations of your implementation?
**Answer:** The primary limitation is that Google Gemini AI reasoning, live threat intelligence lookups (VirusTotal/AbuseIPDB), and automated firewall response actions are scheduled for Phases 5 and 6 and are not yet active in the codebase.

#### Q15: Why use rule-based detection before applying AI?
**Answer:** In professional SOC environments, rule-based detection provides deterministic, instantaneous, low-latency, and zero-cost filtering of known attack patterns. Passing raw terabytes of raw logs directly to an LLM would be prohibitively slow, expensive, and prone to hallucinations. The rules filter signal from noise so the AI only evaluates high-confidence alerts.

#### Q16: How does the application handle bulk log uploads efficiently?
**Answer:** In `routers/logs.py`, the `bulk_insert_events()` function attempts to use PostgreSQL's native `COPY` protocol via `psycopg3`, streaming rows directly into the database. If unavailable, it executes chunked multi-values inserts in batches of 500 records.

#### Q17: What does the "Clear All Data" button do? Does it delete database tables?
**Answer:** No, it does not drop tables or delete migrations. It issues a `DELETE` in strict foreign key order (`AIAnalysis` -> `IncidentAlert` -> `Alert` -> `Incident` -> `Event` -> `ThreatIntelligence` -> `AuditLog`). User accounts and MITRE techniques are intentionally preserved.

#### Q18: What is the purpose of the `incident_alerts` table?
**Answer:** It is a many-to-many junction table. An incident can contain multiple correlated alerts, and theoretically, an alert could belong to multiple investigation cases. This normalizes the database and avoids storing unindexed arrays of IDs.

#### Q19: How do you prevent duplicate alerts from being created repeatedly?
**Answer:** The engine uses two deduplication mechanisms in `detection_engine.py`:
1. It queries existing alert `event_id` records in PostgreSQL before inserting.
2. It tracks a `(source_ip, detection_rule)` tuple in memory per ingestion batch to avoid flooding the database during high-frequency attacks.

#### Q20: How did you test your codebase?
**Answer:** We implemented a comprehensive test suite using Pytest and FastAPI's `TestClient` across 19 unit and integration tests in `backend/tests/`. Tests verify health checks, CRUD operations, format parsers, detection rules, incident correlation, and data reset endpoints against a live PostgreSQL database.

---

## 21. Important Terms (Glossary for Presentation)

- **SOC (Security Operations Center):** A centralized facility where security professionals monitor, detect, analyze, and respond to cybersecurity incidents using telemetry from across the organization.
- **SIEM (Security Information and Event Management):** Software that aggregates and analyzes log data from across an enterprise to detect threat patterns and maintain compliance.
- **Event:** An atomic recorded occurrence within a system or network (e.g. firewall packet drop, user login, file modification).
- **Alert:** A formal warning generated when security telemetry matches a predefined malicious rule or threshold.
- **Incident:** A correlated cluster of confirmed security alerts that represent an unauthorized action or security breach requiring analyst remediation.
- **IOC (Indicator of Compromise):** Forensic artifact or digital evidence indicating that a system has been breached (e.g., malicious IP, domain, file hash).
- **MITRE ATT&CK:** A structured matrix classifying real-world adversary tactics (goals), techniques (methods), and procedures (TTPs).
- **T1110 (Brute Force):** MITRE technique where adversaries guess credentials through repetitive trial-and-error passwords or tokens.
- **T1046 (Network Service Scanning):** MITRE technique where adversaries probe ports to discover remote services running across a network.
- **T1059 (Command and Scripting Interpreter):** MITRE technique abusing command shells (PowerShell, Bash, CMD) to execute malicious code.
- **T1190 (Exploit Public-Facing Application):** MITRE technique exploiting internet-facing web vulnerabilities (SQLi, path traversal) to gain ingress.
- **T1548 (Abuse Elevation Control Mechanism):** MITRE technique circumventing access controls to gain root or administrator privileges (e.g., sudo abuse).
- **Log Normalization:** The process of converting disparate log formats into a standardized, unified schema with consistent fields and timestamps.
- **Detection Rule:** A deterministic conditional logic statement or regex pattern evaluated against security events to identify malicious behavior.
- **Threat Intelligence:** Evidence-based knowledge regarding external cyber threats (e.g., known malicious IP reputations from VirusTotal or AbuseIPDB).
- **FastAPI:** A high-speed, modern Python framework for developing RESTful APIs utilizing Python type hints and Pydantic validation.
- **REST API:** Representational State Transfer API that uses standard HTTP methods (`GET`, `POST`, `PATCH`, `DELETE`) for stateless client-server communication.
- **ORM (Object-Relational Mapping):** A programming technique for converting data between relational database tables and object-oriented code entities (e.g., SQLAlchemy).
- **PostgreSQL:** An open-source, ACID-compliant, highly extensible object-relational SQL database.
- **Supabase:** An open-source cloud backend platform built on top of managed PostgreSQL, providing instant relational database hosting and API access.

---

## 22. Final Project Status

```
PHASE 1 (System Scaffolding, DB & Health Diagnostics): COMPLETE
PHASE 2 (Relational Database, Models & CRUD APIs):    COMPLETE
PHASE 3 (Frontend SOC Console & Dashboard Analytics):  COMPLETE
PHASE 4 (Log Ingestion, Normalization & Detections):   COMPLETE
```

### Currently Working (Verified in Codebase):
- Ingestion of `.log`, `.txt`, `.json`, and `.csv` files via drag-and-drop and multipart REST API.
- Regex and delimiter parsers for Syslog, Linux authentication, Apache/Nginx web logs, CSVs, and JSON arrays.
- Canonical log normalization with UTC timestamp standardization and lossless raw payload retention.
- Supabase PostgreSQL persistence with connection pooling and high-speed insertion.
- 5 Deterministic Detection Rules: Brute Force (T1110), Port Scanning (T1046), Suspicious Commands (T1059), Web Attacks (T1190), and Privilege Escalation (T1548).
- Temporal IP-based Incident Correlation grouping related alerts into multi-stage attack incidents.
- Attack Scenario Simulator executable via both Python CLI and interactive Frontend buttons.
- Modern React 18 / Vite / Tailwind CSS analyst console featuring Recharts analytics, alert triage, incident timelines, raw JSON payload inspection, MITRE ATT&CK navigator, and health probes.
- Non-destructive database reset mechanism (`DELETE /api/system/clear-data`).
- Full test suite passing 19 out of 19 tests with zero errors.

### Not Yet Implemented (Scheduled for Second Half):
- Google Gemini AI Integration (Automated alert reasoning, incident summaries, and conversational Copilot chat).
- Real-time Threat Intelligence API connectors (live lookups to VirusTotal and AbuseIPDB).
- Direct streaming daemon connectors (Suricata EVE socket, Zeek broker).
- JWT User Authentication and role-based endpoint authorization.
- Automated active response / containment scripts.

### Next Phase:
- **Phase 5: AI SOC Copilot Engine (Google Gemini Integration)**
  - Activation of `backend/app/ai/` module.
  - Development of Gemini prompt pipelines with strict temperature control and schema-constrained JSON outputs.
  - Automated generation of incident narratives, kill-chain reconstruction, and analyst recommendations.
  - Interactive Copilot chat interface in the frontend console.
