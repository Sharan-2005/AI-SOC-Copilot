# 🛡️ AI SOC Copilot — Intelligent Security Operations Center Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.x-646CFF?logo=vite)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC?logo=tailwindcss)](https://tailwindcss.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-336791?logo=postgresql)](https://www.postgresql.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Aligned-red)](https://attack.mitre.org/)

An enterprise-grade, full-stack AI-assisted Security Operations Center (SOC) platform designed for modern security analysts. The platform demonstrates end-to-end security operations: universal log collection and normalization, deterministic rule-based threat detection, incident correlation across the cyber kill chain, MITRE ATT&CK mapping, threat intelligence enrichment, live defensive ICMP flood monitoring, and explainable AI-guided investigation powered by Google Gemini.

---

## 🌟 Core Features

- **Universal Log Ingestion**: Ingest and parse `.log`, `.txt`, `.json`, `.csv`, `.xml`, `.ndjson`, Apache, Nginx, Syslog, Suricata EVE, Wazuh, and Zeek logs.
- **Deterministic Detection Engine**: 7 core security rules (`RULE_01` to `RULE_07`) detecting brute force, port scans, command injection, web attacks, account compromises, and ICMP flood attacks (independent of AI hallucinations).
- **Live ICMP Threat Detection (Phase 5)**: Real-time network interface packet capture, directional traffic segregation (evaluating inbound floods to protected IPs while excluding outbound pings to 8.8.8.8), sliding-window rate calculation, and isolated test simulation mode.
- **Incident Correlation Engine**: Automatically correlates related alerts across multi-stage attack timelines.
- **MITRE ATT&CK Alignment**: Maps techniques (e.g., T1110, T1046, T1059) to alerts and incidents with contextual security explanations.
- **Threat Intelligence Enrichment**: Automated IP reputation lookups via VirusTotal and AbuseIPDB.
- **Explainable AI Copilot (Google Gemini)**: Analyzes alerts, constructs incident narratives, and answers natural language queries with read-only tool calling.
- **Human-in-the-Loop Remediation**: AI recommends actions (IP blocking, host isolation, account review) requiring explicit analyst sign-off with audit logging.
- **Modern Responsive SOC Dashboard**: Dark/light mode, real-time telemetry graphs, severity badges, and unified threat feeds.

---

## 🏗️ Architecture Overview

```
                      [ External Log Sources / Live Traffic ]
                (Suricata / Wazuh / Zeek / System Logs / Live ICMP)
                                         │
                                         ▼
                             [ Universal Ingestion ]
                                         │
                                         ▼
                          [ Rule-Based Detection Engine ]
                       (RULE_01 to RULE_07 • DoS/DDoS/MITRE)
                                         │
                        ┌────────────────┴────────────────┐
                        ▼                                 ▼
             [ Incident Correlator ]              [ Supabase PostgreSQL ]
                        │                                 ▲
                        ▼                                 │
             [ Alert & Timeline Store ] ──────────────────┤
                                                          │ Controlled
                                                          │ Read Tools
                                                          ▼
             [ React + Tailwind SOC UI ] ◄──── [ Google Gemini AI Copilot ]
               (Real-time Dashboard)             (Incident Narrator)
```

---

## 📋 System Prerequisites

Ensure you have the following installed on your host machine before starting:

1. **Git**: [Download Git](https://git-scm.com/downloads)
2. **Python**: Version **3.10 to 3.14** — [Download Python](https://www.python.org/downloads/)
   - *Windows users*: Ensure **"Add python.exe to PATH"** is checked during installation.
3. **Node.js & npm**: Node.js **18.x or 20.x+** — [Download Node.js](https://nodejs.org/)
4. **PostgreSQL Database**:
   - A free cloud database instance from [Supabase](https://supabase.com/) (Recommended) or a local PostgreSQL 15+ installation / Docker.
5. *(Optional for Windows Live Packet Capture)*: **Npcap**:
   - Required only if running live raw packet sniffing on Windows network cards: [Download Npcap](https://npcap.com/#download) (Select *"Install Npcap in WinPcap API-compatible Mode"*).
   - *Note: Without Npcap, all other features and the built-in Local Test / Simulation engine work completely out of the box!*

---

## 🚀 Step-by-Step Setup Guide

Follow these steps sequentially to get the entire platform up and running from scratch.

### Step 1: Clone the Repository

Open your terminal or command prompt (PowerShell / Bash) and clone the project:

```bash
git clone https://github.com/Sharan-2005/AI-SOC-Copilot.git
cd AI-SOC-Copilot
```

---

### Step 2: Configure Environment Variables (`.env`)

In the project root directory (`AI-SOC-Copilot/`), create a new file named `.env`.

> [!IMPORTANT]
> The `.env` file contains your private API keys and database credentials. It is automatically ignored by Git to prevent secrets from being pushed to public repositories.

Populate `.env` with your credentials:

```env
# =========================================================================
# DATABASE CONFIGURATION (Supabase or Local PostgreSQL)
# =========================================================================
DATABASE_URL=postgresql://postgres.your_project_ref:your_password@aws-0-region.pooler.supabase.com:6543/postgres

# =========================================================================
# AI COPILOT ENGINE (Google Gemini)
# Obtain free API key from https://aistudio.google.com/
# =========================================================================
GEMINI_API_KEY=your_google_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# =========================================================================
# THREAT INTELLIGENCE (Optional)
# =========================================================================
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# =========================================================================
# LIVE ICMP MONITORING & DETECTION (Phase 5)
# =========================================================================
ICMP_INTERFACE=default
ICMP_WINDOW_SECONDS=10
ICMP_SUSPICIOUS_THRESHOLD=100
ICMP_DOS_THRESHOLD=300
ICMP_DDOS_THRESHOLD=500
ICMP_UNIQUE_SOURCE_THRESHOLD=10
PROTECTED_TARGET_IPS=127.0.0.1
```

---

### Step 3: Set Up and Run the Backend

Open a terminal window in the root directory:

#### 1. Navigate to the backend directory:
```bash
cd backend
```

#### 2. Create and activate a Python virtual environment:
- **On Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .venv\Scripts\activate
  ```
- **On Linux / macOS:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

#### 3. Install required Python packages:
```bash
pip install -r requirements.txt
```

#### 4. Launch the FastAPI backend server:
```bash
uvicorn app.main:app --reload --port 8000
```

You should see log output indicating:
```text
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:soc_copilot:Database connection established successfully.
INFO:soc_copilot:AI SOC Copilot backend initialized successfully.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

- **Backend Health Check**: `http://127.0.0.1:8000/api/health`
- **Interactive OpenAPI Documentation**: `http://127.0.0.1:8000/docs`

> [!TIP]
> Keep this terminal window open and running.

---

### Step 4: Set Up and Run the Frontend

Open a **second** terminal window in the root directory (`AI-SOC-Copilot`):

#### 1. Navigate to the frontend directory:
```bash
cd frontend
```

#### 2. Install Node dependencies:
```bash
npm install
```

#### 3. Launch the Vite development server:
```bash
npm run dev
```

You should see:
```text
  VITE v6.x.x  ready in 400 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

#### 4. Open the Application:
Open your browser and navigate to:
```
http://localhost:5173/
```

> [!NOTE]
> **Proxy Configuration**: The frontend is pre-configured via Vite to automatically proxy all `/api` requests to `http://127.0.0.1:8000`. Always start the Backend first so the proxy can connect seamlessly.

---

## 🧪 Testing the System

### Run the Backend Automated Test Suite
In the `backend/` directory with your virtual environment active, run:
```bash
pytest tests/ -v
```
All **37 tests** across ingestion, normalization, CRUD operations, health checks, incident correlation, and live ICMP DoS/DDoS detection should pass.

### Verify the Frontend Production Build
In the `frontend/` directory, run:
```bash
npm run build
```
This confirms that all Tailwind styling, Recharts visualization components, and React router modules compile with **0 errors**.

---

## 🕹️ Exploring the SOC Platform

1. **Executive Dashboard (`/`)**:
   - View live event counters, alert severity distributions, MITRE technique breakdowns, and real-time security alerts.
2. **Real-time ICMP Monitoring (`/icmp-monitor`)**:
   - **Live Capture**: Capture real ICMP packets from your active NIC.
   - **Directional Classification**: Distinguishes inbound attacks to protected IPs from outbound requests (such as pinging `8.8.8.8`) and echo replies.
   - **Local Test / Simulation**: Inject synthetic DoS/DDoS streams to demonstrate `RULE_06` and `RULE_07` alert creation and Supabase persistence.
3. **Log Upload & Ingestion (`/logs`)**:
   - Upload sample logs (e.g. Apache access logs, auth logs, JSON, Syslog) to watch the parser normalize fields and trigger detection rules.
4. **Incidents & Correlation (`/incidents`)**:
   - Inspect correlated multi-stage security incidents, aggregated timelines, and MITRE kill chain tactics.
5. **MITRE ATT&CK Matrix (`/mitre`)**:
   - Review mapped attack techniques and rule definitions.

---

## 🐳 Optional: Running with Docker Compose

If you have Docker and Docker Compose installed:

```bash
# Build and start all services (Backend, Frontend, and PostgreSQL)
docker compose up --build
```
- Frontend: `http://localhost:3000` or `http://localhost:5173`
- Backend: `http://localhost:8000`

---

## 📁 Repository Structure

```
AI-SOC-Copilot/
├── backend/                  # FastAPI backend application
│   ├── app/
│   │   ├── ai/               # Google Gemini client, alert/incident analyzers, copilot
│   │   ├── database/         # SQLAlchemy connection and base models
│   │   ├── detection/        # Deterministic detection engine (RULE_01 to RULE_07)
│   │   ├── ingestion/        # Universal log parsers & normalizers
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── routers/          # REST API route handlers
│   │   ├── schemas/          # Pydantic data schemas
│   │   ├── security/         # Security & authentication helpers
│   │   └── services/         # ICMP live monitor, threat intel services
│   ├── requirements.txt      # Python dependencies
│   └── tests/                # Full pytest test suite (37 tests)
├── frontend/                 # React 19 + Vite + Tailwind CSS console
│   ├── src/
│   │   ├── components/       # Reusable UI components & badges
│   │   ├── context/          # Theme & telemetry refresh contexts
│   │   ├── layouts/          # Dashboard sidebar & top navigation
│   │   ├── pages/            # View pages (Dashboard, ICMP, Logs, Alerts, Incidents)
│   │   └── services/         # Axios API client
│   ├── package.json          # Node dependencies
│   └── vite.config.js        # Vite build & backend proxy config
├── database/                 # PostgreSQL schema and seed scripts
├── docker/                   # Dockerfiles for containerized deployment
├── docs/                     # Architectural design, API, and setup documentation
├── simulator/                # Security event generation test scripts
├── docker-compose.yml        # Docker compose definition
├── .gitignore                # Git ignore rules (protecting .env and sensitive files)
└── README.md                 # Project documentation
```

---

## 🔒 Security & Privacy Notice

- **No Secrets in Source Control**: `.env` and `.env.example` are excluded from the repository via `.gitignore`.
- **Read-Only AI Operation**: Google Gemini executes under strict read-only query capabilities; all remediation actions require explicit human analyst authorization.
- **Controlled Inbound Detection**: Live ICMP monitoring evaluates only incoming echo requests directed to authorized destination IPs in `PROTECTED_TARGET_IPS`.

---

## 📄 License
Developed for the BE Information Technology Major Project demonstration.
