# AI SOC Copilot – Intelligent Security Operations Center Assistant

An enterprise-grade, full-stack AI-assisted Security Operations Center (SOC) platform designed for modern security analysts. The platform demonstrates end-to-end security operations: event collection and normalization, deterministic rule-based threat detection, incident correlation, MITRE ATT&CK mapping, threat intelligence enrichment, and explainable AI-guided investigation via Google Gemini.

---

## 🛡️ Core Capabilities

- **Event Ingestion & Normalization**: Collects heterogeneous security events (auth logs, network flows, web logs) into a unified schema.
- **Deterministic Detection Engine**: Rule-based detection (brute force, port scans, command injection, web attacks, account compromises) independent of AI.
- **Incident Correlation**: Aggregates disparate alerts into cohesive incident timelines across the cyber kill chain.
- **MITRE ATT&CK Matrix Alignment**: Maps techniques (e.g., T1110, T1046, T1059) to alerts and incidents with contextual explanations.
- **Threat Intelligence Enrichment**: Modular enrichment for IPs and indicators via VirusTotal and AbuseIPDB.
- **Explainable AI SOC Copilot (Google Gemini)**: Analyzes alerts, constructs incident narratives, and answers natural language analyst queries using tool calling.
- **Human-in-the-Loop Remediation**: AI recommends actions (IP blocking, host isolation, account review) while maintaining strict human-in-the-loop analyst authorization with tamper-evident audit logging.
- **Universal Log Ingestion**: Upload and parse `.log`, `.txt`, `.json`, `.csv`, `.xml`, `.ndjson`, Suricata EVE, Wazuh, and Zeek logs.

---

## 🏗️ Architecture Overview

```
[ Security Log Sources ]
  (Suricata / Wazuh / Zeek / System Logs / Simulator)
           │
           ▼
[ FastAPI Ingestion & Normalizer ] ──► [ Rule-Based Detection Engine ]
           │                                      │
           ▼                                      ▼
[ PostgreSQL (Supabase / Docker) ] ◄── [ Alerts & Incident Correlation ]
           ▲
           │ Controlled Read / Tools
[ Google Gemini AI Engine ]
  (Alert Analyzer, Incident Narrator, Copilot Chat)
           │
           ▼
[ React + Tailwind SOC Dashboard ] ──► [ Human Analyst in Control ]
```

---

## 🧰 Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | React 19, Vite, Tailwind CSS, Lucide React, Recharts, Axios |
| **Backend** | Python 3.10+, FastAPI, Pydantic v2, SQLAlchemy 2.0+, Uvicorn |
| **Database** | PostgreSQL 16+ (Docker local / Supabase hosted) |
| **AI Engine** | Google Gemini API (`google-genai` SDK) with backend tool calling |
| **DevOps** | Docker, Docker Compose, Git |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ and npm
- PostgreSQL 15+ (local, Docker, or free Supabase instance)

### 1. Environment Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Update `DATABASE_URL` with your PostgreSQL or Supabase connection string.

### 2. Backend Setup
```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API Documentation will be available at `http://127.0.0.1:8000/docs`.

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to access the SOC console.

### 4. Running with Docker Compose
```bash
docker compose up --build
```

---

## 📁 Repository Structure

```
ai-soc-copilot/
├── frontend/             # React + Vite + Tailwind SOC console
├── backend/              # FastAPI application, detection rules, AI services
│   ├── app/
│   │   ├── ai/           # Gemini client, alert/incident analyzers, copilot
│   │   ├── database/     # SQLAlchemy connection and base models
│   │   ├── detection/    # Deterministic rule engine
│   │   ├── ingestion/    # Universal log parsers & normalizers
│   │   ├── models/       # SQLAlchemy ORM models
│   │   ├── routers/      # REST API endpoints
│   │   ├── schemas/      # Pydantic schemas
│   │   └── services/     # Business logic & threat intel
├── database/             # PostgreSQL DDL schema and seed files
├── simulator/            # Security event generation scripts
├── docs/                 # Architectural, API, AI design, and setup documentation
├── docker/               # Dockerfiles for frontend and backend
├── docker-compose.yml    # Multi-container orchestration
└── README.md
```

---

## 📜 Documentation
- [Architecture & Design Details](docs/ARCHITECTURE.md)
- [REST API Reference](docs/API.md)
- [AI Engine & Copilot Design](docs/AI_DESIGN.md)
- [Deployment & Setup Guide](docs/SETUP.md)

---

## 📄 License
This project is developed for the BE Information Technology Major Project demonstration.
