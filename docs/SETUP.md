# AI SOC Copilot – Setup & Installation Guide

This guide walks through setting up the AI SOC Copilot application locally or with Docker containers.

---

## 1. Prerequisites

- **Python**: Version 3.10 through 3.14.
- **Node.js**: Version 18.0 or newer (npm 9+).
- **PostgreSQL**: Version 15+ (Local instance, Docker container, or hosted Supabase database).
- **Git**: For version control.

---

## 2. Local Development Setup

### Step 2.1: Clone and Configure Environment
```bash
git clone <repository-url>
cd "Major Project"
cp .env.example .env
```

Edit `.env` to configure your PostgreSQL credentials:
```ini
# Local PostgreSQL
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/soc_copilot

# OR Supabase Hosted PostgreSQL
# DATABASE_URL=postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
```

### Step 2.2: Backend Initialization
```bash
cd backend
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

Run database migrations/schema:
```bash
# Execute schema.sql against your PostgreSQL instance
psql -d soc_copilot -U postgres -f ../database/schema.sql
```

Launch the FastAPI backend server:
```bash
uvicorn app.main:app --reload --port 8000
```
Verify the backend is live by opening `http://127.0.0.1:8000/api/health` in your browser.

### Step 2.3: Frontend Initialization
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to access the SOC Copilot web console.

---

## 3. Docker Compose Setup

To start all services (PostgreSQL database, FastAPI backend, and React frontend) with a single command:

```bash
docker compose up --build
```

Services will be mapped as follows:
- **Frontend Dashboard**: `http://localhost:5173`
- **FastAPI Backend API**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **PostgreSQL Database**: `localhost:5432`

---

## 4. Verification

1. Check Backend:
   ```bash
   curl http://127.0.0.1:8000/api/health
   ```
2. Check Frontend:
   Open browser at `http://localhost:5173` and confirm the SOC status card reflects `System Status: Operational` and `Database: Connected`.
