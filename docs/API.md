# AI SOC Copilot – REST API Reference

Base URL: `http://localhost:8000` (or configured deployment host)
All endpoints respond with `application/json` unless otherwise specified.

---

## 1. System Health

### `GET /api/health`
Returns the status of the backend, database connection state, environment mode, and server timestamp.

**Response (200 OK):**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "environment": "development",
  "database": {
    "connected": true,
    "dialect": "postgresql",
    "latency_ms": 4.2
  },
  "timestamp": "2026-09-16T22:30:00.000Z"
}
```

---

## 2. Ingestion & Logs

### `POST /api/logs/upload`
Upload log files (`.log`, `.txt`, `.json`, `.csv`, `.xml`, `.ndjson`, Suricata, Wazuh, Zeek).
- **Body**: `multipart/form-data` containing `file`
- **Response (200 OK)**:
  ```json
  {
    "filename": "auth.log",
    "detected_format": "linux_auth",
    "total_records": 120,
    "parsed_records": 118,
    "failed_records": 2,
    "warnings": ["Line 42: malformed syslog header"],
    "alerts_generated": 3
  }
  ```

### `POST /api/ingest/event`
Ingests a single normalized event.

### `POST /api/ingest/suricata`
Ingests raw Suricata EVE JSON events.

### `POST /api/ingest/wazuh`
Ingests raw Wazuh JSON alerts.

### `POST /api/ingest/zeek`
Ingests Zeek connection or DNS log records.

---

## 3. Events

- `GET /api/events`: Paginated list of security events. Filters: `source_ip`, `destination_ip`, `event_type`, `start_time`, `end_time`.
- `GET /api/events/{id}`: Retrieve detailed event by ID with raw log payload.
- `POST /api/events`: Create an event manually or via simulator.

---

## 4. Alerts

- `GET /api/alerts`: List alerts with filters: `severity`, `status`, `source_ip`.
- `GET /api/alerts/{id}`: Detailed alert with associated events and AI analysis.
- `POST /api/alerts`: Create an alert directly.
- `PATCH /api/alerts/{id}`: Update alert status (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- `DELETE /api/alerts/{id}`: Delete an alert (Admin only).

---

## 5. Incidents

- `GET /api/incidents`: List correlated incidents.
- `GET /api/incidents/{id}`: Detailed incident with linked alerts, timeline, and AI investigation summary.
- `POST /api/incidents`: Create or trigger incident correlation.
- `PATCH /api/incidents/{id}`: Update incident status or priority.

---

## 6. AI & Copilot

### `POST /api/ai/analyze-alert/{alert_id}`
Triggers Gemini analysis of an alert using associated events and threat intel.
**Response (200 OK):**
```json
{
  "alert_id": 103,
  "attack_type": "Possible SSH Brute Force",
  "severity": "HIGH",
  "confidence": 0.88,
  "explanation": "High volume of failed authentication attempts from 192.168.1.150 targeting port 22 within a 60-second window.",
  "evidence": ["37 failed logins in 45 seconds", "Single source IP"],
  "mitre_techniques": ["T1110.001"],
  "recommendations": ["Block source IP at edge firewall", "Verify SSH key authentication enforcement"]
}
```

### `POST /api/ai/analyze-incident/{incident_id}`
Analyzes multiple correlated alerts to reconstruct the attack timeline.

### `POST /api/ai/summarize-incident/{incident_id}`
Generates a concise executive and technical summary of the incident.

### `POST /api/ai/chat`
Interactive SOC Copilot chat session utilizing backend tool calling.
- **Request Body**:
  ```json
  {
    "message": "Investigate alert 103 and check if the source IP is known to AbuseIPDB.",
    "context": { "incident_id": 4 }
  }
  ```

---

## 7. Threat Intelligence & MITRE

- `GET /api/threat-intel/ip/{ip}`: Retrieve cached or live reputation from VirusTotal / AbuseIPDB.
- `GET /api/mitre/techniques`: List mapped MITRE ATT&CK techniques.
- `GET /api/mitre/techniques/{technique_id}`: Retrieve specific technique details and associated detections.

---

## 8. Dashboard

- `GET /api/dashboard/stats`: High-level metrics (total events, open alerts, critical incidents, active hosts).
- `GET /api/dashboard/timeline`: Event volume and alert counts grouped by time bucket.
- `GET /api/dashboard/severity-distribution`: Count of alerts grouped by severity.
- `GET /api/dashboard/top-source-ips`: Top offending source IP addresses with alert counts.
