# AI SOC Copilot – AI Engine Design & Safety Architecture

## 1. Principles of AI in the SOC

1. **Deterministic First, AI Second**: Rule-based engines detect known signatures with absolute determinism. AI is employed for contextual explanation, multi-event narrative synthesis, MITRE technique mapping, and investigative recommendations.
2. **Grounding & Evidence Attribution**: The model must ground every deduction in concrete log artifacts (timestamps, IPs, port numbers, event counts). Hallucinated indicators or logs are unacceptable.
3. **Calibrated Confidence & Hedged Wording**: The model must explicitly distinguish between observed facts and inferences. Required phrases include:
   - *"Evidence suggests..."*
   - *"Possible..."*
   - *"Likely..."*
   - *"Insufficient telemetry to confirm..."*
4. **Tool-Driven Grounding (Function Calling)**: When answering analyst queries, the model must invoke FastAPI backend tools rather than guessing system state.

---

## 2. Gemini Tool Calling Interface

The Copilot employs Google Gemini function calling with the following restricted backend toolset:

| Tool | Parameters | Purpose |
| :--- | :--- | :--- |
| `get_alert` | `alert_id: int` | Fetches alert metadata, severity, rule, and timestamps |
| `get_related_events` | `alert_id: int, limit: int` | Fetches raw and normalized events triggering the alert |
| `search_events` | `query: str, time_range: str` | Queries normalized events by IP, hostname, or event type |
| `get_incident` | `incident_id: int` | Retrieves incident details and correlated alert list |
| `get_ip_reputation` | `ip: str` | Retrieves VirusTotal / AbuseIPDB threat intel score |
| `get_host_events` | `host: str, limit: int` | Retrieves recent telemetry for a specific target host |
| `get_mitre_technique` | `technique_id: str` | Looks up official MITRE ATT&CK definition and mitigations |
| `get_dashboard_summary`| None | Retrieves real-time SOC metrics and critical alert count |

> [!CAUTION]
> The AI engine is strictly forbidden from executing arbitrary shell commands, raw database migrations, or unfiltered SQL queries.

---

## 3. Structured Output Schemas

### 3.1 Alert Analysis Schema
```json
{
  "attack_type": "string",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "confidence": 0.85,
  "explanation": "Clear, jargon-free summary of observed activity",
  "evidence": [
    "Fact 1 (e.g. 5 failed password attempts)",
    "Fact 2 (e.g. Unusual source IP outside normal business hours)"
  ],
  "mitre_techniques": [
    {
      "technique_id": "T1110.001",
      "name": "Password Guessing",
      "tactic": "Credential Access"
    }
  ],
  "recommendations": [
    "Isolate host 192.168.1.10",
    "Rotate credentials for compromised user 'admin'"
  ]
}
```

### 3.2 Incident Synthesis Schema
```json
{
  "summary": "Executive overview of the attack chain",
  "kill_chain_phase": "Initial Access",
  "likely_attack_chain": [
    "Reconnaissance (Port Scan)",
    "Credential Access (Brute Force)",
    "Execution (PowerShell)"
  ],
  "affected_hosts": ["10.0.0.5"],
  "indicators_of_compromise": ["203.0.113.195"],
  "recommended_actions": [
    "Firewall drop rule for 203.0.113.195",
    "Inspect endpoint memory for spawned processes"
  ]
}
```

---

## 4. Fallback Handling

When `GEMINI_API_KEY` is not provided or the Gemini service encounters rate limits or network issues:
- The backend gracefully returns a structured fallback response indicating AI unavailability.
- The core SOC dashboard, rule-based alerts, and manual investigative workflows continue functioning without interruption.
