import io
import json
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_upload_json_log():
    """Verify uploading a JSON security log file."""
    json_data = [
        {
            "timestamp": "2026-09-17T12:00:00Z",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "destination_port": 80,
            "event_type": "http_request",
            "raw_data": {"path": "/index.html", "method": "GET"}
        },
        {
            "timestamp": "2026-09-17T12:01:00Z",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "destination_port": 443,
            "event_type": "http_request",
            "raw_data": {"path": "/login", "method": "POST"}
        }
    ]
    file_bytes = json.dumps(json_data).encode("utf-8")
    response = client.post(
        "/api/logs/upload",
        files={"file": ("access_log.json", io.BytesIO(file_bytes), "application/json")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "access_log.json"
    assert data["format"] == "json"
    assert data["total_records"] == 2
    assert data["parsed_records"] == 2
    assert data["failed_records"] == 0

def test_upload_csv_log():
    """Verify uploading a CSV security log file."""
    csv_content = (
        "timestamp,source_ip,destination_ip,destination_port,event_type\n"
        "2026-09-17 12:00:00,10.10.10.50,192.168.1.1,53,dns_query\n"
        "2026-09-17 12:00:05,10.10.10.50,192.168.1.1,53,dns_query\n"
    )
    response = client.post(
        "/api/logs/upload",
        files={"file": ("network.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "network.csv"
    assert data["format"] == "csv"
    assert data["parsed_records"] == 2

def test_parse_basic_text_log():
    """Verify parsing a plain text auth.log file with SSH failed logins."""
    text_content = (
        "Sep 17 12:05:01 auth-srv sshd[101]: Failed password for invalid user admin from 198.51.100.22 port 54321 ssh2\n"
        "Sep 17 12:05:02 auth-srv sshd[102]: Accepted password for deploy from 10.0.0.15 port 49100 ssh2\n"
    )
    response = client.post(
        "/api/logs/upload",
        files={"file": ("auth.log", io.BytesIO(text_content.encode("utf-8")), "text/plain")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "auth.log"
    assert data["parsed_records"] == 2
    assert data["failed_records"] == 0

def test_brute_force_detection():
    """Verify RULE 1: > 10 failed login attempts from same IP generates Brute Force Alert (T1110)."""
    attacker_ip = "203.0.113.88"
    lines = []
    for i in range(12):
        lines.append(f"Sep 17 13:00:{i:02d} auth-srv sshd[{200+i}]: Failed password for user user{i} from {attacker_ip} port {50000+i} ssh2")

    content = "\n".join(lines)
    response = client.post(
        "/api/logs/upload",
        files={"file": ("brute_force.log", io.BytesIO(content.encode("utf-8")), "text/plain")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parsed_records"] == 12
    assert data["alerts_created"] >= 1

    # Verify alert exists in /api/alerts
    alerts_res = client.get(f"/api/alerts?source_ip={attacker_ip}")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()["items"]
    assert any(a["detection_rule"] == "RULE_01_BRUTE_FORCE" for a in alerts_data)
    bf_alert = next(a for a in alerts_data if a["detection_rule"] == "RULE_01_BRUTE_FORCE")
    assert bf_alert["title"] == "Possible Brute Force Attack"
    assert bf_alert["severity"] == "HIGH"

def test_port_scan_detection():
    """Verify RULE 2: Accessing multiple distinct destination ports generates Port Scan Alert (T1046)."""
    attacker_ip = "198.51.100.99"
    scan_records = []
    for port in [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080]:
        scan_records.append({
            "source": "simulator",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.5",
            "destination_port": port,
            "protocol": "TCP",
            "event_type": "connection",
            "raw_data": {"flag": "SYN", "port": port}
        })

    response = client.post(
        "/api/logs/upload",
        files={"file": ("port_scan.json", io.BytesIO(json.dumps(scan_records).encode("utf-8")), "application/json")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["alerts_created"] >= 1

    # Verify alert exists
    alerts_res = client.get(f"/api/alerts?source_ip={attacker_ip}")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()["items"]
    assert any(a["detection_rule"] == "RULE_02_PORT_SCAN" for a in alerts_data)
    ps_alert = next(a for a in alerts_data if a["detection_rule"] == "RULE_02_PORT_SCAN")
    assert ps_alert["title"] == "Possible Network Service Scanning"

def test_web_attack_detection():
    """Verify RULE 4: SQL Injection payload triggers Web Attack Alert (T1190)."""
    attacker_ip = "192.0.2.45"
    event_payload = {
        "source": "web_server",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "destination_port": 80,
        "protocol": "HTTP",
        "event_type": "http_request",
        "raw_data": {
            "method": "GET",
            "path": "/products.php?id=1' UNION SELECT user, password FROM accounts--",
            "status": 200
        }
    }
    # Posting single event to /api/events
    res = client.post("/api/events", json=event_payload)
    assert res.status_code == 201

    # Check alert was created
    alerts_res = client.get(f"/api/alerts?source_ip={attacker_ip}")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()["items"]
    assert any(a["detection_rule"] == "RULE_04_WEB_ATTACK" for a in alerts_data)

def test_suspicious_command_and_privilege_escalation():
    """Verify RULE 3 (Suspicious Command T1059) and RULE 5 (Privilege Escalation T1548)."""
    # 1. Suspicious command
    res1 = client.post("/api/events", json={
        "source": "endpoint",
        "host": "workstation-02",
        "source_ip": "10.0.0.77",
        "event_type": "command_exec",
        "raw_data": {"command": "powershell.exe -enc dGVzdA=="}
    })
    assert res1.status_code == 201

    alerts_res = client.get("/api/alerts?source_ip=10.0.0.77")
    assert any(a["detection_rule"] == "RULE_03_SUSPICIOUS_COMMAND" for a in alerts_res.json()["items"])

    # 2. Privilege escalation
    res2 = client.post("/api/events", json={
        "source": "endpoint",
        "host": "workstation-02",
        "source_ip": "10.0.0.88",
        "event_type": "command_exec",
        "raw_data": {"command": "sudo visudo -f /etc/sudoers"}
    })
    assert res2.status_code == 201

    alerts_res2 = client.get("/api/alerts?source_ip=10.0.0.88")
    assert any(a["detection_rule"] == "RULE_05_PRIVILEGE_ESCALATION" for a in alerts_res2.json()["items"])

def test_incident_correlation():
    """Verify basic incident correlation links multiple alerts from same source IP into an Incident."""
    target_ip = "198.51.100.7"
    
    # 1. Trigger Port Scan
    scan_records = []
    for port in [21, 22, 23, 25, 80, 110, 143, 443, 3389]:
        scan_records.append({
            "source": "simulator",
            "source_ip": target_ip,
            "destination_port": port,
            "event_type": "connection",
            "raw_data": {"port": port}
        })
    client.post(
        "/api/logs/upload",
        files={"file": ("scan.json", io.BytesIO(json.dumps(scan_records).encode("utf-8")), "application/json")}
    )

    # 2. Trigger Brute Force from same IP
    lines = [f"Sep 17 14:00:{i:02d} srv sshd[{i}]: Failed password for user{i} from {target_ip} port {51000+i}" for i in range(12)]
    client.post(
        "/api/logs/upload",
        files={"file": ("bf.log", io.BytesIO("\n".join(lines).encode("utf-8")), "text/plain")}
    )

    # 3. Check Incidents
    incidents_res = client.get("/api/incidents")
    assert incidents_res.status_code == 200
    incidents = incidents_res.json()["items"]
    # Check that at least one incident mentions target_ip
    matching_incidents = [inc for inc in incidents if target_ip in (inc["title"] + (inc["summary"] or ""))]
    assert len(matching_incidents) >= 1
    assert matching_incidents[0]["status"] == "OPEN"

def test_simulator_endpoints():
    """Verify simulator endpoints function properly."""
    res = client.post("/api/simulator/brute-force")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["scenario"] == "brute_force"
    assert data["events_generated"] == 12

def test_reject_unsupported_file_extension():
    """Verify backend rejects unallowed file extensions (.exe, .pdf, .py, etc.) with HTTP 400."""
    invalid_files = [
        ("malware.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/x-msdownload"),
        ("document.pdf", b"%PDF-1.4 ...", "application/pdf"),
        ("exploit.py", b"import os; os.system('calc')", "text/x-python"),
        ("archive.zip", b"PK\x03\x04", "application/zip"),
    ]
    for filename, content, mime in invalid_files:
        response = client.post(
            "/api/logs/upload",
            files={"file": (filename, io.BytesIO(content), mime)}
        )
        assert response.status_code == 400
        data = response.json()
        assert "Unsupported file format" in data["detail"]
        assert "Only .log, .txt, .json, and .csv files are permitted" in data["detail"]

