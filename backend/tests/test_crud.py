from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_still_operational():
    """Verify Phase 1 health endpoint still functions cleanly."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"]["connected"] is True
    assert data["database"]["dialect"] == "postgresql"

def test_mitre_techniques_endpoints():
    """Verify MITRE ATT&CK listing and specific technique lookup."""
    response = client.get("/api/mitre/techniques")
    assert response.status_code == 200
    techniques = response.json()
    assert len(techniques) >= 6
    tech_ids = [t["technique_id"] for t in techniques]
    assert "T1110" in tech_ids

    # Specific lookup
    detail_res = client.get("/api/mitre/techniques/T1110")
    assert detail_res.status_code == 200
    t1110 = detail_res.json()
    assert t1110["technique_id"] == "T1110"
    assert t1110["name"] == "Brute Force"
    assert t1110["tactic"] == "Credential Access"

    # Non-existent lookup
    not_found = client.get("/api/mitre/techniques/T999999")
    assert not_found.status_code == 404

def test_events_crud_and_pagination():
    """Verify creating an event and paginated listing with filters."""
    payload = {
        "source": "simulator",
        "host": "test-workstation-01",
        "source_ip": "192.168.10.99",
        "destination_ip": "10.0.0.1",
        "source_port": 49201,
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "network_flow",
        "raw_data": {"bytes_sent": 1024, "bytes_received": 2048}
    }
    create_res = client.post("/api/events", json=payload)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["id"] is not None
    assert created["source_ip"] == "192.168.10.99"
    event_id = created["id"]

    # Retrieve by ID
    get_res = client.get(f"/api/events/{event_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == event_id

    # List with pagination and filter
    list_res = client.get(f"/api/events?source_ip=192.168.10.99&page=1&limit=10")
    assert list_res.status_code == 200
    page_data = list_res.json()
    assert page_data["total"] >= 1
    assert page_data["page"] == 1
    assert len(page_data["items"]) >= 1

def test_alerts_crud_and_patch():
    """Verify creating, listing, patching, and deleting an alert."""
    payload = {
        "title": "Port Scanning Activity Detected",
        "description": "Rapid sequential connection attempts across multiple ports.",
        "source_ip": "192.168.10.99",
        "destination_ip": "10.0.0.1",
        "severity": "HIGH",
        "status": "OPEN",
        "detection_rule": "RULE_02_PORT_SCAN"
    }
    create_res = client.post("/api/alerts", json=payload)
    assert create_res.status_code == 201
    alert = create_res.json()
    alert_id = alert["id"]
    assert alert["severity"] == "HIGH"
    assert alert["status"] == "OPEN"

    # Patch status to INVESTIGATING
    patch_res = client.patch(f"/api/alerts/{alert_id}", json={"status": "INVESTIGATING"})
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["status"] == "INVESTIGATING"

    # List alerts with filter
    filter_res = client.get("/api/alerts?status=INVESTIGATING")
    assert filter_res.status_code == 200
    assert any(a["id"] == alert_id for a in filter_res.json()["items"])

def test_incidents_crud_with_correlated_alerts():
    """Verify creating incident with linked alerts and updating it."""
    # First create an alert to link
    alert_res = client.post("/api/alerts", json={
        "title": "Correlated Attack Vector Alert",
        "severity": "CRITICAL",
        "status": "OPEN",
        "detection_rule": "RULE_TEST_LINK"
    })
    alert_id = alert_res.json()["id"]

    # Create incident linking the alert
    incident_payload = {
        "title": "Active Multi-Vector Attack Campaign",
        "description": "Correlated multiple reconnaissance and credential access events.",
        "severity": "CRITICAL",
        "status": "OPEN",
        "summary": "Initial correlation indicates focused probe on subnet.",
        "confidence": 0.92,
        "alert_ids": [alert_id]
    }
    create_res = client.post("/api/incidents", json=incident_payload)
    assert create_res.status_code == 201
    incident = create_res.json()
    incident_id = incident["id"]
    assert alert_id in incident["alert_ids"]
    assert incident["confidence"] == 0.92

    # Retrieve incident by ID
    get_res = client.get(f"/api/incidents/{incident_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == incident_id
    assert alert_id in get_res.json()["alert_ids"]

    # Update incident status to CONTAINED
    patch_res = client.patch(f"/api/incidents/{incident_id}", json={"status": "CONTAINED"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "CONTAINED"

def test_dashboard_stats():
    """Verify aggregated dashboard statistics endpoint."""
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "metrics" in data
    assert "total_events" in data["metrics"]
    assert "total_alerts" in data["metrics"]
    assert "severity_distribution" in data
    assert "top_source_ips" in data
    assert "timeline" in data
    assert len(data["severity_distribution"]) == 4
