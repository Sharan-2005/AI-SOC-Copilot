from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import SessionLocal
from app.models.mitre import MitreTechnique
from app.models.user import User

client = TestClient(app)

def test_clear_soc_data_endpoint():
    # 1. Ingest a quick event and alert to verify data exists
    event_payload = {
        "source": "auth.log",
        "event_type": "ssh_login_failed",
        "source_ip": "192.0.2.1",
        "destination_ip": "10.0.0.1",
        "raw_data": {"user": "test_clear"}
    }
    create_res = client.post("/api/events", json=event_payload)
    assert create_res.status_code in [200, 201]

    # 2. Call DELETE /api/system/clear-data
    res = client.delete("/api/system/clear-data")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "cleared successfully" in data["message"]

    # 3. Verify Events, Alerts, Incidents are empty
    events_res = client.get("/api/events")
    assert events_res.status_code == 200
    assert events_res.json().get("total", 0) == 0

    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    assert alerts_res.json().get("total", 0) == 0

    incidents_res = client.get("/api/incidents")
    assert incidents_res.status_code == 200
    assert incidents_res.json().get("total", 0) == 0

    # 4. Verify MITRE techniques and Users are preserved
    mitre_res = client.get("/api/mitre/techniques")
    assert mitre_res.status_code == 200
    assert len(mitre_res.json()) > 0

    db = SessionLocal()
    try:
        users_count = db.query(User).count()
        assert users_count >= 1
    finally:
        db.close()
