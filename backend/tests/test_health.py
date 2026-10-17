from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "AI SOC Copilot API" in data["message"]
    assert data["health_check"] == "/api/health"

def test_health_endpoint_structure():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "AI SOC Copilot Backend"
    assert "version" in data
    assert "database" in data
    assert data["database"]["dialect"] == "postgresql"
    assert "connected" in data["database"]
