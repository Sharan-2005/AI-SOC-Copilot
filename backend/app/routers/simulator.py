import datetime
from datetime import timezone
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.event import Event
from app.detection.detection_engine import run_detection

router = APIRouter(prefix="/api/simulator", tags=["Attack Simulator"])

def generate_brute_force_events(attacker_ip: str = "192.168.1.185", target_ip: str = "10.0.0.5") -> List[Event]:
    """Generates 12 rapid failed SSH authentication attempts."""
    events = []
    usernames = ["admin", "root", "ubuntu", "guest", "oracle", "user", "test", "deploy", "service", "backup", "operator", "sysadmin"]
    now = datetime.datetime.now(timezone.utc)

    for i, user in enumerate(usernames):
        ts = now - datetime.timedelta(seconds=(12 - i) * 3)
        events.append(Event(
            timestamp=ts,
            source="simulator",
            host="auth-srv-01",
            source_ip=attacker_ip,
            destination_ip=target_ip,
            source_port=49152 + i,
            destination_port=22,
            protocol="TCP",
            event_type="failed_login",
            raw_data={
                "message": f"Failed password for invalid user {user} from {attacker_ip} port {49152 + i} ssh2",
                "user": user,
                "attempt": i + 1
            }
        ))
    return events

def generate_port_scan_events(attacker_ip: str = "192.168.1.185", target_ip: str = "10.0.0.5") -> List[Event]:
    """Generates rapid TCP connection attempts across 12 distinct destination ports."""
    events = []
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    now = datetime.datetime.now(timezone.utc)

    for i, port in enumerate(ports):
        ts = now - datetime.timedelta(seconds=(len(ports) - i) * 2)
        events.append(Event(
            timestamp=ts,
            source="simulator",
            host="gateway-fw-01",
            source_ip=attacker_ip,
            destination_ip=target_ip,
            source_port=52000 + i,
            destination_port=port,
            protocol="TCP",
            event_type="connection",
            raw_data={
                "message": f"TCP SYN connection from {attacker_ip}:{52000 + i} to {target_ip}:{port}",
                "flag": "SYN",
                "probed_port": port
            }
        ))
    return events

def generate_web_attack_events(attacker_ip: str = "192.168.1.185", target_ip: str = "10.0.0.5") -> List[Event]:
    """Generates web attack payloads (SQL Injection, Directory Traversal)."""
    events = []
    payloads = [
        ("GET", "/api/products?cat=1' UNION SELECT username, password_hash FROM users--", 200),
        ("POST", "/login.php", 401),
        ("GET", "/download.php?file=../../../../etc/passwd", 403),
        ("GET", "/search?q=' OR 1=1--", 200),
    ]
    now = datetime.datetime.now(timezone.utc)

    for i, (method, path, status) in enumerate(payloads):
        ts = now - datetime.timedelta(seconds=(len(payloads) - i) * 4)
        events.append(Event(
            timestamp=ts,
            source="simulator",
            host="web-app-01",
            source_ip=attacker_ip,
            destination_ip=target_ip,
            source_port=48100 + i,
            destination_port=80,
            protocol="HTTP",
            event_type="http_request",
            raw_data={
                "method": method,
                "path": path,
                "status_code": status,
                "user_agent": "Mozilla/5.0 (Security Scanner)",
                "payload": path
            }
        ))
    return events

def _execute_simulation(events: List[Event], scenario_name: str, db: Session) -> Dict[str, Any]:
    for ev in events:
        db.add(ev)
    db.commit()
    for ev in events:
        db.refresh(ev)

    alerts, incidents = run_detection(events, db)
    return {
        "status": "success",
        "scenario": scenario_name,
        "events_generated": len(events),
        "alerts_created": len(alerts),
        "incidents_created": len(incidents),
        "alerts": [{"id": a.id, "title": a.title, "severity": a.severity, "rule": a.detection_rule} for a in alerts]
    }

@router.post("/brute-force")
def simulate_brute_force(db: Session = Depends(get_db)):
    """Simulate Brute Force Attack Scenario (T1110)."""
    events = generate_brute_force_events()
    return _execute_simulation(events, "brute_force", db)

@router.post("/port-scan")
def simulate_port_scan(db: Session = Depends(get_db)):
    """Simulate Network Port Scan Scenario (T1046)."""
    events = generate_port_scan_events()
    return _execute_simulation(events, "port_scan", db)

@router.post("/web-attack")
def simulate_web_attack(db: Session = Depends(get_db)):
    """Simulate Web Exploit / SQLi / Traversal Scenario (T1190)."""
    events = generate_web_attack_events()
    return _execute_simulation(events, "web_attack", db)

@router.post("/icmp-flood")
def simulate_icmp_flood():
    """Simulate Possible ICMP DoS Flood Scenario."""
    from app.services.icmp_monitor import icmp_monitor_service
    return icmp_monitor_service.simulate_traffic(scenario="dos")

@router.post("/icmp-ddos")
def simulate_icmp_ddos():
    """Simulate Possible ICMP Distributed DDoS Flood Scenario."""
    from app.services.icmp_monitor import icmp_monitor_service
    return icmp_monitor_service.simulate_traffic(scenario="ddos")

@router.post("/run")
def run_scenario(scenario: str = Query(default="brute_force"), db: Session = Depends(get_db)):
    """Run specified simulation scenario."""
    sc = scenario.lower().strip()
    if sc in ("brute_force", "brute-force"):
        return simulate_brute_force(db)
    elif sc in ("port_scan", "port-scan"):
        return simulate_port_scan(db)
    elif sc in ("web_attack", "web-attack"):
        return simulate_web_attack(db)
    elif sc in ("icmp_flood", "icmp-flood", "icmp_dos"):
        return simulate_icmp_flood()
    elif sc in ("icmp_ddos", "icmp-ddos"):
        return simulate_icmp_ddos()
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{scenario}'. Choose from: brute_force, port_scan, web_attack, icmp_flood, icmp_ddos"
        )
