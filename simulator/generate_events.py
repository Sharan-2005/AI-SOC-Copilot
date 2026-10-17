#!/usr/bin/env python3
"""
AI SOC Copilot - Security Event Simulator
Simulates real-world attack patterns by sending realistic security telemetry to the backend API.

Usage:
    python simulator/generate_events.py --scenario brute_force
    python simulator/generate_events.py --scenario port_scan
    python simulator/generate_events.py --scenario web_attack
    python simulator/generate_events.py --scenario all
"""

import argparse
import sys
import time
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

DEFAULT_API_URL = "http://127.0.0.1:8000"

def post_event(base_url: str, event_data: dict) -> bool:
    """Post an event to /api/events."""
    url = f"{base_url}/api/events"
    req_body = json.dumps(event_data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_body,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except urllib.error.URLError as e:
        print(f"  [-] Connection error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  [-] Error sending event: {e}", file=sys.stderr)
        return False

def run_brute_force_scenario(base_url: str, attacker_ip: str = "192.168.1.185", target_ip: str = "10.0.0.5"):
    print(f"\n[+] Starting Scenario: Brute Force Attack against {target_ip} from {attacker_ip}...")
    usernames = ["admin", "root", "ubuntu", "guest", "oracle", "user", "test", "deploy", "service", "backup", "operator", "sysadmin"]

    for i, user in enumerate(usernames, 1):
        event = {
            "source": "simulator",
            "host": "auth-srv-01",
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 49150 + i,
            "destination_port": 22,
            "protocol": "TCP",
            "event_type": "failed_login",
            "raw_data": {
                "message": f"Failed password for invalid user {user} from {attacker_ip} port {49150 + i} ssh2",
                "user": user,
                "attempt": i
            }
        }
        ok = post_event(base_url, event)
        status_sym = "[OK]" if ok else "[FAIL]"
        print(f"  {status_sym} Attempt {i:02d}/12: Failed login for '{user}'")
        time.sleep(0.1)

    print("[*] Brute Force scenario complete. Detection engine will flag T1110 (Brute Force).")

def run_port_scan_scenario(base_url: str, attacker_ip: str = "192.168.1.185", target_ip: str = "10.0.0.5"):
    print(f"\n[+] Starting Scenario: Network Service Scanning against {target_ip} from {attacker_ip}...")
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]

    for i, port in enumerate(ports, 1):
        event = {
            "source": "simulator",
            "host": "gateway-fw-01",
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 53000 + i,
            "destination_port": port,
            "protocol": "TCP",
            "event_type": "connection",
            "raw_data": {
                "message": f"TCP SYN connection to port {port}",
                "flag": "SYN",
                "probed_port": port
            }
        }
        ok = post_event(base_url, event)
        status_sym = "[OK]" if ok else "[FAIL]"
        print(f"  {status_sym} Probed port {port:5d}/TCP ({i:02d}/{len(ports)})")
        time.sleep(0.08)

    print("[*] Port Scan scenario complete. Detection engine will flag T1046 (Network Scanning).")

def run_web_attack_scenario(base_url: str, attacker_ip: str = "192.168.1.185", target_ip: str = "10.0.0.5"):
    print(f"\n[+] Starting Scenario: Web Application Attack against {target_ip} from {attacker_ip}...")
    payloads = [
        ("GET", "/products?cat=1' UNION SELECT username, password_hash FROM users--", "SQL Injection Probe"),
        ("GET", "/view?page=../../../../etc/passwd", "Path Traversal / LFI Probe"),
        ("POST", "/login?user=' OR 1=1--", "SQL Auth Bypass Attempt"),
        ("GET", "/execute?cmd=whoami; powershell.exe -enc dGVzdA==", "Command Injection in query param"),
    ]

    for i, (method, path, label) in enumerate(payloads, 1):
        event = {
            "source": "simulator",
            "host": "web-srv-01",
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 48200 + i,
            "destination_port": 80,
            "protocol": "HTTP",
            "event_type": "http_request",
            "raw_data": {
                "method": method,
                "path": path,
                "payload": path,
                "type": label
            }
        }
        ok = post_event(base_url, event)
        status_sym = "[OK]" if ok else "[FAIL]"
        print(f"  {status_sym} Sent {method} request: {label}")
        time.sleep(0.1)

    print("[*] Web Attack scenario complete. Detection engine will flag T1190 / T1059.")

def main():
    parser = argparse.ArgumentParser(description="AI SOC Copilot - Attack Simulator")
    parser.add_argument(
        "--scenario",
        choices=["brute_force", "port_scan", "web_attack", "all"],
        default="brute_force",
        help="Attack scenario to simulate"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_API_URL,
        help="Target backend base URL (default: http://127.0.0.1:8000)"
    )

    args = parser.parse_args()
    base_url = args.host.rstrip("/")

    print("=" * 60)
    print(" AI SOC COPILOT - ATTACK SCENARIO SIMULATOR")
    print(f" Target Backend: {base_url}")
    print(f" Scenario:       {args.scenario}")
    print("=" * 60)

    try:
        # Check health first
        with urllib.request.urlopen(f"{base_url}/api/health", timeout=5) as resp:
            if resp.status != 200:
                print(f"[!] Warning: Backend health responded with {resp.status}")
    except Exception as e:
        print(f"[!] Error: Could not connect to backend at {base_url}: {e}")
        sys.exit(1)

    if args.scenario in ("brute_force", "all"):
        run_brute_force_scenario(base_url)
    if args.scenario in ("port_scan", "all"):
        run_port_scan_scenario(base_url)
    if args.scenario in ("web_attack", "all"):
        run_web_attack_scenario(base_url)

    print("\n[SUCCESS] Simulation finished successfully.", flush=True)
    print("[*] Check your SOC Dashboard at http://localhost:5173 to review generated Alerts and Incidents!", flush=True)

if __name__ == "__main__":
    main()
