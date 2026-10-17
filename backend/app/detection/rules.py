import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, desc

from app.models.event import Event
from app.schemas.alert import AlertCreate

# Regex patterns for rules
SUSPICIOUS_COMMAND_PATTERNS = [
    re.compile(r'\bpowershell(?:\.exe)?\b', re.IGNORECASE),
    re.compile(r'\bcmd\.exe\b', re.IGNORECASE),
    re.compile(r'\bbash\s+-c\b', re.IGNORECASE),
    re.compile(r'\bwhoami\b', re.IGNORECASE),
    re.compile(r'\bnet\s+(?:user|group|localgroup)\b', re.IGNORECASE),
    re.compile(r'(?:curl|wget)\s+.*?\s*\|\s*(?:sh|bash)', re.IGNORECASE),
    re.compile(r'\bnc\s+(?:-[a-zA-Z]*e|--exec)\b', re.IGNORECASE),
    re.compile(r'/etc/(?:passwd|shadow)', re.IGNORECASE),
]

WEB_ATTACK_PATTERNS = [
    re.compile(r'UNION\s+SELECT', re.IGNORECASE),
    re.compile(r"'\s*OR\s*(?:'1'='1'|1=1)", re.IGNORECASE),
    re.compile(r'\.\./|\.\.\\|%2e%2e%2f', re.IGNORECASE),
    re.compile(r'<script\b[^>]*>.*?</script>', re.IGNORECASE),
    re.compile(r'SLEEP\s*\(\s*\d+\s*\)', re.IGNORECASE),
]

PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(r'\bsudo\s+(?:su\b|bash\b|sh\b|chmod\b|visudo\b)', re.IGNORECASE),
    re.compile(r'\bsu\s+-\s*root\b|\bsu\s+root\b', re.IGNORECASE),
    re.compile(r'/etc/sudoers', re.IGNORECASE),
    re.compile(r'\busermod\s+-aG\s+(?:sudo|wheel|admin)\b', re.IGNORECASE),
    re.compile(r'\bchown\s+root\b', re.IGNORECASE),
]

def check_brute_force(events: List[Event], db: Session) -> List[AlertCreate]:
    """
    RULE 1: Brute Force Detection
    If same source_ip produces > 10 failed login attempts within window:
    Alert: Possible Brute Force Attack [MITRE T1110]
    """
    alerts: List[AlertCreate] = []
    failed_by_ip: Dict[str, List[Event]] = {}

    for ev in events:
        is_failed = False
        if ev.event_type in ("failed_login", "auth_failed", "login_failed"):
            is_failed = True
        elif ev.raw_data:
            text = str(ev.raw_data).lower()
            if "failed password" in text or "authentication failure" in text or "failed login" in text:
                is_failed = True

        if is_failed and ev.source_ip:
            failed_by_ip.setdefault(ev.source_ip, []).append(ev)

    for ip, ip_events in failed_by_ip.items():
        total_count = len(ip_events)
        
        # Only query recent failed logins from database if this is a small incremental batch
        if total_count <= 10 and len(events) <= 20:
            ten_min_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
            db_failed = db.scalars(
                select(Event)
                .where(
                    and_(
                        Event.source_ip == ip,
                        Event.event_type == "failed_login",
                        Event.timestamp >= ten_min_ago
                    )
                )
                .limit(20)
            ).all()
            total_count = max(total_count, len(db_failed))

        if total_count > 10:
            latest_ev = ip_events[-1]
            alerts.append(AlertCreate(
                title="Possible Brute Force Attack",
                description=f"Observed {total_count} failed login attempts from source IP {ip} within the detection window. [MITRE ATT&CK T1110]",
                source_ip=ip,
                destination_ip=latest_ev.destination_ip,
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_01_BRUTE_FORCE",
                event_id=latest_ev.id,
                timestamp=latest_ev.timestamp
            ))

    return alerts

def check_port_scan(events: List[Event], db: Session) -> List[AlertCreate]:
    """
    RULE 2: Port Scan Detection
    If same source_ip accesses many different destination ports in short period:
    Alert: Possible Network Service Scanning [MITRE T1046]
    """
    alerts: List[AlertCreate] = []
    ports_by_ip: Dict[str, Dict[int, Event]] = {}

    for ev in events:
        if ev.source_ip and ev.destination_port:
            ports_by_ip.setdefault(ev.source_ip, {})[ev.destination_port] = ev

    for ip, port_map in ports_by_ip.items():
        unique_ports = len(port_map)
        
        # Check if >= 8 ports probed (only query DB for small batches)
        if unique_ports < 8 and len(events) <= 20:
            five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
            db_events = db.scalars(
                select(Event)
                .where(
                    and_(
                        Event.source_ip == ip,
                        Event.destination_port.isnot(None),
                        Event.timestamp >= five_min_ago
                    )
                )
                .limit(50)
            ).all()
            for dbev in db_events:
                if dbev.destination_port:
                    port_map[dbev.destination_port] = dbev
            unique_ports = len(port_map)

        if unique_ports >= 8:
            latest_ev = list(port_map.values())[-1]
            alerts.append(AlertCreate(
                title="Possible Network Service Scanning",
                description=f"Source IP {ip} probed {unique_ports} distinct destination ports in a short time window. [MITRE ATT&CK T1046]",
                source_ip=ip,
                destination_ip=latest_ev.destination_ip,
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_02_PORT_SCAN",
                event_id=latest_ev.id,
                timestamp=latest_ev.timestamp
            ))

    return alerts

def check_suspicious_commands(events: List[Event]) -> List[AlertCreate]:
    """
    RULE 3: Suspicious Command Detection
    Detect clearly suspicious command execution patterns (powershell, cmd.exe, bash -c, whoami, net user, curl|sh).
    [MITRE T1059]
    """
    alerts: List[AlertCreate] = []

    for ev in events:
        payload_text = ""
        if ev.raw_data:
            if isinstance(ev.raw_data, dict):
                payload_text = " ".join(str(v) for v in ev.raw_data.values())
            else:
                payload_text = str(ev.raw_data)

        matched_pattern = None
        for pat in SUSPICIOUS_COMMAND_PATTERNS:
            m = pat.search(payload_text)
            if m:
                matched_pattern = m.group(0)
                break

        if matched_pattern:
            alerts.append(AlertCreate(
                title="Suspicious Command Execution Detected",
                description=f"Suspicious command pattern '{matched_pattern}' detected in event payload from source {ev.source_ip or ev.host or 'local system'}. [MITRE ATT&CK T1059]",
                source_ip=ev.source_ip,
                destination_ip=ev.destination_ip,
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_03_SUSPICIOUS_COMMAND",
                event_id=ev.id,
                timestamp=ev.timestamp
            ))

    return alerts

def check_web_attacks(events: List[Event]) -> List[AlertCreate]:
    """
    RULE 4: Web Attack Detection
    Detect simple SQL injection or suspicious web attack patterns (UNION SELECT, ' OR 1=1, ../).
    [MITRE T1190]
    """
    alerts: List[AlertCreate] = []

    for ev in events:
        payload_text = ""
        if ev.raw_data:
            if isinstance(ev.raw_data, dict):
                payload_text = " ".join(str(v) for v in ev.raw_data.values())
            else:
                payload_text = str(ev.raw_data)

        matched_pattern = None
        for pat in WEB_ATTACK_PATTERNS:
            m = pat.search(payload_text)
            if m:
                matched_pattern = m.group(0)
                break

        if matched_pattern:
            alerts.append(AlertCreate(
                title="Possible Web Attack",
                description=f"Web exploit signature '{matched_pattern}' detected in HTTP telemetry from source IP {ev.source_ip or 'unknown'}. [MITRE ATT&CK T1190]",
                source_ip=ev.source_ip,
                destination_ip=ev.destination_ip,
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_04_WEB_ATTACK",
                event_id=ev.id,
                timestamp=ev.timestamp
            ))

    return alerts

def check_privilege_escalation(events: List[Event]) -> List[AlertCreate]:
    """
    RULE 5: Privilege Escalation Detection
    Detect obvious privilege escalation indicators (sudo, su, modify privileged accounts).
    [MITRE T1548]
    """
    alerts: List[AlertCreate] = []

    for ev in events:
        payload_text = ""
        if ev.raw_data:
            if isinstance(ev.raw_data, dict):
                payload_text = " ".join(str(v) for v in ev.raw_data.values())
            else:
                payload_text = str(ev.raw_data)

        matched_pattern = None
        for pat in PRIVILEGE_ESCALATION_PATTERNS:
            m = pat.search(payload_text)
            if m:
                matched_pattern = m.group(0)
                break

        if matched_pattern:
            alerts.append(AlertCreate(
                title="Possible Privilege Escalation",
                description=f"Privilege escalation indicator '{matched_pattern}' detected in event telemetry. [MITRE ATT&CK T1548]",
                source_ip=ev.source_ip,
                destination_ip=ev.destination_ip,
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_05_PRIVILEGE_ESCALATION",
                event_id=ev.id,
                timestamp=ev.timestamp
            ))

    return alerts
