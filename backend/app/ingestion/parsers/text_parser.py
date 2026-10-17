import re
from typing import List, Dict, Any, Tuple

# Precompiled regex patterns for common security log entries
RE_FAILED_PASSWORD = re.compile(
    r'(?:Failed password for (?:invalid user )?(?P<user>\S+)|authentication failure;.*rhost=(?P<rhost>[\d\.]+)(?:.*user=(?P<ruser>\S+))?|failed login for (?P<fuser>\S+)) from (?P<ip>[\d\.]+)(?: port (?P<port>\d+))?',
    re.IGNORECASE
)
RE_ACCEPTED_PASSWORD = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.]+)(?: port (?P<port>\d+))?',
    re.IGNORECASE
)
RE_SUDO_COMMAND = re.compile(
    r'sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.*)',
    re.IGNORECASE
)
RE_CONNECTION = re.compile(
    r'(?:Connection|Connect|SYN) (?:from|to) (?P<ip>[\d\.]+)(?: port (?P<port>\d+))?',
    re.IGNORECASE
)
RE_HTTP_REQUEST = re.compile(
    r'(?P<ip>[\d\.]+)?.*?"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS) (?P<path>\S+) HTTP/\d\.\d"',
    re.IGNORECASE
)
RE_GENERIC_IP = re.compile(
    r'\b(?P<ip>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b'
)
RE_SYSLOG_HEADER = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:'
)

def parse_text_line(line: str) -> Dict[str, Any]:
    """Parse a single text or auth.log line into standard event fields."""
    record: Dict[str, Any] = {
        "raw_data": {"message": line},
        "event_type": "generic_log",
        "source": "auth_log"
    }

    # Extract syslog header if present (e.g. "Oct 12 09:15:20 soc-srv01 sshd[1234]: ...")
    syslog_match = RE_SYSLOG_HEADER.match(line)
    if syslog_match:
        record["timestamp"] = syslog_match.group("timestamp")
        record["host"] = syslog_match.group("host")

    # 1. Failed Login Check
    m = RE_FAILED_PASSWORD.search(line)
    if m:
        user = m.group("user") or m.group("ruser") or m.group("fuser") or "unknown"
        ip = m.group("ip") or m.group("rhost")
        port = m.group("port")
        record["event_type"] = "failed_login"
        record["source_ip"] = ip
        if port:
            record["source_port"] = int(port)
        record["raw_data"]["user"] = user
        return record

    # 2. Accepted Login Check
    m = RE_ACCEPTED_PASSWORD.search(line)
    if m:
        record["event_type"] = "successful_login"
        record["source_ip"] = m.group("ip")
        if m.group("port"):
            record["source_port"] = int(m.group("port"))
        record["raw_data"]["user"] = m.group("user")
        return record

    # 3. Sudo / Suspicious Command Check
    m = RE_SUDO_COMMAND.search(line)
    if m:
        record["event_type"] = "command_exec"
        record["raw_data"]["user"] = m.group("user")
        record["raw_data"]["command"] = m.group("cmd").strip()
        # Look for source IP in the line if available
        ip_m = RE_GENERIC_IP.search(line)
        if ip_m:
            record["source_ip"] = ip_m.group("ip")
        return record

    # 4. HTTP Request Check
    m = RE_HTTP_REQUEST.search(line)
    if m:
        record["event_type"] = "http_request"
        if m.group("ip"):
            record["source_ip"] = m.group("ip")
        record["raw_data"]["method"] = m.group("method")
        record["raw_data"]["path"] = m.group("path")
        return record

    # 5. Connection Check
    m = RE_CONNECTION.search(line)
    if m:
        record["event_type"] = "connection"
        record["source_ip"] = m.group("ip")
        if m.group("port"):
            record["destination_port"] = int(m.group("port"))
        return record

    # 6. Generic Fallback with IP extraction
    ip_m = RE_GENERIC_IP.search(line)
    if ip_m:
        record["source_ip"] = ip_m.group("ip")
    
    # Check if keyword indicates event type
    lower = line.lower()
    if "failed" in lower or "denied" in lower or "invalid user" in lower:
        record["event_type"] = "failed_login"
    elif "accepted" in lower or "session opened" in lower:
        record["event_type"] = "successful_login"
    elif "command" in lower or "exec" in lower:
        record["event_type"] = "command_exec"

    return record

def parse_text_content(content: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses plaintext / log content line by line.
    Returns (valid_records, failed_count).
    """
    records: List[Dict[str, Any]] = []
    failed_count = 0

    for line in content.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        try:
            record = parse_text_line(line_clean)
            records.append(record)
        except Exception:
            failed_count += 1

    return records, failed_count
