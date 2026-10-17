import re
from typing import List, Dict, Any, Tuple

# Apache / Nginx Combined Log Regex
RE_COMBINED_LOG = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>.*?)\s+(?P<proto>\S+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>.*?)"\s+"(?P<agent>.*?)")?',
    re.IGNORECASE
)

def parse_apache_content(content: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses Apache/Nginx web server access logs.
    Returns (valid_records, failed_count).
    """
    records: List[Dict[str, Any]] = []
    failed_count = 0

    for line in content.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        m = RE_COMBINED_LOG.match(line_clean)
        if m:
            ip = m.group("ip")
            method = m.group("method")
            path = m.group("path")
            status = int(m.group("status"))
            records.append({
                "timestamp": m.group("time"),
                "source": "apache_access",
                "source_ip": ip,
                "destination_port": 80 if status != 443 else 443,
                "protocol": "HTTP",
                "event_type": "http_request",
                "raw_data": {
                    "method": method,
                    "path": path,
                    "status_code": status,
                    "user_agent": m.group("agent") or "",
                    "original_line": line_clean
                }
            })
        else:
            failed_count += 1

    return records, failed_count
