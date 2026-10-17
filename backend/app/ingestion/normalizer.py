import datetime
from datetime import timezone
import re
from typing import Dict, Any, Optional

COMMON_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S%z",
    "%b %d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
]

def parse_iso_or_flexible_timestamp(val: Any) -> datetime.datetime:
    """Parse flexible timestamp using Python standard library."""
    if not val:
        return datetime.datetime.now(timezone.utc)
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(val, tz=timezone.utc)
        except Exception:
            return datetime.datetime.now(timezone.utc)

    if isinstance(val, str):
        val_str = val.strip()
        # Try fromisoformat (Python 3.11+ supports most ISO variants including 'Z')
        try:
            clean_str = val_str.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Try standard formats
        for fmt in COMMON_DATE_FORMATS:
            try:
                dt = datetime.datetime.strptime(val_str, fmt)
                if dt.tzinfo is None:
                    # If format is syslog like 'Oct 11 14:32:10', year defaults to 1900 -> fix year
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.datetime.now().year)
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                continue

    return datetime.datetime.now(timezone.utc)

def normalize_port(val: Any) -> Optional[int]:
    """Safely convert port to integer or return None."""
    if val is None or val == "" or val == "-":
        return None
    try:
        p = int(val)
        if 1 <= p <= 65535:
            return p
        return None
    except (ValueError, TypeError):
        return None

def normalize_event_dict(raw_record: Dict[str, Any], default_source: str = "log_upload") -> Dict[str, Any]:
    """
    Converts a loosely structured log dictionary into canonical Event model fields.
    Does not invent data; missing fields default to None. Preserves raw_record.
    """
    # 1. Timestamps
    raw_ts = (
        raw_record.get("timestamp")
        or raw_record.get("time")
        or raw_record.get("@timestamp")
        or raw_record.get("datetime")
        or raw_record.get("date")
    )
    timestamp = parse_iso_or_flexible_timestamp(raw_ts)

    # 2. Source & Host
    source = raw_record.get("source") or default_source
    host = raw_record.get("host") or raw_record.get("hostname") or raw_record.get("server") or None

    # 3. Network Addresses & Ports
    source_ip = (
        raw_record.get("source_ip")
        or raw_record.get("src_ip")
        or raw_record.get("src")
        or raw_record.get("client_ip")
        or raw_record.get("ip")
        or None
    )
    if source_ip and isinstance(source_ip, str):
        source_ip = source_ip.strip()

    destination_ip = (
        raw_record.get("destination_ip")
        or raw_record.get("dst_ip")
        or raw_record.get("dst")
        or raw_record.get("server_ip")
        or raw_record.get("target_ip")
        or None
    )
    if destination_ip and isinstance(destination_ip, str):
        destination_ip = destination_ip.strip()

    source_port = normalize_port(
        raw_record.get("source_port")
        or raw_record.get("src_port")
        or raw_record.get("sport")
    )
    destination_port = normalize_port(
        raw_record.get("destination_port")
        or raw_record.get("dst_port")
        or raw_record.get("dport")
        or raw_record.get("port")
    )

    # 4. Protocol
    protocol = raw_record.get("protocol") or raw_record.get("proto") or None
    if protocol and isinstance(protocol, str):
        protocol = protocol.strip().upper()

    # 5. Event Type
    event_type = (
        raw_record.get("event_type")
        or raw_record.get("event")
        or raw_record.get("type")
        or raw_record.get("action")
        or "generic_log"
    )
    if isinstance(event_type, str):
        event_type = event_type.strip().lower()

    # 6. Raw Data preservation
    raw_payload = raw_record.get("raw_data") or raw_record

    return {
        "timestamp": timestamp,
        "source": str(source),
        "host": str(host) if host else None,
        "source_ip": str(source_ip) if source_ip else None,
        "destination_ip": str(destination_ip) if destination_ip else None,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": str(protocol) if protocol else None,
        "event_type": str(event_type),
        "raw_data": raw_payload,
    }
