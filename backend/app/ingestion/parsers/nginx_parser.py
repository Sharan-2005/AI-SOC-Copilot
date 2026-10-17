from typing import List, Dict, Any, Tuple
from app.ingestion.parsers.apache_parser import parse_apache_content

def parse_nginx_content(content: str) -> Tuple[List[Dict[str, Any]], int]:
    """Parses Nginx access logs."""
    records, failed = parse_apache_content(content)
    for r in records:
        r["source"] = "nginx_access"
    return records, failed
