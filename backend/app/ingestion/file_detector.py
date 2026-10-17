import os
import re
from typing import Optional

def detect_file_type(filename: str, sample_content: str) -> str:
    """
    Detect log format from filename extension and content preview.
    Returns: 'json', 'csv', 'apache', 'nginx', 'text', or 'log'.
    """
    ext = os.path.splitext(filename)[1].lower()
    sample = sample_content.strip()

    # 1. Check by explicit extension
    if ext == ".json":
        return "json"
    if ext == ".csv":
        return "csv"

    # 2. Inspect content signatures
    if sample.startswith("[") or sample.startswith("{"):
        return "json"

    # Check for Apache / Nginx combined log format
    # Sample line: 127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
    combined_log_pattern = re.compile(
        r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ .*? \S+" \d{3} \S+'
    )
    first_line = sample.splitlines()[0] if sample.splitlines() else ""
    if combined_log_pattern.match(first_line):
        if "nginx" in filename.lower():
            return "nginx"
        return "apache"

    # Check for CSV characteristics (comma-separated with header)
    if "," in first_line and ("ip" in first_line.lower() or "time" in first_line.lower() or "event" in first_line.lower()):
        return "csv"

    if ext == ".log":
        return "log"
    if ext == ".txt":
        return "text"

    return "text"
