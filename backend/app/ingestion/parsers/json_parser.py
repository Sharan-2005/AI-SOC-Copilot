import json
from typing import List, Dict, Any, Tuple

def parse_json_content(content: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses JSON content (JSON array, single JSON object, or NDJSON).
    Returns (valid_records, failed_count).
    """
    records: List[Dict[str, Any]] = []
    failed_count = 0
    clean = content.strip()
    if not clean:
        return records, 0

    # 1. Try parsing whole content as JSON array or single object
    try:
        parsed = json.loads(clean)
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    records.append(item)
                else:
                    failed_count += 1
            return records, failed_count
        elif isinstance(parsed, dict):
            return [parsed], 0
    except json.JSONDecodeError:
        pass

    # 2. Fallback: Parse line-delimited JSON (NDJSON)
    for line in clean.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        try:
            item = json.loads(line_clean)
            if isinstance(item, dict):
                records.append(item)
            else:
                failed_count += 1
        except Exception:
            failed_count += 1

    return records, failed_count
