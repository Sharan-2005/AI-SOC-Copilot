import csv
import io
from typing import List, Dict, Any, Tuple

def parse_csv_content(content: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses CSV content into list of dictionaries.
    Returns (valid_records, failed_count).
    """
    records: List[Dict[str, Any]] = []
    failed_count = 0
    clean = content.strip()
    if not clean:
        return records, 0

    try:
        # Detect delimiter (comma or semicolon)
        sample = clean[:2048]
        delimiter = ";" if ";" in sample and "," not in sample else ","
        reader = csv.DictReader(io.StringIO(clean), delimiter=delimiter)
        
        for row_idx, row in enumerate(reader):
            try:
                # Clean up keys (strip whitespace, lowercasing)
                clean_row: Dict[str, Any] = {}
                for k, v in row.items():
                    if k is not None:
                        clean_row[k.strip().lower()] = v.strip() if isinstance(v, str) else v
                if clean_row:
                    records.append(clean_row)
                else:
                    failed_count += 1
            except Exception:
                failed_count += 1
    except Exception:
        failed_count += len(clean.splitlines())

    return records, failed_count
