from typing import List, Dict, Any, Tuple
from app.ingestion.file_detector import detect_file_type
from app.ingestion.normalizer import normalize_event_dict
from app.ingestion.parsers.json_parser import parse_json_content
from app.ingestion.parsers.csv_parser import parse_csv_content
from app.ingestion.parsers.text_parser import parse_text_content
from app.ingestion.parsers.apache_parser import parse_apache_content
from app.ingestion.parsers.nginx_parser import parse_nginx_content

PARSERS = {
    "json": parse_json_content,
    "csv": parse_csv_content,
    "apache": parse_apache_content,
    "nginx": parse_nginx_content,
    "log": parse_text_content,
    "text": parse_text_content,
}

def parse_and_normalize(
    filename: str,
    content: str
) -> Tuple[List[Dict[str, Any]], str, int, int, int]:
    """
    Parses and normalizes file content into canonical event dictionaries.
    Returns:
        (normalized_events, detected_format, total_records, parsed_records, failed_records)
    """
    fmt = detect_file_type(filename, content)
    parser_fn = PARSERS.get(fmt, parse_text_content)

    raw_records, failed_count = parser_fn(content)

    normalized_events: List[Dict[str, Any]] = []
    for raw in raw_records:
        try:
            norm = normalize_event_dict(raw, default_source=f"upload_{fmt}")
            normalized_events.append(norm)
        except Exception:
            failed_count += 1

    parsed_count = len(normalized_events)
    total_records = parsed_count + failed_count

    return normalized_events, fmt, total_records, parsed_count, failed_count
