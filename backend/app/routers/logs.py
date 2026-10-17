import json
import logging
from typing import Dict, Any, List, Tuple
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import insert

from app.database.connection import get_db
from app.models.event import Event
from app.ingestion.parser_registry import parse_and_normalize
from app.detection.detection_engine import run_detection

logger = logging.getLogger("routers.logs")

router = APIRouter(prefix="/api/logs", tags=["Log Ingestion"])

def bulk_insert_events(events_data: List[Dict[str, Any]], db: Session) -> Tuple[int, int]:
    """
    Inserts normalized events into Supabase PostgreSQL efficiently.
    Uses PostgreSQL COPY protocol via DBAPI connection (fastest for bulk data).
    Falls back to chunked multi-values insert if COPY is unavailable.
    Returns (inserted_count, failed_count).
    """
    if not events_data:
        return 0, 0

    # 1. Try PostgreSQL COPY protocol via raw DBAPI connection
    try:
        raw_conn = db.connection().connection
        if hasattr(raw_conn, "cursor"):
            with raw_conn.cursor() as cur:
                if hasattr(cur, "copy"):
                    with cur.copy(
                        "COPY events (source, host, source_ip, destination_ip, source_port, destination_port, protocol, event_type, raw_data, timestamp) FROM STDIN"
                    ) as copy:
                        for r in events_data:
                            raw_json = json.dumps(r["raw_data"]) if r.get("raw_data") is not None else None
                            ts = r["timestamp"]
                            ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
                            copy.write_row((
                                r["source"],
                                r.get("host"),
                                r.get("source_ip"),
                                r.get("destination_ip"),
                                r.get("source_port"),
                                r.get("destination_port"),
                                r.get("protocol"),
                                r["event_type"],
                                raw_json,
                                ts_str
                            ))
                    db.commit()
                    return len(events_data), 0
    except Exception as exc:
        logger.warning(f"Fast COPY failed ({exc}), falling back to chunked multi-values insert.")
        db.rollback()

    # 2. Fallback: Core multi-values insert in chunks of 500
    CHUNK_SIZE = 500
    inserted = 0
    failed = 0
    for i in range(0, len(events_data), CHUNK_SIZE):
        chunk = events_data[i : i + CHUNK_SIZE]
        try:
            db.execute(insert(Event), chunk)
            db.commit()
            inserted += len(chunk)
        except Exception as exc:
            db.rollback()
            for item in chunk:
                try:
                    db.execute(insert(Event), [item])
                    db.commit()
                    inserted += 1
                except Exception:
                    db.rollback()
                    failed += 1

    return inserted, failed

import os

ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".csv"}

@router.post("/upload")
def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Receives an uploaded security log file (.log, .txt, .json, .csv).
    Detects format, parses and normalizes records, batch inserts events into Supabase,
    and executes deterministic detection and incident correlation.
    
    Uses synchronous worker execution so the main event loop remains unblocked,
    ensuring health checks and other requests continue responding without delay.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file has no filename.")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext or 'unknown'}'. Only .log, .txt, .json, and .csv files are permitted."
        )

    try:
        content_bytes = file.file.read()
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(exc)}")

    # 1. Parse and normalize
    try:
        norm_events, fmt, total, parsed, failed = parse_and_normalize(file.filename, content)
    except Exception as exc:
        logger.error(f"Error parsing log file {file.filename}: {exc}", exc_info=True)
        return {
            "filename": file.filename,
            "format": "unknown",
            "total_records": 0,
            "parsed_records": 0,
            "failed_records": 1,
            "alerts_created": 0,
            "incidents_created": 0,
            "error": str(exc)
        }

    # 2. Batch insert valid events into Supabase PostgreSQL
    inserted_count = 0
    if norm_events:
        try:
            inserted_count, insert_failed = bulk_insert_events(norm_events, db)
            failed += insert_failed
        except Exception as exc:
            logger.error(f"Database error during bulk insert: {exc}", exc_info=True)
            raise HTTPException(status_code=500, detail="Database error persisting log events.")

    # 3. Run deterministic detection engine on the ingested batch
    alerts_created = 0
    incidents_created = 0
    if norm_events:
        try:
            # Build in-memory event objects for the rule engine
            event_objects = [Event(**e) for e in norm_events]
            alerts, incidents = run_detection(event_objects, db)
            alerts_created = len(alerts)
            incidents_created = len(incidents)
        except Exception as exc:
            logger.error(f"Error executing detection engine on uploaded events: {exc}", exc_info=True)

    return {
        "filename": file.filename,
        "format": fmt,
        "total_records": total,
        "parsed_records": inserted_count,
        "failed_records": failed,
        "alerts_created": alerts_created,
        "incidents_created": incidents_created
    }
