import logging
from typing import List, Set
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, and_

from app.models.event import Event
from app.models.alert import Alert
from app.schemas.alert import AlertCreate
from app.detection.rules import (
    check_brute_force,
    check_port_scan,
    check_suspicious_commands,
    check_web_attacks,
    check_privilege_escalation,
)
from app.detection.correlator import correlate_alerts

logger = logging.getLogger("detection.engine")

def run_detection(events: List[Event], db: Session) -> List[Alert]:
    """
    Executes all deterministic detection rules against the provided events.
    Persists non-duplicate alerts to Supabase PostgreSQL and runs incident correlation.
    """
    if not events:
        return []

    # 1. Collect potential alerts from all rules
    candidates: List[AlertCreate] = []
    
    try:
        candidates.extend(check_brute_force(events, db))
        candidates.extend(check_port_scan(events, db))
        candidates.extend(check_suspicious_commands(events))
        candidates.extend(check_web_attacks(events))
        candidates.extend(check_privilege_escalation(events))
    except Exception as exc:
        logger.error(f"Error evaluating detection rules: {exc}", exc_info=True)

    created_alerts: List[Alert] = []
    
    # Pre-fetch existing alert event_ids in a single query
    cand_event_ids = [c.event_id for c in candidates if c.event_id]
    existing_event_ids = set()
    if cand_event_ids:
        existing_event_ids = set(
            db.scalars(
                select(Alert.event_id).where(Alert.event_id.in_(cand_event_ids))
            ).all()
        )

    # Track (source_ip, detection_rule) in this batch to avoid duplicate alert storms
    seen_in_batch = set()

    for cand in candidates:
        if cand.event_id and cand.event_id in existing_event_ids:
            continue
        
        dedup_key = (cand.source_ip, cand.detection_rule)
        if cand.source_ip and dedup_key in seen_in_batch:
            continue
        if cand.source_ip:
            seen_in_batch.add(dedup_key)

        alert = Alert(
            event_id=cand.event_id,
            title=cand.title,
            description=cand.description,
            source_ip=cand.source_ip,
            destination_ip=cand.destination_ip,
            severity=cand.severity,
            status=cand.status,
            detection_rule=cand.detection_rule,
            timestamp=cand.timestamp or datetime.now(timezone.utc),
        )
        db.add(alert)
        created_alerts.append(alert)

    correlated_incidents: List = []
    if created_alerts:
        db.commit()
        for a in created_alerts:
            db.refresh(a)

        # 2. Run incident correlation
        try:
            correlated_incidents = correlate_alerts(created_alerts, db)
        except Exception as exc:
            logger.error(f"Error during incident correlation: {exc}", exc_info=True)

    return created_alerts, correlated_incidents
