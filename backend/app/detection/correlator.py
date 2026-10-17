import logging
from typing import List, Dict, Set
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, desc

from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert

logger = logging.getLogger("detection.correlator")

def correlate_alerts(new_alerts: List[Alert], db: Session) -> List[Incident]:
    """
    Correlates new alerts into Incidents based on shared source_ip and temporal proximity.
    Returns list of updated or newly created incidents.
    """
    if not new_alerts:
        return []

    correlated_incidents: List[Incident] = []
    
    # Group alerts by source_ip (ignore alerts with no source IP)
    alerts_by_ip: Dict[str, List[Alert]] = {}
    for alert in new_alerts:
        if alert.source_ip:
            alerts_by_ip.setdefault(alert.source_ip, []).append(alert)

    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

    for ip, ip_alerts in alerts_by_ip.items():
        # 1. Search for existing OPEN incident that already contains alerts from this source_ip
        existing_incident_id = db.scalar(
            select(IncidentAlert.incident_id)
            .join(Alert, IncidentAlert.alert_id == Alert.id)
            .join(Incident, IncidentAlert.incident_id == Incident.id)
            .where(
                and_(
                    Alert.source_ip == ip,
                    Incident.status == "OPEN",
                    Incident.created_at >= one_hour_ago
                )
            )
            .order_by(desc(Incident.created_at))
            .limit(1)
        )

        target_incident: Incident = None
        if existing_incident_id:
            target_incident = db.get(Incident, existing_incident_id)

        # 2. Also check if there are other recent alerts in DB for this source_ip
        recent_db_alerts = db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.source_ip == ip,
                    Alert.timestamp >= one_hour_ago
                )
            )
            .limit(20)
        ).all()

        combined_alerts = list({a.id: a for a in (list(recent_db_alerts) + ip_alerts)}.values())

        # If we have an existing open incident, attach the new alerts
        if target_incident:
            existing_alert_ids: Set[int] = set(
                db.scalars(
                    select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == target_incident.id)
                ).all()
            )

            for alert in ip_alerts:
                if alert.id not in existing_alert_ids:
                    db.add(IncidentAlert(incident_id=target_incident.id, alert_id=alert.id))
                    existing_alert_ids.add(alert.id)

            # Update incident summary
            unique_rules = {a.title for a in combined_alerts}
            target_incident.summary = (
                f"Correlated {len(existing_alert_ids)} alerts ({', '.join(sorted(unique_rules))}) "
                f"originating from {ip}."
            )
            target_incident.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(target_incident)
            correlated_incidents.append(target_incident)

        # Otherwise, if we have >= 1 alert from this IP, create a new Incident!
        elif len(combined_alerts) >= 1:
            unique_rules = {a.title for a in combined_alerts}
            severities = [a.severity for a in combined_alerts]
            highest_severity = "CRITICAL" if "CRITICAL" in severities else ("HIGH" if "HIGH" in severities else "MEDIUM")
            
            # Formulate clear, concise incident title
            title = f"Incident: Correlated Attack Activity from {ip}"
            if len(unique_rules) > 1:
                title = f"Incident: Multi-Stage Attack ({' -> '.join(list(unique_rules)[:2])}) from {ip}"

            new_incident = Incident(
                title=title,
                description=f"Correlated {len(combined_alerts)} security alerts originating from source IP {ip}.",
                severity=highest_severity,
                status="OPEN",
                summary=f"Automated correlation detected {len(combined_alerts)} related alerts ({', '.join(sorted(unique_rules))}) from {ip}.",
                confidence=min(0.95, 0.80 + (len(unique_rules) * 0.05)),
            )
            db.add(new_incident)
            db.flush() # get new_incident.id

            for alert in combined_alerts:
                db.add(IncidentAlert(incident_id=new_incident.id, alert_id=alert.id))

            db.commit()
            db.refresh(new_incident)
            correlated_incidents.append(new_incident)

    return correlated_incidents
