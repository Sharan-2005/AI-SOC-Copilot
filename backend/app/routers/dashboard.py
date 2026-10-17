from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from app.database.connection import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns aggregated real-time metrics for the SOC Dashboard.
    """
    total_events = db.scalar(select(func.count(Event.id))) or 0
    total_alerts = db.scalar(select(func.count(Alert.id))) or 0
    critical_alerts = db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
    ) or 0
    open_incidents = db.scalar(
        select(func.count(Incident.id)).where(Incident.status.in_(["OPEN", "INVESTIGATING"]))
    ) or 0

    # Severity distribution
    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    ).all()
    severity_dict = {row[0]: row[1] for row in severity_rows}
    # Standardize all standard keys
    severity_distribution = [
        {"name": "CRITICAL", "value": severity_dict.get("CRITICAL", 0), "color": "#EF4444"},
        {"name": "HIGH", "value": severity_dict.get("HIGH", 0), "color": "#F97316"},
        {"name": "MEDIUM", "value": severity_dict.get("MEDIUM", 0), "color": "#F59E0B"},
        {"name": "LOW", "value": severity_dict.get("LOW", 0), "color": "#06B6D4"}
    ]

    # Top source IPs
    top_ip_rows = db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("count"))
        .where(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(desc("count"))
        .limit(5)
    ).all()
    top_source_ips = [
        {"ip": row[0], "count": row[1]} for row in top_ip_rows
    ]

    # Recent alerts for timeline activity
    recent_alerts = db.scalars(
        select(Alert).order_by(desc(Alert.timestamp)).limit(10)
    ).all()

    timeline_data = []
    for a in reversed(recent_alerts):
        timeline_data.append({
            "time": a.timestamp.strftime("%H:%M:%S") if a.timestamp else "N/A",
            "title": a.title,
            "severity": a.severity
        })

    return {
        "metrics": {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "open_incidents": open_incidents,
            "high_risk_ips": len(top_source_ips)
        },
        "severity_distribution": severity_distribution,
        "top_source_ips": top_source_ips,
        "timeline": timeline_data
    }
