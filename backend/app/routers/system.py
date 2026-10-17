import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import delete
from app.database.connection import get_db
from app.models.ai_analysis import AIAnalysis
from app.models.incident import Incident, IncidentAlert
from app.models.alert import Alert
from app.models.event import Event
from app.models.threat_intel import ThreatIntelligence
from app.models.audit_log import AuditLog

logger = logging.getLogger("soc_copilot.system")

router = APIRouter(prefix="/api/system", tags=["System"])

@router.delete("/clear-data")
def clear_soc_data(db: Session = Depends(get_db)):
    """
    Clears demo/operational SOC data in strict foreign-key dependency order:
    1. AI analyses (associated with alerts/incidents)
    2. Incident-Alert junction records
    3. Alerts
    4. Incidents
    5. Events
    6. Threat intelligence demo records
    7. Demo operational audit logs
    
    Preserves:
    - Users / account records
    - MITRE ATT&CK techniques
    - Database schema and tables
    """
    try:
        # 1. AI analyses
        db.execute(delete(AIAnalysis))

        # 2. Incident-Alert associations
        db.execute(delete(IncidentAlert))

        # 3. Alerts
        db.execute(delete(Alert))

        # 4. Incidents
        db.execute(delete(Incident))

        # 5. Events
        db.execute(delete(Event))

        # 6. Temporary Threat Intelligence records
        db.execute(delete(ThreatIntelligence))

        # 7. Audit logs
        db.execute(delete(AuditLog))

        db.commit()
        logger.info("Successfully cleared all SOC operational data while preserving reference tables.")
        return {
            "status": "success",
            "message": "SOC data cleared successfully"
        }
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to clear SOC data: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear SOC data: {str(exc)}"
        )
