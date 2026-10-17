from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings
from app.database.connection import check_database_connection

router = APIRouter(prefix="/api", tags=["Health"])

@router.get("/health")
def health_check():
    """
    Returns system health and live PostgreSQL database connectivity status.
    """
    db_status = check_database_connection()
    return {
        "status": "ok",
        "service": "AI SOC Copilot Backend",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
