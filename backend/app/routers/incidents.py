from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select, func, desc
from app.database.connection import get_db
from app.models.incident import Incident, IncidentAlert
from app.models.alert import Alert
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    PaginatedIncidentsResponse
)

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

def _to_incident_response(incident: Incident) -> IncidentResponse:
    alert_ids = [assoc.alert_id for assoc in incident.alert_associations]
    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        summary=incident.summary,
        confidence=incident.confidence,
        alert_ids=alert_ids,
        created_at=incident.created_at,
        updated_at=incident.updated_at
    )

@router.get("", response_model=PaginatedIncidentsResponse)
def list_incidents(
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=200, description="Items per page"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (OPEN, INVESTIGATING, CONTAINED, RESOLVED)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    db: Session = Depends(get_db)
):
    """
    List incidents with filtering, pagination, and correlated alert IDs.
    """
    query = select(Incident).options(selectinload(Incident.alert_associations))
    count_query = select(func.count()).select_from(Incident)

    if status_filter:
        query = query.where(Incident.status == status_filter.upper())
        count_query = count_query.where(Incident.status == status_filter.upper())
    if severity:
        query = query.where(Incident.severity == severity.upper())
        count_query = count_query.where(Incident.severity == severity.upper())

    total = db.scalar(count_query) or 0
    offset = (page - 1) * limit
    incidents = db.scalars(query.order_by(desc(Incident.created_at)).offset(offset).limit(limit)).all()

    items = [_to_incident_response(inc) for inc in incidents]

    return PaginatedIncidentsResponse(
        total=total,
        page=page,
        limit=limit,
        items=items
    )

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """
    Retrieve an incident by ID including its correlated alert IDs.
    """
    query = select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alert_associations))
    incident = db.scalar(query)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident with ID {incident_id} not found")
    return _to_incident_response(incident)

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(incident_in: IncidentCreate, db: Session = Depends(get_db)):
    """
    Create a new incident and link initial alerts.
    """
    incident = Incident(
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        status=incident_in.status,
        summary=incident_in.summary,
        confidence=incident_in.confidence
    )
    db.add(incident)
    db.flush() # assign incident.id

    for alert_id in incident_in.alert_ids:
        # Verify alert exists
        if db.get(Alert, alert_id):
            assoc = IncidentAlert(incident_id=incident.id, alert_id=alert_id)
            db.add(assoc)

    db.commit()
    db.refresh(incident)
    # Re-fetch with associations
    return get_incident(incident.id, db)

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, incident_in: IncidentUpdate, db: Session = Depends(get_db)):
    """
    Update incident status, severity, summary, or correlated alert IDs.
    """
    query = select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alert_associations))
    incident = db.scalar(query)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident with ID {incident_id} not found")

    update_data = incident_in.model_dump(exclude_unset=True)
    alert_ids = update_data.pop("alert_ids", None)

    for field, value in update_data.items():
        setattr(incident, field, value)

    if alert_ids is not None:
        # Clear existing associations and re-create
        incident.alert_associations.clear()
        for alert_id in alert_ids:
            if db.get(Alert, alert_id):
                assoc = IncidentAlert(incident_id=incident.id, alert_id=alert_id)
                incident.alert_associations.append(assoc)

    db.commit()
    db.refresh(incident)
    return _to_incident_response(incident)
