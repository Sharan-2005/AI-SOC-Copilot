from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from app.database.connection import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertUpdate, AlertResponse, PaginatedAlertsResponse

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("", response_model=PaginatedAlertsResponse)
def list_alerts(
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=200, description="Items per page"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP"),
    db: Session = Depends(get_db)
):
    """
    List alerts with filtering and pagination.
    """
    query = select(Alert)
    count_query = select(func.count()).select_from(Alert)

    if severity:
        query = query.where(Alert.severity == severity.upper())
        count_query = count_query.where(Alert.severity == severity.upper())
    if status_filter:
        query = query.where(Alert.status == status_filter.upper())
        count_query = count_query.where(Alert.status == status_filter.upper())
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
        count_query = count_query.where(Alert.source_ip == source_ip)

    total = db.scalar(count_query) or 0
    offset = (page - 1) * limit
    alerts = db.scalars(query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit)).all()

    return PaginatedAlertsResponse(
        total=total,
        page=page,
        limit=limit,
        items=alerts
    )

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Retrieve an alert by its ID.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")
    return alert

@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(alert_in: AlertCreate, db: Session = Depends(get_db)):
    """
    Create a new alert record.
    """
    alert_data = alert_in.model_dump(exclude_unset=True)
    alert = Alert(**alert_data)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, alert_in: AlertUpdate, db: Session = Depends(get_db)):
    """
    Update alert status, severity, or description.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")

    update_data = alert_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(alert, field, value)

    db.commit()
    db.refresh(alert)
    return alert

@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Delete an alert record.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")

    db.delete(alert)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
