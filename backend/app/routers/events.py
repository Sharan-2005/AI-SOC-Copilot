from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from app.database.connection import get_db
from app.models.event import Event
from app.schemas.event import EventCreate, EventResponse, PaginatedEventsResponse

router = APIRouter(prefix="/api/events", tags=["Events"])

@router.get("", response_model=PaginatedEventsResponse)
def list_events(
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=200, description="Items per page"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    source: Optional[str] = Query(default=None, description="Filter by log source"),
    db: Session = Depends(get_db)
):
    """
    List security events with filtering and pagination.
    """
    query = select(Event)
    count_query = select(func.count()).select_from(Event)

    if source_ip:
        query = query.where(Event.source_ip == source_ip)
        count_query = count_query.where(Event.source_ip == source_ip)
    if event_type:
        query = query.where(Event.event_type == event_type)
        count_query = count_query.where(Event.event_type == event_type)
    if source:
        query = query.where(Event.source == source)
        count_query = count_query.where(Event.source == source)

    total = db.scalar(count_query) or 0
    offset = (page - 1) * limit
    events = db.scalars(query.order_by(desc(Event.timestamp)).offset(offset).limit(limit)).all()

    return PaginatedEventsResponse(
        total=total,
        page=page,
        limit=limit,
        items=events
    )

@router.get("/{event_id}", response_model=EventResponse)
def get_event(event_id: int, db: Session = Depends(get_db)):
    """
    Retrieve single event by ID with raw payload.
    """
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event with ID {event_id} not found")
    return event

from app.detection.detection_engine import run_detection

@router.post("", response_model=EventResponse, status_code=201)
def create_event(event_in: EventCreate, db: Session = Depends(get_db)):
    """
    Create a new security event record and evaluate against detection rules.
    """
    event_data = event_in.model_dump(exclude_unset=True)
    event = Event(**event_data)
    db.add(event)
    db.commit()
    db.refresh(event)

    # Run detection engine
    try:
        run_detection([event], db)
    except Exception:
        pass

    return event
