from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, ConfigDict

class EventBase(BaseModel):
    source: str
    host: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str
    raw_data: Optional[Any] = None

class EventCreate(EventBase):
    timestamp: Optional[datetime] = None

class EventResponse(EventBase):
    id: int
    timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PaginatedEventsResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[EventResponse]
