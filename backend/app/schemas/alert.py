from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict

class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    severity: str = "MEDIUM" # LOW, MEDIUM, HIGH, CRITICAL
    status: str = "OPEN"     # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    detection_rule: str
    event_id: Optional[int] = None

class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None

class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None

class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PaginatedAlertsResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[AlertResponse]
