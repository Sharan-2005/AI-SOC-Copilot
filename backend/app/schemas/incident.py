from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "MEDIUM"
    status: str = "OPEN"
    summary: Optional[str] = None
    confidence: Optional[float] = None

class IncidentCreate(IncidentBase):
    alert_ids: List[int] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    summary: Optional[str] = None
    confidence: Optional[float] = None
    alert_ids: Optional[List[int]] = None

class IncidentResponse(IncidentBase):
    id: int
    alert_ids: List[int] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PaginatedIncidentsResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[IncidentResponse]
