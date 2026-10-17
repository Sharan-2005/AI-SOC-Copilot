from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, Text, Float, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="alert_associations")
    alert: Mapped["Alert"] = relationship("Alert", back_populates="incident_associations")

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False, index=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    alert_associations: Mapped[List[IncidentAlert]] = relationship(
        "IncidentAlert", back_populates="incident", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[List["AIAnalysis"]] = relationship(
        "AIAnalysis", back_populates="incident", cascade="all, delete-orphan"
    )
