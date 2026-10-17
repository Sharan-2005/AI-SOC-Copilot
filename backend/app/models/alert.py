from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("events.id", ondelete="SET NULL"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False, index=True)
    detection_rule: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    event: Mapped[Optional["Event"]] = relationship("Event", back_populates="alerts")
    incident_associations: Mapped[List["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="alert", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[List["AIAnalysis"]] = relationship(
        "AIAnalysis", back_populates="alert", cascade="all, delete-orphan"
    )
