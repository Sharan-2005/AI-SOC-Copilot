from datetime import datetime
from typing import Optional, Any
from sqlalchemy import String, Integer, DateTime, Text, Float, JSON, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True
    )
    incident_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
    )
    attack_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    recommendations: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    alert: Mapped[Optional["Alert"]] = relationship("Alert", back_populates="ai_analyses")
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="ai_analyses")
