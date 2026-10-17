from datetime import datetime
from typing import Optional, Any
from sqlalchemy import String, Integer, DateTime, JSON, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(64), nullable=False) # 'ip', 'domain', 'hash'
    source: Mapped[str] = mapped_column(String(64), nullable=False) # 'virustotal', 'abuseipdb'
    reputation: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    raw_result: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("indicator", "source", name="uq_indicator_source"),
    )
